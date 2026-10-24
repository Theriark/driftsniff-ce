"""The snapshot history and the current configuration (P10-T7, backend slice).

The tests drive the services against a migrated database. Snapshots are stored through the real
``store_if_changed`` (and the object bookkeeping a run does), so the manifests and states are the
ones the product writes. Everything is synthetic; text that must never come back starts with
CANARY-.

The two acceptance checks of the plan have a test each:

1. the view equals ``resolve_current_state`` for the fixture:
   ``test_the_view_equals_resolve_current_state``;
2. a baseline marker is visible in the history:
   ``test_the_history_marks_the_baselines_and_the_current_snapshot``.
"""

import json
from collections.abc import Iterable, Iterator
from dataclasses import fields, is_dataclass
from typing import Any

import pytest
import sqlalchemy as sa
from markupsafe import Markup, escape

from driftsniff.core.canonical import JsonValue
from driftsniff.core.normalize import (
    NORMALISER_VERSION,
    CollectionMode,
    FieldClass,
    StaticTypeTable,
)
from driftsniff.core.objects import update_objects
from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    SnapshotOutcome,
    build_manifest,
    resolve_current_state,
    store_if_changed,
)
from driftsniff.db.engine import Database
from driftsniff.db.tables import change_events, snapshots
from driftsniff.history import configuration as configuration_module
from driftsniff.history.configuration import ConfigurationQueries, shipped_tables
from driftsniff.history.errors import StoredConfigurationError
from driftsniff.history.queries import HistoryQueries
from driftsniff.history.service import HistoryService
from driftsniff.history.views import (
    FINGERPRINT_SHOWN_CHARS,
    OBJECTS_PER_PAGE,
    PAGE_SIZE,
    ConfigObject,
    ConfigurationView,
    FieldView,
)
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import MasterKey
from driftsniff.web.templating import make_environment

SOURCE_ID = 1
FINGERPRINTER = Fingerprinter.from_master(MasterKey(bytes(range(32))))
T1 = "2026-10-20T10:00:00Z"
T2 = "2026-10-20T10:05:00Z"
T3 = "2026-10-20T10:10:00Z"
FINGERPRINT = "fp1:0a1b2c3d:" + "ab12cd34ef56" * 2 + "ab12cd34"
HIDDEN = "CANARY-search-secret-0005"
PAYLOADS = (
    "<script>alert('CANARY-xss-0')</script>",
    '"><img src=x onerror=alert("CANARY-xss-1")>',
    "<svg onload=alert('CANARY-xss-2')>",
    "javascript:alert(1) CANARY-xss-3",
    "{{7*7}} ${7*7} CANARY-xss-4",
)

NETWORKS = "networks"
FIREWALL = "firewall_rules"
NETWORK_TABLE = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "vlan": FieldClass.CONFIG,
        "enabled": FieldClass.CONFIG,
        "dns.servers": FieldClass.CONFIG,
        "tags": FieldClass.CONFIG,
        "owners.name": FieldClass.CONFIG,
        "limits.up": FieldClass.CONFIG,
        "passphrase": FieldClass.SECRET,
    },
    collection_modes={"tags": CollectionMode.SET},
)
FIREWALL_TABLE = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "action": FieldClass.CONFIG,
    },
)
TABLES = {NETWORKS: NETWORK_TABLE, FIREWALL: FIREWALL_TABLE}


def network(key: str, **extra: JsonValue) -> CollectedObject:
    state: dict[str, JsonValue] = {
        "_id": key,
        "name": f"net {key}",
        "vlan": 20,
        "enabled": True,
        "dns": {"servers": ["10.0.0.1", "10.0.0.2"], "search": []},
        "tags": ["a", "b"],
        "owners": [{"name": "ann"}, {"name": "bob"}],
        "limits": {"up": 5.5},
        **extra,
    }
    return CollectedObject(key, state, f"net {key}")


def rule(key: str) -> CollectedObject:
    return CollectedObject(key, {"_id": key, "name": f"rule {key}", "action": "accept"}, key)


def collection(
    vlan: int = 20, order: tuple[str, ...] = ("r1", "r2", "r3")
) -> dict[str, CollectedResource]:
    return {
        NETWORKS: CollectedResource([network("n1", vlan=vlan), network("n2")]),
        FIREWALL: CollectedResource([rule(key) for key in order], ordered=True),
    }


def save(
    store: Database,
    resources: dict[str, CollectedResource],
    taken_at: str = T1,
    *,
    controller: str | None = "10.0.1",
    source_id: int = SOURCE_ID,
    normaliser_version: int = NORMALISER_VERSION,
) -> SnapshotOutcome:
    """Store a snapshot and the object bookkeeping of a run."""
    manifest = build_manifest(
        resources, controller_version=controller, normaliser_version=normaliser_version
    )
    with store.write() as connection:
        outcome = store_if_changed(connection, source_id, manifest, taken_at=taken_at)
        update_objects(connection, source_id, manifest, seen_at=taken_at)
    return outcome


def add_source(store: Database, source_id: int, name: str, source_type: str) -> None:
    with store.write() as connection:
        connection.execute(
            sa.text("INSERT INTO sources (id, name, type) VALUES (:id, :name, :type)"),
            {"id": source_id, "name": name, "type": source_type},
        )


def add_snapshot_rows(store: Database, count: int, *, source_id: int = SOURCE_ID) -> None:
    """Rows of the ``snapshots`` table only: enough for the history, which opens no manifest."""
    with store.write() as connection:
        for number in range(count):
            connection.execute(
                sa.insert(snapshots).values(
                    source_id=source_id,
                    taken_at=f"2026-10-20T10:{number:02d}:00Z",
                    manifest_hash=f"m{number}",
                    manifest_zstd=b"x",
                    normaliser_version=1,
                    kind="normal",
                )
            )


def add_change_event(store: Database, snapshot_id: int) -> None:
    with store.write() as connection:
        connection.execute(
            sa.insert(change_events).values(
                source_id=SOURCE_ID,
                snapshot_id=snapshot_id,
                window_start=T1,
                window_end=T2,
                max_severity="low",
                item_count=0,
                summary="a change",
                rule_pack_version="pack-1",
                status="open",
                created_at=T2,
            )
        )


def config_view(
    store: Database,
    *,
    source_id: int = SOURCE_ID,
    tables: dict[str, StaticTypeTable] | None = None,
    **query: Any,
) -> ConfigurationView:
    queries = ConfigurationQueries(store, FINGERPRINTER, TABLES if tables is None else tables)
    view = queries.current(source_id, **query)
    assert view is not None
    return view


def leaves(value: JsonValue, path: str = "") -> Iterator[tuple[str, str]]:
    """The shown fields of a stored value, written out independently of the service."""
    if isinstance(value, dict):
        if not value:
            yield path, "{}"
        for key, member in value.items():
            yield from leaves(member, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        if not value:
            yield path, "[]"
        for position, member in enumerate(value, start=1):
            yield from leaves(member, f"{path}[{position}]")
    elif isinstance(value, str):
        yield path, value
    else:
        yield path, json.dumps(value)


def shown(obj: ConfigObject) -> list[tuple[str, str | None]]:
    return [(item.path, item.value) for item in obj.fields]


def walk_text(value: Any) -> Iterable[Any]:
    """Every value inside a view: dataclass fields, tuples, lists and dicts, depth first."""
    yield value
    if is_dataclass(value) and not isinstance(value, type):
        for part in fields(value):
            yield from walk_text(getattr(value, part.name))
    elif isinstance(value, tuple | list):
        for member in value:
            yield from walk_text(member)
    elif isinstance(value, dict):
        for key, member in value.items():
            yield from walk_text(key)
            yield from walk_text(member)


def field_of(obj: ConfigObject, path: str) -> FieldView:
    return next(item for item in obj.fields if item.path == path)


# -- the history ------------------------------------------------------------------------------


def test_the_history_marks_the_baselines_and_the_current_snapshot(store: Database) -> None:
    first = save(store, collection(vlan=20), T1)
    second = save(store, collection(vlan=30), T2, controller="10.0.2")
    third = save(store, collection(vlan=40), T3, normaliser_version=NORMALISER_VERSION + 1)
    assert (first.kind, second.kind, third.kind) == ("baseline", "normal", "baseline")
    view = HistoryQueries(store).list_snapshots(SOURCE_ID)
    assert view is not None
    ids = [row.id for row in view.rows]
    assert ids == [third.snapshot_id, second.snapshot_id, first.snapshot_id]
    assert [row.is_baseline for row in view.rows] == [True, False, True]
    assert [row.kind for row in view.rows] == ["baseline", "normal", "baseline"]
    assert [row.is_current for row in view.rows] == [True, False, False]
    assert [row.taken_at for row in view.rows] == [T3, T2, T1]
    assert [row.controller_version for row in view.rows] == ["10.0.1", "10.0.2", "10.0.1"]
    assert [row.normaliser_version for row in view.rows] == [
        NORMALISER_VERSION + 1,
        NORMALISER_VERSION,
        NORMALISER_VERSION,
    ]
    assert (view.total, view.baseline_count, view.page, view.pages) == (3, 2, 1, 1)
    assert view.source.name == "lab-controller"


def test_a_source_without_a_snapshot_has_an_empty_history(store: Database) -> None:
    view = HistoryQueries(store).list_snapshots(SOURCE_ID)
    assert view is not None
    assert (view.rows, view.total, view.baseline_count, view.pages) == ((), 0, 0, 1)


def test_an_unknown_source_has_no_history_and_no_configuration(store: Database) -> None:
    assert HistoryQueries(store).list_snapshots(99999) is None
    assert ConfigurationQueries(store, FINGERPRINTER, TABLES).current(99999) is None


def test_the_history_pages_by_fifty_and_clamps_the_page(store: Database) -> None:
    add_snapshot_rows(store, PAGE_SIZE + 3)
    queries = HistoryQueries(store)
    first = queries.list_snapshots(SOURCE_ID)
    assert first is not None
    assert (first.total, first.pages, first.page, len(first.rows)) == (53, 2, 1, 50)
    assert first.rows[0].taken_at == "2026-10-20T10:52:00Z"
    last = queries.list_snapshots(SOURCE_ID, page=2)
    assert last is not None
    assert (last.page, len(last.rows), last.rows[-1].taken_at) == (2, 3, "2026-10-20T10:00:00Z")
    past = queries.list_snapshots(SOURCE_ID, page=99)
    below = queries.list_snapshots(SOURCE_ID, page=0)
    assert past is not None and below is not None
    assert (past.page, below.page) == (2, 1)
    # Only the newest snapshot of the whole history is current, not the top of every page.
    assert [row.is_current for row in first.rows].count(True) == 1
    assert not any(row.is_current for row in last.rows)


def test_each_snapshot_counts_the_changes_found_at_it(store: Database) -> None:
    first = save(store, collection(vlan=20), T1)
    second = save(store, collection(vlan=30), T2)
    assert first.snapshot_id is not None and second.snapshot_id is not None
    add_change_event(store, second.snapshot_id)
    add_change_event(store, second.snapshot_id)
    view = HistoryQueries(store).list_snapshots(SOURCE_ID)
    assert view is not None
    assert [row.change_count for row in view.rows] == [2, 0]


def test_the_history_reads_the_size_of_the_manifest_without_opening_it(store: Database) -> None:
    add_snapshot_rows(store, 1)
    view = HistoryQueries(store).list_snapshots(SOURCE_ID)
    assert view is not None
    assert view.rows[0].manifest_bytes == 1


def test_the_source_picker_counts_snapshots_and_baselines(store: Database) -> None:
    add_source(store, 2, "another", "push")
    add_source(store, 3, "empty", "xo")
    save(store, collection(vlan=20), T1)
    save(store, collection(vlan=30), T2)
    save(store, collection(vlan=40), T3, normaliser_version=NORMALISER_VERSION + 1)
    save(store, collection(), T1, source_id=2)
    rows = {row.name: row for row in HistoryQueries(store).list_sources()}
    assert [row.name for row in HistoryQueries(store).list_sources()] == [
        "another",
        "empty",
        "lab-controller",
    ]
    assert (rows["lab-controller"].snapshot_count, rows["lab-controller"].baseline_count) == (3, 2)
    assert rows["lab-controller"].latest_taken_at == T3
    assert (rows["another"].snapshot_count, rows["another"].baseline_count) == (1, 1)
    assert (rows["empty"].snapshot_count, rows["empty"].baseline_count) == (0, 0)
    assert rows["empty"].latest_taken_at is None
    assert (rows["empty"].type, rows["empty"].enabled) == ("xo", True)


def test_a_controller_version_that_looks_like_a_credential_is_scrubbed(store: Database) -> None:
    canary = "gh" + "p_" + "CANARY-0123456789abcdef01234567"
    save(store, collection(), T1, controller=canary)
    view = HistoryQueries(store).list_snapshots(SOURCE_ID)
    assert view is not None
    assert "CANARY" not in str(view)
    assert view.rows[0].controller_version == "***REDACTED***"


# -- the configuration ------------------------------------------------------------------------


def test_the_view_equals_resolve_current_state(store: Database) -> None:
    save(store, collection(vlan=20), T1)
    save(store, collection(vlan=30, order=("r3", "r1", "r2")), T2)
    with store.read() as connection:
        resolved = resolve_current_state(connection, SOURCE_ID)
    assert resolved is not None
    seen_resources = []
    for resource, states in resolved.items():
        view = config_view(store, resource=resource)
        seen_resources.append(resource)
        assert view.selected_resource == resource
        assert view.total == len(states)
        assert [obj.key for obj in view.objects] == list(states)
        for obj in view.objects:
            assert shown(obj) == list(leaves(states[obj.key])), (resource, obj.key)
    assert seen_resources == [FIREWALL, NETWORKS]
    # The newest snapshot is the one shown, not an older one.
    view = config_view(store, resource=NETWORKS)
    assert view.snapshot is not None and view.snapshot.taken_at == T2
    assert field_of(view.objects[0], "vlan").value == "30"
    assert [resource.object_count for resource in view.resources] == [3, 2]


def test_every_field_path_and_value_of_the_fixture_is_shown(store: Database) -> None:
    save(store, collection(), T1)
    view = config_view(store, resource=NETWORKS)
    first = view.objects[0]
    assert shown(first) == [
        ("_id", "n1"),
        ("dns.search", "[]"),
        ("dns.servers[1]", "10.0.0.1"),
        ("dns.servers[2]", "10.0.0.2"),
        ("enabled", "true"),
        ("limits.up", "5.5"),
        ("name", "net n1"),
        ("owners[1].name", "ann"),
        ("owners[2].name", "bob"),
        ("tags[1]", "a"),
        ("tags[2]", "b"),
        ("vlan", "20"),
    ]
    assert first.name == "net n1"
    assert {item.field_class for item in first.fields} == {"config"}
    assert not any(item.secret or item.fingerprint for item in first.fields)


def test_an_ordered_resource_is_shown_in_order_with_its_positions(store: Database) -> None:
    save(store, collection(order=("r3", "r1", "r2")), T1)
    view = config_view(store, resource=FIREWALL)
    assert [(obj.key, obj.position) for obj in view.objects] == [("r3", 1), ("r1", 2), ("r2", 3)]
    summaries = {summary.resource: summary for summary in view.resources}
    assert summaries[FIREWALL].ordered is True
    assert summaries[NETWORKS].ordered is False
    unordered = config_view(store, resource=NETWORKS)
    assert [obj.position for obj in unordered.objects] == [None, None]


def test_a_new_order_shows_as_the_new_order(store: Database) -> None:
    save(store, collection(order=("r1", "r2", "r3")), T1)
    save(store, collection(order=("r2", "r3", "r1")), T2)
    view = config_view(store, resource=FIREWALL)
    assert [obj.key for obj in view.objects] == ["r2", "r3", "r1"]


def test_lists_say_whether_their_order_means_something(store: Database) -> None:
    save(store, collection(), T1)
    view = config_view(store, resource=NETWORKS)
    first = view.objects[0]
    assert field_of(first, "dns.servers[1]").ordered is True
    assert field_of(first, "owners[1].name").ordered is True
    assert field_of(first, "tags[1]").ordered is False
    assert field_of(first, "name").ordered is False


def test_a_resource_that_is_not_asked_for_selects_the_first(store: Database) -> None:
    save(store, collection(), T1)
    for asked in (None, "no-such-resource", ""):
        view = config_view(store, resource=asked)
        assert view.selected_resource == FIREWALL
    assert [summary.resource for summary in config_view(store).resources] == [FIREWALL, NETWORKS]


def test_the_configuration_pages_by_fifty_with_absolute_positions(store: Database) -> None:
    keys = tuple(f"r{number:03d}" for number in range(OBJECTS_PER_PAGE + 3))
    save(store, {FIREWALL: CollectedResource([rule(key) for key in keys], ordered=True)}, T1)
    first = config_view(store)
    assert (first.total, first.pages, first.page, len(first.objects)) == (53, 2, 1, 50)
    second = config_view(store, page=2)
    assert (second.page, [obj.key for obj in second.objects]) == (2, list(keys[50:]))
    assert [obj.position for obj in second.objects] == [51, 52, 53]
    assert config_view(store, page=99).page == 2
    assert config_view(store, page=-4).page == 1


def test_before_the_first_snapshot_the_configuration_is_empty(store: Database) -> None:
    view = config_view(store)
    assert view.snapshot is None
    assert (view.resources, view.selected_resource, view.objects, view.total) == ((), None, (), 0)
    assert (view.page, view.pages) == (1, 1)


def test_a_snapshot_without_objects_is_empty_but_has_its_snapshot(store: Database) -> None:
    save(store, {}, T1)
    view = config_view(store)
    assert view.snapshot is not None and view.snapshot.kind == "baseline"
    assert (view.resources, view.selected_resource, view.objects) == ((), None, ())


def test_the_snapshot_of_the_view_names_its_controller_and_kind(store: Database) -> None:
    outcome = save(store, collection(), T1, controller="10.0.7")
    view = config_view(store)
    assert view.snapshot is not None
    assert view.snapshot.id == outcome.snapshot_id
    assert (view.snapshot.taken_at, view.snapshot.kind) == (T1, "baseline")
    assert view.snapshot.controller_version == "10.0.7"


# -- secrets ----------------------------------------------------------------------------------


def test_a_fingerprint_marker_shows_its_short_fingerprint_only(store: Database) -> None:
    save(store, {NETWORKS: CollectedResource([network("n1", passphrase=FINGERPRINT)])}, T1)
    obj = config_view(store, resource=NETWORKS).objects[0]
    item = field_of(obj, "passphrase")
    assert item.secret is True
    assert item.field_class == "secret"
    assert item.value is None
    assert item.fingerprint == "ab12cd34ef56"
    assert len(item.fingerprint) == FINGERPRINT_SHOWN_CHARS
    assert FINGERPRINT not in str(obj)


def test_a_marker_in_a_field_the_table_calls_config_is_still_a_secret(store: Database) -> None:
    save(store, {NETWORKS: CollectedResource([network("n1", name=FINGERPRINT)])}, T1)
    item = field_of(config_view(store, resource=NETWORKS).objects[0], "name")
    assert (item.secret, item.value, item.fingerprint) == (True, None, "ab12cd34ef56")


def test_a_secret_value_stored_in_clear_is_never_shown(store: Database) -> None:
    canary = "CANARY-secret-in-clear-0001"
    save(store, {NETWORKS: CollectedResource([network("n1", passphrase=canary)])}, T1)
    view = config_view(store, resource=NETWORKS)
    item = field_of(view.objects[0], "passphrase")
    assert item.value is None and item.secret is True
    expected = FINGERPRINTER.fingerprint(NETWORKS, "passphrase", canary)
    assert item.fingerprint == expected.short(FINGERPRINT_SHOWN_CHARS)
    assert canary not in str(view)


def test_an_unclassified_field_is_stored_in_clear_and_shown_as_a_fingerprint(
    store: Database,
) -> None:
    canary = "CANARY-unclassified-0002"
    stored = network("n1", extra=canary, deep={"k": canary})
    save(store, {NETWORKS: CollectedResource([stored])}, T1)
    view = config_view(store, resource=NETWORKS)
    extra = field_of(view.objects[0], "extra")
    deep = field_of(view.objects[0], "deep.k")
    for item in (extra, deep):
        assert (item.field_class, item.secret, item.value) == ("unclassified", True, None)
    assert extra.fingerprint == FINGERPRINTER.fingerprint(NETWORKS, "extra", canary).short(12)
    assert deep.fingerprint == FINGERPRINTER.fingerprint(NETWORKS, "deep.k", canary).short(12)
    assert canary not in str(view)


def test_a_resource_without_a_type_table_shows_fingerprints_only(store: Database) -> None:
    canary = "CANARY-no-table-0003"
    state: dict[str, JsonValue] = {"_id": "n1", "name": "plain", "note": canary}
    save(store, {"mystery": CollectedResource([CollectedObject("n1", state)])}, T1)
    view = config_view(store, resource="mystery")
    assert all(item.secret and item.value is None for item in view.objects[0].fields)
    assert canary not in str(view)
    assert view.objects[0].fields


def test_a_secret_container_is_one_masked_field(store: Database) -> None:
    table = StaticTypeTable(
        object_key_field="_id",
        name_field="name",
        field_classes={"_id": FieldClass.CONFIG, "creds": FieldClass.SECRET},
    )
    canary = "CANARY-container-0004"
    state: dict[str, JsonValue] = {"_id": "k1", "creds": {"user": "u", "password": canary}}
    save(store, {"keys": CollectedResource([CollectedObject("k1", state)])}, T1)
    view = config_view(store, resource="keys", tables={"keys": table})
    assert [(item.path, item.secret) for item in view.objects[0].fields] == [
        ("_id", False),
        ("creds", True),
    ]
    assert canary not in str(view)


def test_the_hidden_by_xo_fields_are_named_for_an_xo_source_only(store: Database) -> None:
    add_source(store, 2, "xo-lab", "xo")
    state: dict[str, JsonValue] = {"id": "s1", "label": "lab", "host": "xo.example.invalid"}
    save(store, {"servers": CollectedResource([CollectedObject("s1", state)])}, T1, source_id=2)
    save(store, {"servers": CollectedResource([CollectedObject("s1", state)])}, T1)
    queries = ConfigurationQueries(store, FINGERPRINTER)
    xo = queries.current(2)
    push = queries.current(SOURCE_ID)
    assert xo is not None and push is not None
    assert xo.resources[0].hidden_by_xo == ("password", "token")
    assert push.resources[0].hidden_by_xo == ()
    assert tuple(sorted(shipped_tables()["servers"].hidden_by_xo)) == ("password", "token")


def test_a_field_xo_hides_is_marked_when_the_state_holds_a_fingerprint(store: Database) -> None:
    add_source(store, 2, "xo-lab", "xo")
    state: dict[str, JsonValue] = {"id": "s1", "label": "lab", "password": FINGERPRINT}
    save(store, {"servers": CollectedResource([CollectedObject("s1", state)])}, T1, source_id=2)
    view = ConfigurationQueries(store, FINGERPRINTER).current(2)
    assert view is not None
    by_path = {item.path: item for item in view.objects[0].fields}
    assert by_path["password"].hidden_by_xo is True
    assert by_path["password"].secret is True
    assert by_path["label"].hidden_by_xo is False


def test_the_shipped_tables_load_and_cover_the_xo_servers() -> None:
    assert shipped_tables() is shipped_tables()
    assert shipped_tables().keys() == load_rules().type_tables.keys()
    assert "servers" in shipped_tables()


# -- search -----------------------------------------------------------------------------------


def named(key: str, name: str, **extra: JsonValue) -> CollectedObject:
    state: dict[str, JsonValue] = {"_id": key, "name": name, **extra}
    return CollectedObject(key, state, name)


def search_fixture(store: Database) -> None:
    objects_ = [
        named("a1", "Guest WiFi", vlan=20, owners=[{"name": "ann"}]),
        named("b2", "Office", vlan=30, passphrase=HIDDEN),
        named("c3", "100% trusted_lan", vlan=40),
        named("d4", "trustedXlan", vlan=50),
    ]
    save(store, {NETWORKS: CollectedResource(objects_)}, T1)


def found(store: Database, text: str, **query: Any) -> list[str]:
    return [obj.key for obj in config_view(store, resource=NETWORKS, search=text, **query).objects]


def test_search_matches_the_key_the_name_the_path_and_the_shown_value(store: Database) -> None:
    search_fixture(store)
    assert found(store, "b2") == ["b2"]
    assert found(store, "guest") == ["a1"]
    assert found(store, "OFFICE") == ["b2"]
    assert found(store, "owners") == ["a1"]
    assert found(store, "ann") == ["a1"]
    assert found(store, "30") == ["b2"]
    assert found(store, "no such text") == []
    assert found(store, "") == ["a1", "b2", "c3", "d4"]


def test_search_is_literal_and_ignores_the_ends_of_the_text(store: Database) -> None:
    search_fixture(store)
    assert found(store, "%") == ["c3"]
    assert found(store, "trusted_lan") == ["c3"]
    assert found(store, "  guest  ") == ["a1"]
    assert config_view(store, resource=NETWORKS, search="  guest  ").search == "guest"


def test_search_never_matches_a_hidden_value(store: Database) -> None:
    search_fixture(store)
    assert found(store, HIDDEN) == []
    assert found(store, "search-secret") == []
    # The field's own name is shown, so the object is found by it.
    assert found(store, "passphrase") == ["b2"]


def test_search_totals_pages_and_says_when_it_stopped_early(
    store: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys = [f"o{number:03d}" for number in range(OBJECTS_PER_PAGE + 5)]
    save(store, {NETWORKS: CollectedResource([named(key, f"site {key}") for key in keys])}, T1)
    view = config_view(store, resource=NETWORKS, search="site")
    assert (view.total, view.pages, len(view.objects), view.search_truncated) == (55, 2, 50, False)
    second = config_view(store, resource=NETWORKS, search="site", page=2)
    assert [obj.key for obj in second.objects] == keys[50:]
    monkeypatch.setattr(configuration_module, "SEARCH_SCAN_LIMIT", 10)
    limited = config_view(store, resource=NETWORKS, search="site")
    assert (limited.total, limited.search_truncated) == (10, True)
    plain = config_view(store, resource=NETWORKS)
    assert plain.search_truncated is False and plain.total == 55


def test_search_is_cut_to_its_longest_length(store: Database) -> None:
    search_fixture(store)
    view = config_view(store, resource=NETWORKS, search="x" * 500)
    assert len(view.search) == 200


# -- damaged data and plain text --------------------------------------------------------------


def test_a_damaged_manifest_is_a_fixed_refusal_that_quotes_nothing(store: Database) -> None:
    save(store, collection(), T1)
    with store.write() as connection:
        connection.execute(sa.update(snapshots).values(manifest_zstd=b"CANARY-junk"))
    with pytest.raises(StoredConfigurationError) as raised:
        ConfigurationQueries(store, FINGERPRINTER, TABLES).current(SOURCE_ID)
    assert str(raised.value) == "the stored configuration cannot be read"
    assert "CANARY" not in str(raised.value)


def test_a_missing_state_is_the_same_fixed_refusal(store: Database) -> None:
    save(store, collection(), T1)
    with store.write() as connection:
        connection.exec_driver_sql("DELETE FROM object_states")
    with pytest.raises(StoredConfigurationError):
        ConfigurationQueries(store, FINGERPRINTER, TABLES).current(SOURCE_ID)


def plant_payloads(store: Database) -> None:
    objects_: list[CollectedObject] = []
    for number, text in enumerate(PAYLOADS):
        state: dict[str, JsonValue] = {"_id": f"p{number}", "name": text, "note": [text]}
        objects_.append(CollectedObject(f"p{number}", state, text))
    save(store, {NETWORKS: CollectedResource(objects_)}, T1, controller=PAYLOADS[0])


def test_every_text_is_plain_text_and_prints_escaped(store: Database) -> None:
    plant_payloads(store)
    declared = {
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "note": FieldClass.CONFIG,
    }
    tables = {NETWORKS: StaticTypeTable(field_classes=declared)}
    view = config_view(store, resource=NETWORKS, tables=tables)
    # The contract: stored characters come back as they were, as plain str, never as Markup.
    assert not any(isinstance(value, Markup) for value in walk_text(view))
    assert [obj.name for obj in view.objects] == list(PAYLOADS)
    assert [field_of(obj, "name").value for obj in view.objects] == list(PAYLOADS)
    assert [field_of(obj, "note[1]").value for obj in view.objects] == list(PAYLOADS)
    template = make_environment().from_string(
        "{% for obj in view.objects %}{{ obj.name }} {{ obj.key }}"
        "{% for item in obj.fields %} {{ item.path }}={{ item.value }}{% endfor %}{% endfor %}"
    )
    html = template.render(view=view)
    for tag in ("<script", "<img", "<svg"):
        assert tag not in html
    for text in PAYLOADS:
        assert str(escape(text)) in html
    assert html.count("&lt;script&gt;") >= 3


def test_the_history_texts_are_plain_text_too(store: Database) -> None:
    plant_payloads(store)
    view = HistoryQueries(store).list_snapshots(SOURCE_ID)
    assert view is not None
    assert not any(isinstance(value, Markup) for value in walk_text(view))
    html = make_environment().from_string("{{ row.controller_version }}").render(row=view.rows[0])
    assert "<script" not in html
    assert str(escape(PAYLOADS[0])) in html


def test_a_field_name_with_markup_prints_escaped(store: Database) -> None:
    state: dict[str, JsonValue] = {"_id": "k", PAYLOADS[0]: "v", "name": "n"}
    save(store, {NETWORKS: CollectedResource([CollectedObject("k", state, "n")])}, T1)
    view = config_view(store, resource=NETWORKS)
    paths = [item.path for item in view.objects[0].fields]
    assert PAYLOADS[0] in paths
    template = make_environment().from_string("{% for i in obj.fields %}{{ i.path }}{% endfor %}")
    assert "<script" not in template.render(obj=view.objects[0])


# -- the service ------------------------------------------------------------------------------


def test_the_service_builds_both_reads_on_one_database(store: Database) -> None:
    save(store, collection(), T1)
    service = HistoryService(store, FINGERPRINTER, TABLES)
    sources = service.history.list_sources()
    assert [row.name for row in sources] == ["lab-controller"]
    view = service.configuration.current(SOURCE_ID)
    assert view is not None and view.selected_resource == FIREWALL
