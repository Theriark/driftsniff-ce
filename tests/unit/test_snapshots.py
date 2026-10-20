"""Tests for core/snapshots.py: manifests, store on change, resolving and garbage collection."""

import json
from hashlib import sha256

import pytest
import sqlalchemy as sa

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    Manifest,
    ManifestError,
    SnapshotOutcome,
    build_manifest,
    gc_unreferenced_states,
    latest_snapshot,
    load_manifest,
    resolve_current_state,
    store_if_changed,
)
from driftsniff.core.states import (
    StateMissingError,
    StoredDataError,
    compress_bytes,
    get_state,
    put_state,
)
from driftsniff.db import tables
from driftsniff.db.engine import Database

SOURCE_ID = 1
T1 = "2026-10-20T10:00:00Z"
T2 = "2026-10-20T10:05:00Z"
T3 = "2026-10-20T10:10:00Z"
T4 = "2026-10-20T10:15:00Z"


def net(key: str, **fields: JsonValue) -> CollectedObject:
    return CollectedObject(key, {"_id": key, "name": f"net {key}", **fields}, f"net {key}")


def collection(
    vlan: int = 20, order: tuple[str, ...] = ("r1", "r2", "r3")
) -> dict[str, CollectedResource]:
    rules = [CollectedObject(key, {"_id": key, "action": "accept"}, key) for key in order]
    return {
        "networks": CollectedResource([net("n1", vlan=vlan), net("n2", vlan=30)]),
        "firewall_rules": CollectedResource(rules, ordered=True),
    }


def manifest_of(
    vlan: int = 20,
    order: tuple[str, ...] = ("r1", "r2", "r3"),
    controller: str | None = "10.0.1",
) -> Manifest:
    return build_manifest(collection(vlan, order), controller_version=controller)


def count(database: Database, table: sa.Table) -> int:
    with database.read() as connection:
        return connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()


def save(database: Database, manifest: Manifest, taken_at: str = T1) -> SnapshotOutcome:
    with database.write() as connection:
        return store_if_changed(connection, SOURCE_ID, manifest, taken_at=taken_at)


# ---- build_manifest and the manifest layout --------------------------------------------------


def test_build_manifest_maps_every_object_key_to_its_state_hash() -> None:
    manifest = manifest_of()
    expected = sha256(canonical_dumps({"_id": "n1", "name": "net n1", "vlan": 20})).hexdigest()
    assert manifest.objects["networks"]["n1"] == expected
    assert set(manifest.objects["networks"]) == {"n1", "n2"}
    assert manifest.object_count == 5
    assert manifest.controller_version == "10.0.1"
    assert manifest.normaliser_version == 1
    assert manifest.state_hashes() <= manifest.pending_states.keys()
    assert manifest.names["networks"] == {"n1": "net n1", "n2": "net n2"}


def test_only_ordered_resources_get_a_position_list() -> None:
    manifest = manifest_of(order=("r3", "r1", "r2"))
    assert manifest.positions == {"firewall_rules": ["r3", "r1", "r2"]}


def test_a_duplicate_object_key_is_refused() -> None:
    resources = {"networks": CollectedResource([net("n1"), net("n1", vlan=2)])}
    with pytest.raises(ValueError, match="duplicate object key 'n1'"):
        build_manifest(resources, controller_version=None)


def test_the_manifest_hash_ignores_the_order_of_unordered_objects() -> None:
    forward = build_manifest(
        {"networks": CollectedResource([net("n1"), net("n2")])}, controller_version=None
    )
    backward = build_manifest(
        {"networks": CollectedResource([net("n2"), net("n1")])}, controller_version=None
    )
    assert forward.manifest_hash == backward.manifest_hash


def test_the_manifest_hash_follows_the_order_of_an_ordered_resource() -> None:
    in_order = manifest_of(order=("r1", "r2", "r3"))
    swapped = manifest_of(order=("r2", "r1", "r3"))
    assert in_order.manifest_hash != swapped.manifest_hash


def test_the_manifest_hash_covers_state_and_both_versions() -> None:
    base = manifest_of()
    assert manifest_of(vlan=21).manifest_hash != base.manifest_hash
    assert manifest_of(controller="10.0.2").manifest_hash != base.manifest_hash
    other_normaliser = build_manifest(
        collection(), controller_version="10.0.1", normaliser_version=2
    )
    assert other_normaliser.manifest_hash != base.manifest_hash


def test_a_manifest_round_trips_through_its_canonical_bytes() -> None:
    manifest = manifest_of(order=("r2", "r3", "r1"))
    parsed = Manifest.from_bytes(manifest.canonical_bytes())
    assert parsed == manifest
    assert parsed.pending_states == {}
    assert parsed.manifest_hash == manifest.manifest_hash
    assert json.loads(manifest.canonical_bytes())["format"] == 1


def good_document() -> dict[str, JsonValue]:
    return manifest_of().to_json()


def corrupt(mutation: str) -> bytes:
    document = json.loads(canonical_dumps(good_document()))
    resource = document["resources"]["firewall_rules"]
    match mutation:
        case "format":
            document["format"] = 2
        case "normaliser":
            document["normaliser_version"] = "1"
        case "normaliser-bool":
            document["normaliser_version"] = True
        case "controller":
            document["controller_version"] = 10
        case "resources":
            document["resources"] = []
        case "entry":
            document["resources"]["networks"] = "x"
        case "objects":
            resource["objects"] = ["r1"]
        case "hash":
            resource["objects"]["r1"] = "abc"
        case "hash-type":
            resource["objects"]["r1"] = 5
        case "order-type":
            resource["order"] = "r1r2r3"
        case "order-member":
            resource["order"] = ["r1", "r2", 3]
        case "order-duplicate":
            resource["order"] = ["r1", "r1", "r2"]
        case "order-set":
            resource["order"] = ["r1", "r2", "r9"]
        case "top":
            return b"[1]"
        case "json":
            return b"{not json"
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    "mutation",
    [
        "format",
        "normaliser",
        "normaliser-bool",
        "controller",
        "resources",
        "entry",
        "objects",
        "hash",
        "hash-type",
        "order-type",
        "order-member",
        "order-duplicate",
        "order-set",
        "top",
        "json",
    ],
)
def test_a_malformed_manifest_is_refused(mutation: str) -> None:
    with pytest.raises(ManifestError):
        Manifest.from_bytes(corrupt(mutation))


def test_a_manifest_without_a_controller_version_is_valid() -> None:
    manifest = manifest_of(controller=None)
    assert Manifest.from_bytes(manifest.canonical_bytes()).controller_version is None


def test_load_manifest_checks_the_recorded_hash() -> None:
    manifest = manifest_of()
    packed = compress_bytes(manifest.canonical_bytes())
    assert load_manifest(packed, manifest.manifest_hash) == manifest
    with pytest.raises(ManifestError, match="recorded hash"):
        load_manifest(packed, "0" * 64)
    with pytest.raises(StoredDataError):
        load_manifest(b"garbage", manifest.manifest_hash)


# ---- store_if_changed ------------------------------------------------------------------------


def test_the_first_snapshot_is_a_baseline_and_stores_every_state(store: Database) -> None:
    manifest = manifest_of()
    outcome = save(store, manifest)
    assert outcome.stored is True
    assert outcome.kind == "baseline"
    assert outcome.previous_snapshot_id is None
    assert outcome.snapshot_id == 1
    assert outcome.new_state_count == 5
    assert outcome.new_state_bytes > 0
    assert outcome.manifest_bytes > 0
    assert count(store, tables.object_states) == 5
    with store.read() as connection:
        row = connection.execute(sa.select(tables.snapshots)).one()
    assert row.source_id == SOURCE_ID
    assert row.taken_at == T1
    assert row.manifest_hash == manifest.manifest_hash
    assert row.controller_version == "10.0.1"
    assert row.normaliser_version == 1
    assert row.kind == "baseline"
    assert len(row.manifest_zstd) == outcome.manifest_bytes
    assert load_manifest(row.manifest_zstd, row.manifest_hash) == manifest


def test_an_unchanged_manifest_adds_nothing(store: Database) -> None:
    first = save(store, manifest_of(), T1)
    again = save(store, manifest_of(), T2)
    assert again == SnapshotOutcome(stored=False, previous_snapshot_id=first.snapshot_id)
    assert count(store, tables.snapshots) == 1
    assert count(store, tables.object_states) == 5


def test_a_change_adds_one_snapshot_and_only_the_changed_state(store: Database) -> None:
    first = save(store, manifest_of(vlan=20), T1)
    second = save(store, manifest_of(vlan=21), T2)
    assert second.stored is True
    assert second.kind == "normal"
    assert second.previous_snapshot_id == first.snapshot_id
    assert second.new_state_count == 1
    assert 0 < second.new_state_bytes < first.new_state_bytes
    assert count(store, tables.snapshots) == 2
    assert count(store, tables.object_states) == 6


def test_a_return_to_an_older_manifest_is_a_new_snapshot_without_new_states(
    store: Database,
) -> None:
    save(store, manifest_of(vlan=20), T1)
    save(store, manifest_of(vlan=21), T2)
    third = save(store, manifest_of(vlan=20), T3)
    assert third.stored is True
    assert third.kind == "normal"
    assert third.new_state_count == 0
    assert third.new_state_bytes == 0
    assert count(store, tables.snapshots) == 3
    assert count(store, tables.object_states) == 6


def test_a_new_position_order_is_a_change(store: Database) -> None:
    save(store, manifest_of(order=("r1", "r2", "r3")), T1)
    moved = save(store, manifest_of(order=("r3", "r1", "r2")), T2)
    assert moved.stored is True
    assert moved.new_state_count == 0


def test_a_normaliser_version_change_starts_a_new_baseline(store: Database) -> None:
    save(store, manifest_of(), T1)
    save(store, manifest_of(vlan=21), T2)
    upgraded = build_manifest(collection(), controller_version="10.0.1", normaliser_version=2)
    outcome = save(store, upgraded, T3)
    assert outcome.stored is True
    assert outcome.kind == "baseline"
    with store.read() as connection:
        kinds = connection.execute(
            sa.select(tables.snapshots.c.kind).order_by(tables.snapshots.c.id)
        ).scalars()
        assert list(kinds) == ["baseline", "normal", "baseline"]
        # A state keeps the version it was first stored with; its content is unchanged.
        versions = connection.execute(
            sa.select(tables.object_states.c.normaliser_version).distinct()
        ).scalars()
        assert set(versions) == {1}


def test_a_controller_version_change_is_a_normal_snapshot(store: Database) -> None:
    save(store, manifest_of(controller="10.0.1"), T1)
    outcome = save(store, manifest_of(controller="10.0.2"), T2)
    assert outcome.stored is True
    assert outcome.kind == "normal"
    assert outcome.new_state_count == 0


def test_snapshots_of_one_source_do_not_hide_those_of_another(store: Database) -> None:
    with store.write() as connection:
        connection.exec_driver_sql("INSERT INTO sources (id, name, type) VALUES (2, 'b', 'push')")
        first = store_if_changed(connection, 1, manifest_of(), taken_at=T1)
        second = store_if_changed(connection, 2, manifest_of(), taken_at=T1)
    assert first.stored is True
    assert second.stored is True
    assert second.kind == "baseline"
    assert second.new_state_count == 0


def test_a_manifest_that_was_not_built_here_is_refused(store: Database) -> None:
    parsed = Manifest.from_bytes(manifest_of().canonical_bytes())
    with pytest.raises(ValueError, match="not made by build_manifest"):
        save(store, parsed)
    assert count(store, tables.snapshots) == 0


# ---- latest_snapshot and resolve_current_state -----------------------------------------------


def test_latest_snapshot_is_none_before_the_first(store: Database) -> None:
    with store.read() as connection:
        assert latest_snapshot(connection, SOURCE_ID) is None
        assert resolve_current_state(connection, SOURCE_ID) is None


def test_latest_snapshot_is_the_newest_one(store: Database) -> None:
    save(store, manifest_of(vlan=20), T1)
    second = manifest_of(vlan=21)
    save(store, second, T2)
    with store.read() as connection:
        newest = latest_snapshot(connection, SOURCE_ID)
    assert newest is not None
    assert newest.snapshot_id == 2
    assert newest.taken_at == T2
    assert newest.kind == "normal"
    assert newest.manifest == second


def test_resolve_current_state_returns_exactly_the_normalised_input(store: Database) -> None:
    resources = collection(vlan=25, order=("r2", "r3", "r1"))
    save(store, build_manifest(resources, controller_version="10.0.1"), T1)
    with store.read() as connection:
        resolved = resolve_current_state(connection, SOURCE_ID)
    assert resolved is not None
    expected = {
        resource: {item.key: dict(item.state) for item in collected.objects}
        for resource, collected in resources.items()
    }
    assert resolved == expected
    # An ordered resource comes back in its stored order, the others by key.
    assert list(resolved["firewall_rules"]) == ["r2", "r3", "r1"]
    assert list(resolved["networks"]) == ["n1", "n2"]


def test_resolve_current_state_follows_the_newest_snapshot(store: Database) -> None:
    save(store, manifest_of(vlan=20), T1)
    save(store, manifest_of(vlan=21), T2)
    with store.read() as connection:
        resolved = resolve_current_state(connection, SOURCE_ID)
    assert resolved is not None
    assert resolved["networks"]["n1"]["vlan"] == 21


def test_resolving_a_manifest_whose_state_was_lost_fails_loudly(store: Database) -> None:
    manifest = manifest_of()
    save(store, manifest)
    with store.write() as connection:
        connection.execute(
            sa.delete(tables.object_states).where(
                tables.object_states.c.state_hash == manifest.objects["networks"]["n1"]
            )
        )
    with store.read() as connection, pytest.raises(StateMissingError):
        resolve_current_state(connection, SOURCE_ID)


# ---- garbage collection ----------------------------------------------------------------------


def test_gc_keeps_every_referenced_state(store: Database) -> None:
    save(store, manifest_of(vlan=20), T1)
    save(store, manifest_of(vlan=21), T2)
    with store.write() as connection:
        result = gc_unreferenced_states(connection)
    assert result.removed_count == 0
    assert result.freed_bytes == 0
    assert count(store, tables.object_states) == 6


def test_gc_removes_only_unreferenced_states(store: Database) -> None:
    save(store, manifest_of(vlan=20), T1)
    with store.write() as connection:
        orphan_a = put_state(connection, {"_id": "orphan-a"})
        orphan_b = put_state(connection, {"_id": "orphan-b", "pad": "x" * 200})
    with store.write() as connection:
        result = gc_unreferenced_states(connection)
    assert result.removed_count == 2
    assert result.freed_bytes == orphan_a.stored_bytes + orphan_b.stored_bytes
    assert count(store, tables.object_states) == 5
    with store.read() as connection:
        assert resolve_current_state(connection, SOURCE_ID) is not None
        with pytest.raises(StateMissingError):
            get_state(connection, orphan_a.state_hash)
    with store.write() as connection:
        assert gc_unreferenced_states(connection).removed_count == 0


def test_gc_frees_a_state_once_its_last_snapshot_is_gone(store: Database) -> None:
    save(store, manifest_of(vlan=20), T1)
    save(store, manifest_of(vlan=21), T2)
    old_state = sha256(canonical_dumps({"_id": "n1", "name": "net n1", "vlan": 20})).hexdigest()
    with store.write() as connection:
        connection.execute(sa.delete(tables.snapshots).where(tables.snapshots.c.id == 1))
        result = gc_unreferenced_states(connection)
    assert result.removed_count == 1
    with store.read() as connection, pytest.raises(StateMissingError):
        get_state(connection, old_state)
    assert count(store, tables.object_states) == 5


def test_gc_removes_in_batches(store: Database) -> None:
    with store.write() as connection:
        for number in range(1200):
            put_state(connection, {"_id": f"orphan-{number}"})
    with store.write() as connection:
        assert gc_unreferenced_states(connection).removed_count == 1200
    assert count(store, tables.object_states) == 0


def test_gc_deletes_nothing_when_a_manifest_is_damaged(store: Database) -> None:
    save(store, manifest_of(), T1)
    with store.write() as connection:
        put_state(connection, {"_id": "orphan"})
        connection.execute(sa.update(tables.snapshots).values(manifest_zstd=b"damaged"))
    with store.write() as connection, pytest.raises(StoredDataError):
        gc_unreferenced_states(connection)
    assert count(store, tables.object_states) == 6
