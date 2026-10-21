"""Tests for core/diff.py: object matching, field walking, secrets, schema drift and baselines."""

import json
from collections.abc import Mapping

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import (
    MIN_DRIFT_OBJECTS,
    SCHEMA_DRIFT_RULE_ID,
    ChangeItem,
    compare,
)
from driftsniff.core.normalize import (
    NORMALISER_VERSION,
    CollectionMode,
    FieldClass,
    StaticTypeTable,
    TypeTable,
)
from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    Manifest,
    build_manifest,
    latest_snapshot,
    store_if_changed,
)
from driftsniff.core.states import get_state
from driftsniff.db.engine import Database
from driftsniff.secrets.fingerprint import Fingerprinter

KEY = bytes(range(32))
FINGERPRINTER = Fingerprinter(KEY, "0a1b2c3d")
CANARY = "CANARY-0001"
START = "2026-10-21T10:00:00Z"
END = "2026-10-21T10:05:00Z"

NETWORK = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "vlan": FieldClass.CONFIG,
        "enabled": FieldClass.CONFIG,
        "dns": FieldClass.CONFIG,
        "tags": FieldClass.CONFIG,
        "opts": FieldClass.CONFIG,
        "x": FieldClass.CONFIG,
        "note": FieldClass.CONFIG,
        "ssid": FieldClass.CONFIG,
        "uptime": FieldClass.IGNORE,
        "wifi.ssid": FieldClass.CONFIG,
        "wifi.passphrase": FieldClass.SECRET,
        "wan.dns.primary": FieldClass.CONFIG,
        "members": FieldClass.CONFIG,
        "members.id": FieldClass.CONFIG,
        "members.role": FieldClass.CONFIG,
        "members.token": FieldClass.SECRET,
        "rules": FieldClass.CONFIG,
        "rules.id": FieldClass.CONFIG,
        "rules.action": FieldClass.CONFIG,
        "ports": FieldClass.CONFIG,
        "ports.idx": FieldClass.CONFIG,
        "ports.mode": FieldClass.CONFIG,
    },
    collection_modes={
        "tags": CollectionMode.SET,
        "members": CollectionMode.SET,
        "rules": CollectionMode.ORDERED_KEYED,
        "ports": CollectionMode.VENDOR_INDEX,
    },
    item_key_fields={"members": "id", "rules": "id", "ports": "idx"},
)
TABLES: Mapping[str, TypeTable] = {"network": NETWORK, "device": NETWORK, "site": NETWORK}


def obj(key: str, /, **fields: JsonValue) -> CollectedObject:
    """An object whose state holds its key, a name and ``fields``."""
    state: dict[str, JsonValue] = {"_id": key, "name": f"net {key}", **fields}
    return CollectedObject(key, state, f"net {key}")


def build(
    resources: Mapping[str, list[CollectedObject]],
    *,
    controller: str | None = "1.0",
    normaliser: int = NORMALISER_VERSION,
) -> Manifest:
    collected = {name: CollectedResource(objects) for name, objects in resources.items()}
    return build_manifest(collected, controller_version=controller, normaliser_version=normaliser)


def run(previous: Manifest | None, new: Manifest) -> list[ChangeItem]:
    pending: dict[str, bytes] = {}
    if previous is not None:
        pending.update(previous.pending_states)
    pending.update(new.pending_states)

    def lookup(state_hash: str) -> Mapping[str, JsonValue]:
        loaded = json.loads(pending[state_hash])
        assert isinstance(loaded, dict)
        return loaded

    return compare(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        fingerprinter=FINGERPRINTER,
        type_tables=TABLES,
    )


def one(items: list[ChangeItem]) -> ChangeItem:
    assert len(items) == 1, items
    return items[0]


def diff_one(before: dict[str, JsonValue], after: dict[str, JsonValue]) -> list[ChangeItem]:
    """Compare one network object with ``before`` fields against the same one with ``after``."""
    return run(build({"network": [obj("n1", **before)]}), build({"network": [obj("n1", **after)]}))


def secret_marker(value: str, path: str = "wifi.passphrase") -> str:
    return FINGERPRINTER.fingerprint("network", path, value).marker()


# ---- objects: added, removed, modified ---------------------------------------------------


def test_an_added_object_is_one_item_with_an_empty_path() -> None:
    previous = build({"network": [obj("n1")]})
    new = build({"network": [obj("n1"), obj("n2")]})
    item = one(run(previous, new))
    assert (item.resource, item.object_key, item.object_name) == ("network", "n2", "net n2")
    assert (item.change_kind, item.path) == ("added", "")
    assert item.before_value is item.after_value is item.before_fp is item.after_fp is None


def test_a_removed_object_is_one_item_with_an_empty_path() -> None:
    previous = build({"network": [obj("n1"), obj("n2")]})
    new = build({"network": [obj("n1")]})
    item = one(run(previous, new))
    assert (item.object_key, item.object_name, item.change_kind, item.path) == (
        "n2",
        "net n2",
        "removed",
        "",
    )


def test_a_changed_value_shows_before_and_after_as_json_text() -> None:
    item = one(diff_one({"vlan": 10}, {"vlan": 20}))
    assert (item.change_kind, item.path) == ("modified", "vlan")
    assert item.field_class is FieldClass.CONFIG
    assert (item.before_value, item.after_value) == ("10", "20")
    assert item.before_fp is item.after_fp is None


def test_strings_are_shown_as_json_text() -> None:
    item = one(diff_one({"note": "old"}, {"note": "new"}))
    assert (item.before_value, item.after_value) == ('"old"', '"new"')


def test_a_new_field_is_added_and_a_dropped_field_is_removed() -> None:
    added = one(diff_one({}, {"vlan": 5}))
    assert (added.change_kind, added.before_value, added.after_value) == ("added", None, "5")
    removed = one(diff_one({"vlan": 5}, {}))
    assert (removed.change_kind, removed.before_value, removed.after_value) == (
        "removed",
        "5",
        None,
    )


def test_every_item_carries_the_detection_window_and_the_object_name() -> None:
    items = diff_one({"vlan": 1, "enabled": True}, {"vlan": 2, "enabled": False})
    assert [item.path for item in items] == ["enabled", "vlan"]
    assert {(item.window_start, item.window_end) for item in items} == {(START, END)}
    assert {item.object_name for item in items} == {"net n1"}


def test_the_item_never_says_who_made_the_change() -> None:
    names = set(ChangeItem.__dataclass_fields__)
    assert not names & {"actor", "author", "user", "changed_by", "made_by", "who"}


def test_an_unchanged_object_is_never_loaded() -> None:
    previous = build({"network": [obj("n1"), obj("n2", vlan=1)]})
    new = build({"network": [obj("n1"), obj("n2", vlan=2)]})
    unchanged = previous.objects["network"]["n1"]
    loaded: list[str] = []
    pending = {**previous.pending_states, **new.pending_states}

    def lookup(state_hash: str) -> Mapping[str, JsonValue]:
        loaded.append(state_hash)
        value = json.loads(pending[state_hash])
        assert isinstance(value, dict)
        return value

    items = compare(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        fingerprinter=FINGERPRINTER,
        type_tables=TABLES,
    )
    assert one(items).object_key == "n2"
    assert unchanged not in loaded


def test_an_equal_manifest_gives_no_items() -> None:
    manifest = build({"network": [obj("n1", vlan=1)]})
    assert run(manifest, manifest) == []


# ---- paths, null versus missing, ignored fields -------------------------------------------


def test_paths_are_dot_separated() -> None:
    before: dict[str, JsonValue] = {"wan": {"dns": {"primary": "192.0.2.1"}}}
    after: dict[str, JsonValue] = {"wan": {"dns": {"primary": "192.0.2.2"}}}
    item = one(diff_one(before, after))
    assert item.path == "wan.dns.primary"
    assert (item.before_value, item.after_value) == ('"192.0.2.1"', '"192.0.2.2"')


def test_null_and_a_missing_field_are_the_same_state() -> None:
    assert diff_one({"note": None}, {}) == []
    assert diff_one({}, {"note": None}) == []
    assert diff_one({"wan": {"dns": None}}, {"wan": {}}) == []


def test_a_null_that_gets_a_value_is_an_added_field() -> None:
    item = one(diff_one({"note": None}, {"note": "x"}))
    assert (item.change_kind, item.before_value, item.after_value) == ("added", None, '"x"')


def test_ignored_fields_are_not_compared() -> None:
    assert diff_one({"uptime": 1, "vlan": 1}, {"uptime": 2, "vlan": 1}) == []


def test_a_scalar_that_becomes_a_map_is_one_modified_item() -> None:
    item = one(diff_one({"x": "text"}, {"x": {"a": 1}}))
    assert (item.change_kind, item.path, item.before_value) == ("modified", "x", '"text"')
    assert item.after_value is not None
    assert item.after_value.startswith('{"a":"fp1:')


def test_an_empty_container_that_appears_is_reported() -> None:
    assert one(diff_one({}, {"opts": {}})).after_value == "{}"
    assert one(diff_one({}, {"dns": []})).after_value == "[]"
    assert one(diff_one({"dns": []}, {})).before_value == "[]"


# ---- lists --------------------------------------------------------------------------------


def test_an_ordered_list_is_compared_by_position_and_the_index_is_in_the_path() -> None:
    item = one(diff_one({"dns": ["192.0.2.1", "192.0.2.2"]}, {"dns": ["192.0.2.1", "192.0.2.9"]}))
    assert (item.change_kind, item.path) == ("modified", "dns.1")
    assert (item.before_value, item.after_value) == ('"192.0.2.2"', '"192.0.2.9"')


def test_a_longer_ordered_list_adds_positions_and_a_shorter_one_removes_them() -> None:
    longer = one(diff_one({"dns": ["a"]}, {"dns": ["a", "b"]}))
    assert (longer.change_kind, longer.path, longer.after_value) == ("added", "dns.1", '"b"')
    shorter = one(diff_one({"dns": ["a", "b"]}, {"dns": ["a"]}))
    assert (shorter.change_kind, shorter.path, shorter.before_value) == ("removed", "dns.1", '"b"')


def test_a_set_reports_members_that_come_and_go() -> None:
    items = diff_one({"tags": ["a", "b"]}, {"tags": ["b", "c"]})
    assert [(i.change_kind, i.path, i.before_value, i.after_value) for i in items] == [
        ("removed", "tags", '"a"', None),
        ("added", "tags", None, '"c"'),
    ]


def test_the_order_of_a_set_is_not_a_change() -> None:
    assert diff_one({"tags": ["a", "b", "c"]}, {"tags": ["c", "a", "b"]}) == []


def test_a_keyed_set_member_that_changed_is_one_modified_item() -> None:
    before: dict[str, JsonValue] = {"members": [{"id": "m1", "role": "user"}]}
    after: dict[str, JsonValue] = {"members": [{"id": "m1", "role": "admin"}]}
    item = one(diff_one(before, after))
    assert (item.change_kind, item.path) == ("modified", "members")
    assert json.loads(item.before_value or "") == {"id": "m1", "role": "user"}
    assert json.loads(item.after_value or "") == {"id": "m1", "role": "admin"}


def test_a_keyed_set_member_that_is_new_or_gone_is_added_or_removed() -> None:
    member: dict[str, JsonValue] = {"id": "m2", "role": "user"}
    added = one(diff_one({"members": []}, {"members": [member]}))
    assert (added.change_kind, added.path, added.before_value) == ("added", "members", None)
    removed = one(diff_one({"members": [member]}, {"members": []}))
    assert (removed.change_kind, removed.after_value) == ("removed", None)


def rule(key: str, action: str = "allow") -> dict[str, JsonValue]:
    return {"id": key, "action": action}


def test_an_ordered_keyed_list_matches_members_by_key_not_by_position() -> None:
    before: dict[str, JsonValue] = {"rules": [rule("r1"), rule("r2"), rule("r3")]}
    after: dict[str, JsonValue] = {"rules": [rule("r0"), rule("r1"), rule("r2"), rule("r3")]}
    item = one(diff_one(before, after))
    assert (item.change_kind, item.path, item.before_value) == ("added", "rules", None)
    assert json.loads(item.after_value or "") == rule("r0")


def test_an_ordered_keyed_member_that_changed_is_one_modified_item_without_an_index() -> None:
    before: dict[str, JsonValue] = {"rules": [rule("r1"), rule("r2", "allow")]}
    after: dict[str, JsonValue] = {"rules": [rule("r1"), rule("r2", "deny")]}
    item = one(diff_one(before, after))
    assert (item.change_kind, item.path) == ("modified", "rules")
    assert json.loads(item.before_value or "") == rule("r2", "allow")
    assert json.loads(item.after_value or "") == rule("r2", "deny")


def test_the_order_of_an_ordered_keyed_list_is_not_read_here() -> None:
    before: dict[str, JsonValue] = {"rules": [rule("r1"), rule("r2")]}
    after: dict[str, JsonValue] = {"rules": [rule("r2"), rule("r1")]}
    assert diff_one(before, after) == []


def test_a_repeated_key_in_an_ordered_list_is_matched_by_occurrence() -> None:
    before: dict[str, JsonValue] = {"rules": [rule("r1", "allow"), rule("r1", "deny")]}
    after: dict[str, JsonValue] = {"rules": [rule("r1", "allow"), rule("r1", "allow")]}
    item = one(diff_one(before, after))
    assert (item.change_kind, item.path) == ("modified", "rules")
    assert json.loads(item.before_value or "") == rule("r1", "deny")


def test_a_vendor_index_list_is_keyed_by_its_index_field() -> None:
    before: dict[str, JsonValue] = {"ports": [{"idx": 1, "mode": "a"}, {"idx": 2, "mode": "b"}]}
    inserted: dict[str, JsonValue] = {
        "ports": [{"idx": 0, "mode": "z"}, {"idx": 1, "mode": "a"}, {"idx": 2, "mode": "b"}]
    }
    added = one(diff_one(before, inserted))
    assert (added.change_kind, added.path) == ("added", "ports")
    changed: dict[str, JsonValue] = {"ports": [{"idx": 1, "mode": "a"}, {"idx": 2, "mode": "c"}]}
    modified = one(diff_one(before, changed))
    assert (modified.change_kind, modified.path) == ("modified", "ports")
    assert json.loads(modified.after_value or "") == {"idx": 2, "mode": "c"}


def test_an_ordered_scalar_list_keeps_the_position_in_the_path() -> None:
    item = one(diff_one({"dns": ["a", "b"]}, {"dns": ["a", "c"]}))
    assert item.path == "dns.1"


# ---- secrets and unclassified fields ------------------------------------------------------


def test_a_secret_change_shows_fingerprints_and_never_a_value() -> None:
    before = secret_marker(CANARY)
    after = secret_marker("CANARY-0002")
    item = one(diff_one({"wifi": {"passphrase": before}}, {"wifi": {"passphrase": after}}))
    assert (item.path, item.field_class) == ("wifi.passphrase", FieldClass.SECRET)
    assert (item.before_fp, item.after_fp) == (before, after)
    assert item.before_value is item.after_value is None
    assert "CANARY" not in repr(item)


def test_an_equal_secret_is_no_change() -> None:
    marker = secret_marker(CANARY)
    assert diff_one({"wifi": {"passphrase": marker}}, {"wifi": {"passphrase": marker}}) == []


def test_a_secret_field_that_holds_a_raw_value_is_fingerprinted_here() -> None:
    item = one(diff_one({"wifi": {"passphrase": CANARY}}, {"wifi": {"passphrase": "CANARY-0002"}}))
    assert item.before_fp == secret_marker(CANARY)
    assert item.after_fp == secret_marker("CANARY-0002")
    assert "CANARY" not in repr(item)


def test_a_secret_that_appears_has_only_an_after_fingerprint() -> None:
    marker = secret_marker(CANARY)
    item = one(diff_one({}, {"wifi": {"passphrase": marker}}))
    assert (item.change_kind, item.before_fp, item.after_fp) == ("added", None, marker)


def test_a_fingerprint_in_a_config_field_is_treated_as_a_secret() -> None:
    forced = secret_marker(CANARY, "ssid")
    item = one(diff_one({"ssid": "plain"}, {"ssid": forced}))
    assert item.field_class is FieldClass.SECRET
    assert item.after_fp == forced
    assert item.before_value is None
    assert item.before_fp == FINGERPRINTER.fingerprint("network", "ssid", "plain").marker()


def test_an_unclassified_field_is_shown_as_a_fingerprint_only() -> None:
    item = one(diff_one({"extra": CANARY}, {"extra": "CANARY-0002"}))
    assert (item.path, item.field_class) == ("extra", FieldClass.UNCLASSIFIED)
    assert item.before_fp == FINGERPRINTER.fingerprint("network", "extra", CANARY).marker()
    assert item.after_fp == FINGERPRINTER.fingerprint("network", "extra", "CANARY-0002").marker()
    assert item.before_value is item.after_value is None
    assert "CANARY" not in repr(item)


def test_unclassified_fields_inside_a_shown_member_are_masked() -> None:
    token = secret_marker(CANARY, "members.token")
    before: dict[str, JsonValue] = {"members": [{"id": "m1", "token": token, "other": CANARY}]}
    after: dict[str, JsonValue] = {"members": [{"id": "m1", "token": token, "other": "x"}]}
    item = one(diff_one(before, after))
    assert item.before_value is not None and item.after_value is not None
    assert "CANARY" not in item.before_value + item.after_value
    assert token in item.before_value
    assert json.loads(item.before_value)["other"].startswith("fp1:")


def test_no_item_of_a_mixed_change_leaks_a_secret() -> None:
    before: dict[str, JsonValue] = {"wifi": {"passphrase": CANARY}, "extra": CANARY}
    after: dict[str, JsonValue] = {"wifi": {"passphrase": "CANARY-0002"}, "extra": "CANARY-0003"}
    assert "CANARY" not in repr(diff_one(before, after))


# ---- schema drift -------------------------------------------------------------------------


def drift_pair(
    count: int = 3, *, before: str | None = "1.0", after: str | None = "2.0"
) -> tuple[Manifest, Manifest]:
    keys = [f"n{index}" for index in range(count)]
    previous = build({"network": [obj(key, vlan=1) for key in keys]}, controller=before)
    new = build({"network": [obj(key, vlan=1, fresh="x") for key in keys]}, controller=after)
    return previous, new


def test_one_new_field_on_every_object_is_one_schema_drift_item() -> None:
    item = one(run(*drift_pair()))
    assert item.change_kind == "schema_drift"
    assert (item.resource, item.object_key, item.object_name) == ("network", None, None)
    assert (item.path, item.severity, item.rule_id) == ("fresh", "low", SCHEMA_DRIFT_RULE_ID)
    assert item.rationale
    assert item.before_value is item.after_value is item.before_fp is item.after_fp is None
    assert item.order_detail == {
        "controller_version_before": "1.0",
        "controller_version_after": "2.0",
        "object_count": 3,
        "paths": ["fresh"],
    }
    assert (item.window_start, item.window_end) == (START, END)


def test_schema_drift_is_one_item_per_resource_type() -> None:
    keys = ["a", "b"]
    previous = build(
        {"network": [obj(k) for k in keys], "device": [obj(k) for k in keys], "site": [obj("s")]},
        controller="1.0",
    )
    new = build(
        {
            "network": [obj(k, fresh=1) for k in keys],
            "device": [obj(k, fresh=1, other=2) for k in keys],
            "site": [obj("s", fresh=1)],
        },
        controller="2.0",
    )
    items = run(previous, new)
    drift = [item for item in items if item.change_kind == "schema_drift"]
    assert sorted(item.resource for item in drift) == ["device", "network"]
    assert [item.path for item in drift if item.resource == "device"] == ["fresh, other"]
    site = [item for item in items if item.resource == "site"]
    assert [(item.change_kind, item.path, item.object_key) for item in site] == [
        ("added", "fresh", "s"),
    ]
    assert len(items) == 3


def test_several_new_paths_are_listed_in_the_one_drift_item() -> None:
    previous = build({"network": [obj("a"), obj("b")]}, controller="1.0")
    new = build(
        {"network": [obj("a", p={"q": 1, "r": 2}), obj("b", p={"q": 3, "r": 4})]},
        controller="2.0",
    )
    item = one(run(previous, new))
    assert item.path == "p.q, p.r"
    assert item.order_detail is not None and item.order_detail["paths"] == ["p.q", "p.r"]


def test_a_change_beside_the_drift_is_still_reported_for_its_object() -> None:
    previous, _ = drift_pair()
    objects = [obj("n0", vlan=9, fresh="x"), obj("n1", vlan=1, fresh="x")]
    changed = build({"network": [*objects, obj("n2", vlan=1, fresh="x")]}, controller="2.0")
    items = run(previous, changed)
    assert sorted((item.change_kind, item.object_key, item.path) for item in items) == [
        ("modified", "n0", "vlan"),
        ("schema_drift", None, "fresh"),
    ]


@pytest.mark.parametrize(
    ("before", "after"),
    [("1.0", "1.0"), (None, "2.0"), ("1.0", None), (None, None)],
)
def test_without_a_known_controller_version_change_there_is_no_drift(
    before: str | None, after: str | None
) -> None:
    items = run(*drift_pair(before=before, after=after))
    assert {item.change_kind for item in items} == {"added"}
    assert len(items) == 3


def test_a_field_missing_on_one_object_is_not_drift() -> None:
    previous = build({"network": [obj("a"), obj("b"), obj("c")]}, controller="1.0")
    new = build(
        {"network": [obj("a", fresh=1), obj("b", fresh=1), obj("c", other=1)]}, controller="2.0"
    )
    items = run(previous, new)
    assert {item.change_kind for item in items} == {"added"}
    assert len(items) == 3


def test_an_unchanged_object_means_the_field_is_not_on_every_object() -> None:
    previous = build({"network": [obj("a"), obj("b"), obj("c")]}, controller="1.0")
    new = build({"network": [obj("a", fresh=1), obj("b", fresh=1), obj("c")]}, controller="2.0")
    assert {item.change_kind for item in run(previous, new)} == {"added"}


def test_a_single_object_is_not_enough_to_call_a_change_drift() -> None:
    assert MIN_DRIFT_OBJECTS == 2
    items = run(*drift_pair(count=1))
    assert [(item.change_kind, item.object_key, item.path) for item in items] == [
        ("added", "n0", "fresh"),
    ]


def test_a_field_that_changes_instead_of_appearing_is_not_drift() -> None:
    previous = build({"network": [obj("a", v=1), obj("b", v=1)]}, controller="1.0")
    new = build({"network": [obj("a", v=2), obj("b", v=2)]}, controller="2.0")
    assert {item.change_kind for item in run(previous, new)} == {"modified"}


def test_a_set_member_added_to_every_object_is_not_schema_drift() -> None:
    user: dict[str, JsonValue] = {"id": "m1", "role": "user"}
    admin: dict[str, JsonValue] = {"id": "m9", "role": "admin"}
    keys = ["a", "b", "c"]
    previous = build({"network": [obj(k, members=[user]) for k in keys]}, controller="1.0")
    new = build({"network": [obj(k, members=[user, admin]) for k in keys]}, controller="2.0")
    items = run(previous, new)
    assert {item.change_kind for item in items} == {"added"}
    assert [(item.object_key, item.path) for item in items] == [(k, "members") for k in keys]
    assert all(json.loads(item.after_value or "") == admin for item in items)


def test_a_tag_added_to_every_object_is_not_schema_drift() -> None:
    previous = build({"network": [obj(k, tags=["x"]) for k in "ab"]}, controller="1.0")
    new = build({"network": [obj(k, tags=["x", "y"]) for k in "ab"]}, controller="2.0")
    items = run(previous, new)
    assert [(item.change_kind, item.object_key, item.path) for item in items] == [
        ("added", "a", "tags"),
        ("added", "b", "tags"),
    ]


def test_an_ordered_keyed_member_added_to_every_object_is_not_schema_drift() -> None:
    previous = build({"network": [obj(k, rules=[rule("r1")]) for k in "ab"]}, controller="1.0")
    new = build(
        {"network": [obj(k, rules=[rule("r1"), rule("r2")]) for k in "ab"]}, controller="2.0"
    )
    assert {item.change_kind for item in run(previous, new)} == {"added"}


def test_drift_covers_a_new_field_and_leaves_the_added_members_per_object() -> None:
    previous = build({"network": [obj(k, tags=["x"]) for k in "ab"]}, controller="1.0")
    new = build({"network": [obj(k, tags=["x", "y"], fresh=1) for k in "ab"]}, controller="2.0")
    items = run(previous, new)
    assert sorted((item.change_kind, item.object_key, item.path) for item in items) == [
        ("added", "a", "tags"),
        ("added", "b", "tags"),
        ("schema_drift", None, "fresh"),
    ]


def test_drift_is_reported_beside_an_added_and_a_removed_object() -> None:
    previous = build(
        {"network": [obj("a", vlan=1), obj("b", vlan=1), obj("gone")]},
        controller="1.0",
    )
    new = build(
        {"network": [obj("a", vlan=1, fresh=1), obj("b", vlan=1, fresh=1), obj("new")]},
        controller="2.0",
    )
    items = run(previous, new)
    assert [(item.change_kind, item.object_key, item.path) for item in items] == [
        ("added", "new", ""),
        ("removed", "gone", ""),
        ("schema_drift", None, "fresh"),
    ]
    assert items[-1].order_detail is not None and items[-1].order_detail["object_count"] == 2


def test_a_scalar_list_that_gains_an_entry_on_every_object_is_still_schema_drift() -> None:
    previous = build({"network": [obj(k, dns=["a", "b"]) for k in "ab"]}, controller="1.0")
    new = build({"network": [obj(k, dns=["a", "b", "c"]) for k in "ab"]}, controller="2.0")
    item = one(run(previous, new))
    assert (item.change_kind, item.object_key, item.path) == ("schema_drift", None, "dns.2")


# ---- baseline and resources ---------------------------------------------------------------


def test_a_normaliser_version_change_is_a_baseline_with_no_items() -> None:
    previous = build({"network": [obj("n1", vlan=1), obj("gone")]}, normaliser=1)
    new = build({"network": [obj("n1", vlan=2), obj("new")]}, normaliser=2)
    assert run(previous, new) == []


def test_the_first_manifest_of_a_source_is_a_baseline_with_no_items() -> None:
    assert run(None, build({"network": [obj("n1")]})) == []


def test_a_resource_missing_from_the_new_manifest_is_left_alone() -> None:
    previous = build({"network": [obj("n1")], "device": [obj("d1")]})
    new = build({"network": [obj("n1")]})
    assert run(previous, new) == []


def test_a_resource_that_is_new_has_all_its_objects_added() -> None:
    previous = build({"network": [obj("n1")]})
    new = build({"network": [obj("n1")], "device": [obj("d1"), obj("d2")]})
    items = run(previous, new)
    assert [(item.resource, item.object_key, item.change_kind) for item in items] == [
        ("device", "d1", "added"),
        ("device", "d2", "added"),
    ]


def test_a_resource_that_is_present_but_empty_removes_its_objects() -> None:
    previous = build({"network": [obj("n1"), obj("n2")]})
    new = build({"network": []})
    assert [item.object_key for item in run(previous, new)] == ["n1", "n2"]


def test_items_come_out_in_a_stable_order() -> None:
    previous = build({"network": [obj("n3", vlan=1), obj("n1", vlan=1), obj("gone")]})
    new = build({"network": [obj("n1", vlan=2), obj("n3", vlan=2), obj("new")]})
    items = run(previous, new)
    assert [(item.change_kind, item.object_key) for item in items] == [
        ("added", "new"),
        ("removed", "gone"),
        ("modified", "n1"),
        ("modified", "n3"),
    ]
    assert run(previous, new) == items


def test_a_resource_without_a_type_table_is_shown_as_fingerprints_only() -> None:
    previous = build({"unknown": [obj("u1", vlan=1)]})
    new = build({"unknown": [obj("u1", vlan=2)]})
    item = one(run(previous, new))
    assert item.field_class is FieldClass.UNCLASSIFIED
    assert item.before_value is item.after_value is None
    assert item.before_fp is not None and item.after_fp is not None


def test_names_fall_back_to_the_name_field_of_a_manifest_read_back_from_storage() -> None:
    previous_built = build({"network": [obj("gone"), obj("n1", vlan=1)]})
    new_built = build({"network": [obj("n1", vlan=2), obj("new")]})
    previous = Manifest.from_bytes(previous_built.canonical_bytes())
    new = Manifest.from_bytes(new_built.canonical_bytes())
    assert previous.names == {} and new.names == {}
    pending = {**previous_built.pending_states, **new_built.pending_states}

    def lookup(state_hash: str) -> Mapping[str, JsonValue]:
        value = json.loads(pending[state_hash])
        assert isinstance(value, dict)
        return value

    items = compare(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        fingerprinter=FINGERPRINTER,
        type_tables=TABLES,
    )
    assert {(item.object_key, item.object_name) for item in items} == {
        ("new", "net new"),
        ("gone", "net gone"),
        ("n1", "net n1"),
    }


# ---- against the real store ---------------------------------------------------------------


def test_compare_reads_states_from_the_database(store: Database) -> None:
    first = build({"network": [obj("n1", vlan=10), obj("n2", vlan=1)]})
    second = build({"network": [obj("n1", vlan=20), obj("n2", vlan=1)]})
    with store.write() as connection:
        store_if_changed(connection, 1, first, taken_at="2026-10-21T10:00:00Z")
        outcome = store_if_changed(connection, 1, second, taken_at=END)
    assert outcome.kind == "normal"
    with store.read() as connection:
        stored = latest_snapshot(connection, 1)
        assert stored is not None
        items = compare(
            first,
            stored.manifest,
            lambda state_hash: get_state(connection, state_hash),
            window_start=START,
            window_end=END,
            fingerprinter=FINGERPRINTER,
            type_tables=TABLES,
        )
    item = one(items)
    assert (item.object_key, item.path, item.before_value, item.after_value) == (
        "n1",
        "vlan",
        "10",
        "20",
    )


def test_a_stored_baseline_is_not_compared_with_the_snapshot_before_it(store: Database) -> None:
    first = build({"network": [obj("n1", vlan=10)]}, normaliser=1)
    second = build({"network": [obj("n1", vlan=20)]}, normaliser=2)
    with store.write() as connection:
        store_if_changed(connection, 1, first, taken_at="2026-10-21T10:00:00Z")
        outcome = store_if_changed(connection, 1, second, taken_at=END)
    assert outcome.kind == "baseline"
    with store.read() as connection:
        stored = latest_snapshot(connection, 1)
        assert stored is not None
        assert stored.kind == "baseline"
        items = compare(
            first,
            stored.manifest,
            lambda state_hash: get_state(connection, state_hash),
            window_start=START,
            window_end=END,
            fingerprinter=FINGERPRINTER,
            type_tables=TABLES,
        )
    assert items == []
