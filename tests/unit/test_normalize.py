"""Tests for core/normalize.py: the same logical object always gives the same bytes."""

import copy
import json
import random
from collections.abc import Mapping
from hashlib import sha256
from typing import Any, cast

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.normalize import (
    NORMALISER_VERSION,
    CollectionMode,
    FieldClass,
    StaticTypeTable,
    TypeTable,
    normalize_object,
)

PROPERTY_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow],
)

# The output for PINNED_RAW under PINNED_TABLE, written out once. If a test below fails
# because this text no longer matches, normalisation output has changed: bump
# NORMALISER_VERSION, set PINNED_VERSION to it, and replace PINNED_TEXT and PINNED_SHA256.
PINNED_VERSION = 1
PINNED_TEXT = (
    '{"_id":"n-1","dns":["9.9.9.9","1.1.1.1"],"empty":[],"flag":false,'
    '"name":"Büro-LAN é́","nested":{"b":{}},"ratio":0.5,'
    '"rules":[{"action":"accept","id":"r1"},{"action":"drop","id":"r2"},'
    '{"action":"anon-a"},{"action":"anon-b"}],'
    '"stats":{"mtu":1500},"tags":[null,"a","a","b"],'
    '"vlan":1152921504606846977,"x_passphrase":"CANARY-0000","zero":0}'
)
PINNED_SHA256 = "8bd28bc87aa3bfe9752b12a7313fb61bd4310224a4fec2bb6d5e220d03356e97"

PINNED_TABLE = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "stats.rx_bytes": FieldClass.IGNORE,
        "last_seen": FieldClass.IGNORE,
        "x_passphrase": FieldClass.SECRET,
    },
    collection_modes={
        "rules": CollectionMode.SET,
        "tags": CollectionMode.SET,
        "dns": CollectionMode.ORDERED_SCALAR,
    },
    item_key_fields={"rules": "id"},
)


def pinned_raw() -> dict[str, JsonValue]:
    return {
        "name": "Büro-LAN é́",
        "_id": "n-1",
        "last_seen": 1760000000,
        "stats": {"rx_bytes": 12345, "mtu": 1500.0},
        "x_passphrase": "CANARY-0000",
        "note": None,
        "nested": {"a": None, "b": {"c": None}},
        "vlan": 2**60 + 1,
        "ratio": 0.5,
        "zero": -0.0,
        "flag": False,
        "empty": [],
        "dns": ["9.9.9.9", "1.1.1.1"],
        "tags": ["b", "a", None, "a"],
        "rules": [
            {"id": "r2", "action": "drop", "log": None},
            {"id": "r1", "action": "accept"},
            {"action": "anon-b"},
            {"action": "anon-a"},
        ],
    }


def digest(value: JsonValue) -> str:
    return sha256(canonical_dumps(value)).hexdigest()


def set_table(item_key: str | None = None, path: str = "items") -> StaticTypeTable:
    keys = {path: item_key} if item_key is not None else {}
    return StaticTypeTable(
        collection_modes={path: CollectionMode.SET},
        item_key_fields=keys,
    )


# ---- the pinned fixture -------------------------------------------------------------------


def test_pinned_fixture_output_has_not_changed() -> None:
    output = canonical_dumps(normalize_object(PINNED_TABLE, pinned_raw()))
    assert output.decode("utf-8") == PINNED_TEXT
    assert sha256(output).hexdigest() == PINNED_SHA256


def test_pinned_output_belongs_to_the_current_normaliser_version() -> None:
    assert NORMALISER_VERSION == PINNED_VERSION


def test_pinned_output_is_the_same_for_a_shuffled_input() -> None:
    raw = pinned_raw()
    raw["rules"] = list(reversed(cast(list[JsonValue], raw["rules"])))
    raw["tags"] = list(reversed(cast(list[JsonValue], raw["tags"])))
    reordered = dict(reversed(list(raw.items())))
    output = canonical_dumps(normalize_object(PINNED_TABLE, reordered))
    assert sha256(output).hexdigest() == PINNED_SHA256


# ---- property tests -----------------------------------------------------------------------


class EverySetTable:
    """Every list is a set keyed by ``id``; the top-level field ``volatile`` is ignored."""

    object_key_field: str | None = "id"
    name_field: str | None = None

    def field_class(self, path: str) -> FieldClass:
        return FieldClass.IGNORE if path == "volatile" else FieldClass.CONFIG

    def collection_mode(self, path: str) -> CollectionMode:
        return CollectionMode.SET

    def item_key_field(self, path: str) -> str | None:
        return "id"


class OrderedTable(EverySetTable):
    """Same ignored field, but every list keeps its order."""

    def collection_mode(self, path: str) -> CollectionMode:
        return CollectionMode.ORDERED_KEYED


KEYS = st.sampled_from(["id", "name", "volatile", "a", "b"])
LEAVES = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-3, max_value=3)
    | st.sampled_from([1.0, 2.0, 0.5, -0.0])
    | st.sampled_from(["a", "b", "é", "é"])
)


def extend(children: st.SearchStrategy[Any]) -> st.SearchStrategy[Any]:
    lists = st.lists(children, max_size=4)
    objects = st.dictionaries(KEYS, children, max_size=4)
    return lists | objects


RAW_OBJECTS = st.dictionaries(KEYS, st.recursive(LEAVES, extend, max_leaves=12), max_size=5)


def shuffle_everything(value: JsonValue, rng: random.Random) -> JsonValue:
    """Reorder every object's keys and every list's members."""
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {key: shuffle_everything(value[key], rng) for key in keys}
    if isinstance(value, list):
        members = [shuffle_everything(member, rng) for member in value]
        rng.shuffle(members)
        return members
    return value


def shuffle_keys_only(value: JsonValue, rng: random.Random) -> JsonValue:
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {key: shuffle_keys_only(value[key], rng) for key in keys}
    if isinstance(value, list):
        return [shuffle_keys_only(member, rng) for member in value]
    return value


def contains_null_key(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return any(member is None or contains_null_key(member) for member in value.values())
    if isinstance(value, list):
        return any(contains_null_key(member) for member in value)
    return False


@PROPERTY_SETTINGS
@given(raw=RAW_OBJECTS, rng=st.randoms(use_true_random=False))
def test_shuffling_keys_and_set_members_never_changes_the_result(
    raw: dict[str, JsonValue], rng: random.Random
) -> None:
    table = EverySetTable()
    shuffled = shuffle_everything(raw, rng)
    assert isinstance(shuffled, dict)
    expected = canonical_dumps(normalize_object(table, raw))
    assert canonical_dumps(normalize_object(table, shuffled)) == expected


@PROPERTY_SETTINGS
@given(raw=RAW_OBJECTS, rng=st.randoms(use_true_random=False))
def test_key_order_never_changes_the_result_when_lists_keep_their_order(
    raw: dict[str, JsonValue], rng: random.Random
) -> None:
    table = OrderedTable()
    shuffled = shuffle_keys_only(raw, rng)
    assert isinstance(shuffled, dict)
    expected = canonical_dumps(normalize_object(table, raw))
    assert canonical_dumps(normalize_object(table, shuffled)) == expected


@PROPERTY_SETTINGS
@given(raw=RAW_OBJECTS, ordered=st.booleans())
def test_normalising_twice_equals_once(raw: dict[str, JsonValue], ordered: bool) -> None:
    table: TypeTable = OrderedTable() if ordered else EverySetTable()
    once = normalize_object(table, raw)
    twice = normalize_object(table, once)
    assert canonical_dumps(twice) == canonical_dumps(once)


@PROPERTY_SETTINGS
@given(raw=RAW_OBJECTS, ordered=st.booleans())
def test_the_result_has_no_null_key_and_no_ignored_field(
    raw: dict[str, JsonValue], ordered: bool
) -> None:
    table: TypeTable = OrderedTable() if ordered else EverySetTable()
    output = normalize_object(table, raw)
    assert not contains_null_key(output)
    assert "volatile" not in output


@PROPERTY_SETTINGS
@given(raw=RAW_OBJECTS)
def test_the_input_is_never_modified(raw: dict[str, JsonValue]) -> None:
    before = copy.deepcopy(raw)
    normalize_object(EverySetTable(), raw)
    assert canonical_dumps(raw) == canonical_dumps(before)


# ---- dropping fields and nulls ------------------------------------------------------------


def test_ignored_fields_are_dropped_and_other_classes_are_kept() -> None:
    table = StaticTypeTable(
        field_classes={
            "volatile": FieldClass.IGNORE,
            "token": FieldClass.SECRET,
            "name": FieldClass.CONFIG,
        }
    )
    raw: dict[str, JsonValue] = {"volatile": 1, "token": "t", "name": "n", "other": "o"}
    assert normalize_object(table, raw) == {"token": "t", "name": "n", "other": "o"}


def test_an_ignored_path_drops_the_whole_subtree_and_only_that_path() -> None:
    classes = {"stats": FieldClass.IGNORE, "a.stats": FieldClass.CONFIG}
    table = StaticTypeTable(field_classes=classes)
    raw: dict[str, JsonValue] = {"stats": {"rx": 1}, "a": {"stats": {"rx": 2}}}
    assert normalize_object(table, raw) == {"a": {"stats": {"rx": 2}}}


def test_nested_ignore_paths_use_dots() -> None:
    table = StaticTypeTable(field_classes={"a.b.c": FieldClass.IGNORE})
    raw: dict[str, JsonValue] = {"a": {"b": {"c": 1, "d": 2}}, "c": 3}
    assert normalize_object(table, raw) == {"a": {"b": {"d": 2}}, "c": 3}


def test_list_members_use_the_path_of_the_list_without_an_index() -> None:
    table = StaticTypeTable(field_classes={"items.secret": FieldClass.IGNORE})
    raw: dict[str, JsonValue] = {"items": [{"secret": 1, "keep": 2}, {"secret": 3}]}
    assert normalize_object(table, raw) == {"items": [{"keep": 2}, {}]}


def test_null_valued_keys_are_dropped_at_every_depth() -> None:
    raw: dict[str, JsonValue] = {"a": None, "b": {"c": None, "d": {"e": None, "f": 1}}}
    assert normalize_object(StaticTypeTable(), raw) == {"b": {"d": {"f": 1}}}


def test_nested_nulls_leave_an_empty_object_not_a_missing_key() -> None:
    raw: dict[str, JsonValue] = {"a": {"b": None}}
    assert normalize_object(StaticTypeTable(), raw) == {"a": {}}


def test_null_equals_missing() -> None:
    table = StaticTypeTable()
    with_null: dict[str, JsonValue] = {"a": 1, "b": None}
    without: dict[str, JsonValue] = {"a": 1}
    one = canonical_dumps(normalize_object(table, with_null))
    assert one == canonical_dumps(normalize_object(table, without))


def test_null_members_inside_a_list_are_kept() -> None:
    raw: dict[str, JsonValue] = {"a": [None, 1, {"b": None}]}
    assert normalize_object(StaticTypeTable(), raw) == {"a": [None, 1, {}]}


def test_empty_lists_and_empty_objects_are_kept() -> None:
    raw: dict[str, JsonValue] = {"a": [], "b": {}, "c": [[]]}
    assert normalize_object(StaticTypeTable(), raw) == {"a": [], "b": {}, "c": [[]]}


def test_an_empty_list_is_not_a_missing_list() -> None:
    table = StaticTypeTable()
    empty = canonical_dumps(normalize_object(table, {"a": []}))
    assert empty != canonical_dumps(normalize_object(table, {}))


# ---- numbers and text ---------------------------------------------------------------------


def test_one_point_zero_and_one_normalise_to_the_same_bytes() -> None:
    table = StaticTypeTable()
    as_float = canonical_dumps(normalize_object(table, {"mtu": 1.0}))
    as_int = canonical_dumps(normalize_object(table, {"mtu": 1}))
    assert as_float == as_int == b'{"mtu":1}'


def test_integers_above_two_to_the_power_53_survive_exactly() -> None:
    raw: dict[str, JsonValue] = {"id": 2**53 + 1, "list": [2**64]}
    output = canonical_dumps(normalize_object(StaticTypeTable(), raw))
    assert output == b'{"id":9007199254740993,"list":[18446744073709551616]}'


def test_unicode_is_neither_normalised_nor_escaped() -> None:
    raw: dict[str, JsonValue] = {"composed": "café", "decomposed": "café"}
    output = normalize_object(StaticTypeTable(), raw)
    assert output == raw
    assert output["composed"] != output["decomposed"]


# ---- collection modes ---------------------------------------------------------------------


def test_set_members_are_sorted_by_their_declared_key() -> None:
    table = set_table("id")
    raw: dict[str, JsonValue] = {"items": [{"id": "b"}, {"id": "c"}, {"id": "a"}]}
    assert normalize_object(table, raw) == {"items": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}


def test_equal_keys_are_ordered_by_content_hash() -> None:
    table = set_table("id")
    first: JsonValue = {"id": "a", "v": 1}
    second: JsonValue = {"id": "a", "v": 2}
    expected = sorted([first, second], key=digest)
    assert normalize_object(table, {"items": [first, second]}) == {"items": expected}
    assert normalize_object(table, {"items": [second, first]}) == {"items": expected}


def test_anonymous_members_are_keyed_by_the_hash_of_their_canonical_form() -> None:
    table = set_table()
    members: list[JsonValue] = [{"b": 1}, {"a": 1}, 7, "x", [1], True]
    output = normalize_object(table, {"items": members})
    assert output == {"items": sorted(members, key=digest)}


def test_keyed_members_come_before_anonymous_ones() -> None:
    table = set_table("id")
    anonymous: JsonValue = {"name": "no key"}
    keyed: JsonValue = {"id": "z"}
    output = normalize_object(table, {"items": [anonymous, keyed]})
    assert output == {"items": [keyed, anonymous]}


def test_a_member_whose_key_is_null_is_anonymous() -> None:
    table = set_table("id")
    keyed: JsonValue = {"id": "z"}
    output = normalize_object(table, {"items": [{"id": None, "n": 1}, keyed]})
    assert output == {"items": [keyed, {"n": 1}]}


def test_non_text_keys_sort_after_text_keys_by_their_canonical_text() -> None:
    table = set_table("id")
    text: JsonValue = {"id": "zzz"}
    ten: JsonValue = {"id": 10}
    two: JsonValue = {"id": 2}
    output = normalize_object(table, {"items": [ten, two, text]})
    assert output == {"items": [text, ten, two]}


def test_a_declared_key_on_scalar_members_is_ignored() -> None:
    table = set_table("id")
    output = normalize_object(table, {"items": ["b", "a"]})
    assert output == {"items": sorted(["a", "b"], key=digest)}


def test_set_members_are_sorted_after_their_own_normalisation() -> None:
    table = set_table("id")
    raw: dict[str, JsonValue] = {"items": [{"id": "b", "x": None}, {"id": "a", "y": 1.0}]}
    assert normalize_object(table, raw) == {"items": [{"id": "a", "y": 1.0}, {"id": "b"}]}


def test_nested_lists_follow_the_mode_of_their_own_path() -> None:
    modes = {"outer": CollectionMode.ORDERED_SCALAR, "outer.inner": CollectionMode.SET}
    table = StaticTypeTable(collection_modes=modes)
    raw: dict[str, JsonValue] = {"outer": [{"inner": ["b", "a"]}, {"inner": ["d", "c"]}]}
    first = sorted(["a", "b"], key=digest)
    second = sorted(["c", "d"], key=digest)
    expected = {"outer": [{"inner": first}, {"inner": second}]}
    assert normalize_object(table, raw) == expected


@pytest.mark.parametrize(
    "mode",
    [CollectionMode.ORDERED_SCALAR, CollectionMode.ORDERED_KEYED, CollectionMode.VENDOR_INDEX],
)
def test_ordered_modes_keep_the_order_they_arrived_in(mode: CollectionMode) -> None:
    table = StaticTypeTable(collection_modes={"items": mode}, item_key_fields={"items": "id"})
    raw: dict[str, JsonValue] = {"items": [{"id": "b"}, {"id": "c"}, {"id": "a"}]}
    assert normalize_object(table, raw) == raw


def test_undeclared_lists_keep_their_order() -> None:
    raw: dict[str, JsonValue] = {"servers": ["9.9.9.9", "1.1.1.1"]}
    assert normalize_object(StaticTypeTable(), raw) == raw


def test_reordering_an_ordered_list_changes_the_bytes() -> None:
    table = StaticTypeTable()
    one = canonical_dumps(normalize_object(table, {"dns": ["a", "b"]}))
    assert one != canonical_dumps(normalize_object(table, {"dns": ["b", "a"]}))


# ---- the type table and bad input ---------------------------------------------------------


def test_static_type_table_defaults() -> None:
    table = StaticTypeTable()
    assert table.object_key_field is None
    assert table.name_field is None
    assert table.field_class("anything") is FieldClass.UNCLASSIFIED
    assert table.collection_mode("anything") is CollectionMode.ORDERED_SCALAR
    assert table.item_key_field("anything") is None


def test_static_type_table_returns_what_was_declared() -> None:
    table = PINNED_TABLE
    assert table.object_key_field == "_id"
    assert table.name_field == "name"
    assert table.field_class("x_passphrase") is FieldClass.SECRET
    assert table.collection_mode("rules") is CollectionMode.SET
    assert table.item_key_field("rules") == "id"


def test_static_type_table_satisfies_the_interface() -> None:
    table: TypeTable = StaticTypeTable()
    assert isinstance(table, StaticTypeTable)


def test_the_enums_use_the_names_the_type_tables_are_written_with() -> None:
    assert [item.value for item in FieldClass] == ["config", "secret", "ignore", "unclassified"]
    assert [item.value for item in CollectionMode] == [
        "set",
        "ordered-keyed",
        "ordered-scalar",
        "vendor-index",
    ]


def test_a_raw_object_must_be_a_mapping() -> None:
    with pytest.raises(TypeError, match="must be a mapping"):
        normalize_object(StaticTypeTable(), cast(Mapping[str, JsonValue], [1, 2]))


def test_object_keys_must_be_strings() -> None:
    raw = cast(Mapping[str, JsonValue], {1: "a"})
    with pytest.raises(TypeError, match="object keys must be strings"):
        normalize_object(StaticTypeTable(), raw)


def test_nested_object_keys_must_be_strings() -> None:
    raw = cast(Mapping[str, JsonValue], {"a": [{2: "b"}]})
    with pytest.raises(TypeError, match="object keys must be strings"):
        normalize_object(StaticTypeTable(), raw)


def test_values_that_are_not_json_fail_when_the_result_is_written() -> None:
    raw = cast(Mapping[str, JsonValue], {"a": b"bytes"})
    output = normalize_object(StaticTypeTable(), raw)
    with pytest.raises(TypeError, match="is not a JSON value"):
        canonical_dumps(output)


def test_the_pinned_text_is_valid_json() -> None:
    assert json.loads(PINNED_TEXT)["vlan"] == 2**60 + 1
