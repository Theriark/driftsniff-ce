"""Tests for core/order.py: moves in ordered lists, inserts and deletes left to the diff."""

import itertools
import json
from collections.abc import Iterator, Mapping

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, StateLookup, compare
from driftsniff.core.normalize import (
    NORMALISER_VERSION,
    CollectionMode,
    FieldClass,
    StaticTypeTable,
    TypeTable,
)
from driftsniff.core.order import (
    LARGE_LIST_NOTE,
    MAX_ORDERED_ENTRIES,
    Move,
    compare_order,
    diff_order,
)
from driftsniff.core.snapshots import CollectedObject, CollectedResource, Manifest, build_manifest
from driftsniff.secrets.fingerprint import Fingerprinter

FINGERPRINTER = Fingerprinter(bytes(range(32)), "0a1b2c3d")
CANARY = "CANARY-0002"
START = "2026-10-21T10:00:00Z"
END = "2026-10-21T10:05:00Z"

FIREWALL = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "action": FieldClass.CONFIG,
        "rules": FieldClass.CONFIG,
        "rules.id": FieldClass.CONFIG,
        "rules.action": FieldClass.CONFIG,
        "acl": FieldClass.CONFIG,
        "acl.entries": FieldClass.CONFIG,
        "acl.entries.id": FieldClass.CONFIG,
        "chain": FieldClass.CONFIG,
        "tokens": FieldClass.CONFIG,
        "tokens.id": FieldClass.SECRET,
        "vault": FieldClass.SECRET,
        "vault.id": FieldClass.CONFIG,
        "history": FieldClass.IGNORE,
        "history.id": FieldClass.CONFIG,
        "tags": FieldClass.CONFIG,
        "dns": FieldClass.CONFIG,
        "ports": FieldClass.CONFIG,
        "ports.idx": FieldClass.CONFIG,
    },
    collection_modes={
        "rules": CollectionMode.ORDERED_KEYED,
        "acl.entries": CollectionMode.ORDERED_KEYED,
        "chain": CollectionMode.ORDERED_KEYED,
        "tokens": CollectionMode.ORDERED_KEYED,
        "vault": CollectionMode.ORDERED_KEYED,
        "history": CollectionMode.ORDERED_KEYED,
        "tags": CollectionMode.SET,
        "dns": CollectionMode.ORDERED_SCALAR,
        "ports": CollectionMode.VENDOR_INDEX,
    },
    item_key_fields={
        "rules": "id",
        "acl.entries": "id",
        "tokens": "id",
        "vault": "id",
        "history": "id",
        "ports": "idx",
    },
)
TABLES: Mapping[str, TypeTable] = {"firewall": FIREWALL, "policy": FIREWALL}


def obj(key: str, /, **fields: JsonValue) -> CollectedObject:
    """An object whose state holds its key, a name and ``fields``."""
    state: dict[str, JsonValue] = {"_id": key, "name": f"fw {key}", **fields}
    return CollectedObject(key, state, f"fw {key}")


def build(
    resources: Mapping[str, list[CollectedObject]],
    *,
    ordered: tuple[str, ...] = (),
    normaliser: int = NORMALISER_VERSION,
) -> Manifest:
    collected = {
        name: CollectedResource(objects, ordered=name in ordered)
        for name, objects in resources.items()
    }
    return build_manifest(collected, controller_version="1.0", normaliser_version=normaliser)


def policies(*keys: str) -> Manifest:
    """A manifest with one ordered resource whose objects are ``keys``, in that order."""
    return build({"policy": [obj(key) for key in keys]}, ordered=("policy",))


def lookup_for(*manifests: Manifest) -> tuple[StateLookup, list[str]]:
    """A state lookup over the manifests, and the list of the hashes it was asked for."""
    pending: dict[str, bytes] = {}
    for manifest in manifests:
        pending.update(manifest.pending_states)
    reads: list[str] = []

    def lookup(state_hash: str) -> Mapping[str, JsonValue]:
        reads.append(state_hash)
        loaded = json.loads(pending[state_hash])
        assert isinstance(loaded, dict)
        return loaded

    return lookup, reads


def order_items(previous: Manifest | None, new: Manifest) -> list[ChangeItem]:
    lookup, _ = lookup_for(*([new] if previous is None else [previous, new]))
    return compare_order(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        type_tables=TABLES,
    )


def diff_items(previous: Manifest, new: Manifest) -> list[ChangeItem]:
    lookup, _ = lookup_for(previous, new)
    return compare(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        fingerprinter=FINGERPRINTER,
        type_tables=TABLES,
    )


def firewall(**fields: JsonValue) -> Manifest:
    return build({"firewall": [obj("fw1", **fields)]})


def rule(key: str, action: str = "allow") -> dict[str, JsonValue]:
    return {"id": key, "action": action}


def rules(*keys: str) -> dict[str, JsonValue]:
    members: list[JsonValue] = [rule(key) for key in keys]
    return {"rules": members}


def one(items: list[ChangeItem]) -> ChangeItem:
    assert len(items) == 1, items
    return items[0]


def detail_of(item: ChangeItem) -> Mapping[str, JsonValue]:
    assert item.order_detail is not None
    return item.order_detail


def keys(count: int) -> list[str]:
    return [f"k{index}" for index in range(count)]


# ---- the order of one list of keys ----------------------------------------------------------


def test_an_unchanged_order_is_no_change() -> None:
    result = diff_order(["a", "b", "c"], ["a", "b", "c"])
    assert (result.inserted, result.deleted, result.moves) == ((), (), ())
    assert result.reordered is False and result.large is False


def test_one_rule_inserted_at_the_top_is_one_insert_and_no_move() -> None:
    result = diff_order(["r1", "r2", "r3"], ["r0", "r1", "r2", "r3"])
    assert result.inserted == ("r0",)
    assert (result.deleted, result.moves, result.reordered) == ((), (), False)


def test_a_rule_deleted_in_the_middle_is_one_delete_and_no_move() -> None:
    result = diff_order(["a", "b", "c", "d"], ["a", "c", "d"])
    assert result.deleted == ("b",)
    assert (result.inserted, result.moves, result.reordered) == ((), (), False)


def test_swapping_two_neighbours_is_one_move() -> None:
    result = diff_order(["a", "b", "c"], ["b", "a", "c"])
    moved = Move("b", from_after="a", from_before="c", to_after=None, to_before="a")
    assert result.moves == (moved,)
    assert result.reordered is True


def test_moving_the_last_key_to_the_first_place_is_one_move() -> None:
    result = diff_order(["a", "b", "c", "d"], ["d", "a", "b", "c"])
    moved = Move("d", from_after="c", from_before=None, to_after=None, to_before="a")
    assert result.moves == (moved,)


def test_moving_the_first_key_to_the_end_is_one_move() -> None:
    result = diff_order(["a", "b", "c"], ["b", "c", "a"])
    moved = Move("a", from_after=None, from_before="b", to_after="c", to_before=None)
    assert result.moves == (moved,)


def test_the_fewest_keys_are_called_moved() -> None:
    result = diff_order(list("abcde"), list("cdeab"))
    assert [move.key for move in result.moves] == ["a", "b"]


def test_reversing_a_list_moves_all_but_one_key() -> None:
    result = diff_order(list("abcd"), list("dcba"))
    assert [move.key for move in result.moves] == ["d", "c", "b"]


def test_inserts_deletes_and_a_move_in_one_change_are_each_reported_once() -> None:
    result = diff_order(list("abcde"), list("xcad"))
    assert (result.inserted, result.deleted) == (("x",), ("b", "e"))
    moved = Move("c", from_after="b", from_before="d", to_after="x", to_before="a")
    assert result.moves == (moved,)


def test_a_move_is_described_in_words() -> None:
    assert Move("r7", "r2", "r8", None, "r1").summary == "r7 moved from after r2 to before r1"
    assert Move("r7", None, "r8", "r3", None).summary == "r7 moved from the top to the end"


def test_the_detail_holds_the_moved_key_and_the_keys_around_it() -> None:
    move = diff_order(["a", "b", "c"], ["c", "a", "b"]).moves[0]
    assert move.detail() == {
        "key": "c",
        "from_after": "b",
        "from_before": None,
        "to_after": None,
        "to_before": "a",
        "summary": "c moved from after b to before a",
    }


def test_the_same_input_always_gives_the_same_moves() -> None:
    old, new = list("abcdefgh"), list("hgfedcba")
    first = diff_order(old, new)
    assert all(diff_order(old, new) == first for _ in range(100))


@pytest.mark.parametrize("side", ["old", "new"])
def test_a_key_listed_twice_is_refused(side: str) -> None:
    twice = ["a", "b", "a"]
    with pytest.raises(ValueError, match=f"the {side} order lists 'a' more than once"):
        diff_order(twice if side == "old" else ["a"], twice if side == "new" else ["a"])


def all_orders(symbols: str) -> Iterator[list[str]]:
    for size in range(len(symbols) + 1):
        for chosen in itertools.permutations(symbols, size):
            yield list(chosen)


def lcs_length(left: list[str], right: list[str]) -> int:
    table = [[0] * (len(right) + 1) for _ in range(len(left) + 1)]
    for i, left_key in enumerate(left, 1):
        for j, right_key in enumerate(right, 1):
            if left_key == right_key:
                table[i][j] = table[i - 1][j - 1] + 1
            else:
                table[i][j] = max(table[i - 1][j], table[i][j - 1])
    return table[-1][-1]


def test_for_every_small_pair_of_orders_the_moves_are_the_fewest() -> None:
    for old in all_orders("abcd"):
        for new in all_orders("abcdx"):
            result = diff_order(old, new)
            common_old = [key for key in old if key in new]
            common_new = [key for key in new if key in old]
            moved = {move.key for move in result.moves}
            still_old = [key for key in common_old if key not in moved]
            still_new = [key for key in common_new if key not in moved]
            assert len(moved) == len(result.moves)
            assert still_old == still_new
            assert len(moved) == len(common_old) - lcs_length(common_old, common_new)
            assert set(result.inserted) == set(new) - set(old)
            assert set(result.deleted) == set(old) - set(new)
            assert result.reordered == (common_old != common_new)


def test_a_list_at_the_limit_still_gets_its_moves() -> None:
    old = keys(MAX_ORDERED_ENTRIES)
    result = diff_order(old, list(reversed(old)))
    assert result.large is False
    assert len(result.moves) == MAX_ORDERED_ENTRIES - 1


def test_a_list_over_the_limit_is_compared_as_a_set() -> None:
    old = keys(MAX_ORDERED_ENTRIES + 1)
    reordered = diff_order(old, list(reversed(old)))
    assert (reordered.large, reordered.reordered, reordered.moves) == (True, True, ())
    inserted = diff_order(old, ["new", *old])
    assert (inserted.large, inserted.reordered, inserted.inserted) == (False, False, ("new",))


# ---- the order of the objects of a resource -------------------------------------------------


def test_an_insert_at_the_top_of_an_ordered_resource_is_one_added_item_and_no_move() -> None:
    previous, new = policies("r1", "r2", "r3"), policies("r0", "r1", "r2", "r3")
    assert order_items(previous, new) == []
    added = one(diff_items(previous, new))
    assert (added.change_kind, added.object_key) == ("added", "r0")


def test_a_deleted_object_of_an_ordered_resource_is_not_a_move() -> None:
    previous, new = policies("r1", "r2", "r3"), policies("r1", "r3")
    assert order_items(previous, new) == []
    assert one(diff_items(previous, new)).change_kind == "removed"


def test_a_moved_object_is_one_item_with_its_neighbours_in_the_detail() -> None:
    item = one(order_items(policies("r1", "r2", "r3"), policies("r3", "r1", "r2")))
    assert (item.resource, item.object_key, item.object_name) == ("policy", "r3", "fw r3")
    assert (item.change_kind, item.path, item.field_class) == ("moved", "", FieldClass.CONFIG)
    assert item.before_value is item.after_value is item.before_fp is item.after_fp is None
    assert (item.window_start, item.window_end) == (START, END)
    assert (item.severity, item.rule_id, item.rationale) == (None, None, None)
    assert detail_of(item) == {
        "key": "r3",
        "from_after": "r2",
        "from_before": None,
        "to_after": None,
        "to_before": "r1",
        "summary": "r3 moved from after r2 to before r1",
    }


def test_several_moved_objects_come_out_in_the_new_order() -> None:
    items = order_items(policies(*"abcde"), policies(*"cdeba"))
    assert [(item.change_kind, item.object_key) for item in items] == [
        ("moved", "b"),
        ("moved", "a"),
    ]


def test_an_insert_and_a_move_together_report_only_the_move_here() -> None:
    previous, new = policies("r1", "r2", "r3"), policies("r0", "r3", "r1", "r2")
    assert [item.object_key for item in order_items(previous, new)] == ["r3"]
    assert [item.change_kind for item in diff_items(previous, new)] == ["added"]


def test_a_move_needs_no_state_when_the_manifests_know_the_name() -> None:
    previous, new = policies("r1", "r2"), policies("r2", "r1")
    lookup, reads = lookup_for(previous, new)
    items = compare_order(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        type_tables=TABLES,
    )
    assert one(items).object_name == "fw r2"
    assert reads == []


def test_the_name_of_a_moved_object_falls_back_to_its_state() -> None:
    previous_built, new_built = policies("r1", "r2"), policies("r2", "r1")
    previous = Manifest.from_bytes(previous_built.canonical_bytes())
    new = Manifest.from_bytes(new_built.canonical_bytes())
    assert previous.names == {} and new.names == {}
    lookup, reads = lookup_for(previous_built, new_built)
    items = compare_order(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        type_tables=TABLES,
    )
    assert one(items).object_name == "fw r2"
    assert len(reads) == 1
    nameless = compare_order(previous, new, lookup, window_start=START, window_end=END)
    assert one(nameless).object_name is None


def test_a_resource_that_is_not_ordered_has_no_moves() -> None:
    previous = build({"policy": [obj("r1"), obj("r2"), obj("r3")]})
    new = build({"policy": [obj("r3"), obj("r1"), obj("r2")]})
    assert previous.manifest_hash == new.manifest_hash
    assert order_items(previous, new) == []


def test_a_resource_that_becomes_ordered_is_not_compared_with_an_order_it_never_had() -> None:
    unordered = build({"policy": [obj("r1"), obj("r2")]})
    assert order_items(unordered, policies("r2", "r1")) == []
    assert order_items(policies("r2", "r1"), unordered) == []


def test_a_resource_missing_from_the_previous_manifest_is_all_new_and_has_no_moves() -> None:
    previous = build({"firewall": [obj("fw1")]})
    assert order_items(previous, policies("r2", "r1")) == []


def test_a_large_ordered_resource_reports_that_its_order_changed() -> None:
    names = keys(MAX_ORDERED_ENTRIES + 1)
    item = one(order_items(policies(*names), policies(*reversed(names))))
    assert (item.resource, item.object_key, item.path) == ("policy", None, "")
    assert item.change_kind == "order_changed"
    assert detail_of(item) == {
        "note": LARGE_LIST_NOTE,
        "old_count": MAX_ORDERED_ENTRIES + 1,
        "new_count": MAX_ORDERED_ENTRIES + 1,
    }


def test_a_large_ordered_resource_that_only_grew_has_no_order_item() -> None:
    names = keys(MAX_ORDERED_ENTRIES + 1)
    assert order_items(policies(*names), policies("new", *names)) == []


def test_the_first_manifest_and_a_new_normaliser_version_are_baselines() -> None:
    assert order_items(None, policies("r2", "r1")) == []
    old = build({"policy": [obj("r1"), obj("r2")]}, ordered=("policy",), normaliser=1)
    new = build({"policy": [obj("r2"), obj("r1")]}, ordered=("policy",), normaliser=2)
    assert order_items(old, new) == []


# ---- the order of the members of a list inside an object ------------------------------------


def test_two_rules_that_swap_places_are_one_move_of_the_object() -> None:
    previous, new = firewall(**rules("r1", "r2", "r3")), firewall(**rules("r1", "r3", "r2"))
    item = one(order_items(previous, new))
    assert (item.resource, item.object_key, item.object_name) == ("firewall", "fw1", "fw fw1")
    assert (item.change_kind, item.path) == ("moved", "rules")
    assert detail_of(item)["key"] == "r3"
    assert detail_of(item)["summary"] == "r3 moved from after r2 to before r2"


def test_a_rule_inserted_at_the_top_of_a_list_is_one_added_item_and_no_move() -> None:
    previous, new = firewall(**rules("r1", "r2")), firewall(**rules("r0", "r1", "r2"))
    assert order_items(previous, new) == []
    added = one(diff_items(previous, new))
    assert (added.change_kind, added.path) == ("added", "rules")


def test_a_rule_that_moves_to_the_top_is_one_move() -> None:
    previous, new = firewall(**rules("r1", "r2", "r3")), firewall(**rules("r3", "r1", "r2"))
    item = one(order_items(previous, new))
    assert detail_of(item) == {
        "key": "r3",
        "from_after": "r2",
        "from_before": None,
        "to_after": None,
        "to_before": "r1",
        "summary": "r3 moved from after r2 to before r1",
    }


def test_a_rule_that_changed_without_moving_is_not_a_move() -> None:
    previous = firewall(rules=[rule("r1"), rule("r2", "allow")])
    new = firewall(rules=[rule("r1"), rule("r2", "deny")])
    assert order_items(previous, new) == []
    assert one(diff_items(previous, new)).change_kind == "modified"


def test_a_move_and_a_change_in_one_object_are_each_reported_by_their_own_engine() -> None:
    previous = firewall(rules=[rule("r1"), rule("r2"), rule("r3", "allow")])
    new = firewall(rules=[rule("r3", "deny"), rule("r1"), rule("r2")])
    assert [item.object_key for item in order_items(previous, new)] == ["fw1"]
    assert [item.change_kind for item in diff_items(previous, new)] == ["modified"]
    assert detail_of(one(order_items(previous, new)))["key"] == "r3"


def test_a_list_below_a_mapping_is_found_by_its_whole_path() -> None:
    def entries(*names: str) -> dict[str, JsonValue]:
        members: list[JsonValue] = [{"id": name} for name in names]
        return {"acl": {"entries": members}}

    item = one(order_items(firewall(**entries("e1", "e2")), firewall(**entries("e2", "e1"))))
    assert (item.object_key, item.path, detail_of(item)["key"]) == ("fw1", "acl.entries", "e2")


def test_a_repeated_key_is_told_apart_by_its_occurrence() -> None:
    previous = firewall(rules=[rule("r1"), rule("r2"), rule("r1")])
    new = firewall(rules=[rule("r1"), rule("r1"), rule("r2")])
    move = detail_of(one(order_items(previous, new)))
    assert (move["key"], move["from_after"], move["from_before"]) == ("r1#2", "r2", None)
    assert (move["to_after"], move["to_before"]) == ("r1", "r2")


def test_members_without_a_key_are_shown_as_a_hash_never_as_their_content() -> None:
    previous = firewall(chain=[CANARY, "second", "third"])
    new = firewall(chain=["second", CANARY, "third"])
    item = one(order_items(previous, new))
    shown = json.dumps(detail_of(item))
    assert CANARY not in shown and "second" not in shown
    assert str(detail_of(item)["key"]).startswith("member:")


def test_the_same_keyless_member_always_has_the_same_label() -> None:
    first = one(order_items(firewall(chain=["x", "y"]), firewall(chain=["y", "x"])))
    second = one(order_items(firewall(chain=["x", "y", "z"]), firewall(chain=["y", "x", "z"])))
    assert detail_of(first)["key"] == detail_of(second)["key"]


def test_a_secret_key_field_is_never_shown() -> None:
    def tokens(*names: str) -> dict[str, JsonValue]:
        members: list[JsonValue] = [{"id": name} for name in names]
        return {"tokens": members}

    item = one(order_items(firewall(**tokens(CANARY, "t2")), firewall(**tokens("t2", CANARY))))
    assert CANARY not in json.dumps(detail_of(item)) and "t2" not in json.dumps(detail_of(item))


@pytest.mark.parametrize("name", ["vault", "history"])
def test_a_secret_or_ignored_list_is_not_read(name: str) -> None:
    def members(*names: str) -> dict[str, JsonValue]:
        listed: list[JsonValue] = [{"id": item} for item in names]
        return {name: listed}

    assert order_items(firewall(**members("a", "b")), firewall(**members("b", "a"))) == []


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ({"tags": ["a", "b", "c"]}, {"tags": ["c", "a", "b"]}),
        ({"dns": ["a", "b"]}, {"dns": ["b", "a"]}),
        ({"ports": [{"idx": 1}, {"idx": 2}]}, {"ports": [{"idx": 2}, {"idx": 1}]}),
        ({"unknown": [1, 2]}, {"unknown": [2, 1]}),
    ],
)
def test_sets_scalar_lists_and_vendor_indexes_have_no_moves(
    before: dict[str, JsonValue], after: dict[str, JsonValue]
) -> None:
    assert order_items(firewall(**before), firewall(**after)) == []


def test_a_list_that_is_missing_or_of_another_kind_on_one_side_has_no_moves() -> None:
    assert order_items(firewall(), firewall(**rules("r2", "r1"))) == []
    assert order_items(firewall(**rules("r1", "r2")), firewall(rules={"id": "r1"})) == []
    assert order_items(firewall(acl={"entries": 1}), firewall(acl=[1, 2])) == []


def test_a_large_list_inside_an_object_reports_that_its_order_changed() -> None:
    names = keys(MAX_ORDERED_ENTRIES + 1)
    item = one(order_items(firewall(**rules(*names)), firewall(**rules(*reversed(names)))))
    assert (item.object_key, item.path, item.change_kind) == ("fw1", "rules", "order_changed")
    assert detail_of(item)["note"] == LARGE_LIST_NOTE
    assert detail_of(item)["old_count"] == MAX_ORDERED_ENTRIES + 1


def test_only_the_objects_whose_state_changed_are_read() -> None:
    unchanged = ("r1", "r2")
    previous = build({"firewall": [obj(f"fw{n}", **rules(*unchanged)) for n in (1, 2, 3)]})
    swapped = [obj(f"fw{n}", **rules("r2", "r1")) for n in (2, 3)]
    new = build({"firewall": [obj("fw1", **rules(*unchanged)), *swapped]})
    lookup, reads = lookup_for(previous, new)
    items = compare_order(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        type_tables=TABLES,
    )
    assert [item.object_key for item in items] == ["fw2", "fw3"]
    assert len(reads) == 4


def test_a_list_in_an_object_of_a_resource_without_a_table_is_not_read() -> None:
    previous = build({"other": [obj("o1", **rules("r1", "r2"))]})
    new = build({"other": [obj("o1", **rules("r2", "r1"))]})
    assert order_items(previous, new) == []


def test_items_come_out_in_a_stable_order() -> None:
    previous = build(
        {
            "firewall": [obj("fw2", **rules("a", "b")), obj("fw1", **rules("a", "b"))],
            "policy": [obj("p1"), obj("p2")],
        },
        ordered=("policy",),
    )
    new = build(
        {
            "firewall": [obj("fw2", **rules("b", "a")), obj("fw1", **rules("b", "a"))],
            "policy": [obj("p2"), obj("p1")],
        },
        ordered=("policy",),
    )
    items = order_items(previous, new)
    assert [(item.resource, item.object_key, item.path) for item in items] == [
        ("firewall", "fw1", "rules"),
        ("firewall", "fw2", "rules"),
        ("policy", "p2", ""),
    ]
    assert order_items(previous, new) == items
