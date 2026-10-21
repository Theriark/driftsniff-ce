"""Property tests for core/diff.py and core/order.py (P4-T3).

Three invariants of ``compare`` hold for generated inventories:

1. the diff of an inventory with itself is empty;
2. applying the diff to the previous states gives the new states (``apply_items`` below lives
   in the tests only, and is the reader of the item format, not a second engine);
3. shuffling the members of a set, or of an ordered list that ``compare`` does not read, or the
   order of objects and resources, never changes the diff.

Two more guard the secret rule and ``diff_order``. The number of generated cases per property is
set by the Hypothesis profile (``tests/properties/conftest.py``): 500 in ``ci``.

Equality in property 2 is modulo three things the item format cannot express, each by design of
``compare`` (docs/diff.md): fields of the ``ignore`` class, the order of the members of lists
that are compared by membership, and the difference between an empty container and a missing one
(an object whose only field of a mapping went away gives the same items either way).
"""

import json
import random
from collections.abc import Mapping, Sequence
from typing import Final, cast

from hypothesis import event, given, settings
from hypothesis import strategies as st

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem
from driftsniff.core.normalize import CollectionMode
from driftsniff.core.order import diff_order

from .fixtures import (
    CANARY_PREFIX,
    TABLE,
    Inventory,
    State,
    diff,
    inventory_pairs,
)

MEMBER_LISTS: Final = ("tags", "rules", "ports")
IGNORED: Final = ("uptime",)


# ---- the apply helper (tests only) ---------------------------------------------------------


def _loads(text: str | None) -> JsonValue:
    assert text is not None
    return cast(JsonValue, json.loads(text))


def _set_path(state: State, path: str, value: JsonValue) -> None:
    node = state
    *parents, leaf = path.split(".")
    for part in parents:
        child = node.setdefault(part, {})
        assert isinstance(child, dict)
        node = child
    node[leaf] = value


def _delete_path(state: State, path: str) -> None:
    node = state
    *parents, leaf = path.split(".")
    for part in parents:
        child = node.get(part)
        if not isinstance(child, dict):
            return
        node = child
    node.pop(leaf, None)


def _list_at(state: State, path: str) -> list[JsonValue]:
    existing = state.setdefault(path, [])
    assert isinstance(existing, list)
    return existing


def _apply_member(state: State, item: ChangeItem) -> None:
    """A member of a list compared by membership: the item path is the list path."""
    members = _list_at(state, item.path)
    if item.change_kind == "added":
        after = _loads(item.after_value)
        if after != []:  # an empty list appearing is an item of its own with value []
            members.append(after)
        return
    before = _loads(item.before_value)
    if before == []:
        return
    position = members.index(before)
    if item.change_kind == "removed":
        del members[position]
    else:
        assert item.change_kind == "modified"
        members[position] = _loads(item.after_value)


def _apply_indexed(state: State, items: Sequence[ChangeItem], list_path: str) -> None:
    """The positions of an ordered-scalar list, ``dns.0``, ``dns.1``, ... in ascending order."""
    members = _list_at(state, list_path)
    dropped: list[int] = []
    for item in items:
        index = int(item.path.rsplit(".", 1)[1])
        if item.change_kind == "removed":
            dropped.append(index)
        elif item.change_kind == "added":
            assert index == len(members)
            members.append(_loads(item.after_value))
        else:
            members[index] = _loads(item.after_value)
    if dropped:
        del members[min(dropped) :]


def apply_items(old: State, items: Sequence[ChangeItem]) -> State:
    """Apply the items of one object to a copy of its previous state."""
    state = cast(State, json.loads(json.dumps(old)))
    indexed: dict[str, list[ChangeItem]] = {}
    for item in items:
        parent, _, last = item.path.rpartition(".")
        if last.isdigit() and TABLE.collection_mode(parent) is CollectionMode.ORDERED_SCALAR:
            indexed.setdefault(parent, []).append(item)
        elif item.path in MEMBER_LISTS:
            _apply_member(state, item)
        elif item.change_kind == "removed":
            _delete_path(state, item.path)
        else:
            _set_path(state, item.path, _loads(item.after_value))
    for list_path, list_items in indexed.items():
        _apply_indexed(state, list_items, list_path)
    return state


def _canonical_form(value: JsonValue, path: str = "") -> JsonValue:
    """The state as property 2 compares it: no ignored field, no empty container, lists that are
    read by membership in a fixed order."""
    if isinstance(value, Mapping):
        shaped: dict[str, JsonValue] = {}
        for key, member in value.items():
            child = f"{path}.{key}" if path else key
            if child in IGNORED:
                continue
            inner = _canonical_form(member, child)
            if inner not in ({}, []):
                shaped[key] = inner
        return shaped
    if isinstance(value, list):
        members = [_canonical_form(member, path) for member in value]
        if path in MEMBER_LISTS:
            members.sort(key=lambda member: json.dumps(member, sort_keys=True))
        return members
    return value


def _items_of(items: Sequence[ChangeItem], resource: str, key: str) -> list[ChangeItem]:
    return [i for i in items if i.resource == resource and i.object_key == key and i.path != ""]


# ---- property 1: a state against itself ----------------------------------------------------


def _check_identity(pair: tuple[Inventory, Inventory]) -> None:
    previous, new = pair
    assert diff(previous, previous) == []
    assert diff(new, new) == []


@given(pair=inventory_pairs(secrets=True))
def test_the_diff_of_a_state_with_itself_is_empty(pair: tuple[Inventory, Inventory]) -> None:
    _check_identity(pair)


# ---- property 2: the diff turns the old state into the new one -----------------------------


def _check_apply(pair: tuple[Inventory, Inventory]) -> None:
    previous, new = pair
    items = diff(previous, new)
    for resource, objects in new.items():
        old_objects = previous[resource]
        top_level = [i for i in items if i.resource == resource and i.path == ""]
        added = {i.object_key for i in top_level if i.change_kind == "added"}
        removed = {i.object_key for i in top_level if i.change_kind == "removed"}
        assert added == set(objects) - set(old_objects)
        assert removed == set(old_objects) - set(objects)
        for key in set(objects) & set(old_objects):
            rebuilt = apply_items(old_objects[key], _items_of(items, resource, key))
            assert _canonical_form(rebuilt) == _canonical_form(objects[key]), (resource, key)
        # every item names an object of its resource, nothing else is reported
        named = {i.object_key for i in items if i.resource == resource}
        assert named <= set(objects) | set(old_objects)


@given(pair=inventory_pairs())
def test_applying_the_diff_to_the_old_state_gives_the_new_state(
    pair: tuple[Inventory, Inventory],
) -> None:
    _check_apply(pair)


# ---- property 3: shuffling what compare does not read changes nothing ----------------------


def _shuffled_state(state: State, rnd: random.Random) -> State:
    shuffled = cast(State, json.loads(json.dumps(state)))
    for path in MEMBER_LISTS:
        members = shuffled.get(path)
        if isinstance(members, list):
            rnd.shuffle(members)
    return shuffled


def _shuffled_inventory(inventory: Inventory, rnd: random.Random) -> Inventory:
    resources = list(inventory)
    rnd.shuffle(resources)
    result: Inventory = {}
    for resource in resources:
        keys = list(inventory[resource])
        rnd.shuffle(keys)
        result[resource] = {key: _shuffled_state(inventory[resource][key], rnd) for key in keys}
    return result


def _check_shuffle(pair: tuple[Inventory, Inventory], rnd: random.Random) -> None:
    previous, new = pair
    expected = diff(previous, new)
    assert diff(_shuffled_inventory(previous, rnd), _shuffled_inventory(new, rnd)) == expected


@given(pair=inventory_pairs(), rnd=st.randoms(use_true_random=False))
def test_shuffling_sets_never_changes_the_diff(
    pair: tuple[Inventory, Inventory], rnd: random.Random
) -> None:
    _check_shuffle(pair, rnd)


# ---- the budget and the share of non-empty diffs ------------------------------------------
# These tests are standalone: each one runs a property body itself, through a counting wrapper,
# so it does not depend on file order, on other tests, on ``-k``, on random order or on xdist,
# and it checks the budget of whatever profile is active (500 in ``ci``, 5000 in ``nightly``).
# The cost is that the three properties run once more.

NON_EMPTY_SHARE: Final = 0.70
"""At least this share of the generated pairs must give a diff with items. Two independent
draws of 0 to 4 objects, each with about ten optional fields, are almost never equal; 70 percent
leaves room for Hypothesis' bias to small examples. If it is missed, widen the generators in
fixtures.py; do not lower this number."""


def _budget() -> int:
    return settings().max_examples


def test_the_identity_property_runs_its_whole_budget() -> None:
    runs = 0

    @given(pair=inventory_pairs(secrets=True))
    def counted(pair: tuple[Inventory, Inventory]) -> None:
        nonlocal runs
        runs += 1
        _check_identity(pair)

    counted()
    assert runs >= _budget(), runs


def test_the_apply_property_runs_its_whole_budget() -> None:
    runs = 0

    @given(pair=inventory_pairs())
    def counted(pair: tuple[Inventory, Inventory]) -> None:
        nonlocal runs
        runs += 1
        _check_apply(pair)

    counted()
    assert runs >= _budget(), runs


def test_the_shuffle_property_runs_its_whole_budget() -> None:
    runs = 0

    @given(pair=inventory_pairs(), rnd=st.randoms(use_true_random=False))
    def counted(pair: tuple[Inventory, Inventory], rnd: random.Random) -> None:
        nonlocal runs
        runs += 1
        _check_shuffle(pair, rnd)

    counted()
    assert runs >= _budget(), runs


def test_most_generated_pairs_give_a_non_empty_diff() -> None:
    total = 0
    non_empty = 0

    @given(pair=inventory_pairs())
    def counted(pair: tuple[Inventory, Inventory]) -> None:
        nonlocal total, non_empty
        total += 1
        has_items = bool(diff(*pair))
        non_empty += has_items
        event("non-empty diff" if has_items else "empty diff")

    counted()
    assert total >= _budget(), total
    assert non_empty / total >= NON_EMPTY_SHARE, f"{non_empty} of {total} pairs gave items"


# ---- secrets never reach an item -----------------------------------------------------------


def _all_text(item: ChangeItem) -> str:
    parts = [
        item.before_value,
        item.after_value,
        item.before_fp,
        item.after_fp,
        item.path,
        item.rationale,
        json.dumps(item.order_detail) if item.order_detail is not None else None,
    ]
    return " ".join(part for part in parts if part is not None)


@given(pair=inventory_pairs(secrets=True))
def test_a_secret_value_never_appears_in_an_item(pair: tuple[Inventory, Inventory]) -> None:
    previous, new = pair
    for item in diff(previous, new):
        assert CANARY_PREFIX not in _all_text(item), item.path
        if item.path == "wifi.passphrase":
            assert item.before_value is None and item.after_value is None


# ---- diff_order ----------------------------------------------------------------------------

_keys = st.lists(st.sampled_from(list("abcdefgh")), max_size=8, unique=True).map(tuple)


@given(old=_keys, new=_keys)
def test_diff_order_leaves_the_common_keys_in_one_order_apart_from_the_moves(
    old: tuple[str, ...], new: tuple[str, ...]
) -> None:
    result = diff_order(old, new)
    common_old = [key for key in old if key in new]
    common_new = [key for key in new if key in old]
    assert result.inserted == tuple(key for key in new if key not in old)
    assert result.deleted == tuple(key for key in old if key not in new)
    assert result.reordered == (common_old != common_new)
    moved = [move.key for move in result.moves]
    assert len(moved) == len(set(moved))
    assert set(moved) <= set(common_old)
    assert bool(moved) == result.reordered
    assert [k for k in common_old if k not in moved] == [k for k in common_new if k not in moved]
    assert diff_order(old, old).moves == ()
