"""The ordering fixtures of P4-T2 run through the rule engine (P5-T4).

``tests/unit/test_order.py`` checks which items ``core/order.py`` reports. These tests go one step
further, with the type tables in this folder in the shipped format: which severity each of those
items gets. The firewall policy list is first-match-wins with the floors added high, removed
critical, modified high and moved high; ``unifi-networks`` is an unordered collection.
"""

from collections import Counter

from driftsniff.core.diff import ChangeItem
from driftsniff.rules.engine import MOVE_BLOCKING_RULE_ID, MOVE_RULE_ID

from .support import State, detect, golden_engine, state

FIREWALL = "unifi-firewall-policies"
# A move among allow policies is HIGH by two floors at once (the object floor of the table and the
# first-match move floor); the engine takes the first of equal floors, so either id may decide.
HIGH_MOVE_RULE_IDS = {"builtin.floor.moved", MOVE_RULE_ID}


def policies(*entries: tuple[str, str]) -> list[State]:
    return [state(id=key, name=f"policy {key}", action=action) for key, action in entries]


def run(before: list[State], after: list[State]) -> list[ChangeItem]:
    return detect(FIREWALL, before, after, ordered=True)


def kinds(items: list[ChangeItem]) -> Counter[str]:
    return Counter(item.change_kind for item in items)


def only(items: list[ChangeItem]) -> ChangeItem:
    assert len(items) == 1, items
    return items[0]


def test_a_policy_inserted_at_the_top_is_one_insert_and_no_move_and_high() -> None:
    before = policies(("p1", "allow"), ("p2", "deny"))
    after = policies(("p0", "allow"), ("p1", "allow"), ("p2", "deny"))
    items = run(before, after)
    assert kinds(items) == {"added": 1}
    result = golden_engine().classify(only(items))
    assert result.severity == "high"
    assert result.rule_id == "builtin.floor.added"


def test_swapping_two_neighbours_is_one_move_and_at_least_high() -> None:
    before = policies(("p1", "allow"), ("p2", "allow"), ("p3", "allow"))
    after = policies(("p2", "allow"), ("p1", "allow"), ("p3", "allow"))
    items = run(before, after)
    assert kinds(items) == {"moved": 1}
    result = golden_engine().classify(only(items))
    assert result.severity == "high"
    assert result.rule_id in HIGH_MOVE_RULE_IDS


def test_swapping_a_deny_policy_with_its_neighbour_is_critical() -> None:
    before = policies(("p1", "allow"), ("p2", "deny"))
    after = policies(("p2", "deny"), ("p1", "allow"))
    items = run(before, after)
    assert kinds(items) == {"moved": 1}
    result = golden_engine().classify(only(items))
    assert (result.severity, result.rule_id) == ("critical", MOVE_BLOCKING_RULE_ID)


def test_moving_the_last_policy_to_the_first_place_is_one_move() -> None:
    before = policies(("p1", "allow"), ("p2", "allow"), ("p3", "allow"))
    after = policies(("p3", "allow"), ("p1", "allow"), ("p2", "allow"))
    items = run(before, after)
    assert kinds(items) == {"moved": 1}
    item = only(items)
    assert item.object_key == "p3"
    assert golden_engine().classify(item).severity == "high"


def test_deleting_a_policy_in_the_middle_is_one_removal_and_critical() -> None:
    before = policies(("p1", "allow"), ("p2", "allow"), ("p3", "allow"))
    after = policies(("p1", "allow"), ("p3", "allow"))
    items = run(before, after)
    assert kinds(items) == {"removed": 1}
    item = only(items)
    assert item.object_key == "p2"
    result = golden_engine().classify(item)
    assert (result.severity, result.rule_id) == ("critical", "builtin.floor.removed")


def test_a_move_above_a_deny_policy_is_critical() -> None:
    before = policies(("p1", "allow"), ("p2", "deny"), ("p3", "allow"))
    after = policies(("p1", "allow"), ("p3", "allow"), ("p2", "deny"))
    items = run(before, after)
    assert kinds(items) == {"moved": 1}
    result = golden_engine().classify(only(items))
    assert (result.severity, result.rule_id) == ("critical", MOVE_BLOCKING_RULE_ID)


def test_a_move_above_a_drop_policy_is_critical() -> None:
    before = policies(("p1", "allow"), ("p2", "drop"), ("p3", "allow"))
    after = policies(("p3", "allow"), ("p1", "allow"), ("p2", "drop"))
    items = run(before, after)
    assert kinds(items) == {"moved": 1}
    assert golden_engine().classify(only(items)).severity == "critical"


def test_a_move_among_allow_policies_is_not_critical() -> None:
    before = policies(("p1", "allow"), ("p2", "allow"), ("p3", "deny"))
    after = policies(("p2", "allow"), ("p1", "allow"), ("p3", "deny"))
    items = run(before, after)
    assert kinds(items) == {"moved": 1}
    assert golden_engine().classify(only(items)).severity == "high"


def test_reordering_a_set_produces_no_item() -> None:
    before = [state(id="n1", name="Guest"), state(id="n2", name="Staff")]
    after = [state(id="n2", name="Staff"), state(id="n1", name="Guest")]
    assert detect("unifi-networks", before, after, ordered=False) == []


def test_an_unchanged_firewall_list_produces_no_item() -> None:
    same = policies(("p1", "allow"), ("p2", "deny"))
    assert run(same, list(same)) == []
