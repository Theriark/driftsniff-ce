"""The ordering merge and the derived action field of the UniFi collector (P7-T4)."""

from typing import Any

import pytest

from driftsniff.collectors.unifi.normalize import (
    ACTION_TYPE_FIELD,
    firewall_orderings,
    firewall_pairs,
    is_system_placed,
    merge_ordering,
    mismatch_text,
    prepare_object,
    zone_pair,
)
from driftsniff.collectors.unifi.resources import RESOURCE_ACL_RULES, RESOURCE_FIREWALL_POLICIES


def policy(
    key: str, source: object = "z1", destination: object = "z2", origin: str | None = None
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": key,
        "name": f"Policy {key}",
        "action": {"type": "BLOCK"},
        "source": {"zoneId": source},
        "destination": {"zoneId": destination},
    }
    if origin is not None:
        item["metadata"] = {"origin": origin}
    return item


def ids(merged_objects: list[dict[str, Any]]) -> list[str]:
    return [item["id"] for item in merged_objects]


# -- the derived action field ------------------------------------------------------------------


def test_the_action_type_is_copied_to_the_flat_field_of_a_firewall_policy() -> None:
    raw = {"id": "p1", "action": {"type": "BLOCK", "allowReturnTraffic": False}}
    prepared = prepare_object(RESOURCE_FIREWALL_POLICIES, raw)
    assert prepared[ACTION_TYPE_FIELD] == "BLOCK"
    assert prepared["action"] == {"type": "BLOCK", "allowReturnTraffic": False}
    assert ACTION_TYPE_FIELD not in raw


def test_a_flat_action_type_from_the_controller_cannot_disagree_with_the_nested_one() -> None:
    raw = {"id": "p1", "actionType": "ALLOW", "action": {"type": "BLOCK"}}
    assert prepare_object(RESOURCE_FIREWALL_POLICIES, raw)[ACTION_TYPE_FIELD] == "BLOCK"


@pytest.mark.parametrize(
    "raw",
    [
        {"id": "p1", "actionType": "ALLOW"},
        {"id": "p1", "actionType": "ALLOW", "action": None},
        {"id": "p1", "actionType": "ALLOW", "action": {"type": 5}},
        {"id": "p1", "actionType": "ALLOW", "action": {}},
        {"id": "p1", "actionType": "ALLOW", "action": "BLOCK"},
    ],
)
def test_a_policy_without_a_usable_nested_action_has_no_flat_one(raw: dict[str, Any]) -> None:
    assert ACTION_TYPE_FIELD not in prepare_object(RESOURCE_FIREWALL_POLICIES, raw)


def test_other_resources_are_only_copied() -> None:
    raw = {"id": "a1", "action": {"type": "BLOCK"}}
    prepared = prepare_object(RESOURCE_ACL_RULES, raw)
    assert prepared == raw
    assert prepared is not raw


# -- zone pairs --------------------------------------------------------------------------------


def test_a_zone_pair_needs_two_plain_zone_ids() -> None:
    assert zone_pair(policy("p1", "z1", "z2")) == ("z1", "z2")
    for source, destination in [
        (None, "z2"),
        ("z1", None),
        ("", "z2"),
        ("z 1", "z2"),
        ("z1", "z2?x=1"),
        ("z" * 65, "z2"),
        (5, "z2"),
    ]:
        assert zone_pair(policy("p1", source, destination)) is None
    assert zone_pair({"id": "p1", "source": "z1", "destination": {"zoneId": "z2"}}) is None
    assert zone_pair({"id": "p1"}) is None


def test_the_pairs_are_distinct_and_sorted() -> None:
    policies = [
        policy("p1", "z2", "z1"),
        policy("p2", "z1", "z2"),
        policy("p3", "z2", "z1"),
        policy("p4", None, "z1"),
    ]
    assert firewall_pairs(policies) == [("z1", "z2"), ("z2", "z1")]
    assert firewall_pairs([]) == []


# -- the merge ---------------------------------------------------------------------------------


def test_the_objects_come_back_in_the_order_of_the_lists() -> None:
    objects = [{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "d"}]
    merged = merge_ordering(objects, [["c", "a"], ["d", "b"]])
    assert ids(merged.objects) == ["c", "a", "d", "b"]
    assert (merged.appended, merged.dropped, merged.mismatch) == (0, 0, False)


def test_an_object_no_list_names_is_appended_in_collected_order_and_counted() -> None:
    objects = [{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "d"}]
    merged = merge_ordering(objects, [["c"]])
    assert ids(merged.objects) == ["c", "a", "b", "d"]
    assert (merged.appended, merged.dropped, merged.mismatch) == (3, 0, True)


def test_an_id_without_an_object_is_dropped_and_counted() -> None:
    objects = [{"id": "a"}, {"id": "b"}]
    merged = merge_ordering(objects, [["b", "ghost", "a"]])
    assert ids(merged.objects) == ["b", "a"]
    assert (merged.appended, merged.dropped, merged.mismatch) == (0, 1, True)


def test_an_id_listed_twice_is_placed_once_and_the_repeat_is_dropped() -> None:
    objects = [{"id": "a"}, {"id": "b"}]
    merged = merge_ordering(objects, [["b", "a"], ["b"]])
    assert ids(merged.objects) == ["b", "a"]
    assert (merged.appended, merged.dropped) == (0, 1)


def test_an_object_without_a_usable_id_is_appended() -> None:
    objects: list[dict[str, Any]] = [{"id": "a"}, {"name": "no id"}, {"id": ""}, {"id": 5}]
    merged = merge_ordering(objects, [["a"]])
    assert merged.objects == objects
    assert (merged.appended, merged.dropped) == (3, 0)


def test_two_objects_with_one_id_keep_the_first_in_place_and_append_the_second() -> None:
    first = {"id": "a", "name": "first"}
    second = {"id": "a", "name": "second"}
    merged = merge_ordering([first, second], [["a"]])
    assert merged.objects == [first, second]
    assert (merged.appended, merged.dropped) == (1, 0)


def test_nothing_in_nothing_out() -> None:
    merged = merge_ordering([], [])
    assert (merged.objects, merged.mismatch) == ([], False)
    assert merge_ordering([], [["ghost"]]).dropped == 1


def test_the_warning_text_holds_counts_and_nothing_else() -> None:
    text = mismatch_text(2, 1)
    assert "2 appended" in text
    assert "1 ids dropped" in text


# -- policies the controller made itself -------------------------------------------------------


def test_only_a_known_non_user_origin_is_placed_by_the_collector() -> None:
    assert is_system_placed(policy("p", origin="SYSTEM_DEFINED"))
    assert is_system_placed(policy("p", origin="DERIVED"))
    assert not is_system_placed(policy("p", origin="USER_DEFINED"))
    assert not is_system_placed(policy("p"))
    assert not is_system_placed({"id": "p", "metadata": {"origin": 5}})
    assert not is_system_placed({"id": "p", "metadata": "SYSTEM_DEFINED"})


def test_system_placed_policies_go_between_the_two_lists_of_their_pair_sorted_by_id() -> None:
    policies = [
        policy("u1", origin="USER_DEFINED"),
        policy("s9", origin="SYSTEM_DEFINED"),
        policy("u2", origin="USER_DEFINED"),
        policy("d1", origin="DERIVED"),
        policy("x1", "z2", "z1", origin="SYSTEM_DEFINED"),
        policy("n1", None, "z1", origin="SYSTEM_DEFINED"),
        policy("n0", None, "z1", origin="DERIVED"),
    ]
    answers = {("z1", "z2"): (["u1"], ["u2"]), ("z2", "z1"): ([], [])}
    orderings = firewall_orderings(policies, answers)
    assert orderings == [["u1", "d1", "s9", "u2"], ["x1"], ["n0", "n1"]]
    merged = merge_ordering(policies, orderings)
    assert ids(merged.objects) == ["u1", "d1", "s9", "u2", "x1", "n0", "n1"]
    assert merged.mismatch is False


def test_the_place_of_system_policies_does_not_depend_on_the_order_they_arrive_in() -> None:
    policies = [policy(key, origin="SYSTEM_DEFINED") for key in ("s3", "s1", "s2")]
    policies.append(policy("u1", origin="USER_DEFINED"))
    answers: dict[tuple[str, str], tuple[list[str], list[str]]] = {("z1", "z2"): (["u1"], [])}
    first = merge_ordering(policies, firewall_orderings(policies, answers))
    reverse = list(reversed(policies))
    second = merge_ordering(reverse, firewall_orderings(reverse, answers))
    assert ids(first.objects) == ids(second.objects) == ["u1", "s1", "s2", "s3"]


def test_a_user_defined_policy_the_lists_miss_is_still_a_mismatch() -> None:
    policies = [
        policy("u1", origin="USER_DEFINED"),
        policy("u2", origin="USER_DEFINED"),
        policy("s1", origin="SYSTEM_DEFINED"),
        policy("old"),
    ]
    merged = merge_ordering(policies, firewall_orderings(policies, {("z1", "z2"): (["u1"], [])}))
    assert ids(merged.objects) == ["u1", "s1", "u2", "old"]
    assert (merged.appended, merged.dropped) == (2, 0)


def test_a_system_policy_the_lists_do_name_keeps_its_listed_place() -> None:
    policies = [policy("u1", origin="USER_DEFINED"), policy("s1", origin="SYSTEM_DEFINED")]
    orderings = firewall_orderings(policies, {("z1", "z2"): ([], ["s1", "u1"])})
    assert orderings == [["s1", "u1"], []]
