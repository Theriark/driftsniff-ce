"""The predicates of the rule engine: every one has cases that match and cases that do not."""

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.rules.predicates import (
    PREDICATE_NAMES,
    PredicateError,
    build_predicate,
    mutually_exclusive,
)


def check(name: str, args: dict[str, object], before: JsonValue, after: JsonValue) -> bool:
    return build_predicate(name, args)(before, after)


# --- changed -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("before", "after"),
    [(1, 2), ("a", "b"), (None, "a"), ("a", None), (True, 1), ([1, 2], [2, 1]), ({"a": 1}, {})],
)
def test_changed_is_true_when_the_value_differs(before: JsonValue, after: JsonValue) -> None:
    assert check("changed", {}, before, after)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (1, 1),
        (1, 1.0),
        ("a", "a"),
        (None, None),
        ([1, 2], [1, 2]),
        ({"a": 1, "b": 2}, {"b": 2, "a": 1}),
    ],
)
def test_changed_is_false_when_the_value_is_equal(before: JsonValue, after: JsonValue) -> None:
    assert not check("changed", {}, before, after)


# --- becomes_empty -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("before", "after"),
    [("text", None), ("text", ""), ([1], []), ({"a": 1}, {}), (0, None), (False, None)],
)
def test_becomes_empty_is_true_when_a_value_is_removed(before: JsonValue, after: JsonValue) -> None:
    assert check("becomes_empty", {}, before, after)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (None, None),
        ("", None),
        (None, ""),
        ([], {}),
        ("text", " "),
        ("text", "other"),
        ([1], [2]),
        ("text", 0),
    ],
)
def test_becomes_empty_is_false_otherwise(before: JsonValue, after: JsonValue) -> None:
    assert not check("becomes_empty", {}, before, after)


# --- boolean_flips_to --------------------------------------------------------------------


@pytest.mark.parametrize(("value", "before"), [(True, False), (False, True)])
def test_boolean_flips_to_is_true_for_a_flip_to_the_value(value: bool, before: bool) -> None:
    assert check("boolean_flips_to", {"value": value}, before, value)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (True, True),
        (False, False),
        (True, False),
        (None, True),
        (0, True),
        (False, 1),
        ("false", True),
    ],
)
def test_boolean_flips_to_is_false_otherwise(before: JsonValue, after: JsonValue) -> None:
    assert not check("boolean_flips_to", {"value": True}, before, after)


# --- decreases_below ---------------------------------------------------------------------


@pytest.mark.parametrize(("before", "after"), [(30, 1), (5, 1.5), (3, 0), (2.5, 1.9)])
def test_decreases_below_is_true_when_the_number_drops_under_the_limit(
    before: JsonValue, after: JsonValue
) -> None:
    assert check("decreases_below", {"n": 2}, before, after)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (30, 2),
        (30, 10),
        (1, 1),
        (1, 1.5),
        (0, 1),
        (None, 1),
        (30, None),
        ("30", 1),
        (30, "1"),
        (True, 0),
        (30, False),
    ],
)
def test_decreases_below_is_false_otherwise(before: JsonValue, after: JsonValue) -> None:
    assert not check("decreases_below", {"n": 2}, before, after)


# --- increases_above ---------------------------------------------------------------------


@pytest.mark.parametrize(("before", "after"), [(1, 20), (10, 10.5), (-5, 11)])
def test_increases_above_is_true_when_the_number_rises_over_the_limit(
    before: JsonValue, after: JsonValue
) -> None:
    assert check("increases_above", {"n": 10}, before, after)


@pytest.mark.parametrize(
    ("before", "after"),
    [(1, 10), (1, 5), (20, 15), (20, 20), (None, 20), (1, None), ("1", 20), (1, "20"), (False, 11)],
)
def test_increases_above_is_false_otherwise(before: JsonValue, after: JsonValue) -> None:
    assert not check("increases_above", {"n": 10}, before, after)


# --- enum_transition ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("before", "after"), [("wpa2", "open"), ("wpa3", "open"), ("wpa2", "owe"), ("wpa3", "owe")]
)
def test_enum_transition_is_true_for_a_listed_transition(
    before: JsonValue, after: JsonValue
) -> None:
    args: dict[str, object] = {"from": ["wpa2", "wpa3"], "to": ["open", "owe"]}
    assert check("enum_transition", args, before, after)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("open", "wpa2"),
        ("wpa2", "wpa3"),
        ("open", "owe"),
        ("wpa2", "wpa2"),
        (None, "open"),
        ("wpa2", None),
    ],
)
def test_enum_transition_is_false_otherwise(before: JsonValue, after: JsonValue) -> None:
    args: dict[str, object] = {"from": ["wpa2", "wpa3"], "to": ["open", "owe"]}
    assert not check("enum_transition", args, before, after)


def test_enum_transition_needs_a_change_even_when_the_lists_overlap() -> None:
    args: dict[str, object] = {"from": ["a", "b"], "to": ["a", "b"]}
    assert check("enum_transition", args, "a", "b")
    assert not check("enum_transition", args, "a", "a")


def test_enum_transition_compares_types_strictly() -> None:
    args: dict[str, object] = {"from": [1], "to": [2]}
    assert check("enum_transition", args, 1, 2)
    assert not check("enum_transition", args, True, 2)
    assert not check("enum_transition", args, "1", 2)


# --- cidr_broadens -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("10.1.0.0/16", "10.0.0.0/8"),
        ("192.168.1.0/24", "0.0.0.0/0"),
        ("10.0.0.5", "10.0.0.0/24"),
        ("10.0.0.0/25", "10.0.0.0/24"),
        ("2001:db8:1::/48", "2001:db8::/32"),
        ("fe80::1", "::/0"),
        ("  10.1.0.0/16 ", "10.0.0.0/8"),
        ("10.1.2.3/16", "10.0.0.0/8"),
    ],
)
def test_cidr_broadens_is_true_when_the_new_network_contains_the_old_one(
    before: JsonValue, after: JsonValue
) -> None:
    assert check("cidr_broadens", {}, before, after)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("10.0.0.0/8", "10.1.0.0/16"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("10.0.0.0/8", "11.0.0.0/8"),
        ("10.0.1.0/24", "10.0.2.0/23"),
        ("10.0.0.0/8", "::/0"),
        ("::/0", "0.0.0.0/0"),
        ("2001:db8::/32", "2001:db8:1::/48"),
        ("not a network", "10.0.0.0/8"),
        ("10.0.0.0/8", "not a network"),
        ("10.0.0.0/8", ""),
        (None, "0.0.0.0/0"),
        ("10.0.0.0/8", None),
        ("10.0.0.0/8", 5),
        (["10.0.0.0/8"], ["0.0.0.0/0"]),
    ],
)
def test_cidr_broadens_is_false_otherwise(before: JsonValue, after: JsonValue) -> None:
    assert not check("cidr_broadens", {}, before, after)


# --- any_to_value ------------------------------------------------------------------------


@pytest.mark.parametrize(("before", "after"), [("wpa2", "open"), (None, "open"), ("", "open")])
def test_any_to_value_is_true_when_the_value_is_reached(
    before: JsonValue, after: JsonValue
) -> None:
    assert check("any_to_value", {"value": "open"}, before, after)


@pytest.mark.parametrize(
    ("before", "after"), [("open", "open"), ("wpa2", "wpa3"), ("open", "wpa2"), ("wpa2", None)]
)
def test_any_to_value_is_false_otherwise(before: JsonValue, after: JsonValue) -> None:
    assert not check("any_to_value", {"value": "open"}, before, after)


def test_any_to_value_compares_types_strictly() -> None:
    assert check("any_to_value", {"value": 0}, 1, 0)
    assert not check("any_to_value", {"value": 0}, 1, False)
    assert check("any_to_value", {"value": False}, True, False)
    assert check("any_to_value", {"value": 1.5}, 1, 1.5)


# --- building a predicate ----------------------------------------------------------------


def test_every_predicate_name_is_known() -> None:
    assert PREDICATE_NAMES == (
        "any_to_value",
        "becomes_empty",
        "boolean_flips_to",
        "changed",
        "cidr_broadens",
        "decreases_below",
        "enum_transition",
        "increases_above",
    )


def test_a_predicate_keeps_its_name_and_arguments() -> None:
    predicate = build_predicate("decreases_below", {"n": 2})
    assert predicate.name == "decreases_below"
    assert predicate.args == {"n": 2}
    assert build_predicate("changed").args == {}
    assert build_predicate("changed", None).name == "changed"


@pytest.mark.parametrize(
    ("name", "args", "fragment"),
    [
        ("nope", {}, "unknown predicate 'nope'"),
        ("changed", {"x": 1}, "does not take x"),
        ("becomes_empty", {"value": True}, "does not take value"),
        ("cidr_broadens", {"n": 1}, "does not take n"),
        ("decreases_below", {}, "needs the argument(s) n"),
        ("decreases_below", {"n": 1, "m": 2}, "does not take m"),
        ("boolean_flips_to", {}, "needs the argument(s) value"),
        ("enum_transition", {"from": ["a"]}, "needs the argument(s) to"),
        ("any_to_value", {}, "needs the argument(s) value"),
    ],
)
def test_wrong_names_and_argument_sets_are_refused(
    name: str, args: dict[str, object], fragment: str
) -> None:
    with pytest.raises(PredicateError) as error:
        build_predicate(name, args)
    assert fragment in str(error.value)


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("boolean_flips_to", {"value": "true"}),
        ("boolean_flips_to", {"value": 1}),
        ("decreases_below", {"n": "2"}),
        ("decreases_below", {"n": True}),
        ("decreases_below", {"n": None}),
        ("decreases_below", {"n": float("inf")}),
        ("increases_above", {"n": [1]}),
        ("increases_above", {"n": float("nan")}),
        ("enum_transition", {"from": [], "to": ["a"]}),
        ("enum_transition", {"from": ["a"], "to": []}),
        ("enum_transition", {"from": "a", "to": ["a"]}),
        ("enum_transition", {"from": [["a"]], "to": ["a"]}),
        ("enum_transition", {"from": [None], "to": ["a"]}),
        ("any_to_value", {"value": None}),
        ("any_to_value", {"value": ["a"]}),
        ("any_to_value", {"value": float("inf")}),
    ],
)
def test_arguments_of_the_wrong_type_are_refused(name: str, args: dict[str, object]) -> None:
    with pytest.raises(PredicateError):
        build_predicate(name, args)


# --- mutually_exclusive ------------------------------------------------------------------


def test_flips_to_different_values_exclude_each_other() -> None:
    to_true = build_predicate("boolean_flips_to", {"value": True})
    to_false = build_predicate("boolean_flips_to", {"value": False})
    assert mutually_exclusive(to_true, to_false)
    assert not mutually_exclusive(to_true, to_true)


def test_any_to_different_values_exclude_each_other() -> None:
    to_open = build_predicate("any_to_value", {"value": "open"})
    to_wpa = build_predicate("any_to_value", {"value": "wpa"})
    assert mutually_exclusive(to_open, to_wpa)
    assert not mutually_exclusive(to_open, build_predicate("any_to_value", {"value": "open"}))


def test_transitions_exclude_each_other_when_a_side_has_nothing_in_common() -> None:
    base = build_predicate("enum_transition", {"from": ["a"], "to": ["x"]})
    other_from = build_predicate("enum_transition", {"from": ["b"], "to": ["x"]})
    other_to = build_predicate("enum_transition", {"from": ["a"], "to": ["y"]})
    same = build_predicate("enum_transition", {"from": ["a", "b"], "to": ["x", "y"]})
    assert mutually_exclusive(base, other_from)
    assert mutually_exclusive(base, other_to)
    assert not mutually_exclusive(base, same)


def test_nothing_else_is_known_to_be_exclusive() -> None:
    changed = build_predicate("changed")
    empty = build_predicate("becomes_empty")
    flips = build_predicate("boolean_flips_to", {"value": True})
    assert not mutually_exclusive(changed, changed)
    assert not mutually_exclusive(changed, empty)
    assert not mutually_exclusive(empty, flips)
    assert not mutually_exclusive(None, flips)
    assert not mutually_exclusive(flips, None)
    assert not mutually_exclusive(None, None)
