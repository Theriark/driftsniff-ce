"""Predicates: the conditions a rule can put on the value of a field before and after a change.

A predicate answers yes or no for one pair of values. The values are JSON values as they are
stored (see ``core/canonical.py``); ``None`` stands for a field that is null or missing, which
are the same state (see ``core/normalize.py``). Equality is the canonical one: ``1`` and ``1.0``
are equal, ``true`` and ``1`` are not.

======================  ===========================  ==========================================
Predicate               Arguments                    True when
======================  ===========================  ==========================================
``changed``             none                         the value differs
``becomes_empty``       none                         after is null, ``""``, ``[]`` or ``{}`` and
                                                     before was not
``boolean_flips_to``    ``value`` (true or false)    before and after are booleans, after is
                                                     ``value`` and before is the opposite
``decreases_below``     ``n`` (number)               before and after are numbers, after is
                                                     below ``n`` and below before
``increases_above``     ``n`` (number)               before and after are numbers, after is
                                                     above ``n`` and above before
``enum_transition``     ``from``, ``to`` (lists)     before is in ``from``, after is in ``to``
                                                     and the value changed
``cidr_broadens``       none                         before and after are networks of the same
                                                     IP version and after strictly contains
                                                     before
``any_to_value``        ``value`` (text, number,     after is ``value`` and before was not
                        true or false)
======================  ===========================  ==========================================

A value of the wrong type never matches: a predicate that expects numbers is false for text.
Text is not trimmed or case folded: ``" "`` is not empty and ``"Admin"`` is not ``"admin"``.
"""

import ipaddress
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, TypeGuard

from driftsniff.core.canonical import JsonValue, canonical_dumps

type Test = Callable[[JsonValue, JsonValue], bool]
type Scalar = str | int | float | bool
type Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class PredicateError(ValueError):
    """The name of a predicate or its arguments are not valid."""


@dataclass(frozen=True)
class Predicate:
    """A predicate with its arguments. Call it with the value before and after the change."""

    name: str
    args: Mapping[str, JsonValue]
    test: Test

    def __call__(self, before: JsonValue, after: JsonValue) -> bool:
        return self.test(before, after)


def _same(left: JsonValue, right: JsonValue) -> bool:
    return canonical_dumps(left) == canonical_dumps(right)


def _is_number(value: object) -> TypeGuard[int | float]:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _is_empty(value: JsonValue) -> bool:
    return value is None or (isinstance(value, str | list | tuple | Mapping) and len(value) == 0)


def _network(value: JsonValue) -> Network | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def _changed(before: JsonValue, after: JsonValue) -> bool:
    return not _same(before, after)


def _becomes_empty(before: JsonValue, after: JsonValue) -> bool:
    return _is_empty(after) and not _is_empty(before)


def _cidr_broadens(before: JsonValue, after: JsonValue) -> bool:
    old = _network(before)
    new = _network(after)
    if old is None or new is None or old.version != new.version:
        return False
    # A smaller prefix length that still covers the old range is a strictly larger network.
    return (
        new.prefixlen < old.prefixlen
        and int(new.network_address) <= int(old.network_address)
        and int(old.broadcast_address) <= int(new.broadcast_address)
    )


def _bool_arg(name: str, key: str, value: object) -> bool:
    if isinstance(value, bool):
        return value
    raise PredicateError(f"{name}: {key} must be true or false")


def _number_arg(name: str, key: str, value: object) -> int | float:
    if _is_number(value):
        return value
    raise PredicateError(f"{name}: {key} must be a finite number")


def _scalar_arg(name: str, key: str, value: object) -> Scalar:
    if isinstance(value, str | bool):
        return value
    if _is_number(value):
        return value
    raise PredicateError(f"{name}: {key} must be text, a finite number, true or false")


def _scalar_list_arg(name: str, key: str, value: object) -> list[Scalar]:
    if not isinstance(value, list | tuple) or len(value) == 0:
        raise PredicateError(f"{name}: {key} must be a list with at least one entry")
    return [_scalar_arg(name, key, member) for member in value]


def _build_changed(args: Mapping[str, object]) -> Predicate:
    return Predicate("changed", {}, _changed)


def _build_becomes_empty(args: Mapping[str, object]) -> Predicate:
    return Predicate("becomes_empty", {}, _becomes_empty)


def _build_cidr_broadens(args: Mapping[str, object]) -> Predicate:
    return Predicate("cidr_broadens", {}, _cidr_broadens)


def _build_boolean_flips_to(args: Mapping[str, object]) -> Predicate:
    value = _bool_arg("boolean_flips_to", "value", args["value"])

    def test(before: JsonValue, after: JsonValue) -> bool:
        return (
            isinstance(before, bool)
            and isinstance(after, bool)
            and after is value
            and before is not value
        )

    return Predicate("boolean_flips_to", {"value": value}, test)


def _build_decreases_below(args: Mapping[str, object]) -> Predicate:
    limit = _number_arg("decreases_below", "n", args["n"])

    def test(before: JsonValue, after: JsonValue) -> bool:
        return _is_number(before) and _is_number(after) and after < limit and after < before

    return Predicate("decreases_below", {"n": limit}, test)


def _build_increases_above(args: Mapping[str, object]) -> Predicate:
    limit = _number_arg("increases_above", "n", args["n"])

    def test(before: JsonValue, after: JsonValue) -> bool:
        return _is_number(before) and _is_number(after) and after > limit and after > before

    return Predicate("increases_above", {"n": limit}, test)


def _build_enum_transition(args: Mapping[str, object]) -> Predicate:
    old_values = _scalar_list_arg("enum_transition", "from", args["from"])
    new_values = _scalar_list_arg("enum_transition", "to", args["to"])

    def test(before: JsonValue, after: JsonValue) -> bool:
        return (
            not _same(before, after)
            and any(_same(before, value) for value in old_values)
            and any(_same(after, value) for value in new_values)
        )

    return Predicate("enum_transition", {"from": old_values, "to": new_values}, test)


def _build_any_to_value(args: Mapping[str, object]) -> Predicate:
    target = _scalar_arg("any_to_value", "value", args["value"])

    def test(before: JsonValue, after: JsonValue) -> bool:
        return _same(after, target) and not _same(before, target)

    return Predicate("any_to_value", {"value": target}, test)


_BUILDERS: Final[Mapping[str, Callable[[Mapping[str, object]], Predicate]]] = {
    "changed": _build_changed,
    "becomes_empty": _build_becomes_empty,
    "boolean_flips_to": _build_boolean_flips_to,
    "decreases_below": _build_decreases_below,
    "increases_above": _build_increases_above,
    "enum_transition": _build_enum_transition,
    "cidr_broadens": _build_cidr_broadens,
    "any_to_value": _build_any_to_value,
}
_ARGUMENTS: Final[Mapping[str, tuple[str, ...]]] = {
    "changed": (),
    "becomes_empty": (),
    "boolean_flips_to": ("value",),
    "decreases_below": ("n",),
    "increases_above": ("n",),
    "enum_transition": ("from", "to"),
    "cidr_broadens": (),
    "any_to_value": ("value",),
}
PREDICATE_NAMES: Final = tuple(sorted(_BUILDERS))


def build_predicate(name: str, args: Mapping[str, object] | None = None) -> Predicate:
    """Return the predicate ``name`` for ``args``; anything unexpected raises PredicateError."""
    builder = _BUILDERS.get(name)
    if builder is None:
        known = ", ".join(PREDICATE_NAMES)
        raise PredicateError(f"unknown predicate {name!r}; the known predicates are {known}")
    given = {} if args is None else dict(args)
    expected = _ARGUMENTS[name]
    missing = [key for key in expected if key not in given]
    if missing:
        raise PredicateError(f"predicate {name} needs the argument(s) {', '.join(missing)}")
    unexpected = sorted(str(key) for key in given if key not in expected)
    if unexpected:
        raise PredicateError(f"predicate {name} does not take {', '.join(unexpected)}")
    return builder(given)


def _members(value: JsonValue) -> frozenset[bytes]:
    if isinstance(value, list | tuple):
        return frozenset(canonical_dumps(member) for member in value)
    return frozenset()


def mutually_exclusive(first: Predicate | None, second: Predicate | None) -> bool:
    """Whether no pair of values can satisfy both predicates, as far as it is provable here.

    Only the pairs that are easy to prove are known: two ``boolean_flips_to`` or two
    ``any_to_value`` with different values, and two ``enum_transition`` whose ``from`` lists or
    whose ``to`` lists have no member in common. Everything else answers False, so that the
    loader treats two rules on one path as a tie rather than guess.
    """
    if first is None or second is None or first.name != second.name:
        return False
    if first.name in ("boolean_flips_to", "any_to_value"):
        return not _same(first.args["value"], second.args["value"])
    if first.name == "enum_transition":
        same_from = _members(first.args["from"]) & _members(second.args["from"])
        same_to = _members(first.args["to"]) & _members(second.args["to"])
        return not same_from or not same_to
    return False
