"""Tests for core/canonical.py: one byte string for one logical value."""

import json
import random
from typing import Any, cast

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from driftsniff.core.canonical import JsonValue, canonical_dumps, canonicalize

PROPERTY_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow],
)

INTEGERS = st.integers(min_value=-(2**80), max_value=2**80)
FLOATS = st.floats(allow_nan=False, allow_infinity=False)
JSON_SCALARS = st.none() | st.booleans() | INTEGERS | FLOATS | st.text(max_size=12)


def extend(children: st.SearchStrategy[Any]) -> st.SearchStrategy[Any]:
    lists = st.lists(children, max_size=4)
    objects = st.dictionaries(st.text(max_size=6), children, max_size=4)
    return lists | objects


JSON_VALUES = st.recursive(JSON_SCALARS, extend, max_leaves=15)


def shuffle_keys(value: JsonValue, rng: random.Random) -> JsonValue:
    """Rebuild every object with its keys in a random order."""
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {key: shuffle_keys(value[key], rng) for key in keys}
    if isinstance(value, list):
        return [shuffle_keys(item, rng) for item in value]
    return value


@PROPERTY_SETTINGS
@given(value=JSON_VALUES, rng=st.randoms(use_true_random=False))
def test_key_order_never_changes_the_bytes(value: JsonValue, rng: random.Random) -> None:
    shuffled = shuffle_keys(value, rng)
    assert canonical_dumps(shuffled) == canonical_dumps(value)


@PROPERTY_SETTINGS
@given(value=JSON_VALUES)
def test_output_is_stable_through_a_parse_and_a_second_pass(value: JsonValue) -> None:
    once = canonical_dumps(value)
    assert canonical_dumps(json.loads(once)) == once


@PROPERTY_SETTINGS
@given(value=JSON_VALUES)
def test_canonicalising_twice_equals_once(value: JsonValue) -> None:
    once = canonicalize(value)
    assert canonicalize(once) == once


@PROPERTY_SETTINGS
@given(value=JSON_VALUES)
def test_output_parses_back_to_the_canonical_value(value: JsonValue) -> None:
    text = canonical_dumps(value).decode("utf-8")
    assert json.loads(text) == canonicalize(value)


@PROPERTY_SETTINGS
@given(number=INTEGERS)
def test_integers_are_written_exactly(number: int) -> None:
    assert canonical_dumps(number) == str(number).encode("ascii")


@PROPERTY_SETTINGS
@given(number=INTEGERS)
def test_an_integer_valued_float_and_its_integer_share_bytes(number: int) -> None:
    as_float = float(number)
    if as_float == number:
        assert canonical_dumps(as_float) == canonical_dumps(number)


@PROPERTY_SETTINGS
@given(number=FLOATS)
def test_floats_are_written_without_a_fraction_only_when_integer_valued(number: float) -> None:
    text = canonical_dumps(number).decode("ascii")
    assert ("." in text or "e" in text) == (not number.is_integer())


def test_keys_are_sorted_by_code_point_and_separators_are_compact() -> None:
    value: JsonValue = {"b": 1, "a": 2, "B": 3, "é": 4, "": 5}
    expected = '{"":5,"B":3,"a":2,"b":1,"é":4}'
    assert canonical_dumps(value) == expected.encode("utf-8")


def test_nested_objects_are_sorted_at_every_level() -> None:
    value: JsonValue = {"z": {"y": 1, "x": [{"d": 1, "c": 2}]}, "a": None}
    assert canonical_dumps(value) == b'{"a":null,"z":{"x":[{"c":2,"d":1}],"y":1}}'


def test_empty_containers_are_kept() -> None:
    assert canonical_dumps({"a": [], "b": {}}) == b'{"a":[],"b":{}}'
    assert canonical_dumps([]) == b"[]"
    assert canonical_dumps({}) == b"{}"


def test_null_inside_a_value_is_written_as_null() -> None:
    value: JsonValue = {"a": None, "b": [None, {"c": None}]}
    assert canonical_dumps(value) == b'{"a":null,"b":[null,{"c":null}]}'


def test_unicode_is_written_as_utf8_and_is_not_normalised() -> None:
    composed = "café"
    decomposed = "café"
    assert canonical_dumps(composed) == b'"caf\xc3\xa9"'
    assert canonical_dumps(decomposed) == b'"cafe\xcc\x81"'
    assert canonical_dumps(composed) != canonical_dumps(decomposed)
    assert canonical_dumps("\U0001f98a") == b'"\xf0\x9f\xa6\x8a"'
    expected = '{"über":"日本"}'
    assert canonical_dumps({"über": "日本"}) == expected.encode("utf-8")


def test_only_the_escapes_json_requires_are_written() -> None:
    assert canonical_dumps('a"b\\c\n\t\x01/') == b'"a\\"b\\\\c\\n\\t\\u0001/"'


def test_a_lone_surrogate_is_refused() -> None:
    with pytest.raises(UnicodeEncodeError):
        canonical_dumps("\ud800")


def test_integers_above_two_to_the_power_53_keep_every_digit() -> None:
    assert canonical_dumps(2**53 + 1) == b"9007199254740993"
    assert canonical_dumps(-(2**53) - 1) == b"-9007199254740993"
    assert canonical_dumps(2**64) == b"18446744073709551616"
    assert canonical_dumps({"id": 2**63 + 5}) == b'{"id":9223372036854775813}'


def test_float_with_an_integer_value_becomes_an_integer() -> None:
    assert canonical_dumps(1.0) == b"1"
    assert canonical_dumps(1.0) == canonical_dumps(1)
    assert canonical_dumps(-3.0) == b"-3"
    assert canonical_dumps(2.0**53) == b"9007199254740992"
    assert canonical_dumps(1e22) == b"10000000000000000000000"
    assert canonical_dumps([1.0, 1, 2.0]) == b"[1,1,2]"


def test_negative_zero_becomes_zero() -> None:
    assert canonical_dumps(-0.0) == b"0"
    assert canonical_dumps(0.0) == b"0"
    assert canonical_dumps({"x": -0.0}) == b'{"x":0}'


def test_other_floats_use_the_shortest_representation() -> None:
    assert canonical_dumps(0.1) == b"0.1"
    assert canonical_dumps(1.5) == b"1.5"
    assert canonical_dumps(-2.25) == b"-2.25"
    assert canonical_dumps(0.1 + 0.2) == b"0.30000000000000004"
    assert canonical_dumps(1e-7) == b"1e-07"


def test_booleans_are_not_numbers() -> None:
    assert canonical_dumps(True) == b"true"
    assert canonical_dumps(False) == b"false"
    assert canonical_dumps([True, 1, False, 0]) == b"[true,1,false,0]"
    assert canonical_dumps(True) != canonical_dumps(1)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_nan_and_infinity_are_refused(bad: float) -> None:
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_dumps(bad)
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_dumps({"deep": [bad]})


def test_object_keys_must_be_strings() -> None:
    with pytest.raises(TypeError, match="object keys must be strings"):
        canonical_dumps(cast(JsonValue, {1: "a"}))


@pytest.mark.parametrize("bad", [b"bytes", {1, 2}, object(), 1 + 2j])
def test_values_that_are_not_json_are_refused(bad: object) -> None:
    with pytest.raises(TypeError, match="is not a JSON value"):
        canonical_dumps(cast(JsonValue, bad))


def test_tuples_are_written_as_lists() -> None:
    assert canonical_dumps(cast(JsonValue, (1, (2, 3)))) == b"[1,[2,3]]"


def test_canonicalize_does_not_change_its_input() -> None:
    original: dict[str, JsonValue] = {"a": [1.0, {"b": -0.0}]}
    result = canonicalize(original)
    assert result == {"a": [1, {"b": 0}]}
    members = original["a"]
    assert isinstance(members, list)
    assert isinstance(members[0], float)
    assert members[1] == {"b": -0.0}
