"""Canonical JSON: one byte string for one logical value.

Equal values always serialise to the same bytes, whatever the order of their keys or the
numeric spelling they arrived in. The bytes are what states and manifests are hashed and
stored by, so a change to this output is a change to every stored hash.

Rules:

- UTF-8, object keys sorted by code point, separators ``,`` and ``:``, no whitespace.
- ``NaN`` and the infinities are refused (``ValueError``).
- Integers stay integers, whatever their size.
- A float with an integer value becomes an integer (``1.0`` is written ``1``); negative
  zero becomes ``0``. Any other float uses the shortest representation that round-trips.
- Strings are written as they are: no Unicode normalisation, only the escapes JSON requires.
  A string that cannot be encoded as UTF-8 (a lone surrogate) is refused.
"""

import json
import math
from collections.abc import Mapping, Sequence

type JsonValue = None | bool | int | float | str | Sequence[JsonValue] | Mapping[str, JsonValue]


def canonicalize(value: JsonValue) -> JsonValue:
    """Return ``value`` with numbers in their canonical spelling.

    Tuples become lists and mappings become dicts. Only the number rules are applied here;
    key order is applied by :func:`canonical_dumps`.
    """
    if value is None or isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and Infinity cannot be written as canonical JSON")
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"object keys must be strings, got {type(key).__name__}")
            result[key] = canonicalize(item)
        return result
    if isinstance(value, list | tuple):
        return [canonicalize(item) for item in value]
    raise TypeError(f"{type(value).__name__} is not a JSON value")


def canonical_dumps(value: JsonValue) -> bytes:
    """Serialise ``value`` to its canonical UTF-8 JSON bytes."""
    text = json.dumps(
        canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")
