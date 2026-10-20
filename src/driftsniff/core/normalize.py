"""Normaliser: turns one raw controller object into the form that is stored and diffed.

The output depends only on the logical content of the object, never on the order a
collector happened to see keys or set members in. Changing what this module produces for
any input is a change to every stored state hash, so it must bump ``NORMALISER_VERSION``
(``tests/unit/test_normalize.py`` pins the output of a fixed fixture to catch a silent change).

Steps, applied recursively:

1. Fields whose class is ``ignore`` are dropped (volatile counters, timestamps).
2. Keys whose value is ``null`` are dropped: null and missing are the same state. Nulls inside
   lists are kept, because a list member is not a key.
3. Lists in ``set`` mode are sorted; the other modes keep the order they arrived in.
4. Numbers and everything else are left to :mod:`driftsniff.core.canonical`.

Paths are dot separated field names (``wan.dns.servers``). A list does not add an index to the
path: its members, and any list nested inside them, are described by the path of the list itself.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import Protocol

from driftsniff.core.canonical import JsonValue, canonical_dumps

NORMALISER_VERSION = 1


class FieldClass(StrEnum):
    """How a field is treated: ``ignore`` fields are dropped here, the others are kept."""

    CONFIG = "config"
    SECRET = "secret"  # noqa: S105 - the name of a field class, not a password
    IGNORE = "ignore"
    UNCLASSIFIED = "unclassified"


class CollectionMode(StrEnum):
    """How a list is compared: as a set, or by its order."""

    SET = "set"
    ORDERED_KEYED = "ordered-keyed"
    ORDERED_SCALAR = "ordered-scalar"
    VENDOR_INDEX = "vendor-index"


class TypeTable(Protocol):
    """What the normaliser needs to know about one resource type."""

    @property
    def object_key_field(self) -> str | None:
        """Field that identifies an object of this type inside its collection."""

    @property
    def name_field(self) -> str | None:
        """Field that holds the human readable name of an object of this type."""

    def field_class(self, path: str) -> FieldClass:
        """Class of the field at ``path``."""

    def collection_mode(self, path: str) -> CollectionMode:
        """Mode of the list at ``path``."""

    def item_key_field(self, path: str) -> str | None:
        """Field that keys the object members of the list at ``path``, if one is declared."""


@dataclass(frozen=True)
class StaticTypeTable:
    """A type table written out in code. Undeclared fields are ``unclassified``.

    Undeclared lists keep their order (``ordered-scalar``): a wrongly reported reorder is
    visible, a wrongly merged one would hide a change.
    """

    object_key_field: str | None = None
    name_field: str | None = None
    field_classes: Mapping[str, FieldClass] = field(default_factory=dict)
    collection_modes: Mapping[str, CollectionMode] = field(default_factory=dict)
    item_key_fields: Mapping[str, str] = field(default_factory=dict)

    def field_class(self, path: str) -> FieldClass:
        return self.field_classes.get(path, FieldClass.UNCLASSIFIED)

    def collection_mode(self, path: str) -> CollectionMode:
        return self.collection_modes.get(path, CollectionMode.ORDERED_SCALAR)

    def item_key_field(self, path: str) -> str | None:
        return self.item_key_fields.get(path)


def normalize_object(type_table: TypeTable, raw: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Return the normalised form of ``raw``, a JSON object as the controller sent it."""
    if not isinstance(raw, Mapping):
        raise TypeError("a raw object must be a mapping")
    return _normalize_mapping(type_table, "", raw)


def _normalize_mapping(
    type_table: TypeTable, path: str, raw: Mapping[str, JsonValue]
) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            raise TypeError(f"object keys must be strings, got {type(key).__name__}")
        child_path = f"{path}.{key}" if path else key
        if type_table.field_class(child_path) is FieldClass.IGNORE:
            continue
        normalized = _normalize_value(type_table, child_path, value)
        if normalized is not None:
            result[key] = normalized
    return result


def _normalize_value(type_table: TypeTable, path: str, value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return _normalize_mapping(type_table, path, value)
    if isinstance(value, list | tuple):
        members = [_normalize_value(type_table, path, member) for member in value]
        if type_table.collection_mode(path) is CollectionMode.SET:
            key_field = type_table.item_key_field(path)
            members.sort(key=lambda member: _set_sort_key(key_field, member))
        return members
    return value


def _set_sort_key(key_field: str | None, member: JsonValue) -> tuple[int, str, str]:
    """Total order for set members: keyed members first, then anonymous ones by hash.

    A member with the declared key field sorts by that key. Any other member is anonymous and
    is keyed by the SHA-256 of its canonical form. The hash also breaks ties, so the order never
    depends on the order the members arrived in.
    """
    digest = sha256(canonical_dumps(member)).hexdigest()
    if key_field is not None and isinstance(member, Mapping) and key_field in member:
        key = member[key_field]
        if isinstance(key, str):
            return (0, key, digest)
        return (1, canonical_dumps(key).decode("utf-8"), digest)
    return (2, digest, digest)
