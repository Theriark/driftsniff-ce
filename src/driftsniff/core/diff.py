"""Compare two manifests and describe what changed, object by object and field by field.

``compare`` takes the previous and the new manifest of one source, reads the states of the
objects whose state hash differs, and returns one :class:`ChangeItem` per change. The items carry
the columns of the ``change_items`` table, plus the detection window: the time of the previous
successful check and the time of this check. Classification (severity, rule id, rationale) is the
job of the rule engine; the only item this module classifies itself is ``schema_drift`` (LOW).

What is compared
----------------
- Objects are matched by key inside a resource. A key only in the new manifest is ``added``, a key
  only in the previous one is ``removed``; each gives one item with an empty path. A key in both
  is compared field by field, but only when the two state hashes differ.
- A resource that is in the previous manifest but not in the new one is left alone, never reported
  as removed: the collection could not read it. A resource only in the new manifest is all added.
- Fields of the ``ignore`` class are skipped. Null and a missing field are the same state, so
  neither side's nulls count as a change (list members are values and keep their nulls).
- Paths are dot separated. A list adds no index to the path, except an ``ordered-scalar`` list: it
  is compared position by position and the position is part of the path (``dns.servers.0``).
  Fields of a member are looked up in the type table by the path without the index, as the
  normaliser writes them.
- Every other list (``set``, ``ordered-keyed``, ``vendor-index``) is compared by membership: a
  member that is gone is ``removed``, a new one is ``added``, and a member with a declared item
  key whose content changed is one ``modified`` item. Members are matched by that key (by content
  when none is declared), never by position, so an insert at the top is one ``added`` item. The
  order of the members is not read here, and neither is the order of whole collections (the
  position lists of a manifest); ``core/order.py`` owns both.

What is shown
-------------
- ``config`` fields show their before and after value, as canonical JSON text.
- ``secret`` fields show a fingerprint only (``before_fp``, ``after_fp``, the stored form
  ``fp1:<key id>:<32 hex>``). A stored state already holds the fingerprint, never the value. Any
  string of that exact form is also treated as a secret, whatever the type table says, because the
  scanner can force the secret class on a field the table calls config. If a secret field holds
  something that is not a fingerprint, it is fingerprinted here, and the value is still not shown.
- ``unclassified`` fields are stored in clear but shown as a fingerprint only, until somebody
  classifies them. Inside a ``config`` container the same masking applies to nested fields.
- CE never claims to know who made a change: an item has no actor and no author.

Schema drift
------------
When the controller version differs (both versions known), at least two objects of a resource
exist in both manifests, every one of them changed, and the same new field path appeared on every
one of them, the per-object ``added`` items of those paths are replaced by one ``schema_drift``
item for the resource (severity LOW). The new paths are listed in its ``path`` and in the order
detail. A new field on only some objects is an ordinary change, reported per object. A list member
that is added is never a new field path: a member added to every object (an admin, a tag) stays an
ordinary item on each object.

Baseline
--------
A first snapshot, or one made with another normaliser version, is a baseline: its states cannot be
compared with the previous ones, so ``compare`` returns no items.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Final, Literal

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.normalize import CollectionMode, FieldClass, StaticTypeTable, TypeTable
from driftsniff.core.snapshots import Manifest
from driftsniff.secrets.fingerprint import Fingerprint, Fingerprinter

type ChangeKind = Literal["added", "removed", "modified", "schema_drift"]
type Severity = Literal["low", "medium", "high", "critical"]
type StateLookup = Callable[[str], Mapping[str, JsonValue]]

SCHEMA_DRIFT_RULE_ID: Final = "builtin.schema_drift"
SCHEMA_DRIFT_RATIONALE: Final = (
    "The controller version changed and the same new field appeared on every object of this "
    "resource type: a schema change, not a configuration change."
)
MIN_DRIFT_OBJECTS: Final = 2


class _Missing:
    """The value of a field that is not there (different from a null, which is not kept)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "MISSING"


_MISSING: Final = _Missing()
type _Value = JsonValue | _Missing
_DEFAULT_TABLE: Final = StaticTypeTable()


@dataclass(frozen=True)
class ChangeItem:
    """One change, with the columns of ``change_items`` and the detection window.

    ``object_key`` is None for an item that belongs to no single object (schema drift). Values
    are canonical JSON text. ``severity`` is None until the rule engine has classified the item.
    """

    resource: str
    object_key: str | None
    object_name: str | None
    change_kind: ChangeKind
    path: str
    field_class: FieldClass
    before_value: str | None
    after_value: str | None
    before_fp: str | None
    after_fp: str | None
    window_start: str
    window_end: str
    severity: Severity | None = None
    rule_id: str | None = None
    rationale: str | None = None
    order_detail: Mapping[str, JsonValue] | None = None


@dataclass(frozen=True)
class _Field:
    """A changed field before the object it belongs to is attached."""

    change_kind: ChangeKind
    path: str
    field_class: FieldClass
    before_value: str | None
    after_value: str | None
    before_fp: str | None
    after_fp: str | None
    list_member: bool = False


def _drop_nulls(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return {key: _drop_nulls(member) for key, member in value.items() if member is not None}
    if isinstance(value, list):
        return [_drop_nulls(member) for member in value]
    return value


def _same(left: JsonValue, right: JsonValue) -> bool:
    return canonical_dumps(left) == canonical_dumps(right)


def _is_marker(value: object) -> bool:
    return isinstance(value, str) and Fingerprint.parse(value) is not None


class _Walker:
    """Walks the old and the new state of one object and collects the changed fields."""

    def __init__(self, resource: str, table: TypeTable, fingerprinter: Fingerprinter) -> None:
        self._resource = resource
        self._table = table
        self._fingerprinter = fingerprinter
        self.fields: list[_Field] = []

    def walk(self, cls_path: str, shown_path: str, before: _Value, after: _Value) -> None:
        """Compare two values. ``cls_path`` has no list indices; ``shown_path`` has them."""
        if cls_path and self._table.field_class(cls_path) is FieldClass.IGNORE:
            return
        if not isinstance(before, _Missing) and not isinstance(after, _Missing):
            if _same(before, after):
                return
        if not self._container(cls_path, shown_path, before, after):
            self._leaf(cls_path, shown_path, before, after)

    def _container(self, cls_path: str, shown_path: str, before: _Value, after: _Value) -> bool:
        """Walk into mappings and lists. False when the two values are compared as a leaf.

        That is the case for a secret, for two values of different kinds, and for an empty
        container that appears or disappears (it has no members to report).
        """
        if cls_path and self._table.field_class(cls_path) is FieldClass.SECRET:
            return False
        either_missing = isinstance(before, _Missing) or isinstance(after, _Missing)
        if isinstance(before, Mapping | _Missing) and isinstance(after, Mapping | _Missing):
            old: Mapping[str, JsonValue] = before if isinstance(before, Mapping) else {}
            new: Mapping[str, JsonValue] = after if isinstance(after, Mapping) else {}
            for key in sorted(old.keys() | new.keys()):
                child_cls = f"{cls_path}.{key}" if cls_path else key
                child_shown = f"{shown_path}.{key}" if shown_path else key
                self.walk(child_cls, child_shown, old.get(key, _MISSING), new.get(key, _MISSING))
            return not either_missing or bool(old) or bool(new)
        if isinstance(before, list | _Missing) and isinstance(after, list | _Missing):
            old_list: list[JsonValue] = before if isinstance(before, list) else []
            new_list: list[JsonValue] = after if isinstance(after, list) else []
            mode = self._table.collection_mode(cls_path)
            if mode is CollectionMode.ORDERED_SCALAR:
                for index in range(max(len(old_list), len(new_list))):
                    old_member = old_list[index] if index < len(old_list) else _MISSING
                    new_member = new_list[index] if index < len(new_list) else _MISSING
                    self.walk(cls_path, f"{shown_path}.{index}", old_member, new_member)
            else:
                self._members(cls_path, shown_path, mode, old_list, new_list)
            return not either_missing or bool(old_list) or bool(new_list)
        return False

    def _members(
        self,
        cls_path: str,
        shown_path: str,
        mode: CollectionMode,
        old: list[JsonValue],
        new: list[JsonValue],
    ) -> None:
        """Compare a list by membership: members are matched by key, never by position.

        A set counts a duplicate member once. An ordered list can repeat a key, so its n-th
        member with that key is matched with the n-th one on the other side.
        """
        key_field = self._table.item_key_field(cls_path)
        count_duplicates = mode is not CollectionMode.SET
        old_by_identity = _by_identity(key_field, old, count_duplicates)
        new_by_identity = _by_identity(key_field, new, count_duplicates)
        for identity in sorted(old_by_identity.keys() | new_by_identity.keys()):
            before = old_by_identity.get(identity, _MISSING)
            after = new_by_identity.get(identity, _MISSING)
            if not isinstance(before, _Missing) and not isinstance(after, _Missing):
                if _same(before, after):
                    continue
            self._leaf(cls_path, shown_path, before, after, list_member=True)

    def _leaf(
        self,
        cls_path: str,
        shown_path: str,
        before: _Value,
        after: _Value,
        *,
        list_member: bool = False,
    ) -> None:
        kind: ChangeKind
        if isinstance(before, _Missing):
            kind = "added"
        elif isinstance(after, _Missing):
            kind = "removed"
        else:
            kind = "modified"
        field_class = self._leaf_class(cls_path, before, after)
        before_value, before_fp = self._render(field_class, cls_path, before)
        after_value, after_fp = self._render(field_class, cls_path, after)
        self.fields.append(
            _Field(
                kind,
                shown_path,
                field_class,
                before_value,
                after_value,
                before_fp,
                after_fp,
                list_member,
            )
        )

    def _leaf_class(self, cls_path: str, before: _Value, after: _Value) -> FieldClass:
        declared = self._table.field_class(cls_path)
        if declared is not FieldClass.SECRET and (_is_marker(before) or _is_marker(after)):
            return FieldClass.SECRET
        return declared

    def _render(
        self, field_class: FieldClass, cls_path: str, value: _Value
    ) -> tuple[str | None, str | None]:
        """Return (shown value, fingerprint); exactly one of them is set for a present value."""
        if isinstance(value, _Missing):
            return None, None
        if field_class in (FieldClass.SECRET, FieldClass.UNCLASSIFIED):
            return None, self._fingerprint(cls_path, value)
        return canonical_dumps(self._mask(cls_path, value)).decode("utf-8"), None

    def _fingerprint(self, cls_path: str, value: JsonValue) -> str:
        if isinstance(value, str) and Fingerprint.parse(value) is not None:
            return value
        return self._fingerprinter.fingerprint(self._resource, cls_path, value).marker()

    def _mask(self, cls_path: str, value: JsonValue) -> JsonValue:
        """Hide the secret and unclassified fields nested inside a value that is shown."""
        if isinstance(value, Mapping):
            masked: dict[str, JsonValue] = {}
            for key, member in value.items():
                child = f"{cls_path}.{key}"
                child_class = self._table.field_class(child)
                if child_class is FieldClass.IGNORE:
                    continue
                if child_class is FieldClass.CONFIG:
                    masked[key] = self._mask(child, member)
                else:
                    masked[key] = self._fingerprint(child, member)
            return masked
        if isinstance(value, list):
            return [self._mask(cls_path, member) for member in value]
        return value


def _identity(key_field: str | None, member: JsonValue) -> tuple[str, str]:
    """How a list member is told apart: by its declared key, else by its content."""
    if key_field is not None and isinstance(member, Mapping):
        key = member.get(key_field)
        if isinstance(key, str):
            return ("key", key)
        if isinstance(key, int) and not isinstance(key, bool):
            return ("key", str(key))
    return ("content", canonical_dumps(member).decode("utf-8"))


def _by_identity(
    key_field: str | None, members: list[JsonValue], count_duplicates: bool
) -> dict[tuple[str, str, int], JsonValue]:
    """Index the members by identity; the third part counts repeats when ``count_duplicates``."""
    indexed: dict[tuple[str, str, int], JsonValue] = {}
    seen: dict[tuple[str, str], int] = {}
    for member in members:
        identity = _identity(key_field, member)
        position = seen.get(identity, 0) if count_duplicates else 0
        seen[identity] = position + 1
        indexed[(*identity, position)] = member
    return indexed


@dataclass(frozen=True)
class _Context:
    previous: Manifest
    new: Manifest
    states: StateLookup
    window_start: str
    window_end: str
    fingerprinter: Fingerprinter
    controller_changed: bool
    loaded: dict[str, dict[str, JsonValue]] = dataclass_field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def load(self, state_hash: str) -> dict[str, JsonValue]:
        """The state with its nulls dropped; each state is read once per comparison."""
        cached = self.loaded.get(state_hash)
        if cached is not None:
            return cached
        state = _drop_nulls(dict(self.states(state_hash)))
        if not isinstance(state, dict):  # pragma: no cover - _drop_nulls keeps a dict a dict
            raise TypeError("a state must be a mapping")
        self.loaded[state_hash] = state
        return state

    def name_of(self, table: TypeTable, resource: str, key: str, state_hash: str) -> str | None:
        """The object's display name: the collector's, else the name field of its state."""
        for manifest in (self.new, self.previous):
            name = manifest.names.get(resource, {}).get(key)
            if name is not None:
                return name
        if table.name_field is None:
            return None
        value = self.load(state_hash).get(table.name_field)
        return value if isinstance(value, str) else None

    def item(
        self,
        resource: str,
        key: str | None,
        name: str | None,
        field: _Field,
    ) -> ChangeItem:
        return ChangeItem(
            resource=resource,
            object_key=key,
            object_name=name,
            change_kind=field.change_kind,
            path=field.path,
            field_class=field.field_class,
            before_value=field.before_value,
            after_value=field.after_value,
            before_fp=field.before_fp,
            after_fp=field.after_fp,
            window_start=self.window_start,
            window_end=self.window_end,
        )


_OBJECT_FIELD_CLASS: Final = FieldClass.CONFIG


def _whole_object(kind: ChangeKind) -> _Field:
    return _Field(kind, "", _OBJECT_FIELD_CLASS, None, None, None, None)


def _compare_resource(
    context: _Context, resource: str, table: TypeTable, previous: Mapping[str, str] | None
) -> list[ChangeItem]:
    new = context.new.objects[resource]
    old: Mapping[str, str] = previous if previous is not None else {}
    items: list[ChangeItem] = []
    for key in sorted(new.keys() - old.keys()):
        name = context.name_of(table, resource, key, new[key])
        items.append(context.item(resource, key, name, _whole_object("added")))
    for key in sorted(old.keys() - new.keys()):
        name = context.name_of(table, resource, key, old[key])
        items.append(context.item(resource, key, name, _whole_object("removed")))
    changed = sorted(key for key in new.keys() & old.keys() if new[key] != old[key])
    fields_by_key: dict[str, list[_Field]] = {}
    for key in changed:
        walker = _Walker(resource, table, context.fingerprinter)
        walker.walk("", "", context.load(old[key]), context.load(new[key]))
        fields_by_key[key] = walker.fields
    drift = _drift_paths(context, old, new, fields_by_key)
    for key in changed:
        name = context.name_of(table, resource, key, new[key])
        for field in fields_by_key[key]:
            if drift and _is_new_path(field) and field.path in drift:
                continue
            items.append(context.item(resource, key, name, field))
    if drift:
        items.append(_drift_item(context, resource, drift, fields_by_key))
    return items


def _is_new_path(field: _Field) -> bool:
    """A field that appeared. A member added to a list is a value, not a new field path."""
    return field.change_kind == "added" and not field.list_member


def _drift_paths(
    context: _Context,
    old: Mapping[str, str],
    new: Mapping[str, str],
    fields_by_key: Mapping[str, list[_Field]],
) -> set[str]:
    """The new field paths that appeared on every matched object at once, or an empty set."""
    if not context.controller_changed or len(fields_by_key) < MIN_DRIFT_OBJECTS:
        return set()
    if len(fields_by_key) != len(new.keys() & old.keys()):
        return set()
    appeared = [
        {field.path for field in fields if _is_new_path(field)} for fields in fields_by_key.values()
    ]
    return set.intersection(*appeared)


def _drift_item(
    context: _Context, resource: str, drift: set[str], fields_by_key: Mapping[str, list[_Field]]
) -> ChangeItem:
    paths = sorted(drift)
    first = next(
        field
        for field in next(iter(fields_by_key.values()))
        if _is_new_path(field) and field.path == paths[0]
    )
    detail: dict[str, JsonValue] = {
        "controller_version_before": context.previous.controller_version,
        "controller_version_after": context.new.controller_version,
        "object_count": len(fields_by_key),
        "paths": list(paths),
    }
    return ChangeItem(
        resource=resource,
        object_key=None,
        object_name=None,
        change_kind="schema_drift",
        path=", ".join(paths),
        field_class=first.field_class,
        before_value=None,
        after_value=None,
        before_fp=None,
        after_fp=None,
        window_start=context.window_start,
        window_end=context.window_end,
        severity="low",
        rule_id=SCHEMA_DRIFT_RULE_ID,
        rationale=SCHEMA_DRIFT_RATIONALE,
        order_detail=detail,
    )


def compare(
    previous: Manifest | None,
    new: Manifest,
    states: StateLookup,
    *,
    window_start: str,
    window_end: str,
    fingerprinter: Fingerprinter,
    type_tables: Mapping[str, TypeTable] | None = None,
) -> list[ChangeItem]:
    """Return the change items between two manifests of one source, in a stable order.

    ``states`` returns the normalised state for a state hash; it is called only for the objects
    that were added or removed (for their name) and for those whose hash differs. ``type_tables``
    maps a resource type to its table; a resource without one has every field unclassified, so
    its changes are shown as fingerprints only. ``window_start`` is the previous successful check
    and ``window_end`` this check, both UTC ISO 8601 text.

    No item is returned for a baseline: there is no previous manifest, or the normaliser version
    differs from the previous one.
    """
    if previous is None or previous.normaliser_version != new.normaliser_version:
        return []
    controller_changed = (
        previous.controller_version is not None
        and new.controller_version is not None
        and previous.controller_version != new.controller_version
    )
    context = _Context(
        previous, new, states, window_start, window_end, fingerprinter, controller_changed
    )
    tables = type_tables if type_tables is not None else {}
    items: list[ChangeItem] = []
    for resource in sorted(new.objects):
        table = tables.get(resource, _DEFAULT_TABLE)
        items.extend(_compare_resource(context, resource, table, previous.objects.get(resource)))
    return items
