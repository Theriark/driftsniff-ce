"""Order awareness: report the moves in an ordered list, once, with where the item went.

``core/diff.py`` matches the members of a list by key and never reads their order, so an insert at
the top of a firewall list is one ``added`` item. This module reads the order. :func:`diff_order`
compares two key sequences; :func:`compare_order` applies it to the ordered collections of two
manifests and returns ``moved`` change items to be listed with the items of ``compare``.

Modes
-----
Every list declares one of four modes in its type table. Only one of them is read here.

- ``set``: sorted by key when it is normalised, so there is no order to report.
- ``ordered-keyed``: the members are matched by key and their order is data. Read here, in two
  places: the position list of a whole resource (``Manifest.positions``, the collections a
  collector marks as ordered), and a list of keyed members inside an object.
- ``ordered-scalar``: the array is kept as it is and ``compare`` reports it position by position
  (``dns.servers.0``). Nothing to add here.
- ``vendor-index``: the index the vendor gives a member is a field of the member, so a change to
  it is an ordinary ``modified`` item from ``compare``. Nothing to add here.

What is reported
----------------
Only the keys found on both sides are compared. The longest common subsequence of the old and the
new order stays where it is; every other common key is a move. A key that is only on one side is
an insert or a delete, and ``compare`` already reports it once as ``added`` or ``removed``, so it
is never a move: one rule inserted at the top is one ``added`` item and no ``moved`` item. A
reordered ``set`` is not a list of this kind and gives nothing.

A move is one item with ``change_kind`` ``moved``. For a resource the item is that of the moved
object (empty path). For a list inside an object it is that of the owning object, with the path
of the list. Its ``order_detail`` holds the moved key, the key it followed and the key that
followed it before the move (``from_after``, ``from_before``), the same two after the move
(``to_after``, ``to_before``; null at an end of the list) and a ``summary`` such as
``r7 moved from after r2 to before r1``.

Actions
-------
A type table may name an ``action_field`` (``StaticTypeTable.action_field``): the field of a
member that says what the member does, such as a firewall verdict. Only then, and only when the
field is of the ``config`` class, the order detail of a ``moved`` item also holds
``moved_actions`` (the distinct values of that field on the moved member, before and after,
sorted), ``jumped_actions`` (the same for every member the moved one passed: those whose place
relative to it changed) and ``jumped_count``. The rule engine reads them to tell a move across a
deny rule from a harmless one. A table without an ``action_field`` gets the detail described above
and nothing more.

Limit
-----
A list of more than :data:`MAX_ORDERED_ENTRIES` entries on either side is compared as a set: when
the order of the common keys differs, one item of kind ``order_changed`` says so, with the counts
and no detail about which key moved. Members of a list that is inside another list member are not
examined, and the key of a keyless member is shown as a hash, never as its content.
"""

from bisect import bisect_left
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind, StateLookup, _identity
from driftsniff.core.normalize import CollectionMode, FieldClass, StaticTypeTable, TypeTable
from driftsniff.core.snapshots import Manifest

MAX_ORDERED_ENTRIES: Final = 5_000
LARGE_LIST_NOTE: Final = "order changed, large list, detail not computed"
_DEFAULT_TABLE: Final = StaticTypeTable()


@dataclass(frozen=True)
class Move:
    """One key that changed place, with its neighbours before and after (None at an end)."""

    key: str
    from_after: str | None
    from_before: str | None
    to_after: str | None
    to_before: str | None

    @property
    def summary(self) -> str:
        """The move in words: ``r7 moved from after r2 to before r1``."""
        start = f"after {self.from_after}" if self.from_after is not None else "the top"
        end = f"before {self.to_before}" if self.to_before is not None else "the end"
        return f"{self.key} moved from {start} to {end}"

    def detail(self) -> dict[str, JsonValue]:
        """The order detail stored with the item."""
        return {
            "key": self.key,
            "from_after": self.from_after,
            "from_before": self.from_before,
            "to_after": self.to_after,
            "to_before": self.to_before,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class OrderDiff:
    """The difference between two orders of the same list.

    ``moves`` follow the new order. ``reordered`` is true when the keys found on both sides are
    in another order; ``large`` means a list was too long to say which keys moved, so ``moves``
    is empty even though ``reordered`` is true.
    """

    inserted: tuple[str, ...]
    deleted: tuple[str, ...]
    moves: tuple[Move, ...]
    reordered: bool = False
    large: bool = False


def _index_of(keys: Sequence[str], side: str) -> dict[str, int]:
    index: dict[str, int] = {}
    for position, key in enumerate(keys):
        if key in index:
            raise ValueError(f"the {side} order lists {key!r} more than once")
        index[key] = position
    return index


def _longest_increasing(values: Sequence[int]) -> list[int]:
    """Positions in ``values`` of one longest strictly increasing subsequence.

    The values are all different. Because the keys of an order are all different too, this is the
    longest common subsequence of the two orders, found in n log n instead of n squared. The
    choice among equally long subsequences is fixed, so the same input gives the same answer.
    """
    tail_positions: list[int] = []
    tail_values: list[int] = []
    previous: list[int | None] = []
    for position, value in enumerate(values):
        length = bisect_left(tail_values, value)
        previous.append(tail_positions[length - 1] if length > 0 else None)
        if length == len(tail_values):
            tail_positions.append(position)
            tail_values.append(value)
        else:
            tail_positions[length] = position
            tail_values[length] = value
    chain: list[int] = []
    cursor = tail_positions[-1] if tail_positions else None
    while cursor is not None:
        chain.append(cursor)
        cursor = previous[cursor]
    chain.reverse()
    return chain


def diff_order(old: Sequence[str], new: Sequence[str]) -> OrderDiff:
    """Compare two orders of a list of keys; every key must be listed once on each side."""
    old_index = _index_of(old, "old")
    new_index = _index_of(new, "new")
    inserted = tuple(key for key in new if key not in old_index)
    deleted = tuple(key for key in old if key not in new_index)
    common_old = [key for key in old if key in new_index]
    common_new = [key for key in new if key in old_index]
    if common_old == common_new:
        return OrderDiff(inserted, deleted, ())
    if len(old) > MAX_ORDERED_ENTRIES or len(new) > MAX_ORDERED_ENTRIES:
        return OrderDiff(inserted, deleted, (), reordered=True, large=True)
    rank = {key: position for position, key in enumerate(common_old)}
    ranks = [rank[key] for key in common_new]
    kept = {common_new[position] for position in _longest_increasing(ranks)}
    moves: list[Move] = []
    for key in common_new:
        if key in kept:
            continue
        before, after = old_index[key], new_index[key]
        moves.append(
            Move(
                key,
                from_after=old[before - 1] if before > 0 else None,
                from_before=old[before + 1] if before + 1 < len(old) else None,
                to_after=new[after - 1] if after > 0 else None,
                to_before=new[after + 1] if after + 1 < len(new) else None,
            )
        )
    return OrderDiff(inserted, deleted, tuple(moves), reordered=True)


class _Jumps:
    """Which keys a key passed when an order changed (the keys found on both sides only)."""

    def __init__(self, old: Sequence[str], new: Sequence[str]) -> None:
        self._old = {key: position for position, key in enumerate(old)}
        self._new = list(new)
        self._new_index = {key: position for position, key in enumerate(new)}

    def over(self, key: str) -> list[str]:
        """The keys that were on one side of ``key`` before the change and on the other after."""
        was, now = self._old[key], self._new_index[key]
        return [
            other
            for other in self._new
            if other != key
            and other in self._old
            and (self._old[other] < was) != (self._new_index[other] < now)
        ]


def _action_field(table: TypeTable) -> str | None:
    """The ``action_field`` of a table that declares one (it is not part of the protocol)."""
    declared = getattr(table, "action_field", None)
    return declared if isinstance(declared, str) and declared != "" else None


def _action_of(member: object, field_name: str) -> str | None:
    if isinstance(member, Mapping):
        value = member.get(field_name)
        if isinstance(value, str) and value != "":
            return value
    return None


def _action_detail(
    key: str, jumped: Sequence[str], actions: Mapping[str, frozenset[str]]
) -> dict[str, JsonValue]:
    """The actions of the moved key and of the keys it passed, for the order detail."""
    passed: set[str] = set()
    for other in jumped:
        passed |= actions.get(other, frozenset())
    moved_actions: list[JsonValue] = [*sorted(actions.get(key, frozenset()))]
    jumped_actions: list[JsonValue] = [*sorted(passed)]
    return {
        "moved_actions": moved_actions,
        "jumped_actions": jumped_actions,
        "jumped_count": len(jumped),
    }


class _Builder:
    """Makes the items of one comparison; it holds what every item has in common."""

    def __init__(self, window_start: str, window_end: str) -> None:
        self._window_start = window_start
        self._window_end = window_end

    def moved(
        self,
        resource: str,
        key: str | None,
        name: str | None,
        path: str,
        move: Move,
        actions: Mapping[str, JsonValue] | None = None,
    ) -> ChangeItem:
        detail = move.detail()
        if actions is not None:
            detail.update(actions)
        return self._item(resource, key, name, path, "moved", detail)

    def reordered(
        self,
        resource: str,
        key: str | None,
        name: str | None,
        path: str,
        counts: tuple[int, int],
    ) -> ChangeItem:
        detail: dict[str, JsonValue] = {
            "note": LARGE_LIST_NOTE,
            "old_count": counts[0],
            "new_count": counts[1],
        }
        return self._item(resource, key, name, path, "order_changed", detail)

    def _item(
        self,
        resource: str,
        key: str | None,
        name: str | None,
        path: str,
        kind: ChangeKind,
        detail: dict[str, JsonValue],
    ) -> ChangeItem:
        return ChangeItem(
            resource=resource,
            object_key=key,
            object_name=name,
            change_kind=kind,
            path=path,
            field_class=FieldClass.CONFIG,
            before_value=None,
            after_value=None,
            before_fp=None,
            after_fp=None,
            window_start=self._window_start,
            window_end=self._window_end,
            order_detail=detail,
        )


def _label(identity: tuple[str, str], occurrence: int, *, key_shown: bool) -> str:
    """The text that stands for a list member in an order detail.

    A member is shown by its declared key. A member without one is matched by content, and its
    content may be a secret, so it is shown as a short hash. A repeated key gets ``#2``, ``#3``.
    """
    kind, value = identity
    if kind == "key" and key_shown:
        text = value
    else:
        text = f"member:{sha256(value.encode()).hexdigest()[:12]}"
    return text if occurrence == 0 else f"{text}#{occurrence + 1}"


def _labels(key_field: str | None, members: Sequence[JsonValue], *, key_shown: bool) -> list[str]:
    """One distinct label per member, in list order."""
    seen: dict[tuple[str, str], int] = {}
    labels: list[str] = []
    for member in members:
        identity = _identity(key_field, member)
        occurrence = seen.get(identity, 0)
        seen[identity] = occurrence + 1
        labels.append(_label(identity, occurrence, key_shown=key_shown))
    return labels


def _member_actions(
    field_name: str,
    old: tuple[Sequence[str], Sequence[JsonValue]],
    new: tuple[Sequence[str], Sequence[JsonValue]],
) -> dict[str, frozenset[str]]:
    """The actions of each member of a list, by label, before and after."""
    found: dict[str, set[str]] = {}
    for labels, members in (old, new):
        for label, member in zip(labels, members, strict=True):
            action = _action_of(member, field_name)
            if action is not None:
                found.setdefault(label, set()).add(action)
    return {label: frozenset(actions) for label, actions in found.items()}


def _key_is_shown(table: TypeTable, path: str, key_field: str | None) -> bool:
    """Whether the key of a member of the list at ``path`` may appear in an order detail."""
    if key_field is None:
        return False
    return table.field_class(f"{path}.{key_field}") is FieldClass.CONFIG


def _ordered_lists(
    table: TypeTable, path: str, old: Mapping[str, JsonValue], new: Mapping[str, JsonValue]
) -> Iterator[tuple[str, Sequence[JsonValue], Sequence[JsonValue]]]:
    """Every ordered-keyed list present on both sides, with its path, in path order."""
    for field_name in sorted(old.keys() & new.keys()):
        child = f"{path}.{field_name}" if path else field_name
        if table.field_class(child) in (FieldClass.IGNORE, FieldClass.SECRET):
            continue
        before, after = old[field_name], new[field_name]
        if isinstance(before, Mapping) and isinstance(after, Mapping):
            yield from _ordered_lists(table, child, before, after)
        elif isinstance(before, list) and isinstance(after, list):
            if table.collection_mode(child) is CollectionMode.ORDERED_KEYED:
                yield child, before, after


class _Comparison:
    """Compares the ordered collections of one pair of manifests."""

    def __init__(
        self,
        previous: Manifest,
        new: Manifest,
        states: StateLookup,
        builder: _Builder,
        tables: Mapping[str, TypeTable],
    ) -> None:
        self._previous = previous
        self._new = new
        self._states = states
        self._builder = builder
        self._tables = tables
        self._cache: dict[str, Mapping[str, JsonValue]] = {}
        self._actions: dict[tuple[str, str], frozenset[str]] = {}

    def resource(self, resource: str) -> list[ChangeItem]:
        table = self._tables.get(resource, _DEFAULT_TABLE)
        items = self._positions(resource, table)
        old_objects = self._previous.objects.get(resource, {})
        new_objects = self._new.objects[resource]
        for key in sorted(new_objects.keys() & old_objects.keys()):
            if new_objects[key] != old_objects[key]:
                items.extend(self._lists(resource, table, key, old_objects[key], new_objects[key]))
        return items

    def _positions(self, resource: str, table: TypeTable) -> list[ChangeItem]:
        """The moves in the order of the objects of a whole resource."""
        old = self._previous.positions.get(resource)
        new = self._new.positions.get(resource)
        if old is None or new is None:
            return []
        result = diff_order(old, new)
        if result.large:
            return [self._builder.reordered(resource, None, None, "", (len(old), len(new)))]
        field_name = _action_field(table)
        read_actions = field_name is not None and table.field_class(field_name) is FieldClass.CONFIG
        jumps = _Jumps(old, new) if read_actions and result.moves else None
        items: list[ChangeItem] = []
        for move in result.moves:
            name = self._name(table, resource, move.key)
            detail: dict[str, JsonValue] | None = None
            if jumps is not None and field_name is not None:
                jumped = jumps.over(move.key)
                keys = [move.key, *jumped]
                actions = {key: self._object_actions(resource, field_name, key) for key in keys}
                detail = _action_detail(move.key, jumped, actions)
            items.append(self._builder.moved(resource, move.key, name, "", move, detail))
        return items

    def _object_actions(self, resource: str, field_name: str, key: str) -> frozenset[str]:
        """The actions of one object before and after, for the order of a whole resource."""
        cached = self._actions.get((resource, key))
        if cached is not None:
            return cached
        found: set[str] = set()
        for manifest in (self._previous, self._new):
            state_hash = manifest.objects.get(resource, {}).get(key)
            if state_hash is not None:
                action = _action_of(self._load(state_hash), field_name)
                if action is not None:
                    found.add(action)
        result = frozenset(found)
        self._actions[(resource, key)] = result
        return result

    def _lists(
        self, resource: str, table: TypeTable, key: str, old_hash: str, new_hash: str
    ) -> list[ChangeItem]:
        """The moves inside the ordered-keyed lists of one object whose state changed."""
        old_state = self._load(old_hash)
        new_state = self._load(new_hash)
        name = self._name(table, resource, key)
        items: list[ChangeItem] = []
        for path, old, new in _ordered_lists(table, "", old_state, new_state):
            key_field = table.item_key_field(path)
            key_shown = _key_is_shown(table, path, key_field)
            old_labels = _labels(key_field, old, key_shown=key_shown)
            new_labels = _labels(key_field, new, key_shown=key_shown)
            result = diff_order(old_labels, new_labels)
            if result.large:
                counts = (len(old), len(new))
                items.append(self._builder.reordered(resource, key, name, path, counts))
            field_name = _action_field(table)
            read_actions = (
                field_name is not None
                and bool(result.moves)
                and table.field_class(f"{path}.{field_name}") is FieldClass.CONFIG
            )
            jumps = _Jumps(old_labels, new_labels) if read_actions else None
            actions: dict[str, frozenset[str]] = {}
            if jumps is not None and field_name is not None:
                actions = _member_actions(field_name, (old_labels, old), (new_labels, new))
            for move in result.moves:
                detail: dict[str, JsonValue] | None = None
                if jumps is not None:
                    detail = _action_detail(move.key, jumps.over(move.key), actions)
                items.append(self._builder.moved(resource, key, name, path, move, detail))
        return items

    def _name(self, table: TypeTable, resource: str, key: str) -> str | None:
        """The display name of an object: the collector's, else the name field of its state."""
        for manifest in (self._new, self._previous):
            name = manifest.names.get(resource, {}).get(key)
            if name is not None:
                return name
        if table.name_field is None:
            return None
        state_hash = self._new.objects[resource].get(key) or self._previous.objects[resource][key]
        value = self._load(state_hash).get(table.name_field)
        return value if isinstance(value, str) else None

    def _load(self, state_hash: str) -> Mapping[str, JsonValue]:
        cached = self._cache.get(state_hash)
        if cached is None:
            cached = self._states(state_hash)
            self._cache[state_hash] = cached
        return cached


def compare_order(
    previous: Manifest | None,
    new: Manifest,
    states: StateLookup,
    *,
    window_start: str,
    window_end: str,
    type_tables: Mapping[str, TypeTable] | None = None,
) -> list[ChangeItem]:
    """Return the ``moved`` and ``order_changed`` items between two manifests of one source.

    Call it with the same arguments as ``compare`` and list its items with the ones of
    ``compare``. ``states`` is read only for an object whose state hash differs, to find the
    ordered lists inside it, and for the name of a moved object when the manifests carry none.
    The result is in a stable order: by resource, the moves of the resource itself, then the
    lists inside its objects by key and path. A baseline (no previous manifest, or another
    normaliser version) gives no items.
    """
    if previous is None or previous.normaliser_version != new.normaliser_version:
        return []
    builder = _Builder(window_start, window_end)
    comparison = _Comparison(previous, new, states, builder, type_tables or {})
    items: list[ChangeItem] = []
    for resource in sorted(new.objects):
        items.extend(comparison.resource(resource))
    return items
