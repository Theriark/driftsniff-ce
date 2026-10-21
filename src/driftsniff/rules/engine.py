"""The classification engine: a severity, a rule id and a rationale for every change item.

:class:`RuleEngine` reads a loaded :class:`~driftsniff.rules.loader.RuleIndex` and classifies the
items that ``core/diff.py`` and ``core/order.py`` produce. It holds no vendor knowledge: what a
rule or a floor says comes from the packs and the type tables, nothing is named here.

Order of decisions
------------------
1. A ``schema_drift`` item is classified by the diff already (LOW) and keeps that; no rule or
   floor applies to a change of the schema of the controller.
2. The most specific rule that applies wins. The candidates come from the index, most specific
   first (``RuleIndex.candidates``), and the first one whose predicate holds, or that has none, is
   taken. The predicate reads the value before and after the change: the shown value of a
   ``config`` field, and the fingerprint of a ``secret`` or ``unclassified`` field (so ``changed``
   holds for a secret that changed, while a predicate about numbers or networks never holds for
   it). An added or removed whole object has no value on either side.
3. An item no rule applies to is MEDIUM, rule id ``builtin.unclassified``, rationale
   ``unclassified field, not reviewed``.
4. Floors raise the result, they never lower it. The final severity is the maximum of the rule and
   of every floor that applies:

   - the object floor of the type table of the resource for this kind of change (``added``,
     ``removed``, ``modified``, ``moved``; an ``order_changed`` item counts as ``moved``). This is
     how a table says that a security sensitive object is at least HIGH, or that removing it is
     CRITICAL;
   - a move in a list whose first matching entry wins (``first_match`` in the type table) is at
     least HIGH, and CRITICAL when the moved entry or one of the entries it passed has a blocking
     action (``blocking_actions`` of the table, ``deny`` and ``drop`` unless it says otherwise).
     The actions are read from the order detail that ``core/order.py`` writes.

   When a floor decides the result, its own id (``builtin.floor.<kind>``,
   ``builtin.move.first_match`` or ``builtin.move.blocking``) and rationale are the result and
   the rule that matched is kept in ``matched_rule_id``. When the rule is as high as the floor,
   the rule is the result.

Every result has a rule id and a rationale that are not empty, and the same item always gives the
same result: nothing here reads the clock, a random source or the order of a dictionary.

Mutes
-----
:func:`is_muted` is the check the list views use for the mutes of a workspace (table
``path_mutes``). A mute hides an item from a list; the item is still stored with its real
severity. A mute never applies to an item whose severity is CRITICAL, and an item that has no
severity yet is not muted either.

Where it is called
------------------
Nothing calls the engine yet: the rule loader is not run at application start either. The run
pipeline of P6-T2 loads the rules, compares the manifests, and calls :meth:`RuleEngine.apply` on
every item before the change event is stored with ``RuleIndex.pack_version``.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Final

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import SCHEMA_DRIFT_RATIONALE, SCHEMA_DRIFT_RULE_ID, ChangeItem
from driftsniff.rules.loader import RuleIndex
from driftsniff.rules.schema import (
    ANY_SEGMENT,
    REST_OF_PATH,
    ResourceTable,
    Severity,
    normalize_path,
    path_matches,
    snake_case,
)

UNCLASSIFIED_RULE_ID: Final = "builtin.unclassified"
UNCLASSIFIED_RATIONALE: Final = "unclassified field, not reviewed"
FLOOR_RULE_PREFIX: Final = "builtin.floor."
MOVE_RULE_ID: Final = "builtin.move.first_match"
MOVE_BLOCKING_RULE_ID: Final = "builtin.move.blocking"

_RANK: Final[Mapping[str, int]] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_FLOOR_KINDS: Final = ("added", "removed", "modified", "moved")


def severity_rank(severity: Severity) -> int:
    """0 for low to 3 for critical; the order in which severities are compared."""
    return _RANK[severity]


def highest(first: Severity, second: Severity) -> Severity:
    """The more severe of two severities."""
    return first if severity_rank(first) >= severity_rank(second) else second


@dataclass(frozen=True)
class Classification:
    """The result for one item.

    ``rule_id`` and ``rationale`` explain ``severity``. ``matched_rule_id`` is the rule that
    applied to the field (or ``builtin.unclassified``); it differs from ``rule_id`` only when a
    floor raised the severity above what that rule said, and then ``floored`` is true.
    """

    severity: Severity
    rule_id: str
    rationale: str
    matched_rule_id: str
    floored: bool = False


@dataclass(frozen=True)
class _Floor:
    severity: Severity
    rule_id: str
    rationale: str


@dataclass(frozen=True)
class PathMute:
    """One mute of a workspace: a resource and a path pattern (rule path syntax, see schema)."""

    resource: str
    path_pattern: str


def _value(text: str | None, fingerprint: str | None) -> JsonValue:
    """The value a predicate reads: the shown value, else the fingerprint, else nothing."""
    if text is None:
        return fingerprint
    try:
        parsed: JsonValue = json.loads(text)
    except (ValueError, RecursionError):
        return text
    return parsed


def _floor_kind(change_kind: str) -> str | None:
    if change_kind == "order_changed":
        return "moved"
    return change_kind if change_kind in _FLOOR_KINDS else None


def _actions(detail: Mapping[str, JsonValue] | None) -> list[str]:
    """The actions of the moved entry and of the entries it passed, from the order detail."""
    found: list[str] = []
    if detail is None:
        return found
    for name in ("moved_actions", "jumped_actions"):
        listed = detail.get(name)
        if isinstance(listed, list):
            found.extend(action for action in listed if isinstance(action, str))
    return found


class RuleEngine:
    """Classifies change items with the rules and the type tables of one loaded index."""

    def __init__(self, index: RuleIndex) -> None:
        self._index = index

    @property
    def index(self) -> RuleIndex:
        """The loaded rules and type tables this engine reads."""
        return self._index

    @property
    def pack_version(self) -> str:
        """The rule pack version to store with the change event of the classified items."""
        return self._index.pack_version

    def classify(self, item: ChangeItem) -> Classification:
        """The severity, rule id and rationale of ``item``."""
        if item.change_kind == "schema_drift":
            return Classification(
                item.severity or "low",
                item.rule_id or SCHEMA_DRIFT_RULE_ID,
                item.rationale or SCHEMA_DRIFT_RATIONALE,
                item.rule_id or SCHEMA_DRIFT_RULE_ID,
            )
        matched = self._match(item)
        floor = self._floor(item)
        if floor is not None and severity_rank(floor.severity) > severity_rank(matched.severity):
            return Classification(
                floor.severity, floor.rule_id, floor.rationale, matched.matched_rule_id, True
            )
        return matched

    def apply(self, item: ChangeItem) -> ChangeItem:
        """A copy of ``item`` with its severity, rule id and rationale filled in."""
        result = self.classify(item)
        return replace(
            item, severity=result.severity, rule_id=result.rule_id, rationale=result.rationale
        )

    def _match(self, item: ChangeItem) -> Classification:
        before = _value(item.before_value, item.before_fp)
        after = _value(item.after_value, item.after_fp)
        for compiled in self._index.candidates(item.resource, item.path):
            if compiled.predicate is None or compiled.predicate(before, after):
                rule = compiled.rule
                return Classification(rule.severity, rule.id, rule.rationale, rule.id)
        return Classification(
            "medium", UNCLASSIFIED_RULE_ID, UNCLASSIFIED_RATIONALE, UNCLASSIFIED_RULE_ID
        )

    def _floor(self, item: ChangeItem) -> _Floor | None:
        """The highest floor that applies to ``item``; the first of equal ones wins."""
        table = self._index.type_tables.get(item.resource)
        kind = _floor_kind(item.change_kind)
        if table is None or kind is None:
            return None
        candidates: list[_Floor] = []
        declared = table.floor_for(kind)
        if declared is not None:
            candidates.append(
                _Floor(
                    declared,
                    f"{FLOOR_RULE_PREFIX}{kind}",
                    f"Objects of type {item.resource} are security sensitive: "
                    f"when one is {kind}, the severity is at least {declared}.",
                )
            )
        candidates.extend(_move_floors(table, item))
        best: _Floor | None = None
        for candidate in candidates:
            if best is None or severity_rank(candidate.severity) > severity_rank(best.severity):
                best = candidate
        return best


def _move_floors(table: ResourceTable, item: ChangeItem) -> list[_Floor]:
    """The floors of a move (or an unreadable reorder) in a list where the first match wins."""
    if item.change_kind not in ("moved", "order_changed") or not table.is_first_match(item.path):
        return []
    resource = item.resource
    floors = [
        _Floor(
            "high",
            MOVE_RULE_ID,
            f"The order of {resource} entries decides which one applies first: "
            "a change of order is at least high.",
        )
    ]
    if item.change_kind == "moved" and any(
        table.is_blocking(action) for action in _actions(item.order_detail)
    ):
        floors.append(
            _Floor(
                "critical",
                MOVE_BLOCKING_RULE_ID,
                f"An entry of {resource} that blocks was moved, or an entry was moved across one "
                "that blocks: what is allowed or denied may have changed.",
            )
        )
    return floors


def _pattern(path_pattern: str) -> tuple[str, ...]:
    pattern = path_pattern.strip()
    if pattern == "":
        return ()
    return tuple(
        part if part in (ANY_SEGMENT, REST_OF_PATH) else snake_case(part)
        for part in pattern.split(".")
    )


def is_muted(
    severity: Severity | None, resource: str, path: str, mutes: Iterable[PathMute]
) -> bool:
    """Whether a list view hides the item: a mute of its resource matches its path.

    An item whose severity is critical is never hidden, and neither is one that has no severity
    yet. The pattern is read like the path of a rule: snake case segments, ``*`` for one segment
    and ``**`` for the rest; an empty pattern matches only the empty path of a whole object.
    """
    if severity is None or severity == "critical":
        return False
    segments = normalize_path(path)
    return any(
        mute.resource == resource and path_matches(_pattern(mute.path_pattern), segments)
        for mute in mutes
    )


def item_is_muted(item: ChangeItem, mutes: Iterable[PathMute]) -> bool:
    """:func:`is_muted` for a classified change item."""
    return is_muted(item.severity, item.resource, item.path, mutes)
