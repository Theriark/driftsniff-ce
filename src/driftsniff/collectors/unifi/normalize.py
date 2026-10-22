"""What the UniFi collector does to raw objects before the pipeline normalises them (P7-T4).

Two jobs, both on raw dictionaries and neither with any vendor knowledge beyond the names in
``resources.py`` (all **unverified**, docs/vendor-notes/unifi.md):

* :func:`prepare_object` copies the nested action of a firewall policy (``action.type``) to the
  flat top level field ``actionType`` that the type table names as its action field. Without that
  copy the order check of the engine cannot see that a moved policy jumped over a block rule, and
  the move is only high, not critical.
* :func:`merge_ordering` turns the ordering documents into the position list of a resource. The
  controller orders firewall policies per pair of zones and ACL rules in one list; the engine
  stores one position list per resource. The pipeline keeps the order of the objects a collector
  returns, so the merge simply returns the objects in position order.

The merge for firewall policies reads the pairs in sorted order and, inside a pair, the policies
that run before the system defined ones and then the ones that run after them. The pair order is
sorted so that two runs of an unchanged controller give the same list.

An object that no ordering list names is appended at the end, and an id that no object has is
dropped. Both are counted: the collector reports them as the class ``ordering_mismatch`` and the
run is marked partial, because the position of what was appended is a guess.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from driftsniff.collectors.unifi.resources import RESOURCE_FIREWALL_POLICIES

ERROR_ORDERING_MISMATCH: Final = "ordering_mismatch"
ACTION_TYPE_FIELD: Final = "actionType"
MAX_ZONE_PAIRS: Final = 256

_ZONE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")

type ZonePair = tuple[str, str]


def prepare_object(resource: str, raw: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of ``raw`` with the derived fields of ``resource`` filled in.

    Only firewall policies have one: ``actionType`` is always taken from ``action.type`` and a
    value the controller sent under that name is replaced, so the field cannot disagree with the
    nested action.
    """
    prepared = dict(raw)
    if resource != RESOURCE_FIREWALL_POLICIES:
        return prepared
    action = prepared.get("action")
    kind = action.get("type") if isinstance(action, Mapping) else None
    if isinstance(kind, str):
        prepared[ACTION_TYPE_FIELD] = kind
    else:
        prepared.pop(ACTION_TYPE_FIELD, None)
    return prepared


def _zone(side: object) -> str | None:
    if not isinstance(side, Mapping):
        return None
    zone = side.get("zoneId")
    if isinstance(zone, str) and _ZONE_ID.fullmatch(zone):
        return zone
    return None


def zone_pair(policy: Mapping[str, Any]) -> ZonePair | None:
    """The (source zone, destination zone) of a policy, or None when it has no usable pair."""
    source = _zone(policy.get("source"))
    destination = _zone(policy.get("destination"))
    if source is None or destination is None:
        return None
    return source, destination


def firewall_pairs(policies: Sequence[Mapping[str, Any]]) -> list[ZonePair]:
    """The distinct zone pairs of ``policies``, sorted: the pairs whose ordering is read."""
    return sorted({pair for policy in policies if (pair := zone_pair(policy)) is not None})


def _object_id(item: Mapping[str, Any]) -> str | None:
    key = item.get("id")
    return key if isinstance(key, str) and key else None


@dataclass(frozen=True, slots=True)
class Merged:
    """The objects in position order, and how many entries the ordering lists did not match.

    ``appended`` counts objects that no list named (they are at the end), ``dropped`` counts ids
    that no object has, or that a list names twice.
    """

    objects: list[dict[str, Any]]
    appended: int = 0
    dropped: int = 0

    @property
    def mismatch(self) -> bool:
        """Whether the ordering lists and the objects disagreed."""
        return self.appended > 0 or self.dropped > 0


def merge_ordering(objects: Sequence[dict[str, Any]], orderings: Sequence[Sequence[str]]) -> Merged:
    """``objects`` in the order of ``orderings`` (their lists, one after the other).

    An id that is listed again, or that no object has, is dropped; an object that is not listed
    is appended in the order the controller returned it.
    """
    index_of: dict[str, int] = {}
    for position, item in enumerate(objects):
        key = _object_id(item)
        if key is not None and key not in index_of:
            index_of[key] = position
    used: set[int] = set()
    ordered: list[dict[str, Any]] = []
    dropped = 0
    for listed in orderings:
        for key in listed:
            found = index_of.get(key)
            if found is None or found in used:
                dropped += 1
                continue
            used.add(found)
            ordered.append(objects[found])
    leftover = [item for position, item in enumerate(objects) if position not in used]
    ordered.extend(leftover)
    return Merged(ordered, len(leftover), dropped)


def mismatch_text(appended: int, dropped: int) -> str:
    """The fixed sentence of the warning: counts only, never an id or a name."""
    return f"ordering lists did not match: {appended} appended at the end, {dropped} ids dropped"
