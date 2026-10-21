"""Helpers of the golden tests: load the test-only rules, build manifests, detect change items.

``GOLDEN_ROOT`` is a rules root in the shipped layout (``types/*.yaml``, ``packs/xo``,
``packs/unifi``). :func:`detect` runs the real chain for one resource: two manifests, ``compare``
for the field changes and added or removed objects, ``compare_order`` for the moves. The rule
engine classifies what comes out; nothing here decides a severity.
"""

import json
from collections.abc import Mapping, Sequence
from functools import cache
from pathlib import Path
from typing import Final

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, StateLookup, compare
from driftsniff.core.order import compare_order
from driftsniff.core.snapshots import CollectedObject, CollectedResource, Manifest, build_manifest
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter

GOLDEN_ROOT: Final = Path(__file__).resolve().parent
FINGERPRINTER: Final = Fingerprinter(bytes(range(32)), "0a1b2c3d")
START: Final = "2026-10-21T10:00:00Z"
END: Final = "2026-10-21T10:05:00Z"
NAME_FIELDS: Final = ("name", "name_label", "label", "email")

type State = Mapping[str, JsonValue]


def state(**fields: JsonValue) -> State:
    """One object state, as a collector would hand it over."""
    return fields


@cache
def golden_engine() -> RuleEngine:
    """The engine over the test-only type tables and packs of this folder."""
    return RuleEngine(load_rules(GOLDEN_ROOT))


def _name(member: State) -> str | None:
    for name_field in NAME_FIELDS:
        value = member.get(name_field)
        if isinstance(value, str):
            return value
    return None


def manifest(resource: str, states: Sequence[State], *, ordered: bool) -> Manifest:
    """The manifest of one collection that saw ``states`` (each has an ``id``) in this order."""
    objects = [CollectedObject(str(member["id"]), member, _name(member)) for member in states]
    return build_manifest(
        {resource: CollectedResource(objects, ordered=ordered)}, controller_version="1.0"
    )


def _lookup(*manifests: Manifest) -> StateLookup:
    pending: dict[str, bytes] = {}
    for item in manifests:
        pending.update(item.pending_states)

    def lookup(state_hash: str) -> Mapping[str, JsonValue]:
        loaded = json.loads(pending[state_hash])
        assert isinstance(loaded, dict)
        return loaded

    return lookup


def detect(
    resource: str,
    before: Sequence[State],
    after: Sequence[State],
    *,
    ordered: bool = False,
    engine: RuleEngine | None = None,
) -> list[ChangeItem]:
    """The change items between two collections of ``resource``: fields, objects and moves."""
    tables = (engine or golden_engine()).index.type_tables
    previous = manifest(resource, before, ordered=ordered)
    new = manifest(resource, after, ordered=ordered)
    lookup = _lookup(previous, new)
    items = compare(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        fingerprinter=FINGERPRINTER,
        type_tables=tables,
    )
    moves = compare_order(
        previous, new, lookup, window_start=START, window_end=END, type_tables=tables
    )
    return [*items, *moves]
