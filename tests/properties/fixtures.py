"""Synthetic fixtures and strategies for the diff engine tests, reusable by later phases.

Everything here is made up: object keys are ``n1``.., values are small integers and short words,
and every secret-like value starts with ``CANARY-``. No real host name, address or key appears.

An *inventory* is what a collector would deliver for one source: resource -> object key -> state.
``manifest_of`` hashes it and ``diff`` compares two inventories through the real ``compare``.
"""

import json
from collections.abc import Mapping
from typing import Final

from hypothesis import strategies as st

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, compare
from driftsniff.core.normalize import CollectionMode, FieldClass, StaticTypeTable, TypeTable
from driftsniff.core.snapshots import CollectedObject, CollectedResource, Manifest, build_manifest
from driftsniff.secrets.fingerprint import Fingerprinter

CANARY_PREFIX: Final = "CANARY-"
START: Final = "2026-10-21T10:00:00Z"
END: Final = "2026-10-21T10:05:00Z"
FINGERPRINTER: Final = Fingerprinter(bytes(range(32)), "0a1b2c3d")
KEYS: Final = ("n1", "n2", "n3", "n4")

type State = dict[str, JsonValue]
type Inventory = dict[str, dict[str, State]]

TABLE: Final = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "vlan": FieldClass.CONFIG,
        "enabled": FieldClass.CONFIG,
        "label": FieldClass.CONFIG,
        "cfg": FieldClass.CONFIG,
        "cfg.x": FieldClass.CONFIG,
        "cfg.y": FieldClass.CONFIG,
        "dns": FieldClass.CONFIG,
        "tags": FieldClass.CONFIG,
        "rules": FieldClass.CONFIG,
        "rules.id": FieldClass.CONFIG,
        "rules.action": FieldClass.CONFIG,
        "ports": FieldClass.CONFIG,
        "ports.idx": FieldClass.CONFIG,
        "ports.mode": FieldClass.CONFIG,
        "uptime": FieldClass.IGNORE,
        "wifi": FieldClass.CONFIG,
        "wifi.ssid": FieldClass.CONFIG,
        "wifi.passphrase": FieldClass.SECRET,
    },
    collection_modes={
        "tags": CollectionMode.SET,
        "rules": CollectionMode.ORDERED_KEYED,
        "ports": CollectionMode.VENDOR_INDEX,
        "dns": CollectionMode.ORDERED_SCALAR,
    },
    item_key_fields={"rules": "id", "ports": "idx"},
)
TABLES: Final[Mapping[str, TypeTable]] = {"network": TABLE, "device": TABLE}


def manifest_of(inventory: Inventory, *, controller: str | None = "1.0") -> Manifest:
    """Hash an inventory into a manifest (objects in the dictionary's order)."""
    resources = {
        resource: CollectedResource(
            [CollectedObject(key, state, f"net {key}") for key, state in objects.items()]
        )
        for resource, objects in inventory.items()
    }
    return build_manifest(resources, controller_version=controller)


def diff(previous: Inventory | None, new: Inventory) -> list[ChangeItem]:
    """Run the real ``compare`` on two inventories with the synthetic type table."""
    old_manifest = manifest_of(previous) if previous is not None else None
    new_manifest = manifest_of(new)
    pending: dict[str, bytes] = {}
    if old_manifest is not None:
        pending.update(old_manifest.pending_states)
    pending.update(new_manifest.pending_states)

    def lookup(state_hash: str) -> Mapping[str, JsonValue]:
        loaded = json.loads(pending[state_hash])
        assert isinstance(loaded, dict)
        return loaded

    return compare(
        old_manifest,
        new_manifest,
        lookup,
        window_start=START,
        window_end=END,
        fingerprinter=FINGERPRINTER,
        type_tables=TABLES,
    )


# ---- strategies ---------------------------------------------------------------------------
# The value domains are tiny on purpose: two independent draws then often agree on a field and
# differ on another, which is what a diff needs to be exercised.

_words = st.sampled_from(["a", "b", "c", "dd"])
_small = st.integers(min_value=0, max_value=2)
_rules: st.SearchStrategy[JsonValue] = st.fixed_dictionaries(
    {"id": _words, "action": st.sampled_from(["allow", "deny"])}
)
_ports: st.SearchStrategy[JsonValue] = st.fixed_dictionaries(
    {"idx": _small, "mode": st.sampled_from(["access", "trunk"])}
)


def _members(
    strategy: st.SearchStrategy[JsonValue], field: str
) -> st.SearchStrategy[list[JsonValue]]:
    """Up to four members whose ``field`` is distinct."""

    def identity(member: JsonValue) -> JsonValue:
        assert isinstance(member, dict)
        return member[field]

    return st.lists(strategy, max_size=4, unique_by=identity)


def states(key: str, *, secrets: bool = False) -> st.SearchStrategy[State]:
    """A state for the object ``key``. Fields are optional; no null, no float.

    With ``secrets`` the state may hold ``wifi.passphrase`` as a ``CANARY-`` value.
    """
    wifi: dict[str, st.SearchStrategy[JsonValue]] = {"ssid": _words}
    if secrets:
        wifi["passphrase"] = st.integers(0, 3).map(lambda n: f"{CANARY_PREFIX}{n:04d}")
    optional: dict[str, st.SearchStrategy[JsonValue]] = {
        "vlan": _small,
        "enabled": st.booleans(),
        "label": _words,
        "uptime": st.integers(0, 5),
        "cfg": st.fixed_dictionaries({}, optional={"x": _small, "y": _words}),
        "dns": st.lists(_words, max_size=3),
        "tags": st.lists(_words, max_size=4, unique=True),
        "rules": _members(_rules, "id"),
        "ports": _members(_ports, "idx"),
        "wifi": st.fixed_dictionaries({}, optional=wifi),
    }

    def with_identity(fields: Mapping[str, JsonValue]) -> State:
        return {"_id": key, "name": f"net {key}", **fields}

    return st.fixed_dictionaries({}, optional=optional).map(with_identity)


@st.composite
def _objects(draw: st.DrawFn, secrets: bool) -> dict[str, State]:
    keys = draw(st.lists(st.sampled_from(KEYS), max_size=4, unique=True))
    return {key: draw(states(key, secrets=secrets)) for key in keys}


@st.composite
def inventory_pairs(draw: st.DrawFn, *, secrets: bool = False) -> tuple[Inventory, Inventory]:
    """A previous and a new inventory with the same resources, drawn independently."""
    names = st.sampled_from(sorted(TABLES))
    resources = draw(st.lists(names, min_size=1, max_size=2, unique=True))
    previous: Inventory = {resource: draw(_objects(secrets)) for resource in resources}
    new: Inventory = {resource: draw(_objects(secrets)) for resource in resources}
    return previous, new
