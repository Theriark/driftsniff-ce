"""Manifests and snapshots: store a new picture of a source only when it changed.

A manifest describes everything one collection saw: for each resource, the map of object key to
state hash, plus (for ordered collections) the list of keys in their order, and the controller
and normaliser versions. It is stored as zstd compressed canonical JSON in ``snapshots``. The
states it points to live in ``object_states`` and are shared between snapshots, so a collection
that changed one object stores one new state and one new manifest.

A manifest is stored only when its own hash differs from the last one stored for that source.
The first snapshot of a source, and the first one after a normaliser version change, has kind
``baseline``: the diff engine starts from it instead of comparing across the change.
"""

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import batched
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.normalize import NORMALISER_VERSION
from driftsniff.core.states import (
    StoredDataError,
    canonical_state,
    compress_bytes,
    decompress_bytes,
    get_state,
    put_canonical_state,
)
from driftsniff.db.tables import object_states, snapshots

MANIFEST_FORMAT = 1
MAX_MANIFEST_BYTES = 256 * 1024 * 1024
_STATE_HASH = re.compile(r"[0-9a-f]{64}")
_DELETE_BATCH = 500

type ResolvedState = dict[str, dict[str, dict[str, JsonValue]]]


class ManifestError(StoredDataError):
    """A manifest is malformed, damaged or does not match its recorded hash."""


@dataclass(frozen=True)
class CollectedObject:
    """One object as a collector delivers it: its key, its normalised state and its name."""

    key: str
    state: Mapping[str, JsonValue]
    name: str | None = None


@dataclass(frozen=True)
class CollectedResource:
    """All objects of one resource. ``ordered`` keeps their order as a position list."""

    objects: Sequence[CollectedObject]
    ordered: bool = False


@dataclass(frozen=True)
class Manifest:
    """What one collection saw. Equality and the hash cover only the stored content."""

    controller_version: str | None
    normaliser_version: int
    # resource -> object key -> state hash
    objects: Mapping[str, Mapping[str, str]]
    # resource -> object keys in order, for ordered resources only
    positions: Mapping[str, Sequence[str]]
    # The two fields below exist only on a manifest made by build_manifest. They are not
    # stored in it and are empty on a manifest read back from the database.
    pending_states: Mapping[str, bytes] = field(default_factory=dict, compare=False, repr=False)
    names: Mapping[str, Mapping[str, str | None]] = field(
        default_factory=dict, compare=False, repr=False
    )

    def to_json(self) -> dict[str, JsonValue]:
        """The manifest as a JSON value, in the layout that is stored."""
        resources: dict[str, JsonValue] = {}
        for resource, hashes in self.objects.items():
            entry: dict[str, JsonValue] = {"objects": dict(hashes)}
            if resource in self.positions:
                entry["order"] = list(self.positions[resource])
            resources[resource] = entry
        return {
            "format": MANIFEST_FORMAT,
            "controller_version": self.controller_version,
            "normaliser_version": self.normaliser_version,
            "resources": resources,
        }

    def canonical_bytes(self) -> bytes:
        """The canonical JSON bytes the manifest is hashed and stored by."""
        return canonical_dumps(self.to_json())

    @property
    def manifest_hash(self) -> str:
        """SHA-256 of the canonical bytes."""
        return sha256(self.canonical_bytes()).hexdigest()

    @property
    def object_count(self) -> int:
        """Number of objects over all resources."""
        return sum(len(hashes) for hashes in self.objects.values())

    def state_hashes(self) -> set[str]:
        """Every state hash the manifest refers to."""
        return {state_hash for hashes in self.objects.values() for state_hash in hashes.values()}

    @classmethod
    def from_bytes(cls, data: bytes) -> "Manifest":
        """Parse and validate stored canonical manifest bytes."""
        try:
            document = _mapping(json.loads(data), "the manifest")
        except ValueError as error:
            raise ManifestError("the manifest is not valid JSON") from error
        if document.get("format") != MANIFEST_FORMAT:
            raise ManifestError(f"unknown manifest format {document.get('format')!r}")
        normaliser_version = document.get("normaliser_version")
        if not isinstance(normaliser_version, int) or isinstance(normaliser_version, bool):
            raise ManifestError("normaliser_version must be an integer")
        controller_version = document.get("controller_version")
        if controller_version is not None and not isinstance(controller_version, str):
            raise ManifestError("controller_version must be text or null")
        objects: dict[str, dict[str, str]] = {}
        positions: dict[str, list[str]] = {}
        for resource, raw_entry in _mapping(document.get("resources"), "resources").items():
            entry = _mapping(raw_entry, f"resource {resource!r}")
            hashes: dict[str, str] = {}
            for key, state_hash in _mapping(entry.get("objects"), f"{resource!r} objects").items():
                if not isinstance(state_hash, str) or not _STATE_HASH.fullmatch(state_hash):
                    raise ManifestError(f"{resource!r} object {key!r} has no valid state hash")
                hashes[key] = state_hash
            objects[resource] = hashes
            if "order" in entry:
                order = entry["order"]
                if (
                    not isinstance(order, list)
                    or not all(isinstance(key, str) for key in order)
                    or len(set(order)) != len(order)
                    or set(order) != set(hashes)
                ):
                    raise ManifestError(f"{resource!r} order does not list its objects once each")
                positions[resource] = order
        return cls(controller_version, normaliser_version, objects, positions)


def _mapping(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{what} must be an object")
    return value


def load_manifest(data: bytes, expected_hash: str) -> Manifest:
    """Decompress and parse a stored manifest, checking it against its recorded hash."""
    body = decompress_bytes(data, MAX_MANIFEST_BYTES)
    if sha256(body).hexdigest() != expected_hash:
        raise ManifestError("the manifest does not match its recorded hash")
    return Manifest.from_bytes(body)


def build_manifest(
    resources: Mapping[str, CollectedResource],
    *,
    controller_version: str | None,
    normaliser_version: int = NORMALISER_VERSION,
) -> Manifest:
    """Hash every collected object and describe the whole collection in one manifest.

    The object states must already be normalised. Nothing is written to the database here.
    """
    objects: dict[str, dict[str, str]] = {}
    positions: dict[str, list[str]] = {}
    pending: dict[str, bytes] = {}
    names: dict[str, dict[str, str | None]] = {}
    for resource, collected in resources.items():
        hashes: dict[str, str] = {}
        resource_names: dict[str, str | None] = {}
        for item in collected.objects:
            if item.key in hashes:
                raise ValueError(f"duplicate object key {item.key!r} in resource {resource!r}")
            state_hash, body = canonical_state(item.state)
            hashes[item.key] = state_hash
            resource_names[item.key] = item.name
            pending[state_hash] = body
        objects[resource] = hashes
        names[resource] = resource_names
        if collected.ordered:
            positions[resource] = list(hashes)
    return Manifest(controller_version, normaliser_version, objects, positions, pending, names)


@dataclass(frozen=True)
class StoredSnapshot:
    """The newest snapshot of a source, with its manifest."""

    snapshot_id: int
    taken_at: str
    kind: str
    manifest: Manifest


@dataclass(frozen=True)
class SnapshotOutcome:
    """What ``store_if_changed`` did, and how many bytes it added."""

    stored: bool
    snapshot_id: int | None = None
    previous_snapshot_id: int | None = None
    kind: str | None = None
    new_state_count: int = 0
    new_state_bytes: int = 0
    manifest_bytes: int = 0


def latest_snapshot(connection: Connection, source_id: int) -> StoredSnapshot | None:
    """Return the newest snapshot of the source (by ``taken_at``, then id), or None."""
    row = connection.execute(
        sa.select(
            snapshots.c.id,
            snapshots.c.taken_at,
            snapshots.c.kind,
            snapshots.c.manifest_hash,
            snapshots.c.manifest_zstd,
        )
        .where(snapshots.c.source_id == source_id)
        .order_by(snapshots.c.taken_at.desc(), snapshots.c.id.desc())
        .limit(1)
    ).first()
    if row is None:
        return None
    manifest = load_manifest(row.manifest_zstd, row.manifest_hash)
    return StoredSnapshot(row.id, row.taken_at, row.kind, manifest)


def store_if_changed(
    connection: Connection, source_id: int, manifest: Manifest, *, taken_at: str
) -> SnapshotOutcome:
    """Store ``manifest`` and its new states, unless it equals the last one stored.

    When nothing changed this reads one row and writes nothing. Otherwise every state of the
    manifest that is not stored yet is added, then the snapshot. The kind is ``baseline`` for the
    first snapshot of the source and when the normaliser version differs from the previous one.
    """
    missing = manifest.state_hashes() - manifest.pending_states.keys()
    if missing:
        raise ValueError("the manifest was not made by build_manifest: its states are unknown")
    manifest_hash = manifest.manifest_hash
    previous = connection.execute(
        sa.select(snapshots.c.id, snapshots.c.manifest_hash, snapshots.c.normaliser_version)
        .where(snapshots.c.source_id == source_id)
        .order_by(snapshots.c.taken_at.desc(), snapshots.c.id.desc())
        .limit(1)
    ).first()
    if previous is not None and previous.manifest_hash == manifest_hash:
        return SnapshotOutcome(stored=False, previous_snapshot_id=previous.id)
    new_state_count = 0
    new_state_bytes = 0
    for state_hash, body in manifest.pending_states.items():
        written = put_canonical_state(
            connection, state_hash, body, normaliser_version=manifest.normaliser_version
        )
        if written.is_new:
            new_state_count += 1
            new_state_bytes += written.stored_bytes
    compressed = compress_bytes(manifest.canonical_bytes())
    is_baseline = previous is None or previous.normaliser_version != manifest.normaliser_version
    kind = "baseline" if is_baseline else "normal"
    snapshot_id = connection.execute(
        sa.insert(snapshots)
        .values(
            source_id=source_id,
            taken_at=taken_at,
            manifest_hash=manifest_hash,
            manifest_zstd=compressed,
            controller_version=manifest.controller_version,
            normaliser_version=manifest.normaliser_version,
            kind=kind,
        )
        .returning(snapshots.c.id)
    ).scalar_one()
    return SnapshotOutcome(
        stored=True,
        snapshot_id=snapshot_id,
        previous_snapshot_id=None if previous is None else previous.id,
        kind=kind,
        new_state_count=new_state_count,
        new_state_bytes=new_state_bytes,
        manifest_bytes=len(compressed),
    )


def resolve_manifest(connection: Connection, manifest: Manifest) -> ResolvedState:
    """Expand a manifest into resource -> object key -> normalised state.

    Objects of an ordered resource come back in their stored order.
    """
    resolved: ResolvedState = {}
    for resource, hashes in manifest.objects.items():
        keys = manifest.positions.get(resource, list(hashes))
        resolved[resource] = {key: get_state(connection, hashes[key]) for key in keys}
    return resolved


def resolve_current_state(connection: Connection, source_id: int) -> ResolvedState | None:
    """The normalised state of every object in the newest snapshot, or None before the first."""
    current = latest_snapshot(connection, source_id)
    if current is None:
        return None
    return resolve_manifest(connection, current.manifest)


@dataclass(frozen=True)
class GcResult:
    """What ``gc_unreferenced_states`` removed."""

    removed_count: int
    freed_bytes: int


def referenced_state_hashes(connection: Connection) -> set[str]:
    """Every state hash that any stored snapshot refers to."""
    referenced: set[str] = set()
    rows = connection.execute(sa.select(snapshots.c.manifest_hash, snapshots.c.manifest_zstd)).all()
    for row in rows:
        referenced |= load_manifest(row.manifest_zstd, row.manifest_hash).state_hashes()
    return referenced


def gc_unreferenced_states(connection: Connection) -> GcResult:
    """Delete the states that no stored snapshot refers to; keep every referenced one.

    Every manifest is read and checked first. If one is damaged this raises before anything is
    deleted, so a damaged manifest can never cause a referenced state to be removed. Run it inside
    ``Database.write()``: the single writer lock keeps a snapshot from being stored half way.
    """
    referenced = referenced_state_hashes(connection)
    stored = connection.execute(
        sa.select(object_states.c.state_hash, sa.func.length(object_states.c.body_zstd))
    ).all()
    unreferenced = [row for row in stored if row[0] not in referenced]
    for batch in batched((row[0] for row in unreferenced), _DELETE_BATCH):
        connection.execute(sa.delete(object_states).where(object_states.c.state_hash.in_(batch)))
    return GcResult(len(unreferenced), sum(row[1] for row in unreferenced))
