"""Record the result of one collection: snapshot if changed, objects, source and run record.

``record_collection`` is the one call a source runner makes after it has read and normalised
everything. Run it inside ``Database.write()`` so the snapshot, the object rows, the source's
timestamps and the run record are committed together.

A collection that finds nothing new adds no snapshot and no state. It writes the run record and
moves the source's ``last_checked_at`` (and ``last_success_at`` for a complete run) forward.
"""

from dataclasses import dataclass
from typing import Literal

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.core.objects import ObjectChanges, update_objects
from driftsniff.core.runs import finish_run
from driftsniff.core.snapshots import Manifest, SnapshotOutcome, store_if_changed
from driftsniff.db.tables import sources


@dataclass(frozen=True)
class CollectionResult:
    """What a collection stored. ``object_changes`` is None when no snapshot was stored."""

    run_id: int
    snapshot: SnapshotOutcome
    object_changes: ObjectChanges | None
    bytes_fetched: int


def record_collection(
    connection: Connection,
    *,
    source_id: int,
    run_id: int,
    manifest: Manifest,
    bytes_fetched: int,
    finished_at: str,
    status: Literal["ok", "partial"] = "ok",
) -> CollectionResult:
    """Store the collection's manifest if it changed and close its run record."""
    snapshot = store_if_changed(connection, source_id, manifest, taken_at=finished_at)
    object_changes = None
    if snapshot.stored:
        object_changes = update_objects(connection, source_id, manifest, seen_at=finished_at)
    timestamps: dict[str, str | None] = {"last_checked_at": finished_at}
    if status == "ok":
        timestamps["last_success_at"] = finished_at
    if manifest.controller_version is not None:
        timestamps["controller_version"] = manifest.controller_version
    connection.execute(sa.update(sources).where(sources.c.id == source_id).values(**timestamps))
    finish_run(
        connection,
        run_id,
        finished_at=finished_at,
        status=status,
        object_count=manifest.object_count,
        bytes_fetched=bytes_fetched,
        stored_new_snapshot=snapshot.stored,
        new_state_bytes=snapshot.new_state_bytes,
        manifest_bytes=snapshot.manifest_bytes,
    )
    return CollectionResult(run_id, snapshot, object_changes, bytes_fetched)
