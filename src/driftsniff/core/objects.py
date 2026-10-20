"""Object bookkeeping: when each object was first seen, last seen and removed.

``update_objects`` is called when a new snapshot is stored, with that snapshot's manifest. It adds
the objects that are new, marks the ones that disappeared as removed, and clears the mark on
one that came back. An object's ``last_seen_at`` is the time of the last snapshot it was part of;
a collection that finds nothing new does not touch these rows (the source's ``last_checked_at``
says when it was last looked at).
"""

from dataclasses import dataclass
from itertools import batched

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.core.snapshots import Manifest
from driftsniff.db.tables import objects

_UPDATE_BATCH = 500


@dataclass(frozen=True)
class ObjectChanges:
    """How many objects ``update_objects`` added, marked removed and brought back."""

    added: int
    removed: int
    reappeared: int


def update_objects(
    connection: Connection, source_id: int, manifest: Manifest, *, seen_at: str
) -> ObjectChanges:
    """Bring the ``objects`` rows of a source in line with the manifest of a stored snapshot.

    Only the resources named in the manifest are touched. A resource a collection could not read
    must be carried over into the manifest by the caller, otherwise its objects count as removed.
    """
    added = removed = reappeared = 0
    for resource, hashes in manifest.objects.items():
        existing = {
            row.object_key: (row.id, row.removed_at)
            for row in connection.execute(
                sa.select(objects.c.id, objects.c.object_key, objects.c.removed_at).where(
                    objects.c.source_id == source_id, objects.c.resource == resource
                )
            )
        }
        names = manifest.names.get(resource, {})
        new_rows: list[dict[str, object]] = []
        seen_rows: list[dict[str, object]] = []
        for key in hashes:
            if key in existing:
                object_id, removed_at = existing[key]
                if removed_at is not None:
                    reappeared += 1
                seen_rows.append({"object_id": object_id, "name": names.get(key)})
            else:
                new_rows.append(
                    {
                        "source_id": source_id,
                        "resource": resource,
                        "object_key": key,
                        "display_name": names.get(key),
                        "first_seen_at": seen_at,
                        "last_seen_at": seen_at,
                    }
                )
        if new_rows:
            connection.execute(sa.insert(objects), new_rows)
            added += len(new_rows)
        if seen_rows:
            connection.execute(
                sa.update(objects)
                .where(objects.c.id == sa.bindparam("object_id"))
                .values(
                    last_seen_at=seen_at,
                    removed_at=None,
                    display_name=sa.func.coalesce(sa.bindparam("name"), objects.c.display_name),
                ),
                seen_rows,
            )
        gone = [
            object_id
            for key, (object_id, removed_at) in existing.items()
            if key not in hashes and removed_at is None
        ]
        for batch in batched(gone, _UPDATE_BATCH):
            connection.execute(
                sa.update(objects).where(objects.c.id.in_(batch)).values(removed_at=seen_at)
            )
        removed += len(gone)
    return ObjectChanges(added, removed, reappeared)
