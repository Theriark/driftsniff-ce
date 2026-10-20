"""Run records: one row in ``runs`` per collection attempt, with the size of what it stored."""

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.db.tables import RUN_STATUSES, runs


def start_run(connection: Connection, source_id: int, started_at: str) -> int:
    """Open a run record (status NULL until it finishes) and return its id."""
    return connection.execute(
        sa.insert(runs).values(source_id=source_id, started_at=started_at).returning(runs.c.id)
    ).scalar_one()


def finish_run(
    connection: Connection,
    run_id: int,
    *,
    finished_at: str,
    status: str,
    object_count: int = 0,
    bytes_fetched: int = 0,
    stored_new_snapshot: bool = False,
    new_state_bytes: int = 0,
    manifest_bytes: int = 0,
    error_class: str | None = None,
    error_summary: str | None = None,
) -> None:
    """Close a run record with its status and the sizes that P11 reads to judge growth.

    ``bytes_fetched`` is what the controller sent; ``new_state_bytes`` and ``manifest_bytes`` are
    the compressed bytes this run added to the database.
    """
    if status not in RUN_STATUSES:
        raise ValueError(f"unknown run status {status!r}")
    result = connection.execute(
        sa.update(runs)
        .where(runs.c.id == run_id)
        .values(
            finished_at=finished_at,
            status=status,
            object_count=object_count,
            bytes_fetched=bytes_fetched,
            stored_new_snapshot=stored_new_snapshot,
            new_state_bytes=new_state_bytes,
            manifest_bytes=manifest_bytes,
            error_class=error_class,
            error_summary=error_summary,
        )
    )
    if result.rowcount != 1:
        raise LookupError(f"run {run_id} does not exist")
