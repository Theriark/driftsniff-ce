"""The snapshot history of a source, as SQL (P10-T7, backend slice; docs/history-service.md).

``HistoryQueries.list_sources`` feeds the source picker of the History and Configuration pages and
``list_snapshots`` the history of one source. Both read on one read connection, return the frozen
views of ``driftsniff.history.views`` and never write. Neither opens a manifest: the list holds
what the ``snapshots`` row says (time, kind, controller version) and the number of changes found
at each snapshot, so a long history stays cheap.

A reader needs the viewer role; the route enforces it. The queries write nothing, so they write no
audit event (the audit log records changes, not reads).
"""

import math
from typing import Final

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.db.engine import Database
from driftsniff.db.tables import change_events, snapshots, sources
from driftsniff.history.views import (
    PAGE_SIZE,
    SnapshotPageView,
    SnapshotRow,
    SourceHistoryRow,
    SourceRef,
)
from driftsniff.secrets.redact import scrub_text

BASELINE: Final = "baseline"


def _baseline_total() -> sa.ColumnElement[int]:
    """The number of baseline snapshots in a group (0 for a group without any)."""
    return sa.func.coalesce(sa.func.sum(sa.case((snapshots.c.kind == BASELINE, 1), else_=0)), 0)


def page_bounds(page: int, total: int, page_size: int) -> tuple[int, int]:
    """The page to show (clamped into range) and how many pages there are."""
    pages = max(1, math.ceil(total / page_size))
    return min(max(page, 1), pages), pages


def source_ref(connection: Connection, source_id: int) -> SourceRef | None:
    """The source of ``source_id`` as a page reference, or None when there is none."""
    row = connection.execute(
        sa.select(sources.c.id, sources.c.name, sources.c.type, sources.c.enabled).where(
            sources.c.id == source_id
        )
    ).first()
    if row is None:
        return None
    return SourceRef(int(row.id), str(row.name), str(row.type), bool(row.enabled))


class HistoryQueries:
    """Reads the source picker and the snapshot history."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def list_sources(self) -> tuple[SourceHistoryRow, ...]:
        """Every source by name, with how many snapshots it has and when the newest was taken."""
        statement = (
            sa.select(
                sources.c.id,
                sources.c.name,
                sources.c.type,
                sources.c.enabled,
                sa.func.count(snapshots.c.id).label("snapshot_count"),
                _baseline_total().label("baseline_count"),
                sa.func.max(snapshots.c.taken_at).label("latest_taken_at"),
            )
            .select_from(sources.outerjoin(snapshots, snapshots.c.source_id == sources.c.id))
            .group_by(sources.c.id)
            .order_by(sources.c.name, sources.c.id)
        )
        with self._db.read() as connection:
            rows = connection.execute(statement).all()
        return tuple(
            SourceHistoryRow(
                id=int(row.id),
                name=str(row.name),
                type=str(row.type),
                enabled=bool(row.enabled),
                snapshot_count=int(row.snapshot_count),
                baseline_count=int(row.baseline_count),
                latest_taken_at=None if row.latest_taken_at is None else str(row.latest_taken_at),
            )
            for row in rows
        )

    def list_snapshots(self, source_id: int, page: int = 1) -> SnapshotPageView | None:
        """One page of the snapshots of a source, newest first; None for an unknown source.

        A page past the end is the last page. The newest snapshot is the one
        ``driftsniff.core.snapshots.latest_snapshot`` returns (by time, then id).
        """
        in_source = snapshots.c.source_id == source_id
        newest_first = (snapshots.c.taken_at.desc(), snapshots.c.id.desc())
        with self._db.read() as connection:
            source = source_ref(connection, source_id)
            if source is None:
                return None
            total, baseline_count = connection.execute(
                sa.select(sa.func.count(), _baseline_total()).where(in_source)
            ).one()
            shown, pages = page_bounds(page, int(total), PAGE_SIZE)
            found = connection.execute(
                sa.select(
                    snapshots.c.id,
                    snapshots.c.taken_at,
                    snapshots.c.kind,
                    snapshots.c.controller_version,
                    snapshots.c.normaliser_version,
                    sa.func.length(snapshots.c.manifest_zstd).label("manifest_bytes"),
                )
                .where(in_source)
                .order_by(*newest_first)
                .limit(PAGE_SIZE)
                .offset((shown - 1) * PAGE_SIZE)
            ).all()
            newest = connection.execute(
                sa.select(snapshots.c.id).where(in_source).order_by(*newest_first).limit(1)
            ).scalar_one_or_none()
            identifiers = [int(row.id) for row in found]
            changes: dict[int, int] = {}
            if identifiers:
                counted = connection.execute(
                    sa.select(change_events.c.snapshot_id, sa.func.count())
                    .where(change_events.c.snapshot_id.in_(identifiers))
                    .group_by(change_events.c.snapshot_id)
                ).all()
                changes = {int(row[0]): int(row[1]) for row in counted}
        rows = tuple(
            SnapshotRow(
                id=int(row.id),
                taken_at=str(row.taken_at),
                kind=str(row.kind),
                is_baseline=row.kind == BASELINE,
                is_current=newest is not None and int(row.id) == int(newest),
                controller_version=(
                    None if row.controller_version is None else scrub_text(row.controller_version)
                ),
                normaliser_version=int(row.normaliser_version),
                change_count=changes.get(int(row.id), 0),
                manifest_bytes=int(row.manifest_bytes),
            )
            for row in found
        )
        return SnapshotPageView(
            source=source,
            rows=rows,
            total=int(total),
            baseline_count=int(baseline_count),
            page=shown,
            pages=pages,
            page_size=PAGE_SIZE,
        )
