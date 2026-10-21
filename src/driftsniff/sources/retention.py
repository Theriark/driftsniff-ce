"""Retention: delete old history every day (docs/retention-and-backup.md has the user view).

One run, once a day at 03:30 UTC, does three things in this order:

1. Change events older than the retention window are deleted. The window is the ``retention_days``
   row of the ``settings`` table: 365 days by default, 30 to 365 allowed; a missing or invalid
   value gives 365, the longest window, so a bad value never deletes more than the default would.
   An event's items, acknowledgements, notes, enrichments and notification deliveries go with it
   (their foreign keys cascade).
2. Manifests (the ``snapshots`` rows) older than 90 days are thinned to the last manifest of each
   UTC day of each source. A manifest that a retained change event points to, as its snapshot or
   as its previous snapshot, is always kept. The newest manifest of a source is the last of its
   day and therefore also kept.
3. Object states that no remaining manifest refers to are deleted.

Steps 1 and 2 are one transaction, step 3 (and the audit event ``retention.run``, which holds
counts only) is another, so a crash between them leaves garbage that the next run collects and
never a manifest without its states. Every transaction holds the single writer lock of
``Database.write()``.

Time is injected (``now`` and ``sleep``), so tests never wait. A failed run is logged by the class
of its exception only and does not stop the daily loop.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import batched
from typing import Final

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.core.snapshots import gc_unreferenced_states
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    DEFAULT_WORKSPACE_ID,
    audit_events,
    change_events,
    settings,
    snapshots,
)

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS: Final = 365
MIN_RETENTION_DAYS: Final = 30
MAX_RETENTION_DAYS: Final = 365
THINNING_AFTER_DAYS: Final = 90
RETENTION_DAYS_SETTING: Final = "retention_days"
RUN_HOUR_UTC: Final = 3
RUN_MINUTE_UTC: Final = 30
ACTION_RETENTION_RUN: Final = "retention.run"
ACTOR_SYSTEM: Final = "system"
_DELETE_BATCH: Final = 500
_TIME_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"
_MAX_SETTING_CHARS: Final = 3


@dataclass(frozen=True, slots=True)
class RetentionResult:
    """What one retention run removed."""

    retention_days: int
    events_deleted: int
    snapshots_thinned: int
    states_removed: int
    freed_bytes: int


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(_TIME_FORMAT)


def retention_days(connection: Connection) -> int:
    """The retention window in days: the stored setting when valid, else 365."""
    raw = connection.execute(
        sa.select(settings.c.value).where(
            settings.c.workspace_id == DEFAULT_WORKSPACE_ID,
            settings.c.key == RETENTION_DAYS_SETTING,
        )
    ).scalar_one_or_none()
    if raw is None:
        return DEFAULT_RETENTION_DAYS
    text = raw.strip()
    if (
        text.isascii()
        and text.isdigit()
        and len(text) <= _MAX_SETTING_CHARS
        and MIN_RETENTION_DAYS <= int(text) <= MAX_RETENTION_DAYS
    ):
        return int(text)
    logger.warning(
        "setting %s is not a whole number from %d to %d: using %d",
        RETENTION_DAYS_SETTING,
        MIN_RETENTION_DAYS,
        MAX_RETENTION_DAYS,
        DEFAULT_RETENTION_DAYS,
    )
    return DEFAULT_RETENTION_DAYS


def delete_old_events(connection: Connection, cutoff: str) -> int:
    """Delete the change events created before ``cutoff`` with everything that hangs on them."""
    result = connection.execute(sa.delete(change_events).where(change_events.c.created_at < cutoff))
    return int(result.rowcount)


def thin_snapshots(connection: Connection, cutoff: str) -> int:
    """Thin the manifests taken before ``cutoff`` to the last one per source and UTC day.

    A manifest that a change event still points to is never removed. Run it after the old events
    were deleted, so only retained events protect a manifest. Returns the number removed.
    """
    candidates = connection.execute(
        sa.select(snapshots.c.id, snapshots.c.source_id, snapshots.c.taken_at)
        .where(snapshots.c.taken_at < cutoff)
        .order_by(snapshots.c.source_id, snapshots.c.taken_at, snapshots.c.id)
    ).all()
    if not candidates:
        return 0
    protected: set[int] = set()
    pointers = connection.execute(
        sa.select(change_events.c.snapshot_id, change_events.c.previous_snapshot_id)
    ).all()
    for snapshot_id, previous_id in pointers:
        protected.add(snapshot_id)
        if previous_id is not None:
            protected.add(previous_id)
    # The rows are in time order, so the last id seen for a (source, day) is that day's last.
    last_of_day: dict[tuple[int, str], int] = {}
    for row in candidates:
        last_of_day[(row.source_id, row.taken_at[:10])] = row.id
    doomed = [
        row.id
        for row in candidates
        if row.id not in protected and row.id != last_of_day[(row.source_id, row.taken_at[:10])]
    ]
    for batch in batched(doomed, _DELETE_BATCH):
        connection.execute(sa.delete(snapshots).where(snapshots.c.id.in_(batch)))
    return len(doomed)


def run_retention(database: Database, *, now: datetime | None = None) -> RetentionResult:
    """Run the three steps once; ``now`` must be timezone aware (default: the current time)."""
    moment = datetime.now(UTC) if now is None else now
    with database.write() as connection:
        days = retention_days(connection)
        events_deleted = delete_old_events(connection, _stamp(moment - timedelta(days=days)))
        thinned = thin_snapshots(connection, _stamp(moment - timedelta(days=THINNING_AFTER_DAYS)))
    with database.write() as connection:
        collected = gc_unreferenced_states(connection)
        result = RetentionResult(
            retention_days=days,
            events_deleted=events_deleted,
            snapshots_thinned=thinned,
            states_removed=collected.removed_count,
            freed_bytes=collected.freed_bytes,
        )
        connection.execute(
            sa.insert(audit_events).values(
                at=_stamp(moment),
                actor=ACTOR_SYSTEM,
                action=ACTION_RETENTION_RUN,
                target=None,
                detail={
                    "retention_days": result.retention_days,
                    "events_deleted": result.events_deleted,
                    "snapshots_thinned": result.snapshots_thinned,
                    "states_removed": result.states_removed,
                    "freed_bytes": result.freed_bytes,
                },
            )
        )
    return result


def seconds_until_next_run(now: datetime) -> float:
    """Seconds from ``now`` (timezone aware) to the next 03:30 UTC, never zero."""
    current = now.astimezone(UTC)
    target = current.replace(hour=RUN_HOUR_UTC, minute=RUN_MINUTE_UTC, second=0, microsecond=0)
    if target <= current:
        target += timedelta(days=1)
    return (target - current).total_seconds()


def _utc_now() -> datetime:
    return datetime.now(UTC)


async def _real_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


class RetentionJob:
    """Runs ``run_retention`` every day at 03:30 UTC, started and stopped with the application.

    A run is made at the next 03:30 after ``start``; an application that is stopped at every
    03:30 never prunes. Every method must be used from the thread of the event loop.
    """

    def __init__(
        self,
        database: Database,
        *,
        now: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = _real_sleep,
    ) -> None:
        self._database = database
        self._now = now
        self._sleep = sleep
        self._task: asyncio.Task[None] | None = None
        self._closed = False

    async def start(self) -> None:
        """Start the daily loop; calling it twice, or after ``stop``, does nothing."""
        if self._task is None and not self._closed:
            self._task = asyncio.get_running_loop().create_task(
                self._loop(), name="driftsniff-retention"
            )

    async def stop(self) -> None:
        """Cancel the loop. A run already inside its worker thread finishes by itself."""
        self._closed = True
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def run_once(self) -> RetentionResult | None:
        """Run retention now in a worker thread; None when it failed (the failure is logged)."""
        moment = self._now()
        try:
            return await asyncio.to_thread(run_retention, self._database, now=moment)
        except Exception as error:
            # Only the class: the text of a database error may hold stored values.
            logger.error("retention run failed: %s", type(error).__name__)
            return None

    async def _loop(self) -> None:
        while True:
            await self._sleep(seconds_until_next_run(self._now()))
            result = await self.run_once()
            if result is not None:
                logger.info(
                    "retention: %d event(s) deleted, %d manifest(s) thinned, %d state(s) removed",
                    result.events_deleted,
                    result.snapshots_thinned,
                    result.states_removed,
                )
