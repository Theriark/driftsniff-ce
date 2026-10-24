"""The data of the Change Replay of a source (WP4a of the interface revision): counts, nothing else.

``ReplayService.load`` counts the real change items of one source per UTC day, resource type and
severity, on one read connection. The route (``GET /sources/{id}/replay`` in
``driftsniff.web.routes_replay``) returns it as JSON; the replay view of the source page draws
it. Nothing is invented: a day, resource type and severity without items has no cell, and a
source without items answers an empty list.

The day of an item is the UTC day of its event (``change_events.created_at``, the same day the
dashboard trend uses). The window is the last ``days`` UTC days up to and including today.

An answer holds counts, ids, severity words and resource type names only. It never reads a before
or after value, a path, an object name, a rationale, a summary or a note, so nothing a source
stored about its configuration can leave through it.
"""

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Final

import sqlalchemy as sa

from driftsniff.db.engine import Database
from driftsniff.db.tables import change_events, change_items, sources
from driftsniff.web.dashboard import day_start, resource_label
from driftsniff.web.templating import SEVERITIES

DEFAULT_DAYS: Final = 30
MAX_DAYS: Final = 90


@dataclass(frozen=True, slots=True)
class ReplayCell:
    """The number of change items of one resource type and severity on one UTC day."""

    day: str
    resource: str
    severity: str
    count: int


@dataclass(frozen=True, slots=True)
class ReplayResource:
    """A resource type that has items in the window, with its readable name and its total."""

    resource: str
    label: str
    count: int


@dataclass(frozen=True, slots=True)
class Replay:
    """The replay of one source: the window, the totals and the non-empty cells.

    ``cells`` are ordered by day, then resource type, then severity (low to critical);
    ``resources`` by total (most first), then name.
    """

    source_id: int
    first_day: str
    last_day: str
    days: int
    severities: tuple[str, ...]
    total: int
    resources: tuple[ReplayResource, ...]
    cells: tuple[ReplayCell, ...]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def clamp_days(days: int) -> int:
    """The window length kept between one day and ``MAX_DAYS``."""
    return max(1, min(days, MAX_DAYS))


class ReplayService:
    """Reads the change replay of a source from the database, on one read connection."""

    def __init__(self, database: Database, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._db = database
        self._clock = clock

    def load(self, source_id: int, days: int = DEFAULT_DAYS) -> Replay | None:
        """The replay of ``source_id`` over the last ``days`` UTC days; None if it is unknown."""
        length = clamp_days(days)
        today = self._clock().astimezone(UTC).date()
        first = today - timedelta(days=length - 1)
        with self._db.read() as connection:
            known = connection.execute(
                sa.select(sources.c.id).where(sources.c.id == source_id)
            ).first()
            if known is None:
                return None
            day_of = sa.func.substr(change_events.c.created_at, 1, 10)
            rows = connection.execute(
                sa.select(day_of, change_items.c.resource, change_items.c.severity, sa.func.count())
                .select_from(change_items.join(change_events))
                .where(change_events.c.source_id == source_id)
                .where(change_events.c.created_at >= day_start(first))
                .where(change_events.c.created_at < day_start(today + timedelta(days=1)))
                .group_by(day_of, change_items.c.resource, change_items.c.severity)
            ).all()
        return build_replay(
            source_id, first, today, [(str(r[0]), str(r[1]), str(r[2]), int(r[3])) for r in rows]
        )


def build_replay(
    source_id: int, first: date, last: date, rows: list[tuple[str, str, str, int]]
) -> Replay:
    """The replay of a window from the grouped rows (day, resource type, severity, count).

    Pure, so the ordering and the totals can be checked on plain values. Rows of the same cell
    are added up; rows with a count below one or a severity the application does not know are
    left out.
    """
    merged: Counter[tuple[str, str, str]] = Counter()
    for day, resource, severity, count in rows:
        if count > 0 and severity in SEVERITIES:
            merged[(day, resource, severity)] += count
    ordered = sorted(
        merged.items(), key=lambda entry: (entry[0][0], entry[0][1], SEVERITIES.index(entry[0][2]))
    )
    cells = tuple(ReplayCell(day, res, severity, n) for (day, res, severity), n in ordered)
    per_resource: Counter[str] = Counter()
    for cell in cells:
        per_resource[cell.resource] += cell.count
    resources = tuple(
        ReplayResource(resource, resource_label(resource), n)
        for resource, n in sorted(per_resource.items(), key=lambda entry: (-entry[1], entry[0]))
    )
    return Replay(
        source_id=source_id,
        first_day=first.isoformat(),
        last_day=last.isoformat(),
        days=(last - first).days + 1,
        severities=SEVERITIES,
        total=sum(per_resource.values()),
        resources=resources,
        cells=cells,
    )
