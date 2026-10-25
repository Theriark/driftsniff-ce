"""The drawing of the Change Replay on the source page (WP4c of the interface revision).

``replay_view`` turns a ``driftsniff.web.replay.Replay`` (the value ``GET /sources/{id}/replay``
returns as JSON) into plain values that ``sources/_replay.html`` prints: a heat map with one row
per resource type and one column per UTC day, the facts above it, the day panel under it and the
table behind its disclosure. It reads no other field than the replay has: the day, the resource
type, its readable name, the severity and the count of each cell, and the window. Nothing is
inferred or invented: a day without items has no cell, and a window without items has no map.

The drawing is two SVGs at one unit per CSS pixel: the resource type names (``label_width``
wide) and the cells (``width`` wide, x from 0), so the names stay in view while the cells scroll
on a narrow screen and every text keeps its size.

The shade of a cell is its share of the busiest cell of the window, in four steps (``heat-1`` to
``heat-4`` of docs/design-colours.json, each at least 3 to 1 against the card). A cell that holds
a critical item also gets a ring, so the meaning never rests on colour alone; the count is
printed in the cell when it fits, and every cell names its day, resource type and counts.

Every cell links to the change list of its source, resource type and day (muted changes
included, so the list holds every item the cell counts). The day cursor starts on the last day
with items; ``static/replay.js`` moves it (play, pause, step, scrub) and the page works without it.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Final
from urllib.parse import urlencode

from driftsniff.web.replay import DEFAULT_DAYS, Replay
from driftsniff.web.templating import SEVERITIES, number

WINDOWS: Final = (7, 30, 90)
LABEL_WIDTH: Final = 128
ROW_HEIGHT: Final = 24
CELL_HEIGHT: Final = 20
AXIS_HEIGHT: Final = 24
LABEL_CHARS: Final = 17
LEVELS: Final = 4
# per window: the width of one day column, the gap between two cells, the digits a cell can print
# and the distance between two day labels on the axis
_LAYOUT: Final = {7: (48, 4, 3, 1), 30: (17, 2, 2, 7), 90: (5, 1, 0, 14)}
_MONTHS: Final = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def window_of(raw: str) -> int:
    """The window a ``replay_days`` value asks for: one of ``WINDOWS``, else the default."""
    text = raw.strip()
    if text.isascii() and text.isdigit() and int(text) in WINDOWS:
        return int(text)
    return DEFAULT_DAYS


def day_label(day: date) -> str:
    """A day as the axis prints it, for example 19 Oct."""
    return f"{day.day} {_MONTHS[day.month - 1]}"


def long_day_label(day: date) -> str:
    """A day with its year, for example 19 Oct 2026."""
    return f"{day_label(day)} {day.year}"


def items_text(count: int) -> str:
    return f"{number(count)} change {'item' if count == 1 else 'items'}"


def severity_text(counts: tuple[int, ...]) -> str:
    """The non-zero severity counts, most severe first, for example 1 critical, 2 medium."""
    most_first = range(len(SEVERITIES) - 1, -1, -1)
    return ", ".join(f"{counts[i]} {SEVERITIES[i]}" for i in most_first if counts[i])


def changes_href(source_id: int, first: str, last: str, **extra: str) -> str:
    """The change list of a source between two days, muted changes included."""
    query = {"source": str(source_id), **extra, "from": first, "to": last, "muted": "1"}
    return "/changes?" + urlencode(query)


def level_of(count: int, busiest: int) -> int:
    """The shade step of a cell: its share of the busiest cell, rounded up to a quarter."""
    if busiest <= 0 or count <= 0:
        return 0
    return max(1, min(LEVELS, -(-count * LEVELS // busiest)))


@dataclass(frozen=True, slots=True)
class WindowLink:
    days: int
    label: str
    href: str
    current: bool


@dataclass(frozen=True, slots=True)
class ReplayRow:
    """One resource type: its row of the map and the label beside it."""

    resource: str
    label: str
    short_label: str
    count: int
    y: int
    label_y: int


@dataclass(frozen=True, slots=True)
class ReplayColumn:
    """One UTC day of the window; ``axis`` days carry a label under the map."""

    index: int
    day: str
    label: str
    long_label: str
    x: int
    center: float
    axis: bool
    anchor: str
    total: int


@dataclass(frozen=True, slots=True)
class ReplayCellView:
    """One non-empty cell: a resource type on a day, its counts per severity and its link."""

    day_index: int
    day: str
    row: int
    resource_label: str
    x: float
    y: int
    width: float
    count: int
    counts: tuple[int, ...]
    level: int
    critical: bool
    text: str
    text_x: float
    text_y: int
    title: str
    href: str

    @property
    def counts_attr(self) -> str:
        return " ".join(str(n) for n in self.counts)


@dataclass(frozen=True, slots=True)
class DayLine:
    label: str
    count: int
    counts: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DaySummary:
    """What the day panel says about the day under the cursor."""

    long_label: str
    total: int
    total_text: str
    lines: tuple[DayLine, ...]
    href: str
    link_text: str


@dataclass(frozen=True, slots=True)
class Fact:
    term: str
    value: str
    detail: str
    href: str
    link_text: str


@dataclass(frozen=True, slots=True)
class TableRow:
    day: str
    resource_label: str
    counts: tuple[int, ...]
    count: int
    href: str


@dataclass(frozen=True, slots=True)
class ReplayView:
    """Everything the replay section prints for one source and window."""

    source_id: int
    days: int
    first_day: str
    last_day: str
    window_text: str
    windows: tuple[WindowLink, ...]
    total: int
    description: str
    width: int
    height: int
    label_width: int
    grid_height: int
    track_width: int
    pitch: int
    rows: tuple[ReplayRow, ...]
    columns: tuple[ReplayColumn, ...]
    cells: tuple[ReplayCellView, ...]
    week_lines: tuple[int, ...]
    axis_y: int
    cursor_index: int
    cursor_x: int
    cursor_height: int
    summary: DaySummary | None
    facts: tuple[Fact, ...]
    table: tuple[TableRow, ...]

    @property
    def empty(self) -> bool:
        return self.total == 0


def _short(label: str) -> str:
    return label if len(label) <= LABEL_CHARS else label[: LABEL_CHARS - 1].rstrip() + "…"


def day_summary(source_id: int, day: date, cells: list[ReplayCellView]) -> DaySummary:
    """The day panel of ``day`` from the cells of that day (none: a day without items)."""
    lines = tuple(
        DayLine(cell.resource_label, cell.count, cell.counts)
        for cell in sorted(cells, key=lambda c: c.row)
    )
    total = sum(line.count for line in lines)
    kinds = len(lines)
    text = (
        f"{items_text(total)} in {kinds} resource {'type' if kinds == 1 else 'types'}"
        if total
        else "No change items on this day."
    )
    iso = day.isoformat()
    return DaySummary(
        long_label=long_day_label(day),
        total=total,
        total_text=text,
        lines=lines,
        href=changes_href(source_id, iso, iso, sort="oldest"),
        link_text=f"Open the changes of {day_label(day)}",
    )


def replay_view(replay: Replay) -> ReplayView:
    """The drawing of a replay: rows, columns, cells, the cursor, the facts and the table."""
    days = min(_LAYOUT, key=lambda d: abs(d - replay.days))
    pitch, gap, digits, step = _LAYOUT[days]
    first = date.fromisoformat(replay.first_day)
    last = date.fromisoformat(replay.last_day)
    span = (last - first).days + 1
    source_id = replay.source_id

    per_cell: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0] * len(SEVERITIES))
    for item in replay.cells:
        per_cell[(item.day, item.resource)][SEVERITIES.index(item.severity)] += item.count
    busiest = max((sum(c) for c in per_cell.values()), default=0)
    row_of = {resource.resource: index for index, resource in enumerate(replay.resources)}
    label_of = {resource.resource: resource.label for resource in replay.resources}

    rows = tuple(
        ReplayRow(
            resource=resource.resource,
            label=resource.label,
            short_label=_short(resource.label),
            count=resource.count,
            y=index * ROW_HEIGHT,
            label_y=index * ROW_HEIGHT + 15,
        )
        for index, resource in enumerate(replay.resources)
    )
    day_totals: dict[str, int] = defaultdict(int)
    for (day, _), counts in per_cell.items():
        day_totals[day] += sum(counts)
    columns: list[ReplayColumn] = []
    for index in range(span):
        moment = first + timedelta(days=index)
        from_end = span - 1 - index
        columns.append(
            ReplayColumn(
                index=index,
                day=moment.isoformat(),
                label=day_label(moment),
                long_label=long_day_label(moment),
                x=index * pitch,
                center=index * pitch + pitch / 2,
                axis=from_end % step == 0,
                anchor="end" if from_end == 0 and step > 1 else "middle",
                total=day_totals.get(moment.isoformat(), 0),
            )
        )

    cells: list[ReplayCellView] = []
    ordered = sorted(per_cell.items(), key=lambda entry: (entry[0][0], row_of[entry[0][1]]))
    for (day, resource), counts in ordered:
        index = (date.fromisoformat(day) - first).days
        if not 0 <= index < span:
            continue
        row = row_of[resource]
        count = sum(counts)
        level = level_of(count, busiest)
        text = str(count) if digits and len(str(count)) <= digits else ""
        x = index * pitch + gap / 2
        when = long_day_label(date.fromisoformat(day))
        name = label_of[resource]
        flags = severity_text(tuple(counts))
        cells.append(
            ReplayCellView(
                day_index=index,
                day=day,
                row=row,
                resource_label=name,
                x=x,
                y=row * ROW_HEIGHT,
                width=pitch - gap,
                count=count,
                counts=tuple(counts),
                level=level,
                critical=counts[-1] > 0,
                text=text,
                text_x=x + (pitch - gap) / 2,
                text_y=row * ROW_HEIGHT + 14,
                title=f"{when}, {name}: {items_text(count)} ({flags})",
                href=changes_href(source_id, day, day, resource=resource),
            )
        )

    grid_height = len(rows) * ROW_HEIGHT
    cursor_index = max((c.day_index for c in cells), default=span - 1)
    cursor_day = first + timedelta(days=cursor_index)
    summary = (
        day_summary(source_id, cursor_day, [c for c in cells if c.day_index == cursor_index])
        if cells
        else None
    )
    window_text = f"{long_day_label(first)} to {long_day_label(last)}, UTC"
    critical = sum(c.counts[-1] for c in cells)
    facts: list[Fact] = []
    description = f"No change items from {window_text}."
    if cells:
        peak = max(columns, key=lambda c: (c.total, -c.index))
        opening = columns[min(c.day_index for c in cells)]
        facts = [
            Fact(
                "Busiest day",
                peak.long_label,
                items_text(peak.total),
                changes_href(source_id, peak.day, peak.day, sort="oldest"),
                f"Changes of {peak.label}, oldest first",
            ),
            Fact(
                "First change in the window",
                opening.long_label,
                items_text(opening.total),
                changes_href(source_id, opening.day, opening.day, sort="oldest"),
                f"Changes of {opening.label}, oldest first",
            ),
            Fact(
                "Critical items",
                number(critical),
                "in the window" if critical else "none in the window",
                changes_href(source_id, replay.first_day, replay.last_day, severity="critical"),
                "Critical changes of the window",
            ),
        ]
        kinds = len(rows)
        description = (
            f"{items_text(replay.total)} in {kinds} resource {'type' if kinds == 1 else 'types'}"
            f" from {window_text}. Busiest day {peak.long_label} with {items_text(peak.total)}."
            f" {number(critical)} critical {'item' if critical == 1 else 'items'}."
        )
    week_lines = tuple(
        index * pitch for index in range(1, span) if step > 1 and (span - index) % 7 == 0
    )
    table = tuple(
        TableRow(
            day=long_day_label(date.fromisoformat(cell.day)),
            resource_label=cell.resource_label,
            counts=cell.counts,
            count=cell.count,
            href=cell.href,
        )
        for cell in sorted(cells, key=lambda c: (-c.day_index, c.row))
    )
    windows = tuple(
        WindowLink(n, f"{n} days", f"/sources/{source_id}?replay_days={n}#replay", n == days)
        for n in WINDOWS
    )
    return ReplayView(
        source_id=source_id,
        days=days,
        first_day=replay.first_day,
        last_day=replay.last_day,
        window_text=window_text,
        windows=windows,
        total=replay.total,
        description=description,
        width=span * pitch,
        height=grid_height + AXIS_HEIGHT,
        label_width=LABEL_WIDTH,
        grid_height=grid_height,
        track_width=span * pitch,
        pitch=pitch,
        rows=rows,
        columns=tuple(columns),
        cells=tuple(cells),
        week_lines=week_lines,
        axis_y=grid_height + 16,
        cursor_index=cursor_index,
        cursor_x=cursor_index * pitch,
        cursor_height=max(0, grid_height - (ROW_HEIGHT - CELL_HEIGHT)),
        summary=summary,
        facts=tuple(facts),
        table=table,
    )
