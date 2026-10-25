"""The dashboard (P10-T4): every figure, list and strip of the start page, from SQL.

``DashboardService.load`` runs the queries of this module on one read connection and returns a
:class:`Dashboard`; the route (``GET /`` in ``driftsniff.web.routes_ui``) hands it to
``dashboard.html``, which prints and never computes. The geometry of the posture ring and the
trend chart is computed here too, so the template carries no arithmetic and the tests can check
it on plain values.

What the dashboard shows, top to bottom (dev work plan part B, section 18, P10-T4): four stat
cards; the posture ring of open change items by severity (counts only, never a score); the
needs-attention list (open critical and high events, then the sources that are failing, partial,
stale, unsupported, insecure, never checked or whose credential is expiring), with a sentence
that matches the state of the sources when the list is empty; one drift line per source; the
30 day trend of change items per day stacked by severity, with its table (or a designed empty
strip when there were none); the breakdown by source and by resource type; and the activity
timeline (events, acknowledgements, notes, runs and audit events, newest first, 20 entries: the
newest 8 as rows, the rest behind a disclosure, every target named and linked, never a raw id).

Nothing here reads a before or after value, a credential, a note body or an acknowledgement
comment: the dashboard shows summaries, counts, names, class words and times only.
"""

import math
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.collectors.tls import OPTION_INSECURE
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    acknowledgements,
    audit_events,
    change_events,
    change_items,
    notes,
    runs,
    sources,
    users,
)
from driftsniff.sources.service import interval_of
from driftsniff.web.templating import SEVERITIES, SEVERITY_LABELS, number

TREND_DAYS: Final = 30
DRIFT_DAYS: Final = 30
# One mark per check up to this many checks; a busier source gets one mark per UTC day.
DRIFT_MAX_CHECKS: Final = 31
ACTIVITY_LIMIT: Final = 20
# The newest entries shown as rows; the rest of the 20 sit behind a disclosure.
ACTIVITY_ROWS: Final = 8
ATTENTION_EVENTS: Final = 8
BREAKDOWN_ROWS: Final = 8
# A skipped run is not a check: only these statuses count as one.
CHECK_STATUSES: Final = ("ok", "partial", "failed")
# A source is stale when nothing has been checked for this many intervals.
STALE_INTERVALS: Final = 3
# The storage card compares the database file with this size (the plan names no setting, so
# the simplest option is a constant; docs/web-interface.md section 9 records it).
STORAGE_WARNING_BYTES: Final = 2 * 1024 * 1024 * 1024
RING_RADIUS: Final = 60
RING_CIRCUMFERENCE: Final = 2 * math.pi * RING_RADIUS
# Trend chart geometry (a 600 by 170 viewBox, drawn no narrower than 600 px).
CHART_LEFT: Final = 40.0
CHART_RIGHT: Final = 596.0
CHART_TOP: Final = 30.0
CHART_BOTTOM: Final = 150.0
CHART_BAR_WIDTH: Final = 12.0
# The empty trend strip: one 2 unit tick per day across a 600 unit wide drawing.
EMPTY_WIDTH: Final = 600.0
EMPTY_TICK_WIDTH: Final = 2.0

SOURCE_TYPE_LABELS: Final = {"unifi": "UniFi Network", "xo": "Xen Orchestra", "push": "Push source"}
# Source states a later task may store in sources.state; anything else counts as plain.
STATE_UNSUPPORTED: Final = "unsupported"
STATE_TOKEN_EXPIRING: Final = "token_expiring"  # noqa: S105 (a state word, not a value)
STATUS_TEXT: Final = {
    "ok": "Healthy",
    "failing": "Failing",
    "partial": "Partial",
    "stale": "Stale",
    "unsupported": "Unsupported",
    "warn": "Credential expiring",
    "open": "No check yet",
}
# A push source is never checked: its sender pushes. Its words where they differ from a pull's.
PUSH_SOURCE: Final = "push"
PUSH_STATUS_TEXT: Final = {"open": "Nothing pushed yet"}
PROBLEM_KINDS: Final = frozenset({"failing", "partial", "stale", "unsupported", "warn"})

SEVERITY_SHARE: Final = {
    "critical": "needs a decision now",
    "high": "review this week",
    "medium": "worth a look",
    "low": "renames and cosmetic",
}

# Readable labels of the resource types of both type tables (our own table, nothing ported).
RESOURCE_LABELS: Final = {
    "unifi-sites": "Sites",
    "unifi-site-settings": "Site settings",
    "unifi-networks": "Networks",
    "unifi-wifi-broadcasts": "WiFi broadcasts",
    "unifi-firewall-zones": "Firewall zones",
    "unifi-firewall-policies": "Firewall policies",
    "unifi-acl-rules": "ACL rules",
    "unifi-dns-policies": "DNS policies",
    "unifi-traffic-matching-lists": "Traffic matching lists",
    "unifi-wans": "WANs",
    "unifi-vpn-site-to-site-tunnels": "Site-to-site VPN tunnels",
    "unifi-vpn-servers": "VPN servers",
    "unifi-radius-profiles": "RADIUS profiles",
    "unifi-device-tags": "Device tags",
    "unifi-devices": "Devices",
    "vms": "Virtual machines",
    "vm-templates": "VM templates",
    "hosts": "Hosts",
    "pools": "Pools",
    "networks": "Networks",
    "pifs": "Physical interfaces",
    "pbds": "Storage connections",
    "srs": "Storage repositories",
    "vifs": "Virtual interfaces",
    "vbds": "Virtual block devices",
    "vdis": "Virtual disks",
    "backup-jobs": "Backup jobs",
    "schedules": "Schedules",
    "backup-repositories": "Backup repositories",
    "proxies": "Proxies",
    "servers": "Servers",
    "users": "Users",
    "groups": "Groups",
    "acl-roles": "ACL roles",
    "acl-privileges": "ACL privileges",
}

# Audit actions as the timeline words them: actor, verb phrase, then the target.
AUDIT_VERBS: Final = {
    "setup.completed": "completed the first-run setup",
    "user.created": "created user",
    "user.locked": "locked user",
    "user.disabled": "disabled user",
    "user.enabled": "enabled user",
    "token.created": "created API token",
    "token.revoked": "revoked API token",
    "source.create": "added source",
    "source.update": "updated source",
    "source.enable": "enabled source",
    "source.disable": "disabled source",
    "source.delete": "deleted source",
    "source.push_key": "made a new push key for source",
    "source.allow_plain_http": "allowed plain http on source",
    "source.tls_insecure_enabled": "switched certificate checks off on source",
    "notification.channel_saved": "saved the notification channel",
    "notification.channel_removed": "removed the notification channel",
    "notification.test": "sent a test notification",
    "notification.signing_key_shown": "viewed the webhook signing key",
    "retention.run": "ran the retention job",
    "user.credentials_reset": "reset the credentials of user",
    "mute.added": "muted a path of",
    "mute.removed": "removed a mute of",
}
# Audit actions that are noise on a dashboard (every refused token call writes one), and the two
# that repeat an acknowledgement or a note row the timeline already lists with its source.
AUDIT_SKIPPED: Final = frozenset(
    {
        "token.rejected",
        "token.forbidden",
        "enrichment.added",
        "change.acknowledged",
        "change.note_added",
    }
)
# Where a mute entry links: the muted paths section of the changes list.
MUTES_HREF: Final = "/changes#mutes-h"
URGENT_HREF: Final = "/changes?status=open&severity=critical&severity=high"


# ---- what the template prints -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Stat:
    """One stat card: the arguments of the ``metric_card`` macro.

    ``delta_tone`` says how the line reads (down good, up worth a look, alert); ``trend`` is the
    direction of a count against the previous period (up, down or flat), empty when the line is
    not a comparison. An empty ``href`` draws the card without a link.
    """

    label: str
    value: str
    href: str
    unit: str = ""
    delta: str = ""
    delta_tone: str = ""
    trend: str = ""
    spark: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class SeverityCount:
    severity: str
    label: str
    count: int
    share: str
    href: str


@dataclass(frozen=True, slots=True)
class RingSegment:
    """One arc of the posture ring: the ``stroke-dasharray`` and ``stroke-dashoffset``."""

    severity: str
    dasharray: str
    dashoffset: str


@dataclass(frozen=True, slots=True)
class Posture:
    total: int
    counts: tuple[SeverityCount, ...]
    segments: tuple[RingSegment, ...]
    description: str


@dataclass(frozen=True, slots=True)
class Attention:
    """One row of the needs-attention list: a badge, a title that links, a line, an action."""

    badge: str  # severity or status
    badge_value: str  # a severity word, or a status badge kind
    badge_text: str
    title: str
    href: str
    where: str
    action_label: str
    action_href: str
    critical: bool = False


@dataclass(frozen=True, slots=True)
class DriftRow:
    """One drift line: the arguments of the ``drift_line`` macro and whether it is per day."""

    name: str
    href: str
    meta: str
    id_prefix: str
    checks: tuple[dict[str, str], ...]
    per_day: bool


@dataclass(frozen=True, slots=True)
class TrendDay:
    label: str
    low: int
    medium: int
    high: int
    critical: int

    @property
    def total(self) -> int:
        return self.low + self.medium + self.high + self.critical


@dataclass(frozen=True, slots=True)
class TrendBar:
    severity: str
    x: str
    y: str
    width: str
    height: str


@dataclass(frozen=True, slots=True)
class GridLine:
    y: str
    label_y: str
    label: str


@dataclass(frozen=True, slots=True)
class Trend:
    days: tuple[TrendDay, ...]
    bars: tuple[TrendBar, ...]
    grid: tuple[GridLine, ...]
    total: int
    description: str
    # The x of one faint tick per day, for the empty strip drawn when ``total`` is zero.
    ticks: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BarRow:
    label: str
    href: str
    count: int
    width_class: str


@dataclass(frozen=True, slots=True)
class Activity:
    """One timeline entry: text, then a link, then text; ``when`` is the time of the entry."""

    dot: str  # alert, event, run or empty
    text: str
    link_label: str
    href: str
    tail: str
    when: datetime


@dataclass(frozen=True, slots=True)
class SourceHealth:
    """What the dashboard knows about one source."""

    id: int
    name: str
    type: str
    enabled: bool
    kind: str  # ok, failing, partial, stale, unsupported, warn, open (no check yet or disabled)
    reason: str
    insecure: bool
    version: str | None
    href: str
    # When the newest finished check ended, failed or not; a failed run leaves last_checked_at.
    last_attempt: datetime | None = None

    @property
    def status_text(self) -> str:
        """The status badge text, in push words for a push source."""
        return status_text(self.kind, self.type)


@dataclass(frozen=True, slots=True)
class Dashboard:
    now: datetime
    has_sources: bool
    stats: tuple[Stat, ...] = ()
    posture: Posture | None = None
    attention: tuple[Attention, ...] = ()
    driftlines: tuple[DriftRow, ...] = ()
    trend: Trend | None = None
    by_source: tuple[BarRow, ...] = ()
    by_resource: tuple[BarRow, ...] = ()
    activity: tuple[Activity, ...] = ()
    sources: tuple[SourceHealth, ...] = ()
    # Open critical and high changes beyond the ones the attention list shows.
    attention_more: int = 0
    # The sentence of an empty attention list, true to the state of the sources.
    attention_empty: str = ""

    @property
    def activity_rows(self) -> tuple[Activity, ...]:
        """The newest timeline entries, shown as rows."""
        return self.activity[:ACTIVITY_ROWS]

    @property
    def activity_earlier(self) -> tuple[Activity, ...]:
        """The older timeline entries, behind the disclosure."""
        return self.activity[ACTIVITY_ROWS:]


# ---- small pure helpers ------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(UTC)


def stamp(moment: datetime) -> str:
    """The stored form of a time: ISO 8601 text, UTC, ending in Z."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def day_start(day: date) -> str:
    """The stored form of midnight UTC at the start of ``day``."""
    return f"{day.isoformat()}T00:00:00Z"


def parse_stamp(text: str) -> datetime:
    """A stored time back as an aware datetime."""
    parsed = datetime.fromisoformat(text)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def resource_label(resource: str) -> str:
    """The readable name of a resource type; an unknown one is spelled out from its name."""
    known = RESOURCE_LABELS.get(resource)
    if known is not None:
        return known
    words = resource.removeprefix("unifi-").replace("-", " ").replace("_", " ").strip()
    return words[:1].upper() + words[1:] if words else resource


def source_type_label(source_type: str) -> str:
    return SOURCE_TYPE_LABELS.get(source_type, source_type)


def status_text(kind: str, source_type: str) -> str:
    """The badge text of a health kind; a push source says pushed where a pull says checked."""
    if source_type == PUSH_SOURCE:
        return PUSH_STATUS_TEXT.get(kind, STATUS_TEXT[kind])
    return STATUS_TEXT[kind]


def day_label(day: date, today: date) -> str:
    """The word for a day: today, 1 day ago or N days ago."""
    ago = (today - day).days
    if ago <= 0:
        return "today"
    return "1 day ago" if ago == 1 else f"{ago} days ago"


def window_text(start: datetime, end: datetime, now: datetime) -> str:
    """The detection window as words: between 06:40 and 07:10 UTC today, or with the dates."""
    if start.date() == end.date() == now.date():
        return f"between {start:%H:%M} and {end:%H:%M} UTC today"
    if start.date() == end.date():
        return f"between {start:%H:%M} and {end:%H:%M} UTC on {end:%Y-%m-%d}"
    return f"between {start:%Y-%m-%d %H:%M} and {end:%Y-%m-%d %H:%M} UTC"


def delta_text(current: int, previous: int) -> str:
    """The difference as words: 5 fewer than, 3 more than, or the same as the previous 7 days."""
    if current == previous:
        return "the same as the previous 7 days"
    difference = abs(current - previous)
    word = "more" if current > previous else "fewer"
    return f"{number(difference)} {word} than the previous 7 days"


def delta_tone(current: int, previous: int) -> str:
    """The tone of a count of new changes: fewer is good (down), more is worth a look (up)."""
    if current == previous:
        return ""
    return "up" if current > previous else "down"


def silent_text(seconds: float) -> str:
    """How long a source has been silent, in minutes, hours or days."""
    if seconds < 7200:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 48 * 3600:
        return f"{seconds / 3600:.0f} hours"
    return f"{seconds / 86400:.0f} days"


def width_class(count: int, largest: int) -> str:
    """The bar width as one of the ten classes of app.css (w-10 to w-100), w-0 for nothing."""
    if count <= 0 or largest <= 0:
        return "w-0"
    return f"w-{max(1, math.ceil(10 * count / largest)) * 10}"


def ring_segments(counts: Mapping[str, int]) -> tuple[RingSegment, ...]:
    """The arcs of the posture ring, low first, clockwise from the top; none when empty."""
    total = sum(counts.get(severity, 0) for severity in SEVERITIES)
    if total <= 0:
        return ()
    segments: list[RingSegment] = []
    offset = 0.0
    for severity in SEVERITIES:
        count = counts.get(severity, 0)
        if count <= 0:
            continue
        length = RING_CIRCUMFERENCE * count / total
        dasharray = f"{length:.1f} {RING_CIRCUMFERENCE - length:.1f}"
        segments.append(RingSegment(severity, dasharray, f"-{offset:.1f}"))
        offset += length
    return tuple(segments)


def chart_top(largest: int) -> int:
    """The value of the top grid line: a multiple of three, never under three."""
    return max(3, math.ceil(largest / 3) * 3)


def trend_geometry(days: Sequence[TrendDay]) -> tuple[tuple[TrendBar, ...], tuple[GridLine, ...]]:
    """The bars and grid lines of the trend chart for ``days`` (oldest first)."""
    largest = max((day.total for day in days), default=0)
    top = chart_top(largest)
    height = CHART_BOTTOM - CHART_TOP
    grid: list[GridLine] = []
    for step in (3, 2, 1):
        y = CHART_BOTTOM - height * step / 3
        grid.append(GridLine(f"{y:.1f}", f"{y + 4:.1f}", str(top * step // 3)))
    if not days:
        return (), tuple(grid)
    bars: list[TrendBar] = []
    step_x = (CHART_RIGHT - CHART_LEFT) / len(days)
    for index, day in enumerate(days):
        x = CHART_LEFT + step_x * index + (step_x - CHART_BAR_WIDTH) / 2
        bottom = CHART_BOTTOM
        for severity in SEVERITIES:
            count = int(getattr(day, severity))
            if count <= 0:
                continue
            bar_height = height * count / top
            bottom -= bar_height
            width = f"{CHART_BAR_WIDTH:g}"
            bars.append(TrendBar(severity, f"{x:.1f}", f"{bottom:.1f}", width, f"{bar_height:.1f}"))
    return tuple(bars), tuple(grid)


def empty_ticks(count: int) -> tuple[str, ...]:
    """The x of one tick per day, centred in its share of the empty strip; none for no day."""
    if count <= 0:
        return ()
    step = EMPTY_WIDTH / count
    return tuple(f"{step * index + (step - EMPTY_TICK_WIDTH) / 2:.1f}" for index in range(count))


def attention_empty_text(health: Sequence[SourceHealth]) -> str:
    """What an empty needs-attention list says, true to the sources behind the stat card.

    The list is empty only when no open critical or high change waits and no enabled source is
    unwell (every unwell enabled source has a row), so what is left to say is about the sources
    that are switched off.
    """
    disabled = sum(1 for source in health if not source.enabled)
    if health and disabled == len(health):
        return (
            "Nothing is being checked: every source is disabled. "
            "Enable a source on its page and its changes appear here."
        )
    if disabled:
        noun = "source is" if disabled == 1 else "sources are"
        return (
            "Nothing waits for a decision: no open critical or high change, and every enabled "
            f"source is healthy. {number(disabled)} disabled {noun} not checked."
        )
    return (
        "Nothing waits for a decision: no open critical or high change, "
        "and every source is healthy."
    )


def storage_bytes(path: Path) -> int:
    """The size of the database file and its write-ahead log, zero when they do not exist."""
    total = 0
    for candidate in (path, path.with_name(path.name + "-wal")):
        try:
            total += candidate.stat().st_size
        except OSError:
            continue
    return total


def storage_stat(used: int, warning: int = STORAGE_WARNING_BYTES) -> Stat:
    """The storage card: megabytes used against the warning size.

    No link yet: the About section it points to lives on /settings, which comes with P10-T8.
    """
    megabytes = used / (1024 * 1024)
    value = f"{megabytes:.1f}" if megabytes < 10 else number(round(megabytes))
    share = 0 if warning <= 0 else round(100 * used / warning)
    warning_text = f"{warning / (1024 * 1024 * 1024):g} GB"
    tone = "alert" if share >= 100 else ("up" if share >= 80 else "")
    return Stat(
        "Storage used",
        value,
        "",
        unit="MB",
        delta=f"{share}% of the {warning_text} warning size",
        delta_tone=tone,
    )


# ---- source health -----------------------------------------------------------------------


def _source_health(
    row: Any, last_run: Any | None, failed_streak: int, now: datetime
) -> SourceHealth:
    """The health of one source from its row, its last finished run and the time."""
    options = row.options if isinstance(row.options, Mapping) else {}
    insecure = bool(options.get(OPTION_INSECURE, False))
    version = None if row.controller_version is None else str(row.controller_version)
    state = str(row.state)
    push = str(row.type) == PUSH_SOURCE
    check, checks = ("push", "pushes") if push else ("check", "checks")
    kind, reason = "ok", f"Last {check} found no problem"
    if not row.enabled:
        kind, reason = "open", "Disabled"
    elif state == STATE_UNSUPPORTED:
        kind, reason = "unsupported", "The controller version is below the supported floor"
    elif last_run is not None and last_run.status == "failed":
        streak = f"{check} failed"
        if failed_streak > 1:
            streak = f"{failed_streak} {checks} failed in a row"
        detail = last_run.error_summary or last_run.error_class or "no detail recorded"
        kind, reason = "failing", f"{streak}: {detail}"
    elif row.last_checked_at is None:
        kind, reason = "open", status_text("open", str(row.type))
    else:
        interval = interval_of(options)
        silent = (now - parse_stamp(str(row.last_checked_at))).total_seconds()
        if silent > STALE_INTERVALS * interval:
            ago = silent_text(silent)
            silence = f"nothing pushed for {ago}" if push else f"no check for {ago}"
            kind, reason = "stale", f"{silence}, expected every {interval} seconds"
        elif last_run is not None and last_run.status == "partial":
            detail = last_run.error_summary or last_run.error_class or "a resource was not read"
            kind, reason = "partial", f"last {check} was partial: {detail}"
        elif state == STATE_TOKEN_EXPIRING:
            kind, reason = "warn", "The credential expires within 14 days"
    return SourceHealth(
        id=int(row.id),
        name=str(row.name),
        type=str(row.type),
        enabled=bool(row.enabled),
        kind=kind,
        reason=reason,
        insecure=insecure,
        version=version,
        href=f"/sources/{int(row.id)}",
        last_attempt=last_attempt(row.last_checked_at, last_run),
    )


def last_attempt(last_checked_at: object, last_run: Any | None) -> datetime | None:
    """The newer of the end of the last finished run and ``last_checked_at``, or None."""
    stamps = [parse_stamp(str(last_checked_at))] if last_checked_at is not None else []
    if last_run is not None and last_run.finished_at is not None:
        stamps.append(parse_stamp(str(last_run.finished_at)))
    return max(stamps, default=None)


def _source_attention(health: SourceHealth) -> list[Attention]:
    """The attention rows of one source: its problem or first check, and its insecure TLS flag."""
    rows: list[Attention] = []
    if health.kind == "open" and health.enabled:
        push = health.type == PUSH_SOURCE
        rows.append(
            Attention(
                "status",
                "open",
                health.status_text,
                f"{health.name}: {health.status_text.lower()}",
                health.href,
                (
                    "Waiting for its sender's first push; changes appear after it"
                    if push
                    else "Waiting for its first check; changes appear after it"
                ),
                "Open source",
                health.href,
            )
        )
    if health.kind in PROBLEM_KINDS:
        expiring = health.kind == "warn"
        where = source_type_label(health.type)
        if health.version:
            where += f" {health.version}"
        rows.append(
            Attention(
                "status",
                health.kind,
                health.status_text,
                f"{health.name}: {health.reason}",
                health.href,
                where,
                "Renew credential" if expiring else "Open source",
                health.href + ("#credential" if expiring else ""),
            )
        )
    if health.insecure:
        rows.append(
            Attention(
                "status",
                "insecure",
                "Insecure TLS",
                f"{health.name} runs with certificate checks off",
                health.href,
                "Every check trusts whatever certificate the controller presents",
                "Fix TLS",
                health.href + "#tls",
            )
        )
    return rows


def source_overview(
    connection: Connection, source_rows: Sequence[Any], now: datetime
) -> tuple[tuple[SourceHealth, ...], tuple[DriftRow, ...]]:
    """The health and the drift line of each source row, by the rules of the dashboard.

    The sources pages (``driftsniff.web.source_pages``) use it so that a source has the same
    status and the same strip there as on the start page. A row needs the columns id, name, type,
    enabled, last_checked_at, controller_version, state and options.
    """
    since = day_start(now.date() - timedelta(days=DRIFT_DAYS))
    last_runs = _last_runs(connection)
    runs_30 = _runs_since(connection, since)
    events_30 = _events_since(connection, since)
    streaks = _failed_streaks(runs_30)
    health = tuple(
        _source_health(row, last_runs.get(int(row.id)), streaks.get(int(row.id), 0), now)
        for row in source_rows
    )
    return health, _driftlines(health, runs_30, events_30, now)


# ---- the service -------------------------------------------------------------------------


class DashboardService:
    """Reads everything the start page shows from the database, on one read connection."""

    def __init__(self, database: Database, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._db = database
        self._clock = clock

    def load(self) -> Dashboard:
        """The dashboard as of now; an installation without sources gets the empty state."""
        now = self._clock()
        today = now.date()
        with self._db.read() as connection:
            source_rows = connection.execute(
                sa.select(
                    sources.c.id,
                    sources.c.name,
                    sources.c.type,
                    sources.c.enabled,
                    sources.c.last_checked_at,
                    sources.c.controller_version,
                    sources.c.state,
                    sources.c.options,
                ).order_by(sources.c.name)
            ).all()
            if not source_rows:
                return Dashboard(now=now, has_sources=False)
            names = {int(row.id): str(row.name) for row in source_rows}
            open_events = _open_events_by_severity(connection)
            open_items = _open_items_by_severity(connection)
            recent = _events_per_day(connection, day_start(today - timedelta(days=13)))
            last_runs = _last_runs(connection)
            runs_30 = _runs_since(connection, day_start(today - timedelta(days=DRIFT_DAYS)))
            events_30 = _events_since(connection, day_start(today - timedelta(days=DRIFT_DAYS)))
            streaks = _failed_streaks(runs_30)
            health = tuple(
                _source_health(row, last_runs.get(int(row.id)), streaks.get(int(row.id), 0), now)
                for row in source_rows
            )
            attention = _attention(connection, names, health, now)
            shown_events = sum(1 for row in attention if row.badge == "severity")
            urgent_open = open_events.get("critical", 0) + open_events.get("high", 0)
            trend = _trend(connection, now)
            by_source, by_resource = _breakdowns(connection, names)
            activity = _activity(connection, names)
        return Dashboard(
            now=now,
            has_sources=True,
            stats=_stats(open_events, recent, health, now, storage_bytes(self._db.path)),
            posture=_posture(open_items),
            attention=attention,
            driftlines=_driftlines(health, runs_30, events_30, now),
            trend=trend,
            by_source=by_source,
            by_resource=by_resource,
            activity=activity,
            sources=health,
            attention_more=max(0, urgent_open - shown_events),
            attention_empty=attention_empty_text(health),
        )


# ---- queries and the shaping of their rows ------------------------------------------------


def _open_events_by_severity(connection: Connection) -> dict[str, int]:
    rows = connection.execute(
        sa.select(change_events.c.max_severity, sa.func.count())
        .where(change_events.c.status == "open")
        .group_by(change_events.c.max_severity)
    ).all()
    return {str(row[0]): int(row[1]) for row in rows}


def _items_of_events() -> sa.FromClause:
    return change_items.join(change_events, change_items.c.event_id == change_events.c.id)


def _open_items_by_severity(connection: Connection) -> dict[str, int]:
    rows = connection.execute(
        sa.select(change_items.c.severity, sa.func.count())
        .select_from(_items_of_events())
        .where(change_events.c.status == "open")
        .group_by(change_items.c.severity)
    ).all()
    return {str(row[0]): int(row[1]) for row in rows}


def _events_per_day(connection: Connection, since: str) -> dict[date, Counter[str]]:
    """Events created since ``since``: per UTC day, a count per highest severity."""
    day_of = sa.func.substr(change_events.c.created_at, 1, 10)
    rows = connection.execute(
        sa.select(day_of, change_events.c.max_severity, sa.func.count())
        .where(change_events.c.created_at >= since)
        .group_by(day_of, change_events.c.max_severity)
    ).all()
    result: dict[date, Counter[str]] = defaultdict(Counter)
    for row in rows:
        result[date.fromisoformat(str(row[0]))][str(row[1])] += int(row[2])
    return result


def _last_runs(connection: Connection) -> dict[int, Any]:
    """The last finished check of every source, by source id (a skipped run is not a check)."""
    newest = (
        sa.select(sa.func.max(runs.c.id))
        .where(runs.c.status.in_(CHECK_STATUSES))
        .group_by(runs.c.source_id)
        .scalar_subquery()
    )
    rows = connection.execute(
        sa.select(
            runs.c.source_id,
            runs.c.status,
            runs.c.error_class,
            runs.c.error_summary,
            runs.c.finished_at,
        ).where(runs.c.id.in_(newest))
    ).all()
    return {int(row.source_id): row for row in rows}


def _runs_since(connection: Connection, since: str) -> list[Any]:
    """Finished runs since ``since``, oldest first (a skipped run is not a check)."""
    rows = connection.execute(
        sa.select(runs.c.id, runs.c.source_id, runs.c.finished_at, runs.c.status)
        .where(runs.c.started_at >= since)
        .where(runs.c.status.in_(CHECK_STATUSES))
        .order_by(runs.c.started_at, runs.c.id)
    ).all()
    return list(rows)


def _events_since(connection: Connection, since: str) -> list[Any]:
    rows = connection.execute(
        sa.select(
            change_events.c.id,
            change_events.c.source_id,
            change_events.c.created_at,
            change_events.c.max_severity,
            change_events.c.summary,
        )
        .where(change_events.c.created_at >= since)
        .order_by(change_events.c.created_at, change_events.c.id)
    ).all()
    return list(rows)


def _failed_streaks(runs_30: Sequence[Any]) -> dict[int, int]:
    """How many of the newest runs of each source failed in a row."""
    streaks: dict[int, int] = {}
    for run in runs_30:
        source_id = int(run.source_id)
        streaks[source_id] = streaks.get(source_id, 0) + 1 if run.status == "failed" else 0
    return streaks


def _per_day(
    recent: Mapping[date, Counter[str]], days: Iterable[date], severities: Sequence[str]
) -> list[int]:
    empty: Counter[str] = Counter()
    return [sum(recent.get(day, empty).get(s, 0) for s in severities) for day in days]


def _stats(
    open_events: Mapping[str, int],
    recent: Mapping[date, Counter[str]],
    health: Sequence[SourceHealth],
    now: datetime,
    used_bytes: int,
) -> tuple[Stat, ...]:
    today = now.date()
    last_week = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
    previous_week = [today - timedelta(days=offset) for offset in range(13, 6, -1)]
    urgent = ("high", "critical")
    this_week = _per_day(recent, last_week, SEVERITIES)
    before = sum(_per_day(recent, previous_week, SEVERITIES))
    new_count = sum(this_week)
    open_total = sum(open_events.get(severity, 0) for severity in SEVERITIES)
    critical, high = open_events.get("critical", 0), open_events.get("high", 0)
    urgent_week = _per_day(recent, last_week, urgent)
    urgent_before = sum(_per_day(recent, previous_week, urgent))
    healthy = sum(1 for source in health if source.kind == "ok" and source.enabled)
    unwell = Counter(
        source.status_text.lower() for source in health if source.kind != "ok" and source.enabled
    )
    # A disabled source is not healthy either: the card names it, so its total adds up.
    disabled = sum(1 for source in health if not source.enabled)
    not_healthy = unwell + Counter({"disabled": disabled})
    unwell_text = ", ".join(f"{count} {text}" for text, count in sorted(not_healthy.items()))
    return (
        Stat(
            "Open changes",
            number(open_total),
            "/changes?status=open",
            delta=f"{number(new_count)} new this week, {delta_text(new_count, before)}",
            delta_tone=delta_tone(new_count, before),
            trend=delta_tone(new_count, before) or "flat",
            spark=tuple(this_week),
        ),
        Stat(
            "Critical and high, open",
            number(critical + high),
            URGENT_HREF,
            delta=f"{number(critical)} critical, {number(high)} high",
            delta_tone="alert" if critical else ("up" if high else ""),
            spark=tuple(urgent_week) if sum(urgent_week) + urgent_before else (),
        ),
        Stat(
            "Sources healthy",
            number(healthy),
            "/sources",
            unit=f"of {number(len(health))}",
            delta=unwell_text or "every source is healthy",
            delta_tone="up" if unwell else "",
        ),
        storage_stat(used_bytes),
    )


def _posture(open_items: Mapping[str, int]) -> Posture:
    total = sum(open_items.get(severity, 0) for severity in SEVERITIES)
    counts = tuple(
        SeverityCount(
            severity,
            SEVERITY_LABELS[severity],
            open_items.get(severity, 0),
            SEVERITY_SHARE[severity],
            f"/changes?status=open&severity={severity}",
        )
        for severity in reversed(SEVERITIES)
    )
    parts = ", ".join(f"{count.count} {count.severity}" for count in reversed(counts))
    if total:
        description = f"{number(total)} open change items: {parts}. Counts only, not a score."
    else:
        description = "No open change items."
    return Posture(total, counts, ring_segments(open_items), description)


def _attention(
    connection: Connection, names: Mapping[int, str], health: Sequence[SourceHealth], now: datetime
) -> tuple[Attention, ...]:
    severity_rank = sa.case((change_events.c.max_severity == "critical", 0), else_=1)
    rows = connection.execute(
        sa.select(
            change_events.c.id,
            change_events.c.source_id,
            change_events.c.max_severity,
            change_events.c.summary,
            change_events.c.window_start,
            change_events.c.window_end,
        )
        .where(change_events.c.status == "open")
        .where(change_events.c.max_severity.in_(("critical", "high")))
        .order_by(severity_rank, change_events.c.created_at.desc(), change_events.c.id.desc())
        .limit(ATTENTION_EVENTS)
    ).all()
    result: list[Attention] = []
    for row in rows:
        severity = str(row.max_severity)
        start = parse_stamp(str(row.window_start))
        end = parse_stamp(str(row.window_end))
        source = names.get(int(row.source_id), "a removed source")
        result.append(
            Attention(
                "severity",
                severity,
                SEVERITY_LABELS[severity],
                str(row.summary),
                f"/changes/{int(row.id)}",
                f"{source}, detected {window_text(start, end, now)}",
                "Review",
                f"/changes/{int(row.id)}#acknowledge",
                critical=severity == "critical",
            )
        )
    for source_health in health:
        result.extend(_source_attention(source_health))
    return tuple(result)


def _driftlines(
    health: Sequence[SourceHealth],
    runs_30: Sequence[Any],
    events_30: Sequence[Any],
    now: datetime,
) -> tuple[DriftRow, ...]:
    """One strip per source: per check up to 31 checks in 30 days, else one mark per UTC day."""
    by_source: dict[int, list[Any]] = defaultdict(list)
    for run in runs_30:
        by_source[int(run.source_id)].append(run)
    events_by_key: dict[tuple[int, str], Any] = {}
    events_by_day: dict[tuple[int, date], Any] = {}
    for event in events_30:
        source_id = int(event.source_id)
        created = str(event.created_at)
        events_by_key.setdefault((source_id, created), event)
        day = date.fromisoformat(created[:10])
        current = events_by_day.get((source_id, day))
        if current is None or _rank(event) > _rank(current):
            events_by_day[(source_id, day)] = event
    rows: list[DriftRow] = []
    for source in health:
        source_runs = by_source.get(source.id, [])
        per_day = len(source_runs) > DRIFT_MAX_CHECKS
        if per_day:
            checks = _checks_per_day(source.id, source_runs, events_by_day, now)
        else:
            checks = _checks_per_run(source.id, source_runs, events_by_key)
        count = len(source_runs)
        meta = source_type_label(source.type)
        if source.version:
            meta += f" {source.version}"
        if source.type == PUSH_SOURCE:
            noun = "push" if count == 1 else "pushes"
        else:
            noun = "check" if count == 1 else "checks"
        meta += f", {number(count)} {noun} in 30 days"
        row = DriftRow(source.name, source.href, meta, f"dl-{source.id}", tuple(checks), per_day)
        rows.append(row)
    return tuple(rows)


def _rank(event: Any) -> int:
    return SEVERITIES.index(str(event.max_severity))


def _check_of(event: Any | None, failed: bool) -> dict[str, str]:
    if event is not None:
        return {
            "kind": "change",
            "severity": str(event.max_severity),
            "summary": str(event.summary),
            "href": f"/changes/{int(event.id)}",
        }
    return {"kind": "failed" if failed else "ok"}


def _checks_per_run(
    source_id: int, source_runs: Sequence[Any], events_by_key: Mapping[tuple[int, str], Any]
) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    for run in source_runs:
        event = events_by_key.get((source_id, str(run.finished_at)))
        checks.append(_check_of(event, run.status != "ok" and event is None))
    return checks


def _checks_per_day(
    source_id: int,
    source_runs: Sequence[Any],
    events_by_day: Mapping[tuple[int, date], Any],
    now: datetime,
) -> list[dict[str, str]]:
    """One check per UTC day of the window that had a run: the worst outcome of that day."""
    bad_days: set[date] = set()
    run_days: set[date] = set()
    for run in source_runs:
        day = date.fromisoformat(str(run.finished_at)[:10])
        run_days.add(day)
        if run.status != "ok":
            bad_days.add(day)
    today = now.date()
    checks: list[dict[str, str]] = []
    for offset in range(DRIFT_DAYS, -1, -1):
        day = today - timedelta(days=offset)
        if day not in run_days:
            continue
        event = events_by_day.get((source_id, day))
        checks.append(_check_of(event, day in bad_days and event is None))
    return checks


def _trend(connection: Connection, now: datetime) -> Trend:
    today = now.date()
    day_of = sa.func.substr(change_events.c.created_at, 1, 10)
    rows = connection.execute(
        sa.select(day_of, change_items.c.severity, sa.func.count())
        .select_from(_items_of_events())
        .where(change_events.c.created_at >= day_start(today - timedelta(days=TREND_DAYS - 1)))
        .group_by(day_of, change_items.c.severity)
    ).all()
    counts: dict[date, Counter[str]] = defaultdict(Counter)
    for row in rows:
        counts[date.fromisoformat(str(row[0]))][str(row[1])] += int(row[2])
    window = [today - timedelta(days=offset) for offset in range(TREND_DAYS - 1, -1, -1)]
    days = tuple(
        TrendDay(
            day_label(day, today),
            counts[day]["low"],
            counts[day]["medium"],
            counts[day]["high"],
            counts[day]["critical"],
        )
        for day in window
    )
    bars, grid = trend_geometry(days)
    total = sum(day.total for day in days)
    busiest = max((day.total for day in days), default=0)
    if total:
        description = (
            f"{number(total)} change items in the last 30 days; the busiest day had "
            f"{number(busiest)}. The table behind the disclosure holds the same numbers."
        )
    else:
        description = "No change items in the last 30 days."
    ticks = () if total else empty_ticks(len(days))
    return Trend(days, bars, grid, total, description, ticks)


def _breakdowns(
    connection: Connection, names: Mapping[int, str]
) -> tuple[tuple[BarRow, ...], tuple[BarRow, ...]]:
    count = sa.func.count()
    by_source_rows = connection.execute(
        sa.select(change_events.c.source_id, count)
        .select_from(_items_of_events())
        .where(change_events.c.status == "open")
        .group_by(change_events.c.source_id)
        .order_by(count.desc(), change_events.c.source_id)
        .limit(BREAKDOWN_ROWS)
    ).all()
    by_resource_rows = connection.execute(
        sa.select(change_items.c.resource, count)
        .select_from(_items_of_events())
        .where(change_events.c.status == "open")
        .group_by(change_items.c.resource)
        .order_by(count.desc(), change_items.c.resource)
        .limit(BREAKDOWN_ROWS)
    ).all()
    largest_source = max((int(row[1]) for row in by_source_rows), default=0)
    largest_resource = max((int(row[1]) for row in by_resource_rows), default=0)
    by_source = tuple(
        BarRow(
            names.get(int(row[0]), "a removed source"),
            f"/changes?status=open&source={int(row[0])}",
            int(row[1]),
            width_class(int(row[1]), largest_source),
        )
        for row in by_source_rows
    )
    by_resource = tuple(
        BarRow(
            resource_label(str(row[0])),
            f"/changes?status=open&resource={quote(str(row[0]), safe='')}",
            int(row[1]),
            width_class(int(row[1]), largest_resource),
        )
        for row in by_resource_rows
    )
    return by_source, by_resource


def _activity(connection: Connection, names: Mapping[int, str]) -> tuple[Activity, ...]:
    """The newest 20 entries over events, acknowledgements, notes, runs and audit events."""
    entries: list[Activity] = []
    event_rows = connection.execute(
        sa.select(
            change_events.c.id,
            change_events.c.source_id,
            change_events.c.created_at,
            change_events.c.max_severity,
            change_events.c.summary,
        )
        .order_by(change_events.c.created_at.desc(), change_events.c.id.desc())
        .limit(ACTIVITY_LIMIT)
    ).all()
    for event_row in event_rows:
        severity = str(event_row.max_severity)
        source = names.get(int(event_row.source_id), "a removed source")
        entries.append(
            Activity(
                "alert" if severity == "critical" else "event",
                "",
                f"{SEVERITY_LABELS[severity]} change",
                f"/changes/{int(event_row.id)}",
                f" on {source}: {event_row.summary}",
                parse_stamp(str(event_row.created_at)),
            )
        )
    for table, verb in ((acknowledgements, "acknowledged"), (notes, "added a note to")):
        user_rows = connection.execute(
            sa.select(
                table.c.created_at, table.c.event_id, users.c.username, change_events.c.source_id
            )
            .select_from(
                table.join(users, table.c.user_id == users.c.id).join(
                    change_events, table.c.event_id == change_events.c.id
                )
            )
            .order_by(table.c.created_at.desc(), table.c.id.desc())
            .limit(ACTIVITY_LIMIT)
        ).all()
        for user_row in user_rows:
            source = names.get(int(user_row.source_id), "a removed source")
            entries.append(
                Activity(
                    "",
                    f"{user_row.username} {verb} ",
                    f"change {number(int(user_row.event_id))}",
                    f"/changes/{int(user_row.event_id)}",
                    f" on {source}",
                    parse_stamp(str(user_row.created_at)),
                )
            )
    run_rows = connection.execute(
        sa.select(
            runs.c.source_id,
            runs.c.finished_at,
            runs.c.status,
            runs.c.object_count,
            runs.c.error_summary,
        )
        .where(runs.c.status.in_(CHECK_STATUSES))
        .order_by(runs.c.finished_at.desc(), runs.c.id.desc())
        .limit(ACTIVITY_LIMIT)
    ).all()
    for run_row in run_rows:
        if run_row.status == "ok":
            tail = f" finished, {number(int(run_row.object_count))} objects"
        else:
            tail = f" {run_row.status}: {run_row.error_summary or 'no detail recorded'}"
        entries.append(
            Activity(
                "run",
                "Check of ",
                names.get(int(run_row.source_id), "a removed source"),
                f"/sources/{int(run_row.source_id)}",
                tail,
                parse_stamp(str(run_row.finished_at)),
            )
        )
    audit_rows = connection.execute(
        sa.select(
            audit_events.c.at,
            audit_events.c.actor,
            audit_events.c.action,
            audit_events.c.target,
            audit_events.c.detail,
        )
        .where(audit_events.c.action.not_in(AUDIT_SKIPPED))
        .order_by(audit_events.c.at.desc(), audit_events.c.id.desc())
        .limit(ACTIVITY_LIMIT)
    ).all()
    for audit_row in audit_rows:
        action = str(audit_row.action)
        verb = AUDIT_VERBS.get(action, action.replace(".", " ").replace("_", " "))
        target = "" if audit_row.target is None else str(audit_row.target)
        detail = audit_row.detail if isinstance(audit_row.detail, Mapping) else {}
        label, href = audit_target(target, names, detail)
        text = f"{audit_row.actor} {verb}" + (" " if label else "")
        entries.append(Activity("", text, label, href, "", parse_stamp(str(audit_row.at))))
    entries.sort(key=lambda entry: entry.when, reverse=True)
    return tuple(entries[:ACTIVITY_LIMIT])


def audit_target(
    target: str, names: Mapping[int, str], detail: Mapping[str, Any] | None = None
) -> tuple[str, str]:
    """The readable label and the link of an audit target; never a raw ``kind:id`` text.

    A source gets its name and page, a change its number and page, a mute the resource type it
    applies to and the muted paths list. Any other target (a user name, a token prefix, a channel
    type) is already readable and stays as it is.
    """
    kind, _, rest = target.partition(":")
    if kind == "source" and rest.isdigit():
        source_id = int(rest)
        return names.get(source_id, f"source {source_id}"), f"/sources/{source_id}"
    if kind == "event" and rest.isdigit():
        return f"change {number(int(rest))}", f"/changes/{int(rest)}"
    if kind == "mute" and rest.isdigit():
        resource = (detail or {}).get("resource")
        label = resource_label(str(resource)) if resource else "a resource type"
        return label, MUTES_HREF
    return target, ""
