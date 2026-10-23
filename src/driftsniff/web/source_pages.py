"""The read side of the sources pages (P10-T5): the source list, the source page and its panels.

``SourcePages.listing`` and ``SourcePages.detail`` run the queries of this module on one read
connection and return plain values that ``sources/list.html`` and ``sources/detail.html`` print.
The status and the drift line of a source come from ``driftsniff.web.dashboard.source_overview``,
so a source reads the same here as on the start page.

The coverage panel has one row per resource the type reads (for a push source: per resource it
declared), in the order the collector reads them, followed by any stored row of a resource that
is no longer in that list. A stored row is shown exactly as the run pipeline wrote it (status,
object count, last good read, stale since); a resource the admin turned off says so, and one that
no run has read yet says that. For Xen Orchestra the values XO itself never returns are named
under the label hidden by XO (``hidden_by_xo`` of the type table).

Nothing here reads a credential: ``SourceView`` only says whether one is stored.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from functools import cache
from typing import Any, Final

import sqlalchemy as sa

from driftsniff.collectors.tls import MODE_VERIFY, OPTION_TLS_MODE
from driftsniff.collectors.unifi.resources import RESOURCES as UNIFI_RESOURCES
from driftsniff.collectors.xo.client import entered_expiry, expiry_is_near
from driftsniff.collectors.xo.resources import COLLECTIONS as XO_COLLECTIONS
from driftsniff.db.engine import Database
from driftsniff.db.tables import objects, resource_coverage, runs, sources
from driftsniff.rules.loader import load_rules
from driftsniff.sources.probe import ProbeFactory, ProbeResult, ProbeRow
from driftsniff.sources.service import (
    OPTION_CREDENTIAL_EXPIRES_ON,
    OPTION_PUSH_FIELDS,
    OPTION_RESOURCES_OFF,
    SourceService,
    SourceView,
    interval_of,
)
from driftsniff.web.dashboard import (
    STATE_TOKEN_EXPIRING,
    STATE_UNSUPPORTED,
    STATUS_TEXT,
    DriftRow,
    SourceHealth,
    parse_stamp,
    resource_label,
    source_overview,
    source_type_label,
)
from driftsniff.web.templating import number

RECENT_RUNS: Final = 8
TLS_MODE_LABELS: Final = {
    "verify": "Verify with the system trust store",
    "ca_file": "Verify with your own CA bundle",
    "pinned": "Pinned certificate",
    "insecure": "Insecure, certificate checks off",
}
CREDENTIAL_LABELS: Final = {"unifi": "API key", "xo": "Authentication token"}
STATUS_OK: Final = "200"
STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
COVERAGE_OFF: Final = "off"
COVERAGE_NEVER: Final = ""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def resources_of(source_type: str, options: Mapping[str, object]) -> tuple[str, ...]:
    """The resources a source of ``source_type`` reads, in the order its collector reads them.

    A push source reads what it declared (``push_fields``), in name order.
    """
    if source_type == "unifi":
        return tuple(resource.name for resource in UNIFI_RESOURCES)
    if source_type == "xo":
        return tuple(XO_COLLECTIONS)
    declared = options.get(OPTION_PUSH_FIELDS)
    return tuple(sorted(declared)) if isinstance(declared, dict) else ()


def resources_off(options: Mapping[str, object]) -> frozenset[str]:
    """The resources the admin turned off for a source."""
    value = options.get(OPTION_RESOURCES_OFF)
    if not isinstance(value, list):
        return frozenset()
    return frozenset(str(name) for name in value)


@cache
def _hidden_by_xo() -> dict[str, tuple[str, ...]]:
    tables = load_rules().type_tables
    return {name: tuple(sorted(table.hidden_by_xo)) for name, table in tables.items()}


def hidden_by_xo(source_type: str, resource: str) -> tuple[str, ...]:
    """The fields of an XO resource that Xen Orchestra itself never returns in clear."""
    if source_type != "xo":
        return ()
    return _hidden_by_xo().get(resource, ())


def expiry_date(options: Mapping[str, object]) -> date | None:
    """The credential expiry date the admin entered, or None."""
    value = options.get(OPTION_CREDENTIAL_EXPIRES_ON)
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def credential_expiring(state: str, options: Mapping[str, object], now: datetime) -> bool:
    """Whether the credential is expiring: the stored state says so, or the entered date does."""
    if state == STATE_TOKEN_EXPIRING:
        return True
    return expiry_is_near(entered_expiry(expiry_date(options)), now)


def interval_text(seconds: int) -> str:
    """How often a source is checked, in words."""
    if seconds % 60 == 0:
        minutes = seconds // 60
        return "Every minute" if minutes == 1 else f"Every {minutes} minutes"
    return f"Every {seconds} seconds"


@dataclass(frozen=True, slots=True)
class Badge:
    """A flag of a source next to its status: insecure TLS, unsupported or credential expiring."""

    kind: str
    text: str


def badges_of(
    health: SourceHealth, state: str, options: Mapping[str, object], now: datetime
) -> tuple[Badge, ...]:
    """The flags of a source; a flag that is already its status is not repeated."""
    found: list[Badge] = []
    if health.insecure:
        found.append(Badge("insecure", "Insecure TLS"))
    if state == STATE_UNSUPPORTED and health.kind != "unsupported":
        found.append(Badge("unsupported", "Unsupported version"))
    if credential_expiring(state, options, now) and health.kind != "warn":
        found.append(Badge("warn", "Credential expiring"))
    return tuple(found)


@dataclass(frozen=True, slots=True)
class SourceRow:
    """One row of the source list."""

    health: SourceHealth
    status_text: str
    type_label: str
    last_checked: datetime | None
    badges: tuple[Badge, ...]
    driftline: DriftRow


@dataclass(frozen=True, slots=True)
class SourceListing:
    now: datetime
    rows: tuple[SourceRow, ...]


@dataclass(frozen=True, slots=True)
class CoverageRow:
    """One resource of the coverage panel.

    ``status`` is the stored ``last_status`` (``200``, ``403``, ``404``, ``error`` or another HTTP
    status), ``off`` for a resource turned off, or empty when no run has read it yet.
    ``object_count`` is None when there is no stored row.
    """

    resource: str
    label: str
    status: str
    kind: str
    text: str
    note: str
    object_count: int | None = None
    last_ok_at: datetime | None = None
    stale_since: datetime | None = None
    hidden_by_xo: tuple[str, ...] = ()


def _stamp_or_none(value: object) -> datetime | None:
    return None if value is None else parse_stamp(str(value))


def coverage_row(
    source_type: str, resource: str, stored: Any | None, *, turned_off: bool
) -> CoverageRow:
    """The coverage panel row of ``resource`` from its stored row (or none)."""
    label = resource_label(resource)
    hidden = hidden_by_xo(source_type, resource)
    if stored is None:
        if turned_off:
            return CoverageRow(
                resource, label, COVERAGE_OFF, "open", "Off", "Turned off for this source.", None
            )
        note = "No run has read this resource yet."
        return CoverageRow(
            resource, label, COVERAGE_NEVER, "open", "Not read yet", note, hidden_by_xo=hidden
        )
    status = str(stored.last_status)
    last_ok = _stamp_or_none(stored.last_ok_at)
    stale = _stamp_or_none(stored.stale_since)
    count = int(stored.object_count)
    if status == STATUS_OK:
        kind, text, note = "ok", "200", ""
    elif status == STATUS_FORBIDDEN:
        kind, text = "stale", "403, stale"
        note = "The credential may lack a permission. The last good data is kept."
    elif status == STATUS_NOT_FOUND:
        kind, text = "unsupported", "404, not on this version"
        note = "Not available on this version of the controller."
    else:
        kind = "failing"
        text = f"HTTP {status}" if status.isdigit() else "Error"
        note = "The last read failed. The last good data is kept."
    if turned_off:
        note = f"Turned off for this source. {note}".strip()
    return CoverageRow(resource, label, status, kind, text, note, count, last_ok, stale, hidden)


def coverage_rows(
    source_type: str, options: Mapping[str, object], stored: Sequence[Any]
) -> tuple[CoverageRow, ...]:
    """The coverage panel: every resource of the type, then the stored rows of any other one."""
    by_resource = {str(row.resource): row for row in stored}
    off = resources_off(options)
    names = list(resources_of(source_type, options))
    names += sorted(name for name in by_resource if name not in names)
    return tuple(
        coverage_row(source_type, name, by_resource.get(name), turned_off=name in off)
        for name in names
    )


def probe_row(source_type: str, row: ProbeRow) -> CoverageRow:
    """A row of a test connection, in the words of the coverage panel; nothing is stored."""
    label = resource_label(row.resource)
    hidden = hidden_by_xo(source_type, row.resource)
    count: int | None = row.object_count
    if row.status == STATUS_OK:
        kind, text, note = "ok", "200", ""
    elif row.status == STATUS_FORBIDDEN:
        kind, text = "stale", "403"
        note = "The credential may lack a permission for this resource."
    elif row.status == STATUS_NOT_FOUND:
        kind, text = "unsupported", "404, not on this version"
        note = "Not available on this version of the controller."
        count = None
    else:
        kind = "failing"
        text = f"HTTP {row.status}" if row.status.isdigit() else "Error"
        note = "The read failed."
        count = None
    if row.error_text and row.status != STATUS_OK:
        note = _sentence(row.error_text)
    return CoverageRow(row.resource, label, row.status, kind, text, note, count, None, None, hidden)


def probe_rows(source_type: str, result: ProbeResult | None) -> tuple[CoverageRow, ...]:
    """The rows of a test connection result (none without a result)."""
    if result is None:
        return ()
    return tuple(probe_row(source_type, row) for row in result.rows)


def _sentence(text: str) -> str:
    cleaned = text[:1].upper() + text[1:]
    return cleaned if cleaned.endswith(".") else cleaned + "."


@dataclass(frozen=True, slots=True)
class RunEntry:
    """One entry of the recent runs of a source: a dot, the outcome in words and the time."""

    dot: str
    text: str
    when: datetime


def run_entry(row: Any) -> RunEntry:
    """A run record in words; a failed or partial run gets the alert dot."""
    detail = row.error_summary or row.error_class or "no detail recorded"
    status = row.status
    when = parse_stamp(str(row.finished_at or row.started_at))
    if status is None:
        return RunEntry("", "Running", when)
    if status == "ok":
        count = int(row.object_count)
        noun = "object" if count == 1 else "objects"
        return RunEntry("run", f"OK, {number(count)} {noun}", when)
    words = {"partial": "Partial", "failed": "Failed", "skipped": "Skipped"}
    dot = "" if status == "skipped" else "alert"
    return RunEntry(dot, f"{words.get(str(status), str(status))}: {detail}", when)


@dataclass(frozen=True, slots=True)
class SourceDetail:
    """Everything the source page shows about one source."""

    now: datetime
    view: SourceView
    health: SourceHealth
    status_text: str
    last_checked: datetime | None
    badges: tuple[Badge, ...]
    driftline: DriftRow
    coverage: tuple[CoverageRow, ...]
    runs: tuple[RunEntry, ...]
    object_count: int
    type_label: str
    interval: str
    tls_mode: str
    tls_label: str
    credential_label: str
    expires_on: date | None
    expiring: bool
    resources_total: int
    resources_off: tuple[str, ...]

    @property
    def polled(self) -> bool:
        return self.view.type in CREDENTIAL_LABELS


_SOURCE_COLUMNS: Final = (
    sources.c.id,
    sources.c.name,
    sources.c.type,
    sources.c.enabled,
    sources.c.last_checked_at,
    sources.c.controller_version,
    sources.c.state,
    sources.c.options,
)


class SourcePages:
    """The reads of the sources pages, and the services the pages act through.

    ``service`` makes every change (create, update, enable, disable, delete, sender key).
    ``probe_factory`` builds the collector of a test connection; None means the test is not
    available on this installation (``serve`` has no collector factory yet).
    """

    def __init__(
        self,
        database: Database,
        service: SourceService,
        *,
        probe_factory: ProbeFactory | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._db = database
        self.service = service
        self.probe_factory = probe_factory
        self._clock = clock

    def now(self) -> datetime:
        return self._clock()

    def listing(self) -> SourceListing:
        """Every source in name order with its status, flags, last check and drift line."""
        now = self._clock()
        with self._db.read() as connection:
            rows = connection.execute(sa.select(*_SOURCE_COLUMNS).order_by(sources.c.name)).all()
            health, lines = source_overview(connection, rows, now)
        result = tuple(
            SourceRow(
                health=state,
                status_text=STATUS_TEXT[state.kind],
                type_label=source_type_label(state.type),
                last_checked=_stamp_or_none(row.last_checked_at),
                badges=badges_of(state, str(row.state), _options(row), now),
                driftline=line,
            )
            for row, state, line in zip(rows, health, lines, strict=True)
        )
        return SourceListing(now, result)

    def detail(self, source_id: int) -> SourceDetail:
        """The source page of ``source_id``; ``SourceNotFoundError`` when there is none."""
        view = self.service.get(source_id)
        now = self._clock()
        with self._db.read() as connection:
            row = connection.execute(
                sa.select(*_SOURCE_COLUMNS).where(sources.c.id == source_id)
            ).one()
            health, lines = source_overview(connection, [row], now)
            stored = connection.execute(
                sa.select(resource_coverage).where(resource_coverage.c.source_id == source_id)
            ).all()
            recent = connection.execute(
                sa.select(runs)
                .where(runs.c.source_id == source_id)
                .order_by(runs.c.id.desc())
                .limit(RECENT_RUNS)
            ).all()
            count = connection.execute(
                sa.select(sa.func.count())
                .select_from(objects)
                .where(objects.c.source_id == source_id, objects.c.removed_at.is_(None))
            ).scalar_one()
        options = view.options
        mode = str(options.get(OPTION_TLS_MODE, MODE_VERIFY))
        off = resources_off(options)
        return SourceDetail(
            now=now,
            view=view,
            health=health[0],
            status_text=STATUS_TEXT[health[0].kind],
            last_checked=_stamp_or_none(view.last_checked_at),
            badges=badges_of(health[0], view.state, options, now),
            driftline=lines[0],
            coverage=coverage_rows(view.type, options, stored),
            runs=tuple(run_entry(run) for run in recent),
            object_count=int(count),
            type_label=source_type_label(view.type),
            interval=interval_text(interval_of(options)),
            tls_mode=mode,
            tls_label=TLS_MODE_LABELS.get(mode, mode),
            credential_label=CREDENTIAL_LABELS.get(view.type, "Sender key"),
            expires_on=expiry_date(options),
            expiring=credential_expiring(view.state, options, now),
            resources_total=len(resources_of(view.type, options)),
            resources_off=tuple(resource_label(name) for name in sorted(off)),
        )


def _options(row: Any) -> Mapping[str, object]:
    return row.options if isinstance(row.options, Mapping) else {}
