"""The dashboard (P10-T4): the queries, the pure helpers and the rendered page.

The queries run against a migrated database seeded with plain inserts (sources, runs, events,
items, acknowledgements, notes and audit events), the way the run pipeline and the services
write them. The page is driven through the real application as a browser. Values that must
never reach the dashboard (before and after values, a credential, a note body, an
acknowledgement comment) are canaries.
"""

import re
import time
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from httpx import Response

from driftsniff.config import Settings
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.db.tables import (
    acknowledgements,
    audit_events,
    change_events,
    change_items,
    notes,
    objects,
    runs,
    snapshots,
    sources,
)
from driftsniff.main import create_app
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.dashboard import (
    DRIFT_MAX_CHECKS,
    RING_CIRCUMFERENCE,
    STORAGE_WARNING_BYTES,
    Dashboard,
    DashboardService,
    TrendDay,
    chart_top,
    day_label,
    delta_text,
    delta_tone,
    parse_stamp,
    resource_label,
    ring_segments,
    silent_text,
    stamp,
    storage_bytes,
    storage_stat,
    trend_geometry,
    width_class,
    window_text,
)

ORIGIN = "http://testserver"
BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
CORRECT = "CANARY-correct horse battery"  # noqa: S105
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
HOSTILE_NAME = "eve<script>alert(1)</script>"
CANARY_BEFORE = "CANARY-before-value-0001"
CANARY_AFTER = "CANARY-after-value-0002"
CANARY_NOTE = "CANARY-note-body-0003"
CANARY_COMMENT = "CANARY-ack-comment-0004"
CANARY_CREDENTIAL = "CANARY-credential-0005"  # noqa: S105
CANARIES = (CANARY_BEFORE, CANARY_AFTER, CANARY_NOTE, CANARY_COMMENT, CANARY_CREDENTIAL)


class Parsed(HTMLParser):
    """The tags of a page with their attributes, and its text, in document order."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[str] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        self.text.append(data)

    def find(self, name: str) -> list[dict[str, str | None]]:
        return [attrs for tag, attrs in self.tags if tag == name]


def assert_page(response: Response, status: int = 200) -> Parsed:
    """The answer is a page of the shell that obeys the content security policy."""
    assert response.status_code == status, response.text[:300]
    assert response.headers["content-type"].startswith("text/html")
    text = response.text
    parsed = Parsed(text)
    assert parsed.find("main") == [{"id": "main", "class": "page"}]
    for tag, attrs in parsed.tags:
        assert "style" not in attrs, f"<{tag}> carries a style attribute"
        assert not [name for name in attrs if name.startswith("on")], f"<{tag}> has a handler"
        if tag == "script":
            assert (attrs.get("src") or "").startswith("/static/")
    return parsed


# ---- the seed -------------------------------------------------------------------------------


def at(**delta: int) -> str:
    """A stored time relative to NOW (``hours=-2`` is two hours before)."""
    return stamp(NOW + timedelta(**delta))


def add_source(
    store: Database,
    name: str,
    source_type: str,
    *,
    enabled: bool = True,
    version: str | None = None,
    options: dict[str, object] | None = None,
    last_checked_at: str | None = None,
    state: str = "new",
) -> int:
    with store.write() as connection:
        return int(
            connection.execute(
                sa.insert(sources)
                .values(
                    name=name,
                    type=source_type,
                    enabled=enabled,
                    controller_version=version,
                    options=options or {},
                    last_checked_at=last_checked_at,
                    credential_ciphertext=CANARY_CREDENTIAL,
                    state=state,
                )
                .returning(sources.c.id)
            ).scalar_one()
        )


def add_run(
    store: Database,
    source_id: int,
    finished_at: str,
    status: str = "ok",
    *,
    object_count: int = 10,
    error_summary: str | None = None,
) -> int:
    started = stamp(parse_stamp(finished_at) - timedelta(minutes=1))
    with store.write() as connection:
        return int(
            connection.execute(
                sa.insert(runs)
                .values(
                    source_id=source_id,
                    started_at=started,
                    finished_at=finished_at,
                    status=status,
                    object_count=object_count,
                    error_class=None if status == "ok" else "timeout",
                    error_summary=error_summary,
                )
                .returning(runs.c.id)
            ).scalar_one()
        )


def add_event(
    store: Database,
    source_id: int,
    created_at: str,
    severity: str,
    items: list[tuple[str, str]],
    *,
    status: str = "open",
    summary: str | None = None,
) -> int:
    """An event with one item per (resource, severity) pair, created the way the pipeline does."""
    window_start = stamp(parse_stamp(created_at) - timedelta(hours=1))
    with store.write() as connection:
        snapshot_id = connection.execute(
            sa.insert(snapshots)
            .values(
                source_id=source_id,
                taken_at=created_at,
                manifest_hash="m",
                manifest_zstd=b"x",
                normaliser_version=1,
            )
            .returning(snapshots.c.id)
        ).scalar_one()
        event_id = int(
            connection.execute(
                sa.insert(change_events)
                .values(
                    source_id=source_id,
                    snapshot_id=snapshot_id,
                    window_start=window_start,
                    window_end=created_at,
                    max_severity=severity,
                    item_count=len(items),
                    summary=summary or f"{len(items)} changes, highest severity {severity}",
                    rule_pack_version="pack-1",
                    status=status,
                    created_at=created_at,
                )
                .returning(change_events.c.id)
            ).scalar_one()
        )
        connection.execute(
            sa.insert(change_items),
            [
                {
                    "event_id": event_id,
                    "resource": resource,
                    "object_name_at_time": "obj",
                    "change_kind": "changed",
                    "path": "name",
                    "field_class": "config",
                    "before_value": CANARY_BEFORE,
                    "after_value": CANARY_AFTER,
                    "severity": item_severity,
                    "rule_id": "rule-1",
                    "rationale": "because",
                }
                for resource, item_severity in items
            ],
        )
    return event_id


def add_audit(store: Database, when: str, actor: str, action: str, target: str | None) -> None:
    with store.write() as connection:
        connection.execute(
            sa.insert(audit_events).values(at=when, actor=actor, action=action, target=target)
        )


@pytest.fixture
def auth(store: Database) -> AuthService:
    return AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))


@pytest.fixture
def seeded(store: Database, auth: AuthService) -> dict[str, int]:
    """Four sources, a few runs and events, a note, an acknowledgement and audit rows.

    Source 1 (the ``lab-controller`` push source of the store fixture) has three checks: one
    plain, one that found the critical event, one that failed. ``office-xo`` is polled every
    five minutes with certificate checks off and has more checks than fit per mark, with one
    failed day and one high event that was acknowledged. ``branch-gw`` is disabled. The fourth
    source has a hostile name and no check yet.
    """
    ada = auth.create_user("ada", CORRECT, "admin")
    with store.write() as connection:
        # The service stamps its audit row with the real clock; move it behind the fixed time.
        connection.execute(sa.update(audit_events).values(at=at(days=-20)))
        connection.execute(
            sa.update(sources).where(sources.c.id == 1).values(last_checked_at=at(minutes=-30))
        )
    xo = add_source(
        store,
        "office-xo",
        "xo",
        version="5.108",
        options={"interval_seconds": 300, "tls_mode": "insecure", "insecure": True},
        last_checked_at=at(minutes=-5),
    )
    gateway = add_source(store, "branch-gw", "unifi", enabled=False, last_checked_at=at(days=-9))
    hostile = add_source(store, HOSTILE_NAME, "unifi")
    add_run(store, 1, at(hours=-2))
    critical = add_event(
        store,
        1,
        at(hours=-1),
        "critical",
        [
            ("unifi-firewall-policies", "critical"),
            ("unifi-firewall-policies", "critical"),
            ("unifi-networks", "low"),
        ],
        summary="3 changes in 2 resource types, highest severity critical",
    )
    add_run(store, 1, at(hours=-1))
    add_run(store, 1, at(minutes=-30), "failed", error_summary="no answer within 30 seconds")
    # 40 checks over ten days, one failed day, one high event (acknowledged) on another day.
    for day in range(10, 0, -1):
        for hour in (2, 8, 14, 20):
            status = "failed" if day == 4 else "ok"
            add_run(store, xo, at(days=-day, hours=hour - 12), status)
    high = add_event(
        store,
        xo,
        at(days=-3, hours=-10),
        "high",
        [("vms", "high")],
        status="acknowledged",
        summary="1 change in 1 resource type, highest severity high",
    )
    medium = add_event(
        store,
        1,
        at(days=-9),
        "medium",
        [("vms", "medium"), ("vms", "medium")],
        summary="2 changes in 1 resource type, highest severity medium",
    )
    with store.write() as connection:
        connection.execute(
            sa.insert(acknowledgements).values(
                event_id=high, user_id=ada, comment=CANARY_COMMENT, created_at=at(days=-2)
            )
        )
        connection.execute(
            sa.insert(notes).values(
                event_id=critical, user_id=ada, body=CANARY_NOTE, created_at=at(minutes=-20)
            )
        )
    add_audit(store, at(days=-1), "ada", "source.create", f"source:{xo}")
    add_audit(store, at(minutes=-10), "ada", "token.rejected", None)
    add_audit(store, at(days=-12), "system", "retention.run", None)
    return {
        "xo": xo,
        "gateway": gateway,
        "hostile": hostile,
        "critical": critical,
        "high": high,
        "medium": medium,
        "ada": ada,
    }


@pytest.fixture
def service(store: Database) -> DashboardService:
    return DashboardService(store, clock=lambda: NOW)


@pytest.fixture
def client(auth: AuthService, service: DashboardService) -> Iterator[TestClient]:
    app = create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN, "DRIFTSNIFF_ENVIRONMENT_LABEL": "Test"}),
        auth=auth,
        dashboard=service,
    )
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as built:
        yield built


def sign_in(client: TestClient, auth: AuthService) -> dict[str, str]:
    """A session cookie of a fresh admin (created directly, so the setup page is not needed)."""
    if not auth.has_admin():
        auth.create_user("root", CORRECT, "admin")
        username = "root"
    else:
        username = "ada"
    response = client.post("/login", data={"username": username, "password": CORRECT})
    assert response.status_code == 303, response.text
    match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
    assert match is not None
    client.cookies.clear()
    return {**BROWSER, "Cookie": f"{SESSION_COOKIE}={match.group(1)}"}


# ---- the pure helpers -----------------------------------------------------------------------


def test_ring_segments_fill_the_circumference_in_severity_order() -> None:
    segments = ring_segments({"low": 1, "medium": 0, "high": 1, "critical": 2})
    assert [segment.severity for segment in segments] == ["low", "high", "critical"]
    lengths = [float(segment.dasharray.split()[0]) for segment in segments]
    assert lengths == pytest.approx(
        [RING_CIRCUMFERENCE / 4, RING_CIRCUMFERENCE / 4, RING_CIRCUMFERENCE / 2], abs=0.1
    )
    offsets = [float(segment.dashoffset) for segment in segments]
    expected = [0.0, -RING_CIRCUMFERENCE / 4, -RING_CIRCUMFERENCE / 2]
    assert offsets == pytest.approx(expected, abs=0.1)
    assert ring_segments({}) == ()
    assert ring_segments({"low": 0}) == ()


def test_chart_top_is_a_multiple_of_three() -> None:
    assert [chart_top(n) for n in (0, 1, 3, 4, 11, 12)] == [3, 3, 3, 6, 12, 12]


def test_trend_geometry_stacks_the_bars_and_labels_the_grid() -> None:
    days = [TrendDay("x", 1, 2, 0, 3)] + [TrendDay("y", 0, 0, 0, 0)] * 29
    bars, grid = trend_geometry(days)
    assert [line.label for line in grid] == ["6", "4", "2"]
    assert [line.y for line in grid] == ["30.0", "70.0", "110.0"]
    assert [line.label_y for line in grid] == ["34.0", "74.0", "114.0"]
    assert [bar.severity for bar in bars] == ["low", "medium", "critical"]
    # heights: 1, 2 and 3 of 6 on a 120 unit scale, stacked from the baseline at 150
    assert [bar.height for bar in bars] == ["20.0", "40.0", "60.0"]
    assert [bar.y for bar in bars] == ["130.0", "90.0", "30.0"]
    assert len({bar.x for bar in bars}) == 1 and bars[0].width == "12"
    empty_bars, empty_grid = trend_geometry([])
    assert empty_bars == () and [line.label for line in empty_grid] == ["3", "2", "1"]


def test_width_class_rounds_up_to_a_tenth() -> None:
    assert width_class(0, 10) == "w-0"
    assert width_class(1, 10) == "w-10"
    assert width_class(1, 100) == "w-10"
    assert width_class(5, 10) == "w-50"
    assert width_class(51, 100) == "w-60"
    assert width_class(10, 10) == "w-100"


def test_text_helpers() -> None:
    today = date(2026, 10, 22)
    assert day_label(today, today) == "today"
    assert day_label(today - timedelta(days=1), today) == "1 day ago"
    assert day_label(today - timedelta(days=7), today) == "7 days ago"
    assert delta_text(3, 8) == "5 fewer than the previous 7 days"
    assert delta_text(8, 3) == "5 more than the previous 7 days"
    assert delta_text(3, 3) == "the same as the previous 7 days"
    assert (delta_tone(3, 8), delta_tone(8, 3), delta_tone(3, 3)) == ("down", "up", "")
    assert resource_label("unifi-firewall-policies") == "Firewall policies"
    assert resource_label("vms") == "Virtual machines"
    assert resource_label("unifi-new-thing") == "New thing"
    assert resource_label("") == ""
    start, end = NOW - timedelta(hours=2), NOW - timedelta(hours=1)
    assert window_text(start, end, NOW) == "between 10:00 and 11:00 UTC today"
    earlier = NOW - timedelta(days=1)
    assert window_text(earlier, earlier, NOW) == "between 12:00 and 12:00 UTC on 2026-10-21"
    assert window_text(earlier, NOW, NOW) == "between 2026-10-21 12:00 and 2026-10-22 12:00 UTC"
    assert parse_stamp("2026-10-22T08:00:00Z") == datetime(2026, 10, 22, 8, tzinfo=UTC)
    assert [silent_text(s) for s in (90, 5400, 7200, 100_000, 300_000)] == [
        "2 minutes",
        "90 minutes",
        "2 hours",
        "28 hours",
        "3 days",
    ]


def test_storage_stat_and_bytes(tmp_path: Path) -> None:
    card = storage_stat(412 * 1024 * 1024)
    assert (card.value, card.unit) == ("412", "MB")
    assert card.delta == "20% of the 2 GB warning size" and card.delta_tone == ""
    small = storage_stat(1_500_000)
    assert small.value == "1.4"
    assert storage_stat(int(STORAGE_WARNING_BYTES * 0.85)).delta_tone == "up"
    assert storage_stat(STORAGE_WARNING_BYTES).delta_tone == "alert"
    path = tmp_path / "driftsniff.db"
    assert storage_bytes(path) == 0
    path.write_bytes(b"a" * 10)
    (tmp_path / "driftsniff.db-wal").write_bytes(b"b" * 5)
    assert storage_bytes(path) == 15


# ---- the queries ----------------------------------------------------------------------------


def test_an_installation_without_sources_is_empty(tmp_path: Path) -> None:
    database = Database(database_path(tmp_path))
    try:
        upgrade_to_head(database)
        data = DashboardService(database, clock=lambda: NOW).load()
    finally:
        database.close()
    assert data == Dashboard(now=NOW, has_sources=False)


def test_the_stat_cards_count_open_changes_new_changes_and_sources(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    data = service.load()
    assert data.has_sources
    open_changes, urgent, healthy, storage = data.stats
    assert (open_changes.label, open_changes.value) == ("Open changes", "2")
    assert open_changes.href == "/changes?status=open"
    # two events this week (the critical one and the acknowledged high one), one the week before
    assert open_changes.delta == "2 new this week, 1 more than the previous 7 days"
    assert open_changes.delta_tone == "up" and open_changes.spark == (0, 0, 0, 1, 0, 0, 1)
    assert open_changes.trend == "up" and urgent.trend == healthy.trend == storage.trend == ""
    assert (urgent.label, urgent.value) == ("Critical and high, open", "1")
    assert urgent.delta == "1 critical, 0 high" and urgent.delta_tone == "alert"
    assert urgent.spark == (0, 0, 0, 1, 0, 0, 1)
    assert (healthy.label, healthy.value, healthy.unit) == ("Sources healthy", "1", "of 4")
    assert healthy.delta == "1 failing, 1 no check yet" and healthy.delta_tone == "up"
    assert storage.label == "Storage used" and storage.unit == "MB"


def test_the_posture_ring_counts_open_items_by_severity(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    posture = service.load().posture
    assert posture is not None
    assert posture.total == 5
    assert [(count.severity, count.count) for count in posture.counts] == [
        ("critical", 2),
        ("high", 0),
        ("medium", 2),
        ("low", 1),
    ]
    assert posture.counts[0].href == "/changes?status=open&severity=critical"
    assert [segment.severity for segment in posture.segments] == ["low", "medium", "critical"]
    assert posture.description == (
        "5 open change items: 1 low, 2 medium, 0 high, 2 critical. Counts only, not a score."
    )


def test_source_health_covers_failing_insecure_disabled_and_new(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    health = {source.name: source for source in service.load().sources}
    lab = health["lab-controller"]
    assert lab.kind == "failing" and lab.reason == "push failed: no answer within 30 seconds"
    xo = health["office-xo"]
    assert xo.kind == "ok" and xo.insecure and xo.version == "5.108"
    gateway = health["branch-gw"]
    assert gateway.kind == "open" and gateway.reason == "Disabled" and not gateway.enabled
    new = health[HOSTILE_NAME]
    assert new.kind == "open" and new.reason == "No check yet"


def test_a_source_goes_stale_after_three_intervals_and_partial_after_a_partial_run(
    store: Database, service: DashboardService
) -> None:
    quiet = add_source(
        store, "quiet", "unifi", options={"interval_seconds": 600}, last_checked_at=at(minutes=-31)
    )
    add_run(store, quiet, at(minutes=-31))
    partial = add_source(store, "partial", "xo", last_checked_at=at(minutes=-1))
    add_run(store, partial, at(minutes=-1), "partial", error_summary="failed: users (403)")
    recent = at(minutes=-1)
    unsupported = add_source(store, "old", "unifi", last_checked_at=recent, state="unsupported")
    expiring = add_source(store, "exp", "xo", last_checked_at=recent, state="token_expiring")
    add_run(store, expiring, at(minutes=-1))
    health = {source.id: source for source in service.load().sources}
    assert health[quiet].kind == "stale"
    assert health[quiet].reason == "no check for 31 minutes, expected every 600 seconds"
    assert health[partial].kind == "partial"
    assert health[partial].reason == "last check was partial: failed: users (403)"
    assert health[unsupported].kind == "unsupported"
    assert health[expiring].kind == "warn"


def test_the_attention_list_puts_critical_events_first_then_the_sources(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    attention = service.load().attention
    kinds = [(row.badge, row.badge_value) for row in attention]
    assert kinds == [("severity", "critical"), ("status", "failing"), ("status", "insecure")]
    event = attention[0]
    assert event.critical and event.href == f"/changes/{seeded['critical']}"
    assert event.title == "3 changes in 2 resource types, highest severity critical"
    assert event.where == "lab-controller, detected between 10:00 and 11:00 UTC today"
    assert (event.action_label, event.action_href) == (
        "Review",
        f"/changes/{seeded['critical']}#acknowledge",
    )
    failing = attention[1]
    assert failing.title == "lab-controller: push failed: no answer within 30 seconds"
    assert failing.where == "Push source" and failing.action_label == "Open source"
    insecure = attention[2]
    assert insecure.title == "office-xo runs with certificate checks off"
    assert insecure.action_href == f"/sources/{seeded['xo']}#tls"


def test_a_failing_streak_is_counted(store: Database, service: DashboardService) -> None:
    for minutes in (-40, -30, -20):
        add_run(store, 1, at(minutes=minutes), "failed", error_summary="timeout")
    with store.write() as connection:
        connection.execute(
            sa.update(sources).where(sources.c.id == 1).values(last_checked_at=at(minutes=-20))
        )
    lab = service.load().sources[0]
    assert lab.reason == "3 pushes failed in a row: timeout"


def test_a_skipped_run_does_not_hide_a_failing_source(
    store: Database, service: DashboardService
) -> None:
    broken = add_source(store, "CANARY-broken", "xo", last_checked_at=at(minutes=-1))
    add_run(store, broken, at(minutes=-10), "failed", error_summary="CANARY-timeout")
    add_run(store, broken, at(minutes=-1), "skipped")
    health = {source.id: source for source in service.load().sources}[broken]
    assert health.kind == "failing"
    assert health.reason == "check failed: CANARY-timeout"


def test_a_source_with_only_skipped_runs_is_not_failing_or_healthy_by_them(
    store: Database, service: DashboardService
) -> None:
    waiting = add_source(store, "CANARY-waiting", "xo", last_checked_at=at(minutes=-1))
    add_run(store, waiting, at(minutes=-1), "skipped")
    health = {source.id: source for source in service.load().sources}[waiting]
    assert health.kind == "ok"


def test_a_resource_name_is_encoded_in_the_breakdown_link(
    store: Database, service: DashboardService
) -> None:
    source = add_source(store, "CANARY-link", "unifi", last_checked_at=at(minutes=-1))
    add_event(store, source, at(minutes=-5), "low", [("CANARY a&b=c d#e", "low")])
    data = service.load()
    hrefs = [row.href for row in data.by_resource]
    assert "/changes?status=open&resource=CANARY%20a%26b%3Dc%20d%23e" in hrefs
    assert not any("a&b=c" in href for href in hrefs)


def test_the_drift_lines_mark_each_check_or_each_day(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    lines = {row.name: row for row in service.load().driftlines}
    lab = lines["lab-controller"]
    assert not lab.per_day and lab.href == "/sources/1"
    assert lab.meta == "Push source, 3 pushes in 30 days"
    assert [check["kind"] for check in lab.checks] == ["ok", "change", "failed"]
    assert lab.checks[1] == {
        "kind": "change",
        "severity": "critical",
        "summary": "3 changes in 2 resource types, highest severity critical",
        "href": f"/changes/{seeded['critical']}",
    }
    xo = lines["office-xo"]
    assert xo.per_day and len(xo.checks) == 10 and xo.meta.endswith("40 checks in 30 days")
    assert xo.meta.startswith("Xen Orchestra 5.108")
    assert [check["kind"] for check in xo.checks] == [
        "ok",
        "ok",
        "ok",
        "ok",
        "ok",
        "ok",
        "failed",
        "change",
        "ok",
        "ok",
    ]
    assert xo.checks[7]["severity"] == "high"
    assert lines["branch-gw"].checks == () and lines[HOSTILE_NAME].checks == ()
    assert DRIFT_MAX_CHECKS == 31


def test_the_trend_counts_items_per_day_by_severity(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    trend = service.load().trend
    assert trend is not None
    assert len(trend.days) == 30 and trend.days[-1].label == "today"
    assert trend.days[0].label == "29 days ago"
    assert trend.total == 6
    listed = [
        (day.label, day.low, day.medium, day.high, day.critical) for day in trend.days if day.total
    ]
    assert listed == [
        ("9 days ago", 0, 2, 0, 0),
        ("3 days ago", 0, 0, 1, 0),
        ("today", 1, 0, 0, 2),
    ]
    assert [bar.severity for bar in trend.bars] == ["medium", "high", "low", "critical"]
    assert trend.description.startswith("6 change items in the last 30 days; the busiest day had 3")
    assert [line.label for line in trend.grid] == ["3", "2", "1"]


def test_the_breakdowns_count_open_items_by_source_and_resource(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    data = service.load()
    assert [(row.label, row.count, row.width_class) for row in data.by_source] == [
        ("lab-controller", 5, "w-100")
    ]
    assert data.by_source[0].href == "/changes?status=open&source=1"
    assert [(row.label, row.count, row.width_class) for row in data.by_resource] == [
        ("Firewall policies", 2, "w-100"),
        ("Virtual machines", 2, "w-100"),
        ("Networks", 1, "w-50"),
    ]
    assert data.by_resource[0].href == "/changes?status=open&resource=unifi-firewall-policies"


def test_the_activity_timeline_is_newest_first_without_bodies_or_noise(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    activity = service.load().activity
    assert len(activity) <= 20
    assert [entry.when for entry in activity] == sorted(
        (entry.when for entry in activity), reverse=True
    )
    texts = [entry.text + entry.link_label + entry.tail for entry in activity]
    assert texts[0] == "ada added a note on change " + str(seeded["critical"])
    assert texts[1] == "Check of lab-controller failed: no answer within 30 seconds"
    critical_text = "Critical change on lab-controller: 3 changes in 2 resource types, "
    assert critical_text + "highest severity critical" in texts
    assert f"ada acknowledged change {seeded['high']}" in texts
    assert "ada added source office-xo" in texts
    assert "system ran the retention job" not in texts  # older than the 20 newest entries
    assert not any("token.rejected" in text or "rejected" in text for text in texts)
    for canary in CANARIES:
        assert not any(canary in text for text in texts)
    first = activity[0]
    assert first.href == f"/changes/{seeded['critical']}" and first.dot == ""
    critical = next(entry for entry in activity if entry.link_label == "Critical change")
    assert critical.dot == "alert"
    run = next(entry for entry in activity if entry.text == "Check of ")
    assert run.dot == "run" and run.href == "/sources/1"
    added = next(entry for entry in activity if entry.text == "ada added source ")
    assert added.href == f"/sources/{seeded['xo']}"


# ---- the page -------------------------------------------------------------------------------


def test_the_empty_dashboard_shows_the_designed_empty_state(
    store: Database, client: TestClient, auth: AuthService
) -> None:
    with store.write() as connection:
        connection.execute(sa.delete(sources))
    headers = sign_in(client, auth)
    parsed = assert_page(client.get("/", headers=headers))
    text = "".join(parsed.text)
    assert "Nothing to watch yet" in text
    assert {"class": "btn btn--primary", "href": "/sources/new"} in parsed.find("a")
    assert "metric-grid" not in client.get("/", headers=headers).text


def test_the_dashboard_page_renders_every_section_with_text_alternatives(
    client: TestClient, auth: AuthService, seeded: dict[str, int]
) -> None:
    response = client.get("/", headers=sign_in(client, auth))
    parsed = assert_page(response)
    page = response.text
    text = "".join(parsed.text)
    for heading in (
        "Open items by severity",
        "Needs attention",
        "Drift line, last 30 days",
        "Change items per day",
        "Where the open items are",
        "Activity",
    ):
        assert heading in text, heading
    # one primary action, the four stat cards, each a link
    primary = [a for a in parsed.find("a") if a.get("class") == "btn btn--primary"]
    assert primary == [{"class": "btn btn--primary", "href": "/sources/new"}]
    stats = [a for a in parsed.find("a") if a.get("class") == "card metric"]
    assert [a["href"] for a in stats] == [
        "/changes?status=open",
        "/changes?status=open&severity=critical&severity=high",
        "/sources",
        "/settings#about",
    ]
    # every chart is an image with a title and a description
    charts = [svg for svg in parsed.find("svg") if svg.get("role") == "img"]
    assert len(charts) == 2 + 4  # the ring, the trend, four drift lines
    for chart in charts:
        labelled = str(chart["aria-labelledby"]).split()
        assert len(labelled) == 2 and labelled[0].endswith("-t") and labelled[1].endswith("-d")
    assert "Show the numbers as a table" in text
    assert {"class": "visually-hidden"} in parsed.find("caption")
    # the hostile source name is escaped everywhere it appears
    assert "<script>alert(1)</script>" not in page
    assert "eve&lt;script&gt;alert(1)&lt;/script&gt;" in page
    # the critical row is highlighted and the insecure badge is the filled one
    assert {"class": "is-critical"} in parsed.find("li")
    assert "status status--insecure" in page
    # nothing secret, no value, no body
    for canary in CANARIES:
        assert canary not in page, canary
    assert "CANARY" not in page


def test_the_dashboard_page_as_a_plain_client_is_still_the_page(
    client: TestClient, auth: AuthService, seeded: dict[str, int]
) -> None:
    headers = sign_in(client, auth)
    del headers["Accept"]
    response = client.get("/", headers=headers)
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/html")


def test_the_dashboard_with_the_thousand_object_fixture_renders_in_under_half_a_second(
    store: Database, client: TestClient, auth: AuthService
) -> None:
    second = add_source(store, "office-xo", "xo", version="5.108", last_checked_at=at(minutes=-5))
    with store.write() as connection:
        connection.execute(
            sa.update(sources).where(sources.c.id == 1).values(last_checked_at=at(minutes=-5))
        )
        connection.execute(
            sa.insert(objects),
            [
                {
                    "source_id": 1 if index % 2 else second,
                    "resource": "vms" if index % 2 else "unifi-networks",
                    "object_key": f"k{index}",
                    "display_name": f"object {index}",
                    "first_seen_at": at(days=-40),
                    "last_seen_at": at(minutes=-5),
                }
                for index in range(1000)
            ],
        )
        connection.execute(
            sa.insert(runs),
            [
                {
                    "source_id": 1 if index % 2 else second,
                    "started_at": at(days=-(index // 20), minutes=-(index % 20) * 60),
                    "finished_at": at(days=-(index // 20), minutes=-(index % 20) * 60 + 1),
                    "status": "failed" if index % 17 == 0 else "ok",
                    "object_count": 500,
                }
                for index in range(600)
            ],
        )
        connection.execute(
            sa.insert(audit_events),
            [
                {
                    "at": at(days=-index),
                    "actor": "ada",
                    "action": "source.update",
                    "target": "source:1",
                }
                for index in range(50)
            ],
        )
    severities = ("low", "medium", "high", "critical")
    for index in range(100):
        resource = "vms" if index % 2 else "unifi-networks"
        add_event(
            store,
            1 if index % 2 else second,
            at(days=-(index % 30), hours=-(index % 5)),
            severities[index % 4],
            [(resource, severities[(index + k) % 4]) for k in range(20)],
            status="open" if index % 3 else "acknowledged",
        )
    headers = sign_in(client, auth)
    assert_page(client.get("/", headers=headers))  # warms the template cache
    started = time.perf_counter()
    response = client.get("/", headers=headers)
    elapsed = time.perf_counter() - started
    assert response.status_code == 200
    assert elapsed < 0.5, f"the dashboard took {elapsed:.3f} s"
    parsed = Parsed(response.text)
    stats = [a for a in parsed.find("a") if a.get("class") == "card metric"]
    assert len(stats) == 4
    assert len(parsed.find("li")) >= 20
