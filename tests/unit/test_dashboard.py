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
    ACTIVITY_ROWS,
    CHART_BOTTOM,
    CHART_TOP,
    DRIFT_MAX_CHECKS,
    MUTES_HREF,
    RING_CIRCUMFERENCE,
    STORAGE_WARNING_BYTES,
    Dashboard,
    DashboardService,
    SourceHealth,
    TrendDay,
    attention_empty_text,
    audit_target,
    chart_top,
    day_label,
    delta_text,
    delta_tone,
    empty_ticks,
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
from driftsniff.web.templating import drift_marks

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


def add_audit(
    store: Database,
    when: str,
    actor: str,
    action: str,
    target: str | None,
    detail: dict[str, object] | None = None,
) -> None:
    with store.write() as connection:
        connection.execute(
            sa.insert(audit_events).values(
                at=when, actor=actor, action=action, target=target, detail=detail
            )
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


def _health(name: str, kind: str, *, enabled: bool = True) -> SourceHealth:
    return SourceHealth(1, name, "xo", enabled, kind, "", False, None, "/sources/1")


def test_the_empty_attention_sentence_matches_the_sources() -> None:
    healthy = _health("a", "ok")
    off = _health("b", "open", enabled=False)
    every = attention_empty_text([healthy])
    assert every.endswith("and every source is healthy.")
    with_off = attention_empty_text([healthy, off])
    assert "every source is healthy" not in with_off
    assert with_off.endswith("every enabled source is healthy. 1 disabled source is not checked.")
    two_off = attention_empty_text([healthy, off, _health("c", "open", enabled=False)])
    assert two_off.endswith("2 disabled sources are not checked.")
    all_off = attention_empty_text([off])
    assert all_off.startswith("Nothing is being checked: every source is disabled.")
    assert "healthy" not in all_off


def test_audit_targets_read_as_names_and_never_as_raw_ids() -> None:
    names = {3: "office-xo"}
    assert audit_target("source:3", names) == ("office-xo", "/sources/3")
    assert audit_target("source:9", names) == ("source 9", "/sources/9")
    assert audit_target("event:2", names) == ("change 2", "/changes/2")
    detail = {"resource": "unifi-firewall-policies", "path_pattern": "name"}
    assert audit_target("mute:7", names, detail) == ("Firewall policies", MUTES_HREF)
    assert audit_target("mute:7", names) == ("a resource type", MUTES_HREF)
    # a plain target (a user name, a token prefix, a channel type) is already readable
    assert audit_target("bob", names) == ("bob", "")
    assert audit_target("", names) == ("", "")


def test_the_empty_trend_has_one_tick_per_day_across_the_strip() -> None:
    ticks = empty_ticks(30)
    assert len(ticks) == 30
    assert (ticks[0], ticks[1], ticks[-1]) == ("9.0", "29.0", "589.0")
    assert empty_ticks(0) == ()


def _css_rules() -> dict[str, list[str]]:
    """The rule bodies of app.css by selector, comments removed, in source order; a selector
    list gives its body to every selector it names."""
    stylesheet = Path(__file__).resolve().parents[2] / "src" / "driftsniff" / "web" / "static"
    css = (stylesheet / "app.css").read_text(encoding="utf-8")
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    rules: dict[str, list[str]] = {}
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        for name in (part.strip() for part in selector.split(",")):
            rules.setdefault(name, []).append(body)
    return rules


def _column_tracks(rules: dict[str, list[str]], selector: str) -> list[str]:
    """The grid-template-columns values declared for the selector, widest viewport first."""
    tracks: list[str] = []
    for body in rules[selector]:
        found = re.search(r"grid-template-columns:\s*([^;]+);", body)
        if found is not None:
            tracks.append(found.group(1).strip())
    return tracks


def test_the_dashboard_grids_cannot_widen_the_page() -> None:
    """G1: every track of the dashboard grids is minmax(0, ...), at every width, so a wide child
    (the trend chart, a long stat value) scrolls or wraps inside its card instead of making the
    page scroll sideways."""
    rules = _css_rules()
    assert _column_tracks(rules, ".grid-2") == [
        "minmax(0, 1fr) minmax(0, 1fr)",
        "minmax(0, 1fr)",
    ]
    assert _column_tracks(rules, ".grid-5-7") == [
        "minmax(0, 5fr) minmax(0, 7fr)",
        "minmax(0, 1fr)",
    ]
    assert _column_tracks(rules, ".stat-grid") == [
        "repeat(4, minmax(0, 1fr))",
        "repeat(2, minmax(0, 1fr))",
        "minmax(0, 1fr)",
    ]


def test_the_severity_list_wraps_under_the_ring_instead_of_leaving_its_card() -> None:
    """THE-1240: at 1024 px the 5fr card is about 287 px wide, and a 160px 1fr grid pushed the
    166 px severity list 89 px out of it, under Needs attention. The posture is a wrapping flex
    row: the ring keeps its 160 px, the list has a zero basis and the default min-width, so it
    moves under the ring as soon as its widest row no longer fits beside it, at every width."""
    rules = _css_rules()
    posture = "".join(rules[".posture"])
    ring = "".join(rules[".posture > svg"])
    listing = "".join(rules[".posture-list"])
    assert re.search(r"display:\s*flex", posture)
    assert re.search(r"flex-wrap:\s*wrap", posture)
    assert _column_tracks(rules, ".posture") == []
    assert re.search(r"flex:\s*none", ring)
    assert re.search(r"width:\s*160px", ring)
    assert re.search(r"flex:\s*1 1 0;", listing)
    # min-width: 0 would let the rows shrink below their content and spill again
    assert "min-width" not in listing


def test_a_narrow_attention_list_gives_the_text_its_own_line() -> None:
    """THE-1255: at 1024 px the 7fr card leaves the list 351 px, and the three columns of a row
    (a 167 px "Nothing pushed yet" badge, the text, a 112 px "Open source" button) squeezed the
    title to "pilo..." and its line to one word per line. The list is a size container; below
    its breakpoint the badge and the action share the first line and the text spans the row
    under them, wrapping instead of clipping. The breakpoint is above 351 px and leaves the
    text at least 200 px beside the widest badge and button, at 1024 px and on a phone alike."""
    css = (
        Path(__file__).resolve().parents[2] / "src" / "driftsniff" / "web" / "static" / "app.css"
    ).read_text(encoding="utf-8")
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    rules = _css_rules()
    assert re.search(r"container:\s*attention\s*/\s*inline-size", "".join(rules[".attention"]))
    query = re.search(r"@container attention \(max-width:\s*(\d+)px\)\s*\{(.*?)\n\}", css, re.S)
    assert query is not None
    breakpoint, narrow = int(query.group(1)), query.group(2)
    assert 351 < breakpoint
    assert breakpoint - 167 - 112 - 2 * 12 >= 200
    assert re.search(
        r"\.attention li\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\) auto;", narrow
    )
    what = re.search(r"\.attention \.what\s*\{([^}]*)\}", narrow)
    assert what is not None
    assert re.search(r"grid-column:\s*1\s*/\s*-1", what.group(1))
    assert re.search(r"grid-row:\s*2", what.group(1))
    title = re.search(r"\.attention \.what a\s*\{([^}]*)\}", narrow)
    assert title is not None
    assert re.search(r"white-space:\s*normal", title.group(1))
    # a viewport rule would miss the 1024 px card, so the row layout follows the list only
    for media in re.finditer(r"@media[^{]*\{", css):
        depth, end = 1, media.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(css[end], 0)
            end += 1
        assert ".attention li" not in css[media.end() : end], media.group(0)


def test_the_trend_chart_fits_a_desktop_card_and_opens_on_today() -> None:
    """THE-1371: at 1440 px the half-width card leaves 502 px for the chart, and a 520 px
    minimum hid the y-axis labels behind the scroll that opens on today. The chart is a 30 unit
    y-axis beside a 570 unit plot at one scale; it may shrink to 480 px. Narrower, only the plot
    scrolls (from the right, so today is in view first) and the y-axis stays beside it."""
    rules = _css_rules()
    chart = "".join(rules[".chart"])
    wrap = "".join(rules[".chart-wrap"])
    frame = re.search(
        r"grid-template-columns:\s*max\(5%,\s*(\d+)px\)\s+minmax\(0,\s*1fr\);",
        "".join(rules[".chart-frame"]),
    )
    plot = re.search(r"min-width:\s*(\d+)px", chart)
    assert frame is not None and plot is not None
    axis, plot_min = int(frame.group(1)), int(plot.group(1))
    # 5 % of the frame is 30 of 600 units: both drawings share one scale at every width
    assert axis * 570 == plot_min * 30
    assert axis + plot_min <= 502
    assert re.search(r"overflow-x:\s*auto", wrap)
    assert re.search(r"direction:\s*rtl", wrap)
    assert re.search(r"direction:\s*ltr", chart)
    assert re.search(r"display:\s*block", chart)
    assert re.search(r"overflow:\s*visible", "".join(rules[".chart-axis"]))


def test_the_trend_chart_axis_labels_are_html_text_at_the_14_px_floor() -> None:
    """THE-1402 F3: as SVG text the 15 unit labels shrank with the drawing to 12 px at 1440 and
    390 px. They are HTML text at 14 px now: the y-axis column is as tall as the 154 unit plot
    and spreads its labels from the top grid line to the baseline, as the grid lines are spread;
    the time axis is as wide as the plot and scrolls with it."""
    rules = _css_rules()
    for selector in (".chart-axis .axis-label", ".chart-days"):
        assert re.search(r"font-size:\s*var\(--fs-14\)", "".join(rules[selector])), selector
    assert ".chart .axis-label" not in rules
    column = "".join(rules[".chart-axis"])
    assert re.search(r"aspect-ratio:\s*30\s*/\s*154", column)
    labels = "".join(rules[".chart-axis__labels"])
    top = re.search(r"top:\s*calc\(100%\s*\*\s*(\d+)\s*/\s*154\)", labels)
    bottom = re.search(r"bottom:\s*calc\(100%\s*\*\s*(\d+)\s*/\s*154\)", labels)
    assert top is not None and bottom is not None
    assert int(top.group(1)) == CHART_TOP and 154 - int(bottom.group(1)) == CHART_BOTTOM
    assert re.search(r"justify-content:\s*space-between", labels)
    days = "".join(rules[".chart-days"])
    assert re.search(r"min-width:\s*456px", days) and re.search(r"direction:\s*ltr", days)
    _, grid = trend_geometry([TrendDay("x", 1, 0, 0, 0)] * 30)
    # the labels are spread evenly, so the grid lines must be: thirds of the plot height
    assert [float(line.y) for line in grid] == [30.0, 70.0, 110.0]


def test_the_trend_row_stacks_before_its_cards_are_too_narrow_for_the_chart() -> None:
    """THE-1371: the half-width card at 1024 px leaves 294 px, so the trend row keeps two
    columns only while a card holds the whole chart (its minimum plus 50 px of padding and
    border): two columns at 1440 px, stacked at 1024 px, and never wider than the row."""
    rules = _css_rules()
    plot = re.search(r"min-width:\s*(\d+)px", "".join(rules[".chart"]))
    frame = re.search(r"max\(5%,\s*(\d+)px\)", "".join(rules[".chart-frame"]))
    (tracks,) = _column_tracks(rules, ".grid-2--chart")
    card = re.fullmatch(r"repeat\(auto-fit,\s*minmax\(min\(100%,\s*(\d+)px\),\s*1fr\)\)", tracks)
    assert plot is not None and frame is not None and card is not None
    card_min = int(card.group(1))
    assert card_min == int(frame.group(1)) + int(plot.group(1)) + 50
    sidebar, padding, gap = 248, 2 * 32, 24
    assert 2 * card_min + gap <= 1440 - sidebar - padding
    assert 2 * card_min + gap > 1024 - sidebar - padding


def test_the_breakdown_bars_have_a_visible_fill() -> None:
    """The track and fill of "Where the open items are" are spans; inline, the fill ignored its
    width class and height, so every bar showed as an empty track on Development."""
    rules = _css_rules()
    for selector in (".bars .track", ".bars .fill"):
        body = "".join(rules[selector])
        assert re.search(r"display:\s*block", body), selector
    assert re.search(r"height:\s*100%", "".join(rules[".bars .fill"]))
    assert re.search(r"width:\s*70%", "".join(rules[".bars .w-70"]))


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
    # the disabled source is named too, so the card's parts add up to its total of four
    assert healthy.delta == "1 disabled, 1 failing, 1 no check yet" and healthy.delta_tone == "up"
    assert storage.label == "Storage used" and storage.unit == "MB"
    # the About section of the settings page (P10-T8), a link for admins only
    assert storage.href == "/settings#about" and storage.admin_only


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
    # sources in name order: the never-checked hostile one, then lab-controller, then office-xo;
    # the disabled branch-gw has no row
    assert kinds == [
        ("severity", "critical"),
        ("status", "open"),
        ("status", "failing"),
        ("status", "insecure"),
    ]
    event = attention[0]
    assert event.critical and event.href == f"/changes/{seeded['critical']}"
    assert event.title == "3 changes in 2 resource types, highest severity critical"
    assert event.where == "lab-controller, detected between 10:00 and 11:00 UTC today"
    assert (event.action_label, event.action_href) == (
        "Review",
        f"/changes/{seeded['critical']}#acknowledge",
    )
    never = attention[1]
    assert never.title == f"{HOSTILE_NAME}: no check yet"
    assert never.badge_text == "No check yet" and never.href == f"/sources/{seeded['hostile']}"
    assert never.where == "Waiting for its first check; changes appear after it"
    assert (never.action_label, never.action_href) == ("Open source", never.href)
    failing = attention[2]
    assert failing.title == "lab-controller: push failed: no answer within 30 seconds"
    assert failing.where == "Push source" and failing.action_label == "Open source"
    insecure = attention[3]
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
    # each check is aged from when it finished, so it is drawn at its time (THE-1402 F2)
    assert [check["age"] * 48 for check in lab.checks] == pytest.approx([4, 2, 1])
    assert lab.checks[1] == {
        "kind": "change",
        "age": lab.checks[1]["age"],
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
    # one mark per day, at its day: ten days ago up to yesterday
    assert [check["age"] for check in xo.checks] == [float(day) for day in range(10, 0, -1)]
    assert lines["branch-gw"].checks == () and lines[HOSTILE_NAME].checks == ()
    assert DRIFT_MAX_CHECKS == 31


def test_the_checks_of_the_last_hours_are_drawn_at_the_today_end_of_the_strip(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    """THE-1402 F2: three pushes of the last two hours were drawn at x 8, 28 and 48, beside
    "30 days ago"; they belong beside "today", one hour being 20 / 24 of a unit."""
    lines = {row.name: row for row in service.load().driftlines}
    lab = {mark.kind: mark.x for mark in drift_marks(lines["lab-controller"].checks)}
    assert lab == {"ok": 608.3, "change": 609.2, "failed": 609.6}
    office = drift_marks(lines["office-xo"].checks)
    assert [mark.x for mark in office if mark.kind != "change"][-1] == 590.0
    (high,) = [mark for mark in office if mark.kind == "change"]
    assert high.x == 550.0 and high.severity == "high"


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
    # an acknowledgement or a note names the source of its change
    assert texts[0] == f"ada added a note to change {seeded['critical']} on lab-controller"
    assert texts[1] == "Check of lab-controller failed: no answer within 30 seconds"
    critical_text = "Critical change on lab-controller: 3 changes in 2 resource types, "
    assert critical_text + "highest severity critical" in texts
    assert f"ada acknowledged change {seeded['high']} on office-xo" in texts
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


def test_the_activity_names_every_target_and_lists_an_acknowledgement_once(
    store: Database, service: DashboardService, seeded: dict[str, int]
) -> None:
    """G3: the audit rows of an acknowledgement and a note repeat their own entries and are left
    out; a mute names its resource type; no entry shows a raw ``kind:id`` target."""
    high, critical = seeded["high"], seeded["critical"]
    add_audit(store, at(days=-2), "ada", "change.acknowledged", f"event:{high}")
    add_audit(store, at(minutes=-20), "ada", "change.note_added", f"event:{critical}")
    mute = {"resource": "unifi-firewall-policies", "path_pattern": "name", "item_id": 1}
    add_audit(store, at(minutes=-15), "ada", "mute.added", "mute:7", mute)
    add_audit(store, at(minutes=-14), "ada", "mute.removed", "mute:7", mute)
    activity = service.load().activity
    texts = [entry.text + entry.link_label + entry.tail for entry in activity]
    assert not any(re.search(r"\b(event|mute|source):\d", text) for text in texts), texts
    assert sum("acknowledged" in text for text in texts) == 1
    assert texts.count(f"ada acknowledged change {high} on office-xo") == 1
    assert sum("note" in text for text in texts) == 1
    assert texts.count(f"ada added a note to change {critical} on lab-controller") == 1
    assert "ada muted a path of Firewall policies" in texts
    assert "ada removed a mute of Firewall policies" in texts
    muted = next(entry for entry in activity if entry.text == "ada muted a path of ")
    assert muted.href == MUTES_HREF
    assert "name" not in muted.tail and muted.tail == ""


def test_the_activity_shows_eight_rows_and_keeps_the_rest_for_the_disclosure(
    service: DashboardService, seeded: dict[str, int]
) -> None:
    data = service.load()
    assert len(data.activity) == 20
    assert ACTIVITY_ROWS == 8
    assert data.activity_rows == data.activity[:8]
    assert data.activity_earlier == data.activity[8:] and len(data.activity_earlier) == 12


def test_a_never_checked_push_source_asks_for_its_first_push(
    store: Database, service: DashboardService
) -> None:
    attention = service.load().attention
    assert [(row.badge_value, row.title) for row in attention] == [
        ("open", "lab-controller: nothing pushed yet")
    ]
    assert attention[0].where == "Waiting for its sender's first push; changes appear after it"


def test_an_empty_attention_list_says_why_without_contradicting_the_card(
    store: Database, service: DashboardService
) -> None:
    """G2: one healthy source and one disabled one: nothing waits, but the card counts the
    disabled source, so the list never says that every source is healthy."""
    with store.write() as connection:
        connection.execute(
            sa.update(sources).where(sources.c.id == 1).values(last_checked_at=at(minutes=-5))
        )
    add_run(store, 1, at(minutes=-5))
    add_source(store, "branch-gw", "unifi", enabled=False, last_checked_at=at(days=-9))
    data = service.load()
    assert data.attention == ()
    healthy = data.stats[2]
    assert (healthy.value, healthy.unit, healthy.delta) == ("1", "of 2", "1 disabled")
    assert healthy.delta_tone == ""
    assert "every source is healthy" not in data.attention_empty
    assert data.attention_empty.endswith("1 disabled source is not checked.")


def test_every_source_healthy_is_said_only_when_the_card_agrees(
    store: Database, service: DashboardService
) -> None:
    with store.write() as connection:
        connection.execute(
            sa.update(sources).where(sources.c.id == 1).values(last_checked_at=at(minutes=-5))
        )
    add_run(store, 1, at(minutes=-5))
    data = service.load()
    assert data.attention == () and data.stats[2].delta == "every source is healthy"
    assert data.attention_empty.endswith("and every source is healthy.")


def test_more_open_urgent_changes_than_the_list_shows_are_counted(
    store: Database, service: DashboardService
) -> None:
    for minutes in range(10):
        add_event(store, 1, at(minutes=-minutes - 1), "high", [("vms", "high")])
    add_event(store, 1, at(minutes=-30), "medium", [("vms", "medium")])
    data = service.load()
    assert sum(1 for row in data.attention if row.badge == "severity") == 8
    assert data.attention_more == 2


def test_no_change_item_in_thirty_days_gives_the_empty_trend(
    store: Database, service: DashboardService
) -> None:
    trend = service.load().trend
    assert trend is not None
    assert trend.total == 0 and trend.bars == ()
    assert len(trend.ticks) == 30 and trend.description == "No change items in the last 30 days."


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
    assert "stat-grid" not in client.get("/", headers=headers).text


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
    # one primary action, the four stat cards, each a link (storage: an admin's, /settings)
    primary = [a for a in parsed.find("a") if a.get("class") == "btn btn--primary"]
    assert primary == [{"class": "btn btn--primary", "href": "/sources/new"}]
    stats = [a for a in parsed.find("a") if a.get("class") == "card metric"]
    assert [a["href"] for a in stats] == [
        "/changes?status=open",
        "/changes?status=open&severity=critical&severity=high",
        "/sources",
        "/settings#about",
    ]
    assert parsed.find("div").count({"class": "card metric"}) == 0
    assert {"href": "/settings"} in parsed.find("a")  # the sidebar's Admin > Settings
    # every chart is an image with a title and a description; a drift line with change links
    # is a group instead, so its links are not hidden inside an image (THE-1351)
    charts = [svg for svg in parsed.find("svg") if svg.get("role") in ("img", "group")]
    assert len(charts) == 2 + 4  # the ring, the trend, four drift lines
    assert [svg for svg in charts if svg.get("role") == "group"]
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


def test_a_viewer_or_an_operator_gets_the_storage_card_without_the_settings_link(
    client: TestClient, auth: AuthService, seeded: dict[str, int]
) -> None:
    # /settings answers 403 to them, so neither the card nor the sidebar points there
    for role in ("viewer", "operator"):
        auth.create_user(f"{role}-1", CORRECT, role)
        response = client.post("/login", data={"username": f"{role}-1", "password": CORRECT})
        assert response.status_code == 303, response.text
        match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
        assert match is not None
        client.cookies.clear()
        headers = {**BROWSER, "Cookie": f"{SESSION_COOKIE}={match.group(1)}"}
        parsed = assert_page(client.get("/", headers=headers))
        stats = [a["href"] for a in parsed.find("a") if a.get("class") == "card metric"]
        assert len(stats) == 3 and "/settings#about" not in stats, role
        assert parsed.find("div").count({"class": "card metric"}) == 1, role
        assert not [a for a in parsed.find("a") if str(a.get("href")).startswith("/settings")]
        assert "Storage used" in "".join(parsed.text), role


def test_the_dashboard_page_shows_eight_activity_rows_and_a_disclosure_of_the_rest(
    client: TestClient, auth: AuthService, seeded: dict[str, int]
) -> None:
    response = client.get("/", headers=sign_in(client, auth))
    parsed = assert_page(response)
    page = response.text
    text = "".join(parsed.text)
    timelines = re.findall(r'<ol class="timeline">(.*?)</ol>', page, flags=re.DOTALL)
    assert [timeline.count("<li>") for timeline in timelines] == [8, 12]
    assert {"class": "disclosure activity-earlier"} in parsed.find("details")
    assert "Show 12 earlier entries" in text
    assert "of the last 20 entries" not in text
    # the readable labels link to their pages, and no raw target is printed
    assert f'<a href="/changes/{seeded["critical"]}">change {seeded["critical"]}</a>' in page
    assert not re.search(r"\b(event|mute|source):\d", text)
    # G2: the never-checked source has its row and the card counts the disabled one
    assert f"{HOSTILE_NAME}: no check yet" in text
    assert "1 disabled, 1 failing, 1 no check yet" in text


def test_the_page_links_the_urgent_changes_the_list_has_no_room_for(
    store: Database, client: TestClient, auth: AuthService
) -> None:
    for minutes in range(9):
        add_event(store, 1, at(minutes=-minutes - 1), "critical", [("vms", "critical")])
    response = client.get("/", headers=sign_in(client, auth))
    parsed = assert_page(response)
    more = '<a href="/changes?status=open&amp;severity=critical&amp;severity=high">'
    assert more + "1 more open critical and high change</a>" in response.text
    assert len([li for li in parsed.find("li") if li.get("class") == "is-critical"]) == 8


def test_the_page_says_why_the_attention_list_is_empty(
    store: Database, client: TestClient, auth: AuthService
) -> None:
    with store.write() as connection:
        connection.execute(
            sa.update(sources).where(sources.c.id == 1).values(last_checked_at=at(minutes=-5))
        )
    add_run(store, 1, at(minutes=-5))
    add_source(store, "branch-gw", "unifi", enabled=False, last_checked_at=at(days=-9))
    response = client.get("/", headers=sign_in(client, auth))
    text = "".join(assert_page(response).text)
    assert "1 disabled source is not checked." in text
    assert "every source is healthy" not in text


def test_the_empty_trend_is_a_designed_state_not_a_bare_grid(
    store: Database, client: TestClient, auth: AuthService
) -> None:
    response = client.get("/", headers=sign_in(client, auth))
    parsed = assert_page(response)
    page = response.text
    text = "".join(parsed.text)
    assert '<svg class="chart"' not in page and "Show the numbers as a table" not in text
    assert {"class": "trend-empty"} in parsed.find("div")
    ticks = [rect for rect in parsed.find("rect") if rect.get("class") == "trend-empty__tick"]
    assert len(ticks) == 30
    labels = [(svg.get("aria-labelledby"), svg.get("role")) for svg in parsed.find("svg")]
    assert ("trend-t trend-d", "img") in labels
    assert "No change items in the last 30 days" in text
    assert "this chart shows one bar per day, stacked by severity" in text


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
    assert len(stats) == 4  # an admin's storage card links to /settings#about too
    assert len(parsed.find("li")) >= 20
