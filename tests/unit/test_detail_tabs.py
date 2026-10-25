"""The detail pages of the UI revision WP3 (THE-1161, plan THE-1052 section 2): a summary head,
the tabs under it and the side panel.

- One source reads as one thing: its page (Overview, with Coverage and Runs as parts of it), its
  History and its Configuration share the same tab strip, with the page they sit on current.
- The source page puts its parts in a main column beside the side panel (the facts and the
  delete); every tab that jumps lands on an element of that id.
- The change detail names its parts with their stored counts and jumps to each one.
- The detail head sheet never widens the page on a phone (found in the browser preview at
  390 px): the strip is the containing block of its hidden words, the columns are
  minmax(0, 1fr) and the strip wraps.

The templates render with synthetic fixture views; nothing here reads a database.
"""

import re
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path

from driftsniff.changes.paths import mute_refusal
from driftsniff.changes.views import (
    AcknowledgementRow,
    ChangeDetailView,
    ChangeRow,
    ItemView,
    NoteRow,
    ObjectGroup,
)
from driftsniff.history.views import SnapshotPageView, SourceRef
from driftsniff.sources.service import SourceView
from driftsniff.web import change_pages
from driftsniff.web.dashboard import DriftRow, SourceHealth, parse_stamp, resource_label
from driftsniff.web.history_pages import configuration_href, ledger_mark, range_text, size_text
from driftsniff.web.source_pages import CoverageRow, RunEntry, SourceDetail
from driftsniff.web.templating import TEMPLATES_DIR, Shell, render

NOW = datetime(2026, 10, 24, 21, 0, tzinfo=UTC)
CSRF = "CANARY-csrf-value"
SHEET = Path(TEMPLATES_DIR).parent / "static" / "summary-head.css"


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

    def ids(self) -> set[str]:
        return {str(attrs["id"]) for _tag, attrs in self.tags if attrs.get("id")}

    def no_style(self) -> None:
        for tag, attrs in self.tags:
            assert "style" not in attrs, f"<{tag}> carries a style attribute"


def shell(role: str, nav: str) -> Shell:
    return Shell(title="t", nav_current=nav, user_name=role, user_role=role, csrf_token=CSRF)


def roles(role: str) -> dict[str, bool]:
    return {"can_operate": role in ("operator", "admin"), "can_admin": role == "admin"}


def tabs_of(text: str) -> list[tuple[str, str | None, str]]:
    """The tab strip of a page: (href, aria-current, words) for each link."""
    strip = re.search(r'<nav class="tabs"[^>]*>(.*?)</nav>', text, re.S)
    assert strip is not None, "no tab strip"
    links = re.findall(r'<a href="([^"]*)"((?: aria-current="page")?)>(.*?)</a>', strip.group(1))
    return [
        (href, "page" if current else None, " ".join(re.sub(r"<[^>]+>", " ", words).split()))
        for href, current, words in links
    ]


# ---- the source page --------------------------------------------------------------------------


def source_detail(polled: bool, *, checks: int = 0) -> SourceDetail:
    view = SourceView(
        id=2,
        name="FIXTURE source",
        type="unifi" if polled else "push",
        base_url="https://unifi.fixture.example" if polled else None,
        options={},
        enabled=True,
        state="ok",
        has_credential=polled,
        last_checked_at=None,
        last_success_at=None,
        controller_version=None,
    )
    health = SourceHealth(2, view.name, view.type, True, "ok", "", False, None, "/sources/2")
    marks = tuple({"kind": "ok", "severity": "", "summary": "", "href": ""} for _ in range(checks))
    coverage = (CoverageRow("networks", "Networks", "200", "ok", "200 OK", "", 3, NOW),)
    runs = (RunEntry("", "No change", NOW - timedelta(hours=1)),) if polled else ()
    return SourceDetail(
        now=NOW,
        view=view,
        health=health,
        status_text="Healthy",
        last_attempt=None,
        badges=(),
        driftline=DriftRow(view.name, "/sources/2", "meta", "src", marks, False),
        coverage=coverage,
        runs=runs,
        object_count=3,
        type_label="UniFi Network" if polled else "Push source",
        interval="Every 15 minutes",
        tls_mode="verify",
        tls_label="Verify the certificate",
        credential_label="API key",
        expires_on=None,
        expiring=False,
        resources_total=1,
        resources_off=(),
    )


def render_source(detail: SourceDetail, role: str = "viewer") -> str:
    return render(
        "sources/detail.html",
        shell(role, "sources"),
        detail=detail,
        notice=None,
        problem=None,
        delete_error="",
        push_key="",
        replay=None,
        scheduled=True,
        **roles(role),
    )


def test_the_source_page_carries_the_source_tabs_with_overview_current() -> None:
    text = render_source(source_detail(True))
    assert tabs_of(text) == [
        ("/sources/2", "page", "Overview"),
        ("/sources/2#coverage", None, "Coverage"),
        ("/sources/2#runs", None, "Runs"),
        ("/history/2", None, "History"),
        ("/configuration/2", None, "Configuration"),
    ]
    Parsed(text).no_style()


def test_every_jump_of_the_source_tabs_lands_on_its_part() -> None:
    for polled in (True, False):
        text = render_source(source_detail(polled), "admin")
        parsed = Parsed(text)
        ids = parsed.ids()
        for href, _current, _words in tabs_of(text):
            if href.startswith("/sources/2#"):
                assert href.split("#", 1)[1] in ids, href
        sections = parsed.find("section")
        targets = [a.get("id") for a in sections if "jump-target" in str(a.get("class"))]
        # the replay is a jump target too: its window links land on it (WP4c, THE-1197)
        assert targets == ["overview", "replay", "coverage", "runs"]


def test_the_source_page_puts_its_facts_and_the_delete_in_the_side_panel() -> None:
    text = render_source(source_detail(True), "admin")
    side = text.split('<div class="side detail-side">', 1)
    assert len(side) == 2, "no side panel"
    main = side[0].split('<div class="stack detail-main">', 1)[1]
    assert 'id="coverage"' in main and 'id="runs"' in main
    assert "About this source" in side[1] and 'action="/sources/2/delete"' in side[1]
    # the side panel links to the changes of the source; the tabs replace the two text links
    assert '<a href="/changes?source=2">Changes of this source</a>' in side[1]
    assert "Reading history" not in text and "Current configuration" not in text
    viewer = render_source(source_detail(True)).split('<div class="side detail-side">', 1)[1]
    assert "/delete" not in viewer


def test_an_empty_drift_line_says_why_it_has_no_mark() -> None:
    polled = Parsed(render_source(source_detail(True)))
    assert "No check in the last 30 days" in " ".join(polled.text)
    push = Parsed(render_source(source_detail(False)))
    assert "Nothing pushed in the last 30 days" in " ".join(push.text)
    drawn = Parsed(render_source(source_detail(True, checks=3)))
    assert "in the last 30 days, so the line has no mark yet" not in " ".join(drawn.text)


# ---- the History and Configuration heads ------------------------------------------------------


UNIFI = SourceRef(id=2, name="FIXTURE source", type="unifi", enabled=True)


def render_history(role: str = "viewer") -> str:
    view = SnapshotPageView(UNIFI, (), 0, 0, 1, 1, 50)
    return render(
        "history/snapshots.html",
        shell(role, "history"),
        view=view,
        now=NOW,
        pager=(),
        summary=range_text(0, 1, 50, "reading"),
        ledger_mark=ledger_mark,
        size_text=size_text,
        parse_stamp=parse_stamp,
        count_words=change_pages.count_words,
        configuration_href=configuration_href(2),
        type_label="UniFi Network",
        polled=True,
        scheduled=True,
        **roles(role),
    )


def test_the_history_head_is_the_source_head_with_history_current() -> None:
    text = render_history()
    current = [(href, words) for href, mark, words in tabs_of(text) if mark]
    assert current == [("/history/2", "History")]
    assert [href for href, _mark, _words in tabs_of(text)] == [
        "/sources/2",
        "/sources/2#coverage",
        "/sources/2#runs",
        "/history/2",
        "/configuration/2",
    ]
    # a viewer gets no action, so the head has no empty action box
    assert "page-header__actions" not in text
    actions = render_history("admin").split('<div class="page-header__actions">', 1)[1]
    head = Parsed(actions.split('<nav class="tabs"', 1)[0])
    # Run now is the one primary action of the head; Edit source its only other button
    assert [a.get("class") for a in head.find("button")] == ["btn btn--primary"]
    assert head.find("a") == [{"class": "btn", "href": "/sources/2/edit"}]


# ---- the change detail ------------------------------------------------------------------------


def item(number: int, severity: str, path: str) -> ItemView:
    return ItemView(
        id=number,
        resource="unifi-networks",
        object_name="FIXTURE Office",
        change_kind="modified",
        path=path,
        field_class="config",
        severity=severity,
        rule_id="unifi.networks.vlan",
        rationale="FIXTURE rationale",
        rationale_recorded=True,
        before="10",
        after="11",
        before_fingerprint=None,
        after_fingerprint=None,
        secret=False,
        muted=False,
        mutable=True,
    )


def render_change(role: str = "operator") -> str:
    groups = (
        ObjectGroup("unifi-networks", 11, "FIXTURE Office", (item(1, "medium", "vlanId"),)),
        ObjectGroup(
            "unifi-networks",
            12,
            "FIXTURE Guest",
            (item(2, "low", "name"), item(3, "medium", "vlanId")),
        ),
    )
    change = ChangeRow(
        id=3,
        source_id=2,
        source_name="FIXTURE source",
        severity="medium",
        status="open",
        summary="FIXTURE change",
        item_count=3,
        window_start="2026-10-24T16:00:00Z",
        window_end="2026-10-24T17:00:00Z",
        created_at="2026-10-24T17:00:01Z",
        rule_pack_version="1.4.0",
    )
    detail = ChangeDetailView(
        change=change,
        groups=groups,
        items_truncated=False,
        acknowledgements=(AcknowledgementRow(1, "operator", "", "2026-10-24T18:00:00Z"),),
        notes=(
            NoteRow(1, "admin", "FIXTURE note", "2026-10-24T18:30:00Z"),
            NoteRow(2, "operator", "FIXTURE note", "2026-10-24T19:00:00Z"),
        ),
        enrichments=(),
    )
    return render(
        "changes/detail.html",
        shell(role, "changes"),
        status=200,
        detail=detail,
        change=change,
        now=NOW,
        window="between 16:00 and 17:00 UTC today",
        counts="3 items in 2 objects",
        notice=None,
        problem=None,
        ack_error="",
        note_error="",
        ack_comment="",
        note_body="",
        ack_limit=2000,
        note_limit=4000,
        reason_limit=200,
        parse_stamp=parse_stamp,
        resource_label=resource_label,
        field_label=change_pages.field_label,
        kind_label=change_pages.kind_label,
        item_summary=change_pages.item_summary,
        move_text=change_pages.move_text,
        fingerprint_words=change_pages.fingerprint_words,
        display_value=change_pages.display_value,
        split_difference=change_pages.split_difference,
        mute_refusal=mute_refusal,
        count_words=change_pages.count_words,
        can_operate=role in ("operator", "admin"),
    )


def test_the_change_tabs_name_each_part_with_its_stored_count() -> None:
    for role in ("viewer", "operator"):
        text = render_change(role)
        # the count is read with its label: a hidden comma keeps "What changed, 3" apart
        assert tabs_of(text) == [
            ("#items", None, "What changed , 3"),
            ("#external", None, "External analysis , 0"),
            ("#acknowledge", None, "Acknowledgements , 1"),
            ("#notes", None, "Notes , 2"),
        ]
        ids = Parsed(text).ids()
        for href, _mark, _words in tabs_of(text):
            assert href[1:] in ids, href
        Parsed(text).no_style()


def test_each_object_group_says_how_many_items_it_holds() -> None:
    counts = re.findall(r'<span class="object-group__count">([^<]*)</span>', render_change())
    assert counts == ["1 item", "2 items"]


def test_the_change_detail_loads_the_detail_head_sheet() -> None:
    links = Parsed(render_change()).find("link")
    sheets = [a.get("href") for a in links if a.get("rel") == "stylesheet"]
    assert sheets == ["/static/app.css", "/static/summary-head.css"]


# ---- the sheet --------------------------------------------------------------------------------


def rule(text: str, selector: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", text)
    assert match is not None, f"no rule for {selector}"
    return match.group(1)


def test_the_detail_sheet_never_widens_the_page_on_a_phone() -> None:
    text = SHEET.read_text(encoding="utf-8")
    assert "#" not in text  # the tokens of app.css only, no colour of its own
    # the visually hidden comma of a count is absolutely placed: without a containing block on
    # the strip it escaped the strip's scroll box and made a 390 px page 553 px wide
    assert "position: relative" in rule(text, ".tabs")
    # the columns are grids of their own; an auto track took the drift line's width
    assert "grid-template-columns: minmax(0, 1fr)" in rule(text, ".detail-main")
    assert "grid-template-columns: minmax(0, 1fr)" in rule(text, ".detail-side")
    phone = text.split("@media (max-width: 767px)", 1)
    assert len(phone) == 2 and "flex-wrap: wrap" in phone[1].split("}", 1)[0]
    # the two columns only where the main column still holds the coverage table
    assert "@media (min-width: 1280px)" in text
