"""The Change Replay drawing of the source page (UI revision WP4c, THE-1197).

- Nothing is invented: every cell is a day and resource type of the replay, its counts add up to
  the replay's, and a window without items has no map, no facts and no cursor panel.
- A cell's shade is its share of the busiest cell in four steps, a critical item rings it, its
  count is printed only when it fits, and it links to the changes it counts.
- The cursor starts on the last day with items, and the facts answer where the burst is.
- The section renders without a style attribute, names every cell, keeps the replay controls
  hidden until the script shows them, and says so when the installation has no replay.
- replay.js and replay.css keep the rules of the page: no fetch, no HTML strings, no style
  writes, no transition, and the hidden parts stay hidden.

The views are built from plain ``Replay`` values; nothing here reads a database.
"""

import re
from datetime import date, timedelta
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from driftsniff.web.replay import Replay, ReplayCell, ReplayResource, build_replay
from driftsniff.web.replay_view import (
    LABEL_WIDTH,
    WINDOWS,
    day_summary,
    level_of,
    replay_view,
    window_of,
)
from driftsniff.web.templating import SEVERITIES, TEMPLATES_DIR, environment

LAST = date(2026, 10, 25)
STATIC = Path(TEMPLATES_DIR).parent / "static"


def replay_of(rows: list[tuple[str, str, str, int]], days: int = 30, source_id: int = 2) -> Replay:
    return build_replay(source_id, LAST - timedelta(days=days - 1), LAST, rows)


FIXTURE = [
    ("2026-10-20", "unifi-firewall-policies", "critical", 1),
    ("2026-10-20", "unifi-firewall-policies", "medium", 2),
    ("2026-10-22", "unifi-networks", "low", 1),
    ("2026-10-24", "unifi-firewall-policies", "high", 4),
]


class Tags(HTMLParser):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def find(self, name: str) -> list[dict[str, str | None]]:
        return [attrs for tag, attrs in self.tags if tag == name]


def render_section(replay: Replay | None, source_id: int = 2) -> str:
    view = None if replay is None else replay_view(replay)
    template = environment().from_string(
        '{% from "sources/_replay.html" import change_replay %}{{ change_replay(view, sid) }}'
    )
    return template.render(view=view, sid=source_id)


# ---- the window ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("7", 7), ("30", 30), ("90", 90), (" 90 ", 90), ("8", 30), ("0", 30), ("x", 30), ("", 30)],
)
def test_the_window_is_one_of_the_offered_lengths(raw: str, expected: int) -> None:
    assert window_of(raw) == expected


def test_each_window_link_names_its_length_and_marks_the_current_one() -> None:
    view = replay_view(replay_of(FIXTURE, days=7))
    assert [(w.days, w.current) for w in view.windows] == [(7, True), (30, False), (90, False)]
    assert [w.href for w in view.windows] == [f"/sources/2?replay_days={n}#replay" for n in WINDOWS]


# ---- nothing invented ------------------------------------------------------------------------


def test_an_empty_window_has_no_map_no_facts_and_no_panel() -> None:
    view = replay_view(replay_of([]))
    assert view.empty
    assert (view.cells, view.rows, view.facts, view.table, view.summary) == ((), (), (), (), None)
    assert view.description == "No change items from 26 Sep 2026 to 25 Oct 2026, UTC."
    assert len(view.columns) == 30


def test_every_cell_is_a_day_and_resource_type_of_the_replay_with_its_counts() -> None:
    replay = replay_of(FIXTURE)
    view = replay_view(replay)
    found = {(c.day, c.resource_label): c.counts for c in view.cells}
    assert found == {
        ("2026-10-20", "Firewall policies"): (0, 2, 0, 1),
        ("2026-10-22", "Networks"): (1, 0, 0, 0),
        ("2026-10-24", "Firewall policies"): (0, 0, 4, 0),
    }
    assert sum(c.count for c in view.cells) == replay.total == 8
    assert [r.resource for r in view.rows] == [r.resource for r in replay.resources]
    assert sum(r.count for r in view.rows) == replay.total
    # one table row per cell, newest day first
    assert [(r.day, r.resource_label, r.count) for r in view.table] == [
        ("24 Oct 2026", "Firewall policies", 4),
        ("22 Oct 2026", "Networks", 1),
        ("20 Oct 2026", "Firewall policies", 3),
    ]


def test_a_cell_outside_the_window_is_left_out() -> None:
    replay = replay_of(FIXTURE)
    stray = Replay(
        replay.source_id,
        replay.first_day,
        replay.last_day,
        replay.days,
        replay.severities,
        replay.total,
        replay.resources,
        (*replay.cells, ReplayCell("2026-11-30", "unifi-networks", "low", 1)),
    )
    assert {c.day for c in replay_view(stray).cells} == {"2026-10-20", "2026-10-22", "2026-10-24"}


# ---- shade, ring, count, link ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "busiest", "level"),
    [(0, 4, 0), (1, 0, 0), (1, 4, 1), (2, 4, 2), (3, 4, 3), (4, 4, 4), (1, 100, 1), (26, 100, 2)],
)
def test_the_shade_is_the_share_of_the_busiest_cell_in_four_steps(
    count: int, busiest: int, level: int
) -> None:
    assert level_of(count, busiest) == level


def test_a_critical_item_rings_its_cell_and_the_title_names_every_count() -> None:
    cells = {c.day: c for c in replay_view(replay_of(FIXTURE)).cells}
    assert cells["2026-10-20"].critical and not cells["2026-10-24"].critical
    assert cells["2026-10-20"].title == (
        "20 Oct 2026, Firewall policies: 3 change items (1 critical, 2 medium)"
    )
    assert cells["2026-10-22"].title == "22 Oct 2026, Networks: 1 change item (1 low)"
    assert cells["2026-10-24"].level == 4 and cells["2026-10-22"].level == 1


def test_a_cell_prints_its_count_only_where_it_fits() -> None:
    wide = [
        ("2026-10-24", "unifi-networks", "low", 100),
        ("2026-10-23", "unifi-networks", "low", 7),
    ]
    month = {c.day: c.text for c in replay_view(replay_of(wide)).cells}
    assert month == {"2026-10-24": "", "2026-10-23": "7"}
    week = {c.day: c.text for c in replay_view(replay_of(wide, days=7)).cells}
    assert week == {"2026-10-24": "100", "2026-10-23": "7"}
    quarter = {c.day: c.text for c in replay_view(replay_of(wide, days=90)).cells}
    assert quarter == {"2026-10-24": "", "2026-10-23": ""}


def test_the_map_text_meets_the_14_px_floor_and_fits_its_cells() -> None:
    """THE-1402 F3: the row and day labels were 13 px and the cell counts 11 px. Both drawings
    are one unit per CSS pixel, so 14 units are 14 px; a 15 px cell of the 30 day window then
    holds one bold digit."""
    sheet = (STATIC / "replay.css").read_text(encoding="utf-8")
    sizes = [int(size) for size in re.findall(r"font-size:\s*(\d+)px", sheet)]
    assert sizes and min(sizes) >= 14
    for selector in (r"\.replay-axis \{", r"\.heat-n \{"):
        body = re.search(selector + r"([^}]*)\}", sheet)
        assert body is not None and "font-size: 14px" in body.group(1), selector
    two = [("2026-10-24", "unifi-networks", "low", 12), ("2026-10-23", "unifi-networks", "low", 9)]
    month = {c.day: c.text for c in replay_view(replay_of(two)).cells}
    assert month == {"2026-10-24": "", "2026-10-23": "9"}
    week = {c.day: c.text for c in replay_view(replay_of(two, days=7)).cells}
    assert week == {"2026-10-24": "12", "2026-10-23": "9"}
    assert LABEL_WIDTH == 128


def test_a_cell_links_to_the_changes_it_counts_with_muted_ones_included() -> None:
    cell = next(c for c in replay_view(replay_of(FIXTURE)).cells if c.day == "2026-10-22")
    parts = urlsplit(cell.href)
    assert parts.path == "/changes"
    assert parse_qs(parts.query) == {
        "source": ["2"],
        "resource": ["unifi-networks"],
        "from": ["2026-10-22"],
        "to": ["2026-10-22"],
        "muted": ["1"],
    }


@pytest.mark.parametrize("days", WINDOWS)
def test_every_cell_sits_in_its_day_column_and_its_row(days: int) -> None:
    view = replay_view(replay_of(FIXTURE, days=days))
    for cell in view.cells:
        column = view.columns[cell.day_index]
        assert column.day == cell.day
        assert column.x <= cell.x and cell.x + cell.width <= column.x + view.pitch
        assert cell.y == view.rows[cell.row].y
    assert view.width == days * view.pitch
    # names and cells fit the 654 px main column of a 768 px screen (scroller padding 16)
    assert LABEL_WIDTH + view.width + 16 <= 654
    assert view.columns[-1].axis and view.columns[-1].day == "2026-10-25"


# ---- cursor and facts ------------------------------------------------------------------------


def test_the_cursor_starts_on_the_last_day_with_items_and_the_panel_tells_it() -> None:
    view = replay_view(replay_of(FIXTURE))
    assert view.columns[view.cursor_index].day == "2026-10-24"
    assert view.cursor_x == view.cursor_index * view.pitch
    assert view.summary is not None
    assert view.summary.long_label == "24 Oct 2026"
    assert view.summary.total_text == "4 change items in 1 resource type"
    assert [(line.label, line.counts) for line in view.summary.lines] == [
        ("Firewall policies", (0, 0, 4, 0))
    ]
    assert parse_qs(urlsplit(view.summary.href).query)["sort"] == ["oldest"]


def test_the_facts_name_the_busiest_day_the_first_change_and_the_critical_count() -> None:
    rows = [*FIXTURE, ("2026-10-21", "unifi-networks", "low", 4)]
    view = replay_view(replay_of(rows))
    facts = {f.term: f for f in view.facts}
    # 21 Oct and 24 Oct both hold four items: the earlier day is the busiest
    assert facts["Busiest day"].value == "21 Oct 2026"
    assert facts["Busiest day"].detail == "4 change items"
    assert facts["First change in the window"].value == "20 Oct 2026"
    assert facts["Critical items"].value == "1"
    query = parse_qs(urlsplit(facts["Critical items"].href).query)
    assert query["severity"] == ["critical"]
    assert (query["from"], query["to"]) == (["2026-09-26"], ["2026-10-25"])
    assert view.description == (
        "12 change items in 2 resource types from 26 Sep 2026 to 25 Oct 2026, UTC. "
        "Busiest day 21 Oct 2026 with 4 change items. 1 critical item."
    )


# ---- the rendered section --------------------------------------------------------------------


def test_the_section_names_every_cell_and_carries_no_style_attribute() -> None:
    text = render_section(replay_of(FIXTURE))
    tags = Tags(text)
    for tag, attrs in tags.tags:
        assert "style" not in attrs, f"<{tag}> carries a style attribute"
    (svg,) = [a for a in tags.find("svg") if "data-replay-map" in a]
    assert svg["role"] == "group"
    assert svg["aria-labelledby"] == "replay-t" and svg["aria-describedby"] == "replay-d"
    links = [a for a in tags.find("a") if "replay-cell" in (a.get("class") or "")]
    assert len(links) == 3
    assert text.count('<title id="replay-t">') == 1 and text.count("<title>") == 3
    assert all(str(a.get("href") or "").startswith("/changes?") for a in links)
    assert sum("replay-cell--critical" in (a["class"] or "") for a in links) == 1
    assert 'data-first-day="2026-09-26"' in text and 'data-cursor="28"' in text


def test_the_controls_wait_hidden_for_the_script_and_the_slider_is_labelled() -> None:
    tags = Tags(render_section(replay_of(FIXTURE)))
    controls = [a for a in tags.find("div") if "data-replay-controls" in a]
    assert controls and "hidden" in controls[0]
    (scrub,) = tags.find("input")
    assert scrub["type"] == "range" and scrub["id"] == "replay-scrub"
    assert {a.get("for") for a in tags.find("label")} == {"replay-scrub"}
    assert (scrub["min"], scrub["max"], scrub["value"]) == ("0", "29", "28")
    assert scrub["aria-valuetext"] == "24 Oct 2026"
    (panel,) = [a for a in tags.find("div") if a.get("id") == "replay-day"]
    assert panel["aria-live"] == "polite"


def test_an_empty_window_says_what_to_do_and_draws_no_map() -> None:
    text = render_section(replay_of([]))
    assert "Nothing to replay in the last 30 days" in text
    assert "Choose a longer window" in text
    assert "data-replay-map" not in text and "data-replay " not in text
    assert 'aria-current="true">30 days' in text


def test_without_the_replay_service_the_section_says_so_and_links_the_changes() -> None:
    text = render_section(None, source_id=5)
    assert "not available on this installation" in text
    assert 'href="/changes?source=5"' in text
    assert "<svg" not in text


# ---- the script and the sheet ----------------------------------------------------------------


def test_the_script_fetches_nothing_and_writes_no_html_and_no_style() -> None:
    script = (STATIC / "replay.js").read_text(encoding="utf-8")
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "fetch(", "XMLHttpRequest"):
        assert banned not in script, banned
    assert re.search(r"\.style\b", script) is None
    assert "eval(" not in script and "new Function" not in script
    assert "prefers-reduced-motion: reduce" in script
    assert "visibilitychange" in script and "IntersectionObserver" in script


def test_the_sheet_moves_nothing_and_keeps_hidden_parts_hidden() -> None:
    sheet = (STATIC / "replay.css").read_text(encoding="utf-8")
    assert "transition" not in sheet and "animation" not in sheet
    assert re.search(r"\.replay \[hidden\]\s*\{\s*display:\s*none;", sheet)
    for level in range(1, 5):
        assert f".heat--{level} {{ fill: var(--heat-{level}); }}" in sheet


def test_the_source_page_loads_the_sheet_and_the_deferred_script_from_its_own_origin() -> None:
    page = (Path(TEMPLATES_DIR) / "sources" / "detail.html").read_text(encoding="utf-8")
    assert '<link rel="stylesheet" href="/static/replay.css">' in page
    assert '<script src="/static/replay.js" defer></script>' in page


def test_the_severity_order_of_a_cell_is_the_application_one() -> None:
    replay = replay_of([("2026-10-24", "vms", s, 1) for s in SEVERITIES])
    (cell,) = replay_view(replay).cells
    assert cell.counts == (1, 1, 1, 1) and cell.counts_attr == "1 1 1 1"
    assert cell.title.endswith("(1 critical, 1 high, 1 medium, 1 low)")
    assert replay.resources == (ReplayResource("vms", replay.resources[0].label, 4),)


def test_a_long_resource_type_name_is_cut_beside_the_map_and_whole_in_its_cells() -> None:
    replay = replay_of([("2026-10-24", "unifi-port-forwarding-rules-extra", "low", 1)])
    view = replay_view(replay)
    (row,) = view.rows
    assert len(row.short_label) <= 17 and row.short_label.endswith("…")
    assert row.label == replay.resources[0].label and len(row.label) > 17
    assert view.cells[0].resource_label == row.label


def test_the_row_names_are_a_drawing_beside_the_scroller_so_they_never_scroll_away() -> None:
    # found at 390 px on Development (8afde57a): the scroller opened on today and hid the names
    text = render_section(replay_of(FIXTURE))
    labels = text.index('class="replay-map__labels"')
    scroller = text.index('class="replay-map__scroll"')
    drawing = text.index("data-replay-map")
    assert labels < scroller < drawing
    names = text[labels:scroller]
    assert "Firewall policies" in names and "Networks" in names
    assert 'aria-hidden="true"' in names[:300]
    assert "replay-label" not in text[scroller:]


def test_the_widest_row_name_ends_inside_the_name_drawing() -> None:
    """THE-1416: the names were anchored at x 118 and the widest known name cut to 17 characters
    measured 119.1 px at 14 px on Development, so about 1 px of its first letter was cut off."""
    labels = [a for tag, a in Tags(render_section(replay_of(FIXTURE))).tags if tag == "text"]
    xs = {a.get("x") for a in labels if a.get("class") == "replay-label"}
    assert xs == {"120"}
    (x,) = xs
    widest_measured = 119.1
    assert x is not None and float(x) - widest_measured >= 0


def test_a_day_without_items_offers_no_link_to_an_empty_list() -> None:
    """THE-1402 F11: the panel of an empty day still offered Open the changes of that day."""
    panel = environment().from_string(
        '{% from "sources/_replay.html" import day_panel %}{{ day_panel(summary) }}'
    )
    empty = Tags(panel.render(summary=day_summary(2, LAST, [])))
    (link,) = [a for a in empty.find("a") if "data-replay-day-link" in a]
    assert "hidden" in link
    busy_cell = replay_view(replay_of(FIXTURE)).cells[0]
    busy = Tags(panel.render(summary=day_summary(2, LAST, [busy_cell])))
    (link,) = [a for a in busy.find("a") if "data-replay-day-link" in a]
    assert "hidden" not in link
    # the script keeps the link in step with the day under the cursor
    script = (STATIC / "replay.js").read_text(encoding="utf-8")
    assert "link.hidden = !sum;" in script


def test_the_controls_wrap_and_the_facts_give_way_on_a_narrow_card() -> None:
    sheet = (STATIC / "replay.css").read_text(encoding="utf-8")
    buttons = re.search(r"\.replay-buttons \{([^}]*)\}", sheet)
    assert buttons is not None and "flex-wrap: wrap" in buttons.group(1)
    facts = re.search(r"\.replay-facts \{([^}]*)\}", sheet)
    assert facts is not None and "auto-fit" in facts.group(1)
    drawing = re.search(r"\.replay-map__svg \{([^}]*)\}", sheet)
    assert drawing is not None and "margin-right: auto" in drawing.group(1)


def test_the_card_column_cannot_grow_past_the_card_so_only_the_cells_scroll() -> None:
    # found at 390 px on Development (c114835a): the auto track took the map's 654 px, the page
    # became 695 px wide and the scroller never scrolled
    sheet = (STATIC / "replay.css").read_text(encoding="utf-8")
    card = re.search(r"\.replay-card \{([^}]*)\}", sheet)
    assert card is not None and "grid-template-columns: minmax(0, 1fr)" in card.group(1)
