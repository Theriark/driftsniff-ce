"""THE-1351: the serious axe findings of the THE-1315 browser journeys, fixed in the product.

- D1 nested-interactive: a drift line with change marks drew its links inside an svg with
  role="img", whose children are presentational, so a screen reader could not reach them
  (Dashboard and Sources list). A strip with links is now a named group and each link names
  itself.
- D2 scrollable-region-focusable: the trend chart wrapper (Dashboard at 1440 and 390 px) and a
  drift strip without links (source page at 390 px) scroll with nothing inside to focus. The
  scroller itself now takes the keyboard focus, as a group named by the chart title.
- D3 color-contrast in the dark scheme: a resting rule faded the background of a button, chip,
  tab or menu entry for 120 ms on a colour scheme change while its text colour switched at
  once, so axe measured light text on a still-light button. Colour transitions now sit on the
  hover rules only.

The templates render with synthetic fixture values; nothing here reads a database. The axe
journeys themselves run in the browser e2e job of CI.
"""

import re
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from driftsniff.web.templating import SEVERITY_LABELS, TEMPLATES_DIR, environment

STATIC = Path(TEMPLATES_DIR).parent / "static"
SHEETS = ("app.css", "history.css", "summary-head.css", "settings.css", "replay.css")
# the properties whose fade on a theme change leaves text and background out of step
COLOUR_PROPERTIES = {"all", "background", "background-color", "color"}


class Tree(HTMLParser):
    """Every start tag with its attributes and the tags open around it."""

    VOID = {"area", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}

    def __init__(self) -> None:
        super().__init__()
        self.open: list[tuple[str, dict[str, str]]] = []
        self.tags: list[tuple[str, dict[str, str], list[tuple[str, dict[str, str]]]]] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        self.tags.append((tag, values, list(self.open)))
        if "id" in values:
            self.ids.add(values["id"])
        if tag not in self.VOID:
            self.open.append((tag, values))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        self.tags.append((tag, values, list(self.open)))
        if "id" in values:
            self.ids.add(values["id"])

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.open) - 1, -1, -1):
            if self.open[index][0] == tag:
                del self.open[index:]
                break

    def find(self, tag: str) -> list[dict[str, str]]:
        return [attrs for name, attrs, _ in self.tags if name == tag]


def parse(html: str) -> Tree:
    tree = Tree()
    tree.feed(html)
    return tree


def render_macro(source: str, **context: Any) -> str:
    return environment().from_string(source).render(**context)


def drift_line(checks: list[dict[str, str]], short: bool = False) -> str:
    return render_macro(
        '{% from "components/driftline.html" import drift_line %}'
        '{{ drift_line("FIXTURE source", checks, "dl-1", href="/sources/1", meta="m", '
        "short=short) }}",
        checks=checks,
        short=short,
    )


CHANGE = {
    "kind": "change",
    "severity": "high",
    "summary": "2 objects changed",
    "href": "/changes/7",
}


def assert_no_link_inside_an_image(tree: Tree) -> None:
    """axe nested-interactive: no focusable control inside an element whose role is img."""
    for tag, attrs, ancestors in tree.tags:
        if tag == "a" or "tabindex" in attrs:
            assert all(a.get("role") != "img" for _, a in ancestors), (tag, attrs)


# ---- D1: a drift line with links is a group ---------------------------------------------------


def test_a_drift_line_with_change_links_is_a_group_whose_links_name_themselves() -> None:
    for short in (False, True):
        tree = parse(drift_line([{"kind": "ok"}, CHANGE, {"kind": "failed"}], short=short))
        assert_no_link_inside_an_image(tree)
        (svg,) = tree.find("svg")
        assert svg["role"] == "group"
        assert svg["aria-labelledby"] == "dl-1-t dl-1-d"
        assert {"dl-1-t", "dl-1-d"} <= tree.ids
        links = [a for a in tree.find("a") if a.get("href") == "/changes/7"]
        assert links == [
            {"href": "/changes/7", "aria-label": f"{SEVERITY_LABELS['high']}: 2 objects changed"}
        ]
        # the links take the focus, so the strip itself is no extra tab stop
        strips = [d for d in tree.find("div") if d.get("class") == "driftline__strip"]
        assert strips == [{"class": "driftline__strip"}]


def test_a_drift_line_without_change_links_stays_an_image() -> None:
    tree = parse(drift_line([{"kind": "ok"}, {"kind": "failed"}]))
    (svg,) = tree.find("svg")
    assert svg["role"] == "img"
    assert [a["href"] for a in tree.find("a")] == ["/sources/1"]  # the name, outside the drawing
    assert_no_link_inside_an_image(tree)


# ---- D2: scrollers without focusable content take the focus -----------------------------------


def test_a_drift_strip_without_links_is_a_focusable_named_group() -> None:
    cases: list[list[dict[str, str]]] = [[], [{"kind": "ok"}] * 31]
    for checks in cases:
        tree = parse(drift_line(checks, short=True))
        strips = [d for d in tree.find("div") if d.get("class") == "driftline__strip"]
        assert strips == [
            {
                "class": "driftline__strip",
                "tabindex": "0",
                "role": "group",
                "aria-labelledby": "dl-1-t",
            }
        ]
        assert "dl-1-t" in tree.ids


def trend() -> SimpleNamespace:
    bar = SimpleNamespace(severity="low", x=40, y=140, width=14, height=10)
    grid = [SimpleNamespace(y=100, label_y=104, label="2")]
    day = SimpleNamespace(label="24 Oct", total=1, low=1, medium=0, high=0, critical=0)
    return SimpleNamespace(grid=grid, bars=[bar], days=[day], description="1 item on 24 Oct.")


def test_the_trend_chart_scroller_is_a_focusable_group_named_by_the_chart_title() -> None:
    tree = parse(
        render_macro(
            '{% from "components/charts.html" import trend_chart %}'
            '{{ trend_chart(trend, "trend") }}',
            trend=trend(),
        )
    )
    wraps = [d for d in tree.find("div") if d.get("class") == "chart-wrap"]
    assert wraps == [
        {"class": "chart-wrap", "tabindex": "0", "role": "group", "aria-labelledby": "trend-t"}
    ]
    assert "trend-t" in tree.ids
    (svg,) = [s for s in tree.find("svg") if s.get("class") == "chart"]
    assert svg["role"] == "img"


def test_a_focused_scroller_shows_the_focus_ring() -> None:
    """The scrollers have no focus rule of their own; the one ring of app.css must reach them."""
    css = _strip_comments((STATIC / "app.css").read_text(encoding="utf-8"))
    ring = [body for head, body in _rules(css) if head.strip() == ":focus-visible"]
    assert ring and re.search(r"outline:\s*2px solid var\(--focus\)", ring[0])
    for selector in (".chart-wrap", ".driftline__strip"):
        for head, body in _rules(css):
            if selector in head and ":focus" in head:
                assert not re.search(r"outline:\s*(none|0)", body), head


# ---- D3: colour transitions only on hover -----------------------------------------------------


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _rules(css: str) -> list[tuple[str, str]]:
    """Every style rule as (selector list, body), the rules inside @media blocks included."""
    found: list[tuple[str, str]] = []
    depth, start, body, head = 0, 0, 0, ""
    for index, char in enumerate(css):
        if char == "{":
            if depth == 0:
                head, body = css[start:index].strip(), index + 1
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                inner = css[body:index]
                if head.startswith("@"):
                    found.extend(_rules(inner))
                else:
                    found.append((head, inner))
                start = index + 1
    return found


def _faded_properties(body: str) -> set[str]:
    names: set[str] = set()
    for value in re.findall(r"(?<![-\w])transition(?:-property)?\s*:\s*([^;]+)", body):
        for part in value.split(","):
            words = part.split()
            if words:
                names.add(words[0])
    return names


def colour_fades_at_rest() -> list[str]:
    found = []
    for sheet in SHEETS:
        css = _strip_comments((STATIC / sheet).read_text(encoding="utf-8"))
        for head, body in _rules(css):
            faded = _faded_properties(body) & COLOUR_PROPERTIES
            resting = [part.strip() for part in head.split(",") if ":hover" not in part]
            if faded and resting:
                found.append(f"{sheet}: {', '.join(resting)} fades {sorted(faded)}")
    return found


def test_no_resting_rule_fades_a_text_or_background_colour() -> None:
    assert colour_fades_at_rest() == []


def test_the_check_finds_a_resting_colour_fade() -> None:
    """The check above must be able to fail: a rule like the old .btn one is found."""
    old = ".btn { color: var(--text); transition: background var(--t-fast) var(--ease-out); }"
    [(_, body)] = _rules(old)
    assert _faded_properties(body) == {"background"}
    [(head, _)] = _rules(".btn:hover { transition: background 120ms; }")
    assert all(":hover" in part for part in head.split(","))


def test_the_hover_rules_keep_their_fade() -> None:
    """The look stays: the pointer's hover still fades in on the same controls."""
    wanted = {
        "app.css": (".btn:hover", ".chip:hover", ".nav__group a:hover"),
        "history.css": (".resource-rail a:hover",),
        "summary-head.css": (".tabs a:hover",),
    }
    for sheet, selectors in wanted.items():
        css = _strip_comments((STATIC / sheet).read_text(encoding="utf-8"))
        rules = {head.strip(): body for head, body in _rules(css)}
        for selector in selectors:
            assert re.search(r"var\(--t-fast\)", rules[selector]), (sheet, selector)
            assert _faded_properties(rules[selector]) & COLOUR_PROPERTIES, (sheet, selector)
