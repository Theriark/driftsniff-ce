"""THE-1264: the needs-attention rows and the drift line labels at desktop widths.

Found on Development (e3e1a746) at 1440 px: each attention row was its own grid, so the text
started at x 866, 870, 882 or 968 with the width of its badge, and three of four titles ended
in an ellipsis with no way to read the rest. On the drift line, the 150 px meta column kept
"Push source, 4 pushes in 30 days" on one line, 44 px into the strip, where the marks covered
it. The rendered checks live on Development; these pin the template and stylesheet rules.
"""

import re
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

from driftsniff.web.templating import make_environment

WEB = Path(__file__).resolve().parents[2] / "src" / "driftsniff" / "web"


def _css() -> str:
    css = (WEB / "static" / "app.css").read_text(encoding="utf-8")
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _top_level_rules(selector: str) -> list[str]:
    """The bodies of the rules for the selector outside any @media or @container block."""
    css, bodies = _css(), list[str]()
    depth = start = block = 0
    head = ""
    for index, char in enumerate(css):
        if char == "{":
            if depth == 0:
                head = css[start:index].strip()
                block = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                names = [part.strip() for part in head.split(",")]
                if selector in names and not head.startswith("@"):
                    bodies.append(css[block + 1 : index])
                start = index + 1
    return bodies


class _Links(HTMLParser):
    """The attributes and the text of every link."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[dict[str, str | None], str]] = []
        self._open = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.links.append((dict(attrs), ""))
            self._open = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._open = False

    def handle_data(self, data: str) -> None:
        if self._open:
            attrs, text = self.links[-1]
            self.links[-1] = (attrs, text + data)


def _attention_list(rows: list[SimpleNamespace]) -> str:
    """The needs-attention list of dashboard.html, rendered on its own with the given rows."""
    page = (WEB / "templates" / "dashboard.html").read_text(encoding="utf-8")
    found = re.search(r'<ul class="attention">.*?</ul>', page, re.DOTALL)
    assert found is not None
    source = (
        '{% from "components/badges.html" import severity_badge, status_badge %}'
        + found.group(0)
    )
    template = make_environment().from_string(source)
    return template.render(dashboard=SimpleNamespace(attention=rows))


def _row(title: str, **overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "badge": "severity",
        "badge_value": "critical",
        "badge_text": "",
        "title": title,
        "href": "/changes/7",
        "where": "lab-controller, firewall policies",
        "action_label": "Review",
        "action_href": "/changes/7",
        "critical": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_an_attention_title_carries_its_full_text_as_a_title() -> None:
    long = "DEV-FIXTURE synthetic: nothing pushed for 11 hours, expected every 300 seconds"
    hostile = 'pilot "<b>" & co'
    status = _row(hostile, badge="status", badge_value="open", badge_text="Nothing pushed yet")
    parser = _Links()
    parser.feed(_attention_list([_row(long), status]))
    titles = [(attrs.get("title"), text) for attrs, text in parser.links if attrs.get("title")]
    assert titles == [(long, long), (hostile, hostile)]


def test_the_attention_rows_share_the_columns_of_the_list() -> None:
    """Side by side, every row is a subgrid of one three-column list, so the text column starts
    at the same x in every row; the badge keeps its own width and the action its right edge."""
    listing = "".join(_top_level_rules(".attention"))
    row = "".join(_top_level_rules(".attention li"))
    assert re.search(r"grid-template-columns:\s*auto minmax\(0, 1fr\) auto;", listing)
    assert re.search(r"grid-column:\s*1\s*/\s*-1;", row)
    assert re.search(r"grid-template-columns:\s*subgrid;", row)
    for badge in (".attention li > .sev", ".attention li > .status"):
        assert re.search(r"justify-self:\s*start", "".join(_top_level_rules(badge))), badge
    assert re.search(r"justify-self:\s*end", "".join(_top_level_rules(".attention li > .btn")))


def test_the_attention_text_has_its_own_line_at_1440_and_768() -> None:
    """Side by side at 1440 px the list is 594 px and the text 292 px; at 768 px the list is
    654 px. Both lists are under the breakpoint, so the text spans the row under badge and
    action; a list of at least 720 px (a wide window) keeps the three aligned columns."""
    query = re.search(r"@container attention \(max-width:\s*(\d+)px\)", _css())
    assert query is not None
    assert 654 < int(query.group(1)) < 720


def test_an_attention_title_wraps_at_every_width() -> None:
    title = "".join(_top_level_rules(".attention .what a"))
    assert "nowrap" not in title
    assert "ellipsis" not in title
    assert re.search(r"overflow-wrap:\s*anywhere", title)


def test_the_drift_line_meta_wraps_inside_its_column() -> None:
    """The meta column is 150 px; a meta on one line ran under the marks of the strip."""
    tracks = [
        re.search(r"grid-template-columns:\s*([^;]+);", body)
        for body in _top_level_rules(".driftline")
    ]
    assert [found.group(1) for found in tracks if found] == ["160px 150px 1fr"]
    meta = "".join(_top_level_rules(".driftline__meta"))
    assert "nowrap" not in meta
    assert re.search(r"min-width:\s*0", meta)
    assert re.search(r"overflow-wrap:\s*anywhere", meta)
