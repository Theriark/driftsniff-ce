"""The data view parts of the UI revision WP2 (THE-1128): the date range, the filter chips and
the stylesheet rules of the change list's filter bar and of links in a table.

The macros are rendered with the Jinja environment directly, the way ``test_templates.py``
checks the other components; the pages that use them are tested through the application in
``test_web_changes.py``.
"""

from html.parser import HTMLParser

from driftsniff.web.templating import TEMPLATES_DIR, make_environment

HOSTILE = "a'<b>\"c"
SOURCE = (
    '{% from "components/forms.html" import date_range, filter_chips %}'
    '{{ date_range("d", "Detected", "UTC days", "from", "2026-10-01", "to", "") }}'
    '{{ filter_chips(chips, "/changes") }}'
)


class Parsed(HTMLParser):
    """The tags of a rendered fragment, with their attributes, and its text."""

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


def render(chips: list[dict[str, str]]) -> str:
    return make_environment().from_string(SOURCE).render(chips=chips)


def stylesheet() -> str:
    return (TEMPLATES_DIR.parent / "static" / "app.css").read_text(encoding="utf-8")


def test_the_date_range_says_utc_on_both_fields() -> None:
    text = render([])
    parsed = Parsed(text)
    labelled = {attrs.get("for") for attrs in parsed.find("label")}
    dates = [(a["id"], a["value"], a["aria-describedby"]) for a in parsed.find("input")]
    assert dates == [("d-from", "2026-10-01", "d-help"), ("d-to", "", "d-help")]
    assert {"d-from", "d-to"} <= labelled
    assert parsed.find("fieldset") == [{"class": "date-range"}]
    assert '<legend>Detected <span class="date-range__help" id="d-help">UTC days</span>' in text


def test_each_chip_is_the_link_that_drops_its_filter_and_clear_all_comes_with_two() -> None:
    chips = [{"name": "Search", "value": HOSTILE, "remove_href": "/changes?x=1&y=2"}]
    text = render(chips)
    parsed = Parsed(text)
    assert {"class": "chip", "href": "/changes?x=1&y=2"} in parsed.find("a")
    assert HOSTILE not in text and "a&#39;&lt;b&gt;&#34;c" in text
    assert ", remove this filter" in "".join(parsed.text)
    assert {"class": "chips__list", "aria-labelledby": "chips-label"} in parsed.find("ul")
    # one chip is its own way back; Clear all comes with two or more
    assert not [attrs for attrs in parsed.find("a") if attrs.get("class") == "chips__clear"]
    assert {"class": "chips__clear", "href": "/changes"} in Parsed(render(chips * 2)).find("a")
    assert 'class="chips"' not in render([])


def test_the_filters_panel_joins_the_row_only_where_the_browser_can_and_the_bar_is_wide() -> None:
    css = stylesheet()
    assert "container: filters / inline-size;" in css
    plain, guarded = css.split("@supports selector(::details-content) {", 1)
    # outside the guard the toggle is never hidden, so the fields stay one click away
    assert ".filter-more__toggle {\n  list-style: none;" in plain
    assert ".filter-more__toggle {\n  display: none" not in plain
    wide = guarded.split("@container filters (min-width: 1080px) {", 1)[1].split("@container", 1)[0]
    assert ".filter-more__toggle {\n      display: none;" in wide
    assert "content-visibility: visible;" in wide


def test_a_link_in_a_table_body_is_underlined_before_it_is_hovered() -> None:
    # UI revision G6: a source name on the change and source lists did not read as a link
    block = stylesheet().split(".data-table tbody a:not(.btn) {\n", 1)[1].split("}", 1)[0]
    assert "text-decoration-line: underline;" in block
