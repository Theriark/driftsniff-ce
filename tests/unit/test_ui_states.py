"""THE-1306 (P3): state() is the one entry to the empty, error and loading states.

Each kind is rendered on its own: its markup, its role and live region, its action, and that
every message, label and address it is given is escaped. An unknown kind stops the render.
"""

from html.parser import HTMLParser
from typing import Any

import pytest
from jinja2 import UndefinedError

from driftsniff.web.templating import make_environment

HOSTILE = "a'<b>\"c"


class Parsed(HTMLParser):
    """The tags of a rendered fragment with their attributes, and its text."""

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

    def joined(self) -> str:
        return " ".join(" ".join(self.text).split())


def state(*args: Any, **kwargs: Any) -> str:
    module: Any = make_environment().get_template("components/states.html").module
    return str(module.state(*args, **kwargs))


def test_the_empty_state_is_a_status_with_the_mark_a_heading_and_one_action() -> None:
    text = state("empty", "No changes yet", "Add a source first.", "/sources/new", "Add source")
    parsed = Parsed(text)
    assert parsed.find("div") == [{"class": "empty", "role": "status"}]
    assert parsed.find("img")[0]["alt"] == ""
    assert parsed.find("h2") == [{}]
    assert parsed.find("a") == [{"class": "btn btn--primary", "href": "/sources/new"}]
    assert parsed.joined() == "No changes yet Add a source first. Add source"
    assert Parsed(state("empty", "Nothing here", "Come back later.")).find("a") == []


def test_an_inline_empty_state_is_one_quiet_status_sentence() -> None:
    text = state("empty", "No notes yet.", "An operator writes them.", inline=True)
    parsed = Parsed(text)
    assert parsed.tags == [("p", {"class": "quiet", "role": "status"})]
    assert parsed.joined() == "No notes yet. An operator writes them."
    assert Parsed(state("empty", "Nothing yet.", inline=True)).joined() == "Nothing yet."
    pointed = Parsed(state("empty", "No run yet.", inline=True, id="runs-unscheduled"))
    assert pointed.find("p") == [{"class": "quiet", "id": "runs-unscheduled", "role": "status"}]
    linked = Parsed(state("empty", "None.", "Add one", "/x", "on the list", inline=True))
    assert linked.find("a") == [{"href": "/x"}]
    assert linked.joined() == "None. Add one on the list"


def test_the_error_state_is_an_alert_whose_action_is_the_retry() -> None:
    text = state("error", "The list could not be loaded", "Nothing was changed.", "/changes")
    parsed = Parsed(text)
    assert parsed.find("div")[0] == {"class": "banner banner--error", "role": "alert"}
    assert parsed.find("form") == [{"method": "get", "action": "/changes"}]
    assert parsed.find("button") == [{"class": "btn btn--small", "type": "submit"}]
    assert parsed.joined() == "The list could not be loaded Nothing was changed. Try again"
    named = Parsed(state("error", "Failed", "Nothing was changed.", "/x", "Reload the list"))
    assert "Reload the list" in named.joined()
    assert Parsed(state("error", "Failed", "Nothing was changed.")).find("form") == []


def test_the_loading_state_is_a_polite_live_status_that_says_what_loads() -> None:
    parsed = Parsed(state("loading", "Loading the objects", rows=3))
    assert parsed.find("div") == [
        {
            "class": "skeleton",
            "role": "status",
            "aria-live": "polite",
            "aria-label": "Loading the objects",
        }
    ]
    # a live region speaks its content, so the label is also its (hidden) text
    assert parsed.find("p") == [{"class": "visually-hidden"}]
    assert parsed.joined() == "Loading the objects"
    assert len(parsed.find("span")) == 3
    indicator = Parsed(state("loading", "Loading", indicator=True))
    assert indicator.find("div")[0]["class"] == "skeleton htmx-indicator"
    assert len(indicator.find("span")) == 5


@pytest.mark.parametrize(
    ("kind", "inline"),
    [("empty", False), ("empty", True), ("error", False), ("loading", False)],
)
def test_every_message_label_and_address_is_escaped(kind: str, inline: bool) -> None:
    text = state(kind, HOSTILE, HOSTILE, HOSTILE, HOSTILE, inline=inline, id=HOSTILE)
    parsed = Parsed(text)
    assert "<b>" not in text and parsed.find("b") == []
    assert "a&#39;&lt;b&gt;&#34;c" in text
    assert HOSTILE in parsed.joined()
    # an address or a label in an attribute stays whole: its quote cannot close the attribute
    for tag, attrs in parsed.tags:
        if tag == "use":  # the banner's icon, not an input
            continue
        for name in ("href", "action", "aria-label", "id"):
            if name in attrs:
                assert attrs[name] == HOSTILE, name


def test_an_unknown_kind_stops_the_render() -> None:
    with pytest.raises(UndefinedError):
        state("success", "Saved")
    with pytest.raises(UndefinedError):
        state("warn", "Careful", inline=True)
