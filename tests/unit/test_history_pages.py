"""The History and Configuration pages (P10-T7, frontend slice): the words, the links and the
templates rendered in every state with fixture views.

Acceptance of the plan, each with its test:

1. a baseline marker is visible in the history:
   ``test_the_ledger_marks_a_baseline_and_the_current_reading_in_words`` (and, through the
   application, ``tests/security/test_history_pages.py``);
2. the view equals ``resolve_current_state`` for the fixture: slice A's
   ``tests/unit/test_history_service.py``; here, every field of the view is printed
   (``test_the_configuration_prints_every_shown_field_and_masks_the_rest``).

The routes, the role checks and the canaries run through the real application in
``tests/security/test_history_pages.py``. Everything is synthetic; text that must never be shown
starts with CANARY-.
"""

from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from driftsniff.history.views import (
    ConfigObject,
    ConfigurationView,
    FieldView,
    ResourceSummary,
    SnapshotPageView,
    SnapshotRef,
    SnapshotRow,
    SourceHistoryRow,
    SourceRef,
)
from driftsniff.web.change_pages import count_words, fingerprint_words
from driftsniff.web.dashboard import parse_stamp, resource_label
from driftsniff.web.history_pages import (
    configuration_href,
    field_state,
    hidden_text,
    history_href,
    ledger_mark,
    object_title,
    page_links,
    range_text,
    size_text,
)
from driftsniff.web.templating import TEMPLATES_DIR, Shell, render

NOW = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)
CSRF = "CANARY-csrf-value"
SECRET = "CANARY-the-secret-value"  # noqa: S105 (a canary, never a real secret)
FINGERPRINT = "a1b2c3d4e5f6"
UNIFI = SourceRef(id=2, name="Office UniFi", type="unifi", enabled=True)
PUSH = SourceRef(id=1, name="lab-controller", type="push", enabled=True)
XSS = "<script>alert('CANARY-xss')</script>"


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

    def classes(self) -> list[str]:
        return [str(attrs.get("class") or "") for _tag, attrs in self.tags]

    def joined(self) -> str:
        return " ".join(" ".join(self.text).split())


def shell(role: str, nav: str) -> Shell:
    return Shell(
        title="t", nav_current=nav, user_name=role, user_role=role, csrf_token=CSRF, path="/x"
    )


def roles(role: str) -> dict[str, bool]:
    return {"can_operate": role in ("operator", "admin"), "can_admin": role == "admin"}


def assert_policy_clean(text: str) -> Parsed:
    """No style attribute, no handler, no inline script, every field labelled."""
    parsed = Parsed(text)
    for tag, attrs in parsed.tags:
        assert "style" not in attrs, f"<{tag}> carries a style attribute"
        assert not [name for name in attrs if name.startswith("on")], f"<{tag}> has a handler"
        if tag == "script":
            assert (attrs.get("src") or "").startswith("/static/"), "an inline script"
    labelled = {attrs.get("for") for attrs in parsed.find("label")}
    for tag in ("input", "select", "textarea"):
        for attrs in parsed.find(tag):
            if attrs.get("type") != "hidden":
                assert attrs.get("id") in labelled or attrs.get("aria-label"), f"unlabelled {tag}"
    return parsed


def forms(parsed: Parsed) -> set[str | None]:
    return {attrs.get("action") for attrs in parsed.find("form")} - {"/logout"}


# ---- the words and the links ------------------------------------------------------------------


def row(
    number: int, *, baseline: bool = False, current: bool = False, changes: int = 0
) -> SnapshotRow:
    return SnapshotRow(
        id=number,
        taken_at=f"2026-10-2{number}T08:00:00Z",
        kind="baseline" if baseline else "normal",
        is_baseline=baseline,
        is_current=current,
        controller_version="9.0.114",
        normaliser_version=1,
        change_count=changes,
        manifest_bytes=4300,
    )


def test_the_ledger_mark_has_a_shape_and_a_word_for_every_kind_of_reading() -> None:
    assert ledger_mark(row(1, baseline=True)).shapes == ("baseline",)
    assert ledger_mark(row(1, baseline=True)).word == "Baseline"
    assert ledger_mark(row(1, current=True)).word == "Current"
    assert ledger_mark(row(1)).word == "Reading"
    both = ledger_mark(row(1, baseline=True, current=True))
    assert both.shapes == ("baseline", "current") and both.word == "Baseline, current"


def test_sizes_counts_and_ranges_read_as_words() -> None:
    assert size_text(812) == "812 B"
    assert size_text(4300) == "4.2 KB"
    assert size_text(3 * 1024 * 1024) == "3.0 MB"
    assert range_text(1, 1, 50, "reading") == "1 reading"
    assert range_text(2, 1, 50, "reading") == "2 readings"
    assert range_text(231, 2, 50, "object") == "Showing 51 to 100 of 231 objects"
    assert range_text(231, 5, 50, "object") == "Showing 201 to 231 of 231 objects"


def test_links_carry_only_the_values_given_and_are_encoded() -> None:
    assert history_href(3) == "/history/3"
    assert history_href(3, 2) == "/history/3?page=2"
    assert configuration_href(3) == "/configuration/3"
    assert (
        configuration_href(3, resource="a&b", search="x y\"<", page=2)
        == "/configuration/3?resource=a%26b&q=x+y%22%3C&page=2"
    )
    assert configuration_href(3, resource="", search="", page=1) == "/configuration/3"


def test_the_pager_shows_a_window_around_the_current_page() -> None:
    assert page_links(1, 1, lambda n: f"/p{n}") == ()
    labels = [link.label for link in page_links(5, 9, lambda n: f"/p{n}")]
    assert labels == ["Previous", "1", "3", "4", "5", "6", "7", "9", "Next"]
    current = [link for link in page_links(5, 9, lambda n: f"/p{n}") if link.current]
    assert [(link.label, link.href) for link in current] == [("5", "/p5")]


def test_a_field_without_a_value_is_never_shown_in_clear() -> None:
    plain = FieldView("vlan", "102", "config", False, None, False, False)
    secret = FieldView("passphrase", None, "secret", True, FINGERPRINT, False, False)
    unclassified = FieldView("x_new", None, "unclassified", False, FINGERPRINT, False, False)
    marker = FieldView("odd", None, "config", True, FINGERPRINT, False, False)
    assert [field_state(f) for f in (plain, secret, unclassified, marker)] == [
        "value",
        "secret",
        "unclassified",
        "secret",
    ]
    assert object_title(ConfigObject("k1", None, None, ())) == "k1"
    assert object_title(ConfigObject("k1", "Guest", None, ())) == "Guest"
    assert hidden_text(("x_passphrase", "token")) == "x_passphrase, token"


# ---- the pickers ------------------------------------------------------------------------------


def render_picker(role: str, rows: list[Any], mode: str = "history") -> str:
    return render(
        "history/sources.html",
        shell(role, mode),
        rows=rows,
        mode=mode,
        title=mode.capitalize(),
        purpose="p",
        now=NOW,
        parse_stamp=parse_stamp,
        type_label=lambda kind: kind,
        count_words=count_words,
        **roles(role),
    )


def test_the_picker_links_each_source_to_both_pages() -> None:
    rows = [
        SourceHistoryRow(2, "Office UniFi", "unifi", True, 12, 2, "2026-10-24T08:00:00Z"),
        SourceHistoryRow(3, XSS, "xo", False, 0, 0, None),
    ]
    for mode, other in (("history", "/configuration"), ("configuration", "/history")):
        text = render_picker("viewer", rows, mode)
        parsed = assert_policy_clean(text)
        hrefs = {attrs.get("href") for attrs in parsed.find("a")}
        assert {f"/{mode}/2", f"/{mode}/3", f"{other}/2"} <= hrefs
        assert "No reading yet" in parsed.joined() and "disabled" in parsed.joined()
        assert XSS not in text and "&lt;script&gt;" in text


def test_an_empty_picker_offers_add_source_only_to_an_admin() -> None:
    admin = Parsed(render_picker("admin", []))
    assert {"class": "btn btn--primary", "href": "/sources/new"} in admin.find("a")
    viewer = Parsed(render_picker("viewer", []))
    assert "/sources/new" not in {attrs.get("href") for attrs in viewer.find("a")}
    assert "No sources yet" in viewer.joined()


# ---- the history ------------------------------------------------------------------------------


def history_view(rows: tuple[SnapshotRow, ...], source: SourceRef = UNIFI) -> SnapshotPageView:
    baselines = sum(1 for item in rows if item.is_baseline)
    return SnapshotPageView(source, rows, len(rows), baselines, 1, 1, 50)


def render_history(view: SnapshotPageView, role: str = "viewer", *, scheduled: bool = True) -> str:
    return render(
        "history/snapshots.html",
        shell(role, "history"),
        view=view,
        now=NOW,
        pager=(),
        summary=range_text(view.total, view.page, view.page_size, "reading"),
        ledger_mark=ledger_mark,
        size_text=size_text,
        parse_stamp=parse_stamp,
        count_words=count_words,
        configuration_href=configuration_href(view.source.id),
        type_label="UniFi Network",
        polled=view.source.type in ("unifi", "xo"),
        scheduled=scheduled,
        **roles(role),
    )


def test_the_ledger_marks_a_baseline_and_the_current_reading_in_words() -> None:
    rows = (row(3, current=True, changes=4), row(2), row(1, baseline=True))
    text = render_history(history_view(rows))
    parsed = assert_policy_clean(text)
    heads = [attrs for tag, attrs in parsed.tags if tag == "th" and attrs.get("scope") == "row"]
    assert [attrs.get("class") for attrs in heads] == ["ledger__mark"] * 3
    marks = [c for c in parsed.classes() if c.startswith("mark mark--")]
    assert marks[-3:] == ["mark mark--current", "mark mark--reading", "mark mark--baseline"]
    words = parsed.joined()
    assert "Current" in words and "Reading" in words and "Baseline" in words
    assert "Nothing is compared across it" in words
    hrefs = {attrs.get("href") for attrs in parsed.find("a")}
    assert {"/changes?source=2", "/configuration/2", "/sources/2"} <= hrefs
    assert "4.2 KB" in words and "9.0.114" in words


def test_the_history_offers_run_now_and_edit_by_role() -> None:
    view = history_view((row(1, baseline=True, current=True),))
    viewer = assert_policy_clean(render_history(view, "viewer"))
    assert forms(viewer) == set()
    assert "/sources/2/edit" not in {attrs.get("href") for attrs in viewer.find("a")}
    operator = Parsed(render_history(view, "operator"))
    assert forms(operator) == {"/sources/2/run"}
    hidden = [a for a in operator.find("input") if a.get("name") == "csrf_token"]
    assert {a.get("value") for a in hidden} == {CSRF}
    admin = Parsed(render_history(view, "admin"))
    assert forms(admin) == {"/sources/2/run"}
    assert "/sources/2/edit" in {attrs.get("href") for attrs in admin.find("a")}
    # no run without a scheduler, for a push source or a disabled source
    assert forms(Parsed(render_history(view, "operator", scheduled=False))) == set()
    push = history_view((row(1, baseline=True, current=True),), PUSH)
    assert forms(Parsed(render_history(push, "admin"))) == set()
    off = history_view((), SourceRef(2, "off", "unifi", False))
    assert forms(Parsed(render_history(off, "admin"))) == set()


def test_an_empty_history_says_why_there_is_no_reading() -> None:
    for source, words in (
        (UNIFI, "first check always stores one"),
        (PUSH, "first push of its sender"),
        (SourceRef(2, "off", "unifi", False), "This source is disabled"),
    ):
        parsed = assert_policy_clean(render_history(history_view((), source)))
        assert "No reading yet" in parsed.joined()
        assert words in parsed.joined(), source.name
    unscheduled = Parsed(render_history(history_view(()), scheduled=False))
    assert "not scheduled on this installation" in unscheduled.joined()


# ---- the configuration ------------------------------------------------------------------------


POLICIES = "unifi-firewall-policies"
WLANS = "unifi-wifi-broadcasts"


def config_view(**changes: Any) -> ConfigurationView:
    fields = (
        FieldView("name", "Block guests", "config", False, None, False, False),
        FieldView("rules[1].action", "BLOCK", "config", False, None, True, False),
        FieldView("x_key", None, "secret", True, FINGERPRINT, False, False),
        FieldView("x_new", None, "unclassified", False, FINGERPRINT, False, False),
        FieldView("x_passphrase", None, "secret", True, FINGERPRINT, False, True),
        FieldView("note", "x" * 2000, "config", False, None, False, False, truncated=True),
    )
    objects = tuple(
        ConfigObject(f"p{number}", f"Policy {number}" if number != 2 else XSS, number, fields)
        for number in (1, 2, 3)
    )
    values: dict[str, Any] = {
        "source": UNIFI,
        "snapshot": SnapshotRef(9, "2026-10-24T08:00:00Z", "baseline", "9.0.114"),
        "resources": (
            ResourceSummary(POLICIES, 3, True, ("x_passphrase",)),
            ResourceSummary(WLANS, 0, False, ()),
        ),
        "selected_resource": POLICIES,
        "search": "",
        "objects": objects,
        "total": 3,
        "page": 1,
        "pages": 1,
        "page_size": 50,
    }
    values.update(changes)
    return ConfigurationView(**values)


def render_configuration(view: ConfigurationView, role: str = "viewer") -> str:
    selected = next((r for r in view.resources if r.resource == view.selected_resource), None)
    return render(
        "history/configuration.html",
        shell(role, "configuration"),
        view=view,
        selected=selected,
        now=NOW,
        pager=(),
        summary=range_text(view.total, view.page, view.page_size, "object"),
        clear_href=configuration_href(view.source.id, resource=view.selected_resource),
        resource_href=lambda name: configuration_href(view.source.id, resource=name),
        history_href=history_href(view.source.id),
        unreadable=None,
        field_state=field_state,
        object_title=object_title,
        hidden_text=hidden_text,
        fingerprint_words=fingerprint_words,
        resource_label=resource_label,
        parse_stamp=parse_stamp,
        count_words=count_words,
        type_label="UniFi Network",
        polled=True,
        scheduled=True,
        **roles(role),
    )


def test_the_configuration_prints_every_shown_field_and_masks_the_rest() -> None:
    text = render_configuration(config_view())
    parsed = assert_policy_clean(text)
    words = parsed.joined()
    assert "Block guests" in words and "BLOCK" in words and "rules[1].action" in words
    assert words.count("secret a1b2 c3d4 e5f6") == 6  # x_key and x_passphrase, three objects
    assert words.count("unclassified, not shown a1b2 c3d4 e5f6") == 3
    assert words.count("cut at 2,000 characters") == 3
    assert SECRET not in text
    assert XSS not in text and "&lt;script&gt;alert(&#39;CANARY-xss&#39;)&lt;/script&gt;" in text


def test_an_ordered_resource_numbers_its_objects_in_the_gutter() -> None:
    parsed = Parsed(render_configuration(config_view()))
    assert "sheets sheets--ordered" in parsed.classes()
    assert parsed.classes().count("sheet__pos num") == 3
    assert "Position 1" in parsed.joined() and "Position 3" in parsed.joined()
    unordered = config_view(
        resources=(ResourceSummary(POLICIES, 1, False, ()),),
        objects=(ConfigObject("p1", "One", None, ()),),
        total=1,
    )
    plain = Parsed(render_configuration(unordered))
    assert "sheet__pos num" not in plain.classes()
    assert "No field is shown for this object." in plain.joined()


def test_fields_hidden_by_xo_carry_a_chip_and_the_resource_a_warning() -> None:
    parsed = Parsed(render_configuration(config_view()))
    assert "Some fields are hidden by XO" in parsed.joined()
    assert "a change to them cannot be observed: x_passphrase." in parsed.joined()
    assert parsed.joined().count("Hidden by XO") == 3


def test_the_resource_rail_marks_the_current_resource_and_swaps_with_htmx() -> None:
    parsed = Parsed(render_configuration(config_view()))
    rail = [a for a in parsed.find("a") if a.get("hx-target") == "#config-browser"]
    assert [a.get("href") for a in rail] == [
        f"/configuration/2?resource={POLICIES}",
        f"/configuration/2?resource={WLANS}",
    ]
    assert [a.get("aria-current") for a in rail] == ["page", None]
    assert all(a.get("hx-get") == a.get("href") for a in rail)
    search = [f for f in parsed.find("form") if f.get("role") == "search"]
    assert search and search[0].get("method") == "get" and search[0].get("hx-get")
    assert "Loading the objects" in {a.get("aria-label") for _t, a in parsed.tags}


def test_the_search_states_say_what_was_found_and_offer_to_clear() -> None:
    found = Parsed(render_configuration(config_view(search="guests", total=3)))
    assert "3 objects found for “guests”." in found.joined()
    none = Parsed(render_configuration(config_view(search="nothing", objects=(), total=0)))
    assert "No object matches “nothing”." in none.joined()
    clear = f"/configuration/2?resource={POLICIES}"
    assert clear in {attrs.get("href") for attrs in none.find("a")}
    cut = Parsed(render_configuration(config_view(search="x", search_truncated=True)))
    assert "first 5,000 objects" in cut.joined()


def test_the_configuration_empty_states() -> None:
    nothing = Parsed(render_configuration(config_view(snapshot=None, resources=(), objects=())))
    assert "No reading yet" in nothing.joined()
    assert "config-browser" not in " ".join(nothing.classes())
    empty = Parsed(render_configuration(config_view(resources=(), objects=(), total=0)))
    assert "This reading holds no objects" in empty.joined()


def test_the_configuration_head_offers_actions_by_role() -> None:
    viewer = Parsed(render_configuration(config_view()))
    assert forms(viewer) == {"/configuration/2"}  # the search form only
    assert {"/history/2", "/sources/2"} <= {attrs.get("href") for attrs in viewer.find("a")}
    operator = Parsed(render_configuration(config_view(), "operator"))
    assert forms(operator) == {"/configuration/2", "/sources/2/run"}
    admin = Parsed(render_configuration(config_view(), "admin"))
    assert "/sources/2/edit" in {attrs.get("href") for attrs in admin.find("a")}


def test_the_history_pages_load_their_own_stylesheet() -> None:
    sheet = Path(TEMPLATES_DIR).parent / "static" / "history.css"
    # the tokens of app.css only: no colour value of its own (and no id selector)
    assert sheet.is_file() and "#" not in sheet.read_text(encoding="utf-8")
    pages = (
        render_picker("viewer", []),
        render_history(history_view(())),
        render_configuration(config_view()),
    )
    for text in pages:
        links = [a.get("href") for a in Parsed(text).find("link") if a.get("rel") == "stylesheet"]
        assert links == ["/static/app.css", "/static/history.css"]


def test_a_damaged_store_is_the_designed_error_with_a_retry() -> None:
    text = render(
        "history/configuration.html",
        shell("viewer", "configuration"),
        view=None,
        source=UNIFI,
        unreadable=("The stored configuration cannot be read", "Nothing was changed."),
        retry_href="/configuration/2",
        history_href="/history/2",
        type_label="UniFi Network",
        polled=True,
        scheduled=True,
        **roles("viewer"),
    )
    parsed = assert_policy_clean(text)
    assert "The stored configuration cannot be read" in parsed.joined()
    assert {"method": "get", "action": "/configuration/2"} in parsed.find("form")
    assert {"class": "banner banner--error", "role": "alert"} in parsed.find("div")
