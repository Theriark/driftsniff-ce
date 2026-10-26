"""The app shell and the components of the interface, rendered in every state (P10-T2).

These tests use the Jinja environment directly, without the application, so they check the
markup itself: landmarks, labels, aria attributes, the severity signals, and the two rules the
content security policy imposes on every template (no inline script, no style attribute). The
helper functions of ``driftsniff.web.templating`` are checked on their own as well.
"""

import dataclasses
import json
import re
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute
from markupsafe import Markup

from driftsniff import __version__
from driftsniff.config import Settings
from driftsniff.main import create_app
from driftsniff.web.templating import (
    DRIFT_WIDTH,
    NAV_GROUPS,
    NAV_ICONS,
    NAV_ITEMS,
    SEVERITIES,
    TEMPLATES_DIR,
    Shell,
    drift_marks,
    drift_x,
    environment,
    initials,
    make_environment,
    nav_groups,
    nav_location,
    relative_time,
    render,
    sparkline_points,
    topbar_action,
)

NOW = datetime(2026, 10, 22, 8, 0, tzinfo=UTC)
CSRF = "CANARY-csrf-value"
HOSTILE = "a'<b>\"c"
ADMIN = Shell(
    title="Changes",
    nav_current="changes",
    user_name="r.marques",
    user_role="admin",
    csrf_token=CSRF,
    density="compact",
    environment_label="Development",
    path="/changes?status=open",
)
NOBODY = Shell(title="Sign in")

CHECKS: list[dict[str, Any]] = [
    {"kind": "ok", "age": 30},
    {"kind": "failed", "age": 20},
    {"kind": "change", "age": 10, "severity": "low", "summary": "Guest renamed", "href": "/c/1"},
    {"kind": "change", "age": 3, "severity": "medium", "summary": "to <b>x</b>", "href": "/c/2"},
    {"kind": "change", "age": 1, "severity": "high", "summary": "secure boot off", "href": "/c/3"},
    {"kind": "change", "age": 0, "severity": "critical", "summary": "policy gone", "href": "/c/4"},
]


class Parsed(HTMLParser):
    """The tags of a rendered fragment, with their attributes, in document order."""

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


def assert_policy_clean(text: str) -> None:
    """No style attribute, no inline event handler, no script without a src."""
    parsed = Parsed(text)
    for tag, attrs in parsed.tags:
        assert "style" not in attrs, f"<{tag}> carries a style attribute"
        assert not [name for name in attrs if name.startswith("on")], f"<{tag}> has a handler"
        if tag == "script":
            assert (attrs.get("src") or "").startswith("/static/"), "an inline script"


def assert_fields_are_labelled(text: str) -> None:
    """Every input, select and textarea has a visible label, an aria-label or is hidden."""
    parsed = Parsed(text)
    labelled = {attrs.get("for") for attrs in parsed.find("label")}
    for tag in ("input", "select", "textarea"):
        for attrs in parsed.find(tag):
            if attrs.get("type") == "hidden":
                continue
            assert attrs.get("id") in labelled or attrs.get("aria-label"), f"unlabelled {tag}"


def component(file: str, name: str) -> Callable[..., str]:
    module = make_environment().get_template(f"components/{file}").module
    macro = getattr(module, name)

    def call(*args: Any, **kwargs: Any) -> str:
        return str(macro(*args, **kwargs))

    return call


def rows() -> Markup:
    return Markup('<tr><td>a</td><td class="col-hide-s">b</td></tr>')


# ---- the shell ------------------------------------------------------------------------------


def page(shell: Shell, body: str = "<p>Body</p>") -> str:
    source = '{% extends "base.html" %}{% block content %}' + body + "{% endblock %}"
    return make_environment().from_string(source).render(shell=shell)


def test_the_shell_has_the_landmarks_and_the_skip_link() -> None:
    text = page(ADMIN)
    parsed = Parsed(text)
    assert text.startswith("<!doctype html>")
    assert parsed.find("main") == [{"id": "main", "class": "page"}]
    assert {"class": "skip-link", "href": "#main"} in parsed.find("a")
    assert any(attrs.get("aria-label") == "Main" for attrs in parsed.find("nav"))
    assert len(parsed.find("header")) == 1 and len(parsed.find("footer")) == 1
    assert "<title>Changes, driftsniff</title>" in text
    assert f"driftsniff CE {__version__}" in text
    assert "All times are UTC" in text
    assert_policy_clean(text)


def test_the_shell_navigation_marks_the_current_page_and_lists_every_entry() -> None:
    parsed = Parsed(page(dataclasses.replace(ADMIN, nav_current="sources", path="/sources")))
    links = {attrs.get("href"): attrs for attrs in parsed.find("a")}
    for _key, label, href in NAV_ITEMS:
        assert href in links, label
    assert links["/sources"].get("aria-current") == "page"
    assert "aria-current" not in links["/"]


def test_the_navigation_lists_only_pages_that_exist() -> None:
    # History and Configuration came back with P10-T7; /settings came back with P10-T8.
    assert [href for _key, _label, href in NAV_ITEMS] == [
        "/",
        "/changes",
        "/sources",
        "/history",
        "/configuration",
        "/settings",
    ]
    hrefs = {attrs.get("href") for attrs in Parsed(page(ADMIN)).find("a")}
    assert {"/changes", "/history", "/configuration"} <= hrefs
    assert "/settings" in hrefs


def test_the_sidebar_groups_every_entry_once_under_monitor_inventory_and_admin() -> None:
    assert [(key, label) for key, label, _members in NAV_GROUPS] == [
        ("monitor", "Monitor"),
        ("inventory", "Inventory"),
        ("admin", "Admin"),
    ]
    grouped = [item for _key, _label, members in NAV_GROUPS for item in members]
    assert grouped == [key for key, _label, _href in NAV_ITEMS]
    groups = nav_groups(dataclasses.replace(ADMIN, nav_current="history"))
    assert [[link.label for link in group.links] for group in groups] == [
        ["Dashboard", "Changes"],
        ["Sources", "History", "Configuration"],
        ["Settings"],
    ]
    assert [link.key for group in groups for link in group.links if link.current] == ["history"]


def test_the_sidebar_markup_labels_each_group_and_draws_an_existing_icon_per_entry() -> None:
    text = page(ADMIN)
    parsed = Parsed(text)
    assert parsed.find("header") == [{"class": "sidebar"}]
    headings = [attrs for attrs in parsed.find("p") if attrs.get("class") == "nav__heading"]
    assert [attrs.get("id") for attrs in headings] == ["nav-monitor", "nav-inventory", "nav-admin"]
    assert [attrs.get("aria-labelledby") for attrs in parsed.find("ul")] == [
        "nav-monitor",
        "nav-inventory",
        "nav-admin",
    ]
    sidebar = text.split('<nav class="nav" aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    links = [attrs for tag, attrs in Parsed(sidebar).tags if tag == "a"]
    assert [attrs["href"] for attrs in links] == [href for _key, _label, href in NAV_ITEMS]
    # no class on the entries: pages and the security suite match them as {href, aria-current}
    assert {"href": "/changes", "aria-current": "page"} in links
    symbols = (TEMPLATES_DIR / "_icons.html").read_text(encoding="utf-8")
    uses = {attrs.get("href") for attrs in parsed.find("use")}
    for key, icon in NAV_ICONS.items():
        assert f'<symbol id="{icon}"' in symbols, key
        assert f"#{icon}" in uses, key


def sidebar_links(shell: Shell) -> list[dict[str, str | None]]:
    """The entries of the sidebar navigation of a page rendered for ``shell``."""
    text = page(shell)
    sidebar = text.split('<nav class="nav" aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    return [attrs for tag, attrs in Parsed(sidebar).tags if tag == "a"]


def test_an_admin_sees_settings_under_admin_and_it_is_marked_on_its_page() -> None:
    on_settings = dataclasses.replace(ADMIN, title="Settings", nav_current="settings")
    links = sidebar_links(dataclasses.replace(on_settings, path="/settings"))
    assert links[-1] == {"href": "/settings", "aria-current": "page"}
    text = page(dataclasses.replace(on_settings, path="/settings"))
    sidebar = Parsed(text.split('<nav class="nav" aria-label="Main">', 1)[1].split("</nav>", 1)[0])
    assert sidebar.find("use")[-1] == {"href": "#i-settings"}
    assert sidebar.find("ul")[-1] == {"aria-labelledby": "nav-admin"}
    assert [word.strip() for word in sidebar.text if word.strip()][-2:] == ["Admin", "Settings"]
    # the trail of the top bar names the group, and a notice in the query keeps it the section
    at = nav_location(dataclasses.replace(on_settings, path="/settings?notice=user-added"))
    assert at is not None and (at.group, at.label, at.href, at.at_section) == (
        "Admin",
        "Settings",
        "/settings",
        True,
    )
    # on any other page the entry is a plain link
    assert {"href": "/settings"} in sidebar_links(ADMIN)


def test_a_viewer_or_an_operator_sees_no_settings_entry_and_no_admin_group() -> None:
    for role in ("viewer", "operator"):
        shell = dataclasses.replace(ADMIN, user_role=role)
        hrefs = [attrs.get("href") for attrs in sidebar_links(shell)]
        assert hrefs == ["/", "/changes", "/sources", "/history", "/configuration"], role
        assert "/settings" not in {a.get("href") for a in Parsed(page(shell)).find("a")}, role
        assert [group.key for group in nav_groups(shell)] == ["monitor", "inventory"], role
        assert 'id="nav-admin"' not in page(shell), role


def leaf_routes(routes: Iterable[Any], prefix: str = "") -> Iterator[tuple[Any, str]]:
    """The routes with the prefix of their inclusion; FastAPI wraps an included router."""
    for route in routes:
        nested = getattr(getattr(route, "original_router", None), "routes", None)
        if nested is None:
            nested = getattr(route, "routes", None)
        if nested is not None:
            context = getattr(route, "include_context", None)
            yield from leaf_routes(nested, prefix + str(getattr(context, "prefix", "") or ""))
        else:
            yield route, prefix


def test_every_navigation_entry_is_a_page_the_application_serves() -> None:
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": "http://testserver"}))
    pages = {
        prefix + route.path
        for route, prefix in leaf_routes(app.routes)
        if isinstance(route, APIRoute) and "GET" in (route.methods or set())
    }
    for _key, label, href in NAV_ITEMS:
        assert href in pages, label
    assert "/sources/new" in pages


def test_the_navigation_toggle_works_without_script_below_the_sidebar_width() -> None:
    parsed = Parsed(page(ADMIN))
    toggles = [attrs for attrs in parsed.find("details") if attrs.get("class") == "menu-toggle"]
    assert toggles == [{"class": "menu-toggle"}]
    tags = [(tag, attrs.get("class")) for tag, attrs in parsed.tags]
    # the navigation follows the toggle's summary directly, so the sibling rule can hide it
    after = tags.index(("details", "menu-toggle"))
    assert ("nav", "nav") in tags[after : after + 6]
    css = (TEMPLATES_DIR.parent / "static" / "app.css").read_text(encoding="utf-8")
    narrow = css.split("@media (max-width: 1023px) {\n  .app--signed-in {", 1)[1]
    assert ".menu-toggle:not([open]) + .nav {\n    display: none;" in narrow.split("@media", 1)[0]
    assert "grid-template-columns: var(--sidebar-w) minmax(0, 1fr);" in css


def test_the_top_bar_search_gives_way_before_the_action_wraps() -> None:
    # Found on Development (8da2b2f): with a fixed 320 px search the admin's Add source wrapped
    # to a row of its own at 768 px and at 1024 px beside the sidebar.
    css = (TEMPLATES_DIR.parent / "static" / "app.css").read_text(encoding="utf-8")
    block = css.split(".topbar__search {\n", 1)[1].split("}", 1)[0]
    assert "flex: 1 1 200px;" in block and "max-width: 320px;" in block
    phone = css.split("@media (max-width: 767px) {\n  .user-id {", 1)[1].split("@media", 1)[0]
    assert "flex: 1 1 100%;\n    max-width: none;" in phone


def test_the_location_trail_names_the_group_and_links_back_from_a_page_below() -> None:
    at = nav_location(dataclasses.replace(ADMIN, path="/changes?status=open"))
    assert at is not None and (at.group, at.label, at.at_section) == ("Monitor", "Changes", True)
    below = nav_location(dataclasses.replace(ADMIN, path="/changes/12"))
    assert below is not None and not below.at_section and below.href == "/changes"
    assert nav_location(dataclasses.replace(ADMIN, nav_current="")) is None
    home = nav_location(dataclasses.replace(ADMIN, nav_current="dashboard", path="/"))
    assert home is not None and home.at_section

    parsed = Parsed(page(ADMIN))
    trail = [attrs for attrs in parsed.find("nav") if attrs.get("aria-label") == "Location"]
    assert trail == [{"class": "crumbs", "aria-label": "Location"}]
    assert {"aria-current": "page"} in parsed.find("span")
    detail = Parsed(page(dataclasses.replace(ADMIN, path="/changes/12")))
    current = [attrs.get("href") for attrs in detail.find("a") if attrs.get("aria-current")]
    assert current == ["/changes"]  # only the sidebar entry; the trail links back up
    assert {"href": "/changes"} in detail.find("a")
    # no page-level breadcrumb landmark is added by the shell: pages own theirs
    assert not [a for a in detail.find("nav") if a.get("aria-label") == "Breadcrumb"]


def test_the_top_bar_searches_the_changes_with_a_labelled_get_form() -> None:
    parsed = Parsed(page(ADMIN))
    assert parsed.find("search") == [{"class": "topbar__search"}]
    assert {"method": "get", "action": "/changes"} in parsed.find("form")
    field = next(attrs for attrs in parsed.find("input") if attrs.get("id") == "shell-q")
    assert field["name"] == "q" and field["type"] == "search"
    assert {"class": "visually-hidden", "for": "shell-q"} in parsed.find("label")
    assert_fields_are_labelled(page(ADMIN))
    # the page's own filter forms keep role="search"; the shell form leaves that to <search>
    assert not [f for f in parsed.find("form") if f.get("role") == "search"]


def test_the_top_bar_offers_add_source_to_admins_outside_the_pages_that_lead_with_it() -> None:
    offered = ("Add source", "/sources/new")
    for path in ("/changes?page=2", "/changes/4", "/history", "/history/2", "/configuration/2"):
        assert topbar_action(dataclasses.replace(ADMIN, path=path)) == offered, path
    for path in ("/", "/sources", "/sources/3", "/sources/new?type=xo", "/sources/3/edit"):
        assert topbar_action(dataclasses.replace(ADMIN, path=path)) is None, path
    for role in ("operator", "viewer"):
        assert topbar_action(dataclasses.replace(ADMIN, user_role=role)) is None, role

    def actions(shell: Shell) -> list[dict[str, str | None]]:
        anchors = Parsed(page(shell)).find("a")
        return [a for a in anchors if "btn" in (a.get("class") or "").split()]

    # a secondary button, so the page's own primary button stays the only primary one
    assert actions(ADMIN) == [{"class": "btn topbar__action", "href": "/sources/new"}]
    # the label is its own span, so a phone can hide the words and keep the icon (THE-1416, F5)
    assert '<span class="topbar__action-label">Add source</span></a>' in page(ADMIN)
    for role in ("operator", "viewer"):
        assert actions(dataclasses.replace(ADMIN, user_role=role)) == [], role


def test_the_signed_out_shell_keeps_the_plain_header_without_sidebar_or_search() -> None:
    parsed = Parsed(page(Shell(title="Sign in", environment_label="Stage")))
    assert parsed.find("header") == [{"class": "app-header"}]
    assert parsed.find("body")[0]["class"] == "app"
    assert parsed.find("search") == [] and parsed.find("details") == []
    signed_in = Parsed(page(ADMIN)).find("body")[0]
    assert signed_in["class"] == "app app--signed-in"


def test_the_user_menu_shows_the_name_and_the_role_at_the_foot_of_the_sidebar() -> None:
    text = page(ADMIN)
    assert '<span class="user-name">r.marques</span>' in text
    assert '<span class="user-role"><span class="visually-hidden">, </span>admin</span>' in text
    sidebar = text.split('<header class="sidebar">', 1)[1].split("</header>", 1)[0]
    assert sidebar.index('class="nav"') < sidebar.index('class="user-menu"')


def test_the_shell_header_uses_the_horizontal_logo_at_48_px_with_a_dark_source() -> None:
    parsed = Parsed(page(ADMIN))
    logos = [attrs for attrs in parsed.find("img") if attrs.get("class") == "brand__logo"]
    assert logos == [
        {
            "class": "brand__logo",
            "src": "/static/brand/logo-horizontal-1200x400.png",
            "alt": "driftsniff",
            "width": "144",
            "height": "48",
        }
    ]
    sources = parsed.find("source")
    assert sources == [
        {
            "srcset": "/static/brand/logo-horizontal-dark-1200x400.png",
            "media": "(prefers-color-scheme: dark)",
        }
    ]
    icon = parsed.find("link")[0]
    assert icon["rel"] == "icon"
    assert icon["href"] == "/static/brand/favicon-32x32.png"
    assert icon["sizes"] == "32x32"


def test_the_shell_user_menu_names_the_user_and_signs_out_with_the_csrf_value() -> None:
    text = page(ADMIN)
    assert "Signed in as r.marques, admin" in text
    assert '<span class="avatar" aria-hidden="true">RM</span>' in text
    assert '<span class="env-badge">Development</span>' in text
    parsed = Parsed(text)
    forms = parsed.find("form")
    assert {"method": "post", "action": "/logout"} in forms
    assert {"type": "hidden", "name": "csrf_token", "value": CSRF} in parsed.find("input")


def test_the_shell_sends_the_csrf_value_in_the_htmx_header_and_configures_htmx() -> None:
    parsed = Parsed(page(ADMIN))
    body = parsed.find("body")[0]
    assert body["hx-headers"] == '{"X-CSRF-Token": "' + CSRF + '"}'
    config = next(attrs for attrs in parsed.find("meta") if attrs.get("name") == "htmx-config")
    assert '"allowEval": false' in str(config["content"])
    assert '"selfRequestsOnly": true' in str(config["content"])
    assert '"includeIndicatorStyles": false' in str(config["content"])
    scripts = parsed.find("script")
    assert scripts == [{"src": "/static/htmx.min.js", "defer": None}]


def test_the_csrf_value_is_escaped_in_the_header_attribute_and_the_form() -> None:
    hostile = Shell(title="x", user_name="eve", user_role="viewer", csrf_token=HOSTILE)
    text = page(hostile)
    assert "<b>" not in text.split("<body", 1)[1].split(">", 1)[0]
    parsed = Parsed(text)
    # tojson writes the quote and the angle brackets as JSON escapes, so the attribute holds
    # neither a raw quote nor a tag; parsed back, it is the exact value.
    assert json.loads(str(parsed.find("body")[0]["hx-headers"])) == {"X-CSRF-Token": HOSTILE}
    assert {"type": "hidden", "name": "csrf_token", "value": HOSTILE} in parsed.find("input")


def test_the_shell_without_a_user_has_no_navigation_menu_or_csrf_header() -> None:
    text = page(NOBODY)
    parsed = Parsed(text)
    assert not any(attrs.get("aria-label") == "Main" for attrs in parsed.find("nav"))
    assert parsed.find("form") == []
    assert "hx-headers" not in parsed.find("body")[0]
    assert "env-badge" not in text
    assert parsed.find("main") == [{"id": "main", "class": "page"}]
    assert_policy_clean(text)


def test_the_shell_shows_the_environment_badge_without_a_user_when_set() -> None:
    text = page(Shell(title="Sign in", environment_label="Stage"))
    assert '<span class="env-badge">Stage</span>' in text


def test_page_text_is_escaped() -> None:
    text = page(Shell(title="<script>alert(1)</script>"))
    assert "<script>alert" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


# ---- every component in every state ---------------------------------------------------------


def test_severity_badges_carry_colour_shape_and_word() -> None:
    badge = component("badges.html", "severity_badge")
    for severity in SEVERITIES:
        text = badge(severity)
        parsed = Parsed(text)
        assert parsed.find("span")[0]["class"] == f"sev sev--{severity}"
        assert parsed.find("use") == [{"href": f"#sev-{severity}"}]
        assert parsed.find("svg")[0]["aria-hidden"] == "true"
        assert severity.capitalize() in "".join(parsed.text)


def test_a_severity_shape_takes_the_colour_of_its_badge() -> None:
    """THE-1402 F1: the badge svg had no fill, so its shape rendered black (1.5 to 1 on the dark
    tint). The rule must give the svg the badge's text colour, and the shapes of the sprite must
    have no fill of their own, or they would not inherit it (THE-1416)."""
    css = (TEMPLATES_DIR.parent / "static" / "app.css").read_text(encoding="utf-8")
    block = re.search(r"^\.sev svg \{([^}]*)\}", css, re.MULTILINE)
    assert block is not None and re.search(r"fill:\s*currentColor;", block.group(1), re.I)
    icons = (TEMPLATES_DIR / "_icons.html").read_text(encoding="utf-8")
    for severity in SEVERITIES:
        symbol = re.search(rf'<symbol id="sev-{severity}"[^>]*>(.*?)</symbol>', icons, re.S)
        assert symbol is not None and "fill" not in symbol.group(1), severity


def test_code_fields_stay_mono_and_the_configuration_note_keeps_a_short_line() -> None:
    """THE-1402 F10: the declared resources textarea (class input mono) was set in the sans face,
    because the input rule resets the font after .mono, and the configuration footnote ran about
    150 characters wide."""
    static = TEMPLATES_DIR.parent / "static"
    css = (static / "app.css").read_text(encoding="utf-8")
    block = re.search(r"^\.input\.mono \{([^}]*)\}", css, re.MULTILINE)
    assert block is not None and "font-family: var(--font-mono);" in block.group(1)
    form = (TEMPLATES_DIR / "sources" / "form.html").read_text(encoding="utf-8")
    assert '<textarea class="input mono" id="push_fields"' in form
    history = (static / "history.css").read_text(encoding="utf-8")
    note = re.search(r"^\.config-note \{([^}]*)\}", history, re.MULTILINE)
    assert note is not None
    width = re.search(r"max-width: ([0-9]+)ch;", note.group(1))
    assert width is not None and int(width.group(1)) < 80
    page = (TEMPLATES_DIR / "history" / "configuration.html").read_text(encoding="utf-8")
    assert '<p class="hint config-note">Secret values are never stored.' in page


def test_status_badges_have_an_icon_and_a_word_for_every_kind() -> None:
    badge = component("badges.html", "status_badge")
    expected = {
        "ok": "i-check",
        "failing": "i-cross",
        "partial": "i-half",
        "stale": "i-clock",
        "unsupported": "i-dash",
        "insecure": "i-lock-open",
        "warn": "i-key",
        "open": "i-dash",
    }
    for kind, icon in expected.items():
        parsed = Parsed(badge(kind, "Word"))
        assert parsed.find("span")[0]["class"] == f"status status--{kind}"
        assert parsed.find("use") == [{"href": f"#{icon}"}]
        assert "Word" in parsed.text
    assert Parsed(badge("warn", "Open", icon="i-dash")).find("use") == [{"href": "#i-dash"}]


class Spoken(HTMLParser):
    """The text a screen reader reads: every word outside an aria-hidden element."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.hidden: list[bool] = []
        self.words: list[str] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        inside = bool(self.hidden) and self.hidden[-1]
        self.hidden.append(inside or dict(attrs).get("aria-hidden") == "true")

    def handle_endtag(self, tag: str) -> None:
        self.hidden.pop()

    def handle_data(self, data: str) -> None:
        if not (self.hidden and self.hidden[-1]) and data.strip():
            self.words.append(data.strip())


def spoken(text: str) -> str:
    return " ".join(Spoken(text).words)


def test_metric_card_in_every_state() -> None:
    card = component("cards.html", "metric_card")
    full = card(
        "Open changes",
        23,
        "/changes",
        delta="5 fewer than last week",
        tone="down",
        trend="down",
        spark=[3, 5, 4, 8],
    )
    parsed = Parsed(full)
    assert parsed.find("a")[0] == {"class": "card metric", "href": "/changes"}
    spans = parsed.find("span")
    assert {"class": "metric__value num", "aria-hidden": "true"} in spans
    assert {"class": "metric__delta metric__delta--down", "aria-hidden": "true"} in spans
    # the colour never works alone: the arrow and the words say the same
    assert parsed.find("use") == [{"href": "#i-trend-down"}]
    assert parsed.find("polyline") == [{"points": "0.0,31.0 32.0,20.6 64.0,25.8 96.0,5.0"}]
    # one sentence for a screen reader, starting with the visible label
    sentence = "Open changes: 23. 5 fewer than last week. Last 4 values: 3, 5, 4, 8."
    assert spoken(full) == sentence
    bare = card("Sources healthy", 2, "/sources", unit="of 4")
    assert "<small> of 4</small>" in bare
    assert "polyline" not in bare and "metric__delta" not in bare
    assert spoken(bare) == "Sources healthy: 2 of 4."
    assert_policy_clean(full)


def test_metric_card_glyph_follows_the_trend_then_the_tone() -> None:
    card = component("cards.html", "metric_card")

    def glyph(**kwargs: Any) -> list[dict[str, str | None]]:
        return Parsed(card("Label", 1, "/x", delta="words", **kwargs)).find("use")

    assert glyph(trend="up", tone="up") == [{"href": "#i-trend-up"}]
    assert glyph(trend="flat") == [{"href": "#i-dash"}]
    assert glyph(tone="up") == [{"href": "#sev-high"}]
    assert glyph(tone="alert") == [{"href": "#sev-critical"}]
    assert glyph() == []


def test_metric_card_draws_no_sparkline_for_a_series_of_zeros() -> None:
    card = component("cards.html", "metric_card")
    quiet = card("Open changes", 0, "/changes", delta="none", trend="flat", spark=[0, 0, 0])
    assert "polyline" not in quiet and "Last 3 values" not in quiet
    assert spoken(quiet) == "Open changes: 0. None."


def test_metric_card_escapes_every_text_it_prints() -> None:
    card = component("cards.html", "metric_card")
    text = card(HOSTILE, HOSTILE, '/x?a="b"', unit=HOSTILE, delta=HOSTILE, tone=HOSTILE)
    assert "<b>" not in text
    # three in the sentence, the label, the value, the unit, the tone class and the delta
    assert text.count("a&#39;&lt;b&gt;&#34;c") == 8
    assert text.count("A&#39;&lt;b&gt;&#34;c.") == 1  # the delta as a sentence
    parsed = Parsed(text)
    assert parsed.find("a")[0]["href"] == '/x?a="b"'
    assert parsed.find("span")[-2]["class"] == f"metric__delta metric__delta--{HOSTILE}"
    assert spoken(text) == f"{HOSTILE}: {HOSTILE} {HOSTILE}. A{HOSTILE[1:]}."
    assert_policy_clean(text)


def test_metric_card_draws_negative_values_and_a_series_that_sums_to_zero() -> None:
    card = component("cards.html", "metric_card")
    text = card("Net change", -3, "/x", delta="3 fewer", trend="down", spark=[-2, 0, 2])
    assert Parsed(text).find("polyline") == [{"points": "0.0,31.0 48.0,18.0 96.0,5.0"}]
    assert spoken(text) == "Net change: -3. 3 fewer. Last 3 values: -2, 0, 2."
    below = card("Net change", -1, "/x", spark=[-1, -4])
    assert Parsed(below).find("polyline") == [{"points": "0.0,5.0 96.0,31.0"}]


def test_metric_card_ignores_an_unknown_trend_or_tone_but_keeps_the_words() -> None:
    card = component("cards.html", "metric_card")

    def glyph(**kwargs: Any) -> list[dict[str, str | None]]:
        return Parsed(card("Label", 1, "/x", delta="words", **kwargs)).find("use")

    assert glyph(trend="sideways", tone="up") == [{"href": "#sev-high"}]
    assert glyph(trend="sideways") == []
    assert glyph(tone="bogus") == []
    assert "words" in card("Label", 1, "/x", delta="words", trend="sideways", tone="bogus")


def test_data_table_in_both_densities_with_sort_and_hidden_columns() -> None:
    table = component("table.html", "data_table")
    columns = [
        {"label": "Severity", "sort_href": "/c?sort=sev", "sort_dir": "descending"},
        {"label": "Change"},
        {"label": "Source", "class": "col-hide-s"},
    ]
    comfortable = table("Detected changes", columns, caller=rows)
    parsed = Parsed(comfortable)
    assert parsed.find("table") == [{"class": "data-table"}]
    assert parsed.find("caption")[0]["class"] == "visually-hidden"
    heads = parsed.find("th")
    assert heads[0]["aria-sort"] == "descending" and heads[0]["scope"] == "col"
    assert {"href": "/c?sort=sev"} in parsed.find("a")
    assert heads[2]["class"] == "col-hide-s"
    assert "<tr><td>a</td>" in comfortable
    assert "table-foot" not in comfortable
    compact = table("Detected changes", columns, density="compact", foot_text="1 of 1", caller=rows)
    assert Parsed(compact).find("table") == [{"class": "data-table data-table--compact"}]
    assert "1 of 1" in compact
    assert_policy_clean(compact)


def test_density_switch_is_a_form_post_with_both_choices_pressed_right() -> None:
    switch = component("table.html", "density_switch")
    for density in ("comfortable", "compact"):
        text = switch(density, "/changes?page=2", CSRF)
        parsed = Parsed(text)
        assert parsed.find("form")[0] == {
            "class": "segmented",
            "method": "post",
            "action": "/preferences/density",
            "role": "group",
            "aria-label": "Row density",
        }
        inputs = parsed.find("input")
        assert {"type": "hidden", "name": "csrf_token", "value": CSRF} in inputs
        assert {"type": "hidden", "name": "next", "value": "/changes?page=2"} in inputs
        pressed = {attrs["value"]: attrs["aria-pressed"] for attrs in parsed.find("button")}
        assert pressed == {
            "comfortable": "true" if density == "comfortable" else "false",
            "compact": "true" if density == "compact" else "false",
        }


def test_pager_marks_the_current_page_as_text() -> None:
    pager = component("table.html", "pager")
    text = pager(
        [
            {"label": "1", "href": "", "current": True},
            {"label": "2", "href": "/c?page=2", "current": False},
            {"label": "Next", "href": "/c?page=2", "current": False},
        ],
        summary="Showing 1 to 50 of 231",
    )
    parsed = Parsed(text)
    assert parsed.find("nav") == [{"class": "pager", "aria-label": "Pages"}]
    assert {"aria-current": "page"} in parsed.find("span")
    assert [attrs["href"] for attrs in parsed.find("a")] == ["/c?page=2", "/c?page=2"]
    assert "Showing 1 to 50 of 231" in text


def test_filter_bar_search_box_and_select_are_labelled() -> None:
    # The macros are composed in a template, the way a page does it, so no Markup is built here.
    source = (
        '{% from "components/forms.html" import filter_bar, search_box, select_field %}'
        '{% call filter_bar("/changes", "Filter changes") %}'
        '{{ search_box("q", "q", "Search summary", value=value, placeholder="Search") }}'
        '{{ select_field("f-sev", "severity", "Severity", options, selected="high") }}'
        "{% endcall %}"
    )
    options = [{"value": "", "label": "Any"}, {"value": "high", "label": "High"}]
    text = make_environment().from_string(source).render(value="a<b", options=options)
    parsed = Parsed(text)
    assert parsed.find("form")[0] == {
        "class": "filter-bar",
        "method": "get",
        "action": "/changes",
        "role": "search",
        "aria-label": "Filter changes",
    }
    assert_fields_are_labelled(text)
    assert {"type": "search", "value": "a<b"}.items() <= parsed.find("input")[0].items()
    options_found = parsed.find("option")
    assert options_found == [{"value": ""}, {"value": "high", "selected": None}]
    assert {"class": "btn", "type": "submit"} in parsed.find("button")


def test_text_field_in_its_plain_help_and_error_states() -> None:
    field = component("forms.html", "text_field")
    plain = Parsed(field("name", "name", "Source name", value="office-xo"))
    assert plain.find("input")[0] == {
        "class": "input",
        "id": "name",
        "name": "name",
        "type": "text",
        "value": "office-xo",
    }
    assert plain.find("label") == [{"for": "name"}]
    helped = Parsed(field("key", "key", "API key", type="password", help="Write-only."))
    assert helped.find("input")[0]["aria-describedby"] == "key-help"
    assert "aria-invalid" not in helped.find("input")[0]
    wrong = field("key", "key", "API key", help="Write-only.", error="Enter the API key.")
    parsed = Parsed(wrong)
    assert parsed.find("input")[0]["aria-invalid"] == "true"
    assert parsed.find("input")[0]["aria-describedby"] == "key-help key-error"
    assert "Write-only." in wrong and "Enter the API key." in wrong


def test_confirm_form_asks_for_the_typed_text_and_carries_the_csrf_value() -> None:
    confirm = component("forms.html", "confirm_form")
    text = confirm("/sources/3/delete", "branch-gw", CSRF, "Delete source", "Removes it.")
    parsed = Parsed(text)
    form = parsed.find("form")[0]
    assert form == {"method": "post", "action": "/sources/3/delete", "class": "stack"}
    assert {"type": "hidden", "name": "csrf_token", "value": CSRF} in parsed.find("input")
    typed = parsed.find("input")[1]
    assert typed["name"] == "confirm" and typed["placeholder"] == "branch-gw"
    assert "required" in typed and typed["autocomplete"] == "off"
    assert_fields_are_labelled(text)
    assert {"class": "btn btn--danger", "type": "submit"} in parsed.find("button")
    assert "Removes it." in text


def test_empty_state_with_and_without_an_action() -> None:
    empty = component("states.html", "empty_state")
    with_action = empty("Nothing to watch yet", "Add a source.", "/sources/new", "Add source")
    parsed = Parsed(with_action)
    assert parsed.find("img") == [
        {"src": "/static/brand/logo-mark-512x512.png", "alt": "", "width": "96", "height": "96"}
    ]
    assert parsed.find("a") == [{"class": "btn btn--primary", "href": "/sources/new"}]
    without = empty("Nothing here", "Come back later.")
    assert Parsed(without).find("a") == []


def test_loading_skeleton_is_a_live_status_and_can_be_an_htmx_indicator() -> None:
    skeleton = component("states.html", "skeleton")
    plain = Parsed(skeleton("Loading changes", rows=3))
    assert plain.find("div") == [
        {
            "class": "skeleton",
            "role": "status",
            "aria-live": "polite",
            "aria-label": "Loading changes",
        }
    ]
    assert len(plain.find("span")) == 3
    indicator = Parsed(skeleton("Loading", indicator=True))
    assert indicator.find("div")[0]["class"] == "skeleton htmx-indicator"
    assert len(indicator.find("span")) == 5


def test_error_state_is_an_alert_with_a_retry_form() -> None:
    error = component("states.html", "error_state")
    text = error("The list could not be loaded", "Nothing was changed.", retry_href="/changes")
    parsed = Parsed(text)
    assert parsed.find("div")[0] == {"class": "banner banner--error", "role": "alert"}
    assert parsed.find("form") == [{"method": "get", "action": "/changes"}]
    assert "Try again" in text
    quiet = error("Failed", "Nothing was changed.")
    assert Parsed(quiet).find("form") == []


def test_banners_in_the_three_kinds_and_the_success_shortcut() -> None:
    banner = component("states.html", "banner")
    expected = {
        "success": ("status", "i-check"),
        "warn": ("status", "i-clock"),
        "error": ("alert", "i-info"),
    }
    for kind, (role, icon) in expected.items():
        parsed = Parsed(banner(kind, "Title", "Text", "/x", "Act"))
        assert parsed.find("div")[0] == {"class": f"banner banner--{kind}", "role": role}
        assert parsed.find("use") == [{"href": f"#{icon}"}]
        assert parsed.find("a") == [{"class": "btn btn--small", "href": "/x"}]
    success = component("states.html", "success_banner")("Change acknowledged")
    parsed = Parsed(success)
    assert parsed.find("div")[0]["class"] == "banner banner--success"
    assert parsed.find("a") == [] and "Change acknowledged" in success


def test_definition_list_disclosure_and_time() -> None:
    definition_list = component("details.html", "definition_list")
    items = [{"term": "Type", "value": "UniFi"}, {"term": "Address", "value": "x", "mono": True}]
    text = definition_list(items)
    parsed = Parsed(text)
    assert parsed.find("dl") == [{"class": "kv"}]
    assert parsed.find("dd") == [{}, {"class": "mono"}]
    disclosure = component("details.html", "disclosure")
    closed = disclosure("Why?", kind="rationale", caller=lambda: Markup("<p>Because.</p>"))
    assert Parsed(closed).find("details") == [{"class": "rationale"}]
    opened = disclosure("Table", open=True, caller=lambda: Markup("<table></table>"))
    assert Parsed(opened).find("details") == [{"class": "disclosure", "open": None}]
    time_tag = component("details.html", "time_tag")
    when = NOW - timedelta(hours=2)
    assert time_tag(when, NOW) == (
        '<time datetime="2026-10-22T06:00:00Z" title="2026-10-22 06:00:00 UTC">2 hours ago</time>'
    )


def test_drift_line_draws_every_check_kind_and_describes_itself() -> None:
    drift = component("driftline.html", "drift_line")
    text = drift("lab-controller", CHECKS, "dl1", href="/sources/1", meta="6 checks")
    parsed = Parsed(text)
    svg = parsed.find("svg")[0]
    # it holds change links, so it is a group, not an image (axe nested-interactive, THE-1351)
    assert svg["role"] == "group" and svg["aria-labelledby"] == "dl1-t dl1-d"
    assert svg["viewbox"] == f"0 0 {DRIFT_WIDTH} 32"  # the parser lowercases names
    assert "Drift line of lab-controller, last 30 days" in text
    assert len([a for a in parsed.find("line") if a.get("class") == "tick"]) == 1
    assert parsed.find("rect") == [
        {"class": "tick--hollow", "x": "207", "y": "12", "width": "6", "height": "14"}
    ]
    assert parsed.find("circle") == [{"class": "mark mark--low", "cx": "410", "cy": "18", "r": "6"}]
    paths = [attrs["class"] for attrs in parsed.find("path")]
    assert paths == ["mark mark--medium", "mark mark--high", "mark mark--critical"]
    links = [attrs["href"] for attrs in parsed.find("a") if attrs.get("class") is None]
    assert links == ["/c/1", "/c/2", "/c/3", "/c/4"]
    assert "to &lt;b&gt;x&lt;/b&gt;" in text
    assert "30 days ago" in text and "today" in text
    assert {"class": "driftline__name", "href": "/sources/1"} in parsed.find("a")
    short = drift("lab-controller", CHECKS, "dl2", short=True)
    assert "driftline driftline--short" in short and "driftline__name" not in short


def test_drift_line_with_no_checks_is_an_empty_strip() -> None:
    drift = component("driftline.html", "drift_line")
    text = drift("new-source", [], "dl3")
    parsed = Parsed(text)
    assert parsed.find("circle") == [] and parsed.find("path") == []
    assert "0 checks." in text


def test_page_header_with_crumbs_and_actions() -> None:
    # Jinja's TemplateModule has no static attributes, so mypy needs the macro typed as Any.
    module: Any = make_environment().get_template("page_header.html").module
    macro = module.page_header
    text = str(
        macro(
            "Event 4,812",
            "What changed.",
            crumbs=[{"label": "Changes", "href": "/changes"}],
            caller=lambda: Markup('<a class="btn btn--primary" href="/a">Acknowledge</a>'),
        )
    )
    parsed = Parsed(text)
    assert parsed.find("nav") == [{"class": "breadcrumb", "aria-label": "Breadcrumb"}]
    assert parsed.find("h1") == [{}] and "Event 4,812" in text
    assert "page-header__actions" in text
    plain = str(macro("Dashboard"))
    assert "breadcrumb" not in plain and "page-header__actions" not in plain


# ---- the two rules of the content security policy, over the files themselves ---------------


def test_no_template_file_has_a_style_attribute_or_an_inline_script() -> None:
    for path in sorted(TEMPLATES_DIR.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        assert " style=" not in text, path.name
        assert "<style" not in text, path.name
        assert "javascript:" not in text, path.name
        for line in text.splitlines():
            if "<script" in line:
                assert 'src="/static/' in line and "</script>" in line, path.name


def test_the_stylesheet_and_htmx_are_shipped_with_a_licence_file() -> None:
    static = Path(TEMPLATES_DIR).parent / "static"
    assert (static / "app.css").is_file()
    htmx = (static / "htmx.min.js").read_text(encoding="utf-8")
    assert 'version:"2.0.4"' in htmx
    licence = (static / "htmx.min.js.LICENSE.txt").read_text(encoding="utf-8")
    assert "Zero-Clause BSD" in licence and "2.0.4" in licence


# ---- the helpers ----------------------------------------------------------------------------


def test_initials() -> None:
    assert initials("r.marques") == "RM"
    assert initials("ana silva") == "AS"
    assert initials("ops") == "OP"
    assert initials("") == "?"


def test_relative_time_in_both_directions() -> None:
    assert relative_time(NOW, NOW) == "just now"
    assert relative_time(NOW - timedelta(seconds=59), NOW) == "just now"
    assert relative_time(NOW - timedelta(minutes=1), NOW) == "1 minute ago"
    assert relative_time(NOW - timedelta(minutes=5), NOW) == "5 minutes ago"
    assert relative_time(NOW - timedelta(hours=1, minutes=30), NOW) == "1 hour ago"
    assert relative_time(NOW - timedelta(days=3), NOW) == "3 days ago"
    assert relative_time(NOW + timedelta(seconds=10), NOW) == "in under a minute"
    assert relative_time(NOW + timedelta(minutes=35), NOW) == "in 35 minutes"
    assert relative_time(NOW + timedelta(days=1), NOW) == "in 1 day"


def test_sparkline_points_scale_into_the_box() -> None:
    assert sparkline_points([]) == ""
    assert sparkline_points([4]) == "0.0,18.0 96.0,18.0"
    assert sparkline_points([2, 2, 2]) == "0.0,18.0 48.0,18.0 96.0,18.0"
    assert sparkline_points([0, 10]) == "0.0,31.0 96.0,5.0"
    assert sparkline_points([0, 5, 10], width=100, height=20) == "0.0,15.0 50.0,10.0 100.0,5.0"


def test_drift_marks_and_width() -> None:
    marks = drift_marks(CHECKS)
    assert [mark.kind for mark in marks] == ["ok", "failed", "change", "change", "change", "change"]
    assert [mark.x for mark in marks] == [10.0, 210.0, 410.0, 550.0, 590.0, 610.0]
    assert marks[2].d == "" and marks[3].d == "M550 10 L558 25 H542 Z"
    assert marks[4].d == "M590 9 L599 18 L590 27 L581 18 Z"
    assert marks[5].d == "M606.3 9 H613.7 L619 14.3 V21.7 L613.7 27 H606.3 L601 21.7 V14.3 Z"
    assert DRIFT_WIDTH == 620
    for bad in (
        {"kind": "odd", "age": 1},
        {"kind": "change", "age": 1, "severity": "worse"},
        {"kind": "ok"},
    ):
        try:
            drift_marks([bad])
        except ValueError:
            continue
        raise AssertionError(f"{bad} was accepted")


def test_a_drift_mark_sits_at_the_time_of_its_check_not_at_its_place_in_the_list() -> None:
    """THE-1402 F2: the marks were packed from the left (x = 8 + 20 * index) under the axis
    "30 days ago ... today", so the only check of a source, made an hour ago, was drawn at
    30 days ago and a narrow strip that opens on today opened empty."""
    hour = 1 / 24
    (only,) = drift_marks([{"kind": "change", "age": hour, "severity": "high", "href": "/c/9"}])
    assert only.x == drift_x(hour) and only.x > drift_x(0) - 1
    assert only.d.startswith(f"M{only.x:g} ")
    # two checks a day apart are one day step apart wherever they are in the window
    recent = drift_marks([{"kind": "ok", "age": 1.0}, {"kind": "ok", "age": 0.0}])
    assert [mark.x for mark in recent] == [590.0, 610.0]
    assert drift_x(30) == 10.0 and drift_x(15) == 310.0 and drift_x(0) == 610.0
    # a time outside the window is held at the nearer end, never drawn off the strip
    assert drift_x(30.6) == 10.0 and drift_x(-0.01) == 610.0


@pytest.mark.parametrize("age", [0.0, 30.0])
@pytest.mark.parametrize("severity", SEVERITIES)
def test_every_drift_mark_and_its_focus_stroke_fit_inside_the_strip(
    age: float, severity: str
) -> None:
    """THE-1416: with an 8 unit pad the critical mark at today reached x 617 of a 616 wide
    viewBox (618 with the 2 unit focus stroke), so its right edge was cut off."""
    check = {"kind": "change", "age": age, "severity": severity, "href": "/c/1"}
    (mark,) = drift_marks([check])
    if mark.d:
        xs = [float(n) for n in re.findall(r"[MLH](-?[0-9.]+)", mark.d)]
    else:  # the low circle, radius 6
        xs = [mark.x - 6, mark.x + 6]
    focus = 1  # half of the 2 unit focus stroke lies outside the shape
    assert min(xs) - focus >= 0 and max(xs) + focus <= DRIFT_WIDTH, (severity, age, xs)


def test_a_drift_line_draws_its_changes_over_the_ticks_of_the_same_time() -> None:
    drift = component("driftline.html", "drift_line")
    checks = [
        {"kind": "change", "age": 0.02, "severity": "low", "summary": "a", "href": "/c/1"},
        {"kind": "ok", "age": 0.01},
        {"kind": "failed", "age": 0.0},
    ]
    marks = drift_marks(checks)
    assert [mark.kind for mark in marks] == ["ok", "failed", "change"]
    text = drift("lab-controller", checks, "dl9")
    assert text.index('class="tick"') < text.index('class="tick--hollow"') < text.index("/c/1")
    (circle,) = Parsed(text).find("circle")
    assert circle["cx"] == "609"


def test_render_uses_one_shared_environment() -> None:
    assert environment() is environment()
    # A macro-only template renders to nothing but whitespace; render still goes through.
    assert render("page_header.html", NOBODY).strip() == ""
