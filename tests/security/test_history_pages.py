"""The History and Configuration pages through the real application (P10-T7, frontend slice).

The JSON answers and their status codes are slice A's (``test_history_routes.py``); these tests
ask the same routes for pages, the way a browser does, and check what a person sees: the baseline
marker, the newest values, the controls each role gets, the designed error and empty states, the
HTMX swap of the configuration, and that no canary and no markup from stored data reaches a page.
The role rules themselves are rows of ``ROUTE_TABLE`` and are called as every kind of caller by
``test_route_table.py``. Everything is synthetic; text that must never travel starts with CANARY-.
"""

from html.parser import HTMLParser
from typing import Any

import sqlalchemy as sa
from httpx import Response
from markupsafe import escape

from driftsniff.db.tables import snapshots

from .appkit import Kit
from .canary import WLAN, Leak, assert_no_leaks
from .test_history_routes import (
    every_path,
    plain_lab,
    planted,
    seed,
    two_snapshots,
    use_tables,
    whole,
)
from .test_xss import PAYLOADS

BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
SURFACE = "history page"
MARKUP = tuple(payload for payload in PAYLOADS if "<" in payload)


class Tags(HTMLParser):
    """The start tags of a page with their attributes."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def attrs(self, name: str) -> list[dict[str, str | None]]:
        return [attrs for tag, attrs in self.tags if tag == name]

    def forms(self) -> set[str | None]:
        # the shell's own forms: sign out, and the change search of the top bar (GET /changes)
        return {attrs.get("action") for attrs in self.attrs("form")} - {"/logout", "/changes"}

    def hrefs(self) -> set[str | None]:
        return {attrs.get("href") for attrs in self.attrs("a")}


def page(kit: Kit, path: str, role: str = "viewer", **params: Any) -> Response:
    """``path`` asked for by a browser signed in as ``role``."""
    headers = {**kit.new_session(role).headers(), **BROWSER}
    response = kit.client.get(path, headers=headers, params=params)
    kit.client.cookies.clear()
    return response


def html_page(response: Response, status: int = 200) -> str:
    assert response.status_code == status, response.text[:500]
    assert response.headers["content-type"].startswith("text/html")
    return response.text


# ---- the plan's checks ------------------------------------------------------------------------


def test_the_history_page_marks_the_baseline_and_the_current_reading(kit: Kit) -> None:
    two_snapshots(kit)
    text = html_page(page(kit, "/history/1"))
    # once in the key above the table, once on the reading itself
    assert text.count('class="mark mark--baseline"') == 2
    assert text.count('class="mark mark--current"') == 2
    assert '<span class="ledger__word">Baseline</span>' in text
    assert '<span class="ledger__word">Current</span>' in text
    assert "Nothing is compared across it" in text


def test_the_configuration_page_prints_every_shown_value_of_the_newest_reading(kit: Kit) -> None:
    two_snapshots(kit)
    text = html_page(page(kit, "/configuration/1", resource=WLAN))
    data = kit.client.get(
        "/configuration/1", headers=kit.new_session("viewer").headers(), params={"resource": WLAN}
    ).json()["configuration"]
    kit.client.cookies.clear()
    shown = [
        field["value"]
        for obj in data["objects"]
        for field in obj["fields"]
        if field["value"] is not None
    ]
    assert shown
    for value in shown:
        assert f'<span class="mono field-value">{escape(value)}</span>' in text, value
    assert '<span class="mono field-value">102</span>' in text
    assert '<span class="mono field-value">101</span>' not in text  # the older reading


# ---- secrets and markup -----------------------------------------------------------------------


def test_no_canary_reaches_a_page_and_secrets_show_as_fingerprints(kit: Kit) -> None:
    scanner, _issued = planted(kit)
    session = kit.new_session("viewer")
    leaks: list[Leak] = []
    fingerprints = 0
    for path in every_path():
        response = kit.client.get(path, headers={**session.headers(), **BROWSER})
        html_page(response)
        leaks.extend(scanner.find(SURFACE, path, whole(response)))
        fingerprints += response.text.count('class="fingerprint"')
    swap = kit.client.get(
        f"/configuration/1?resource={WLAN}", headers={**session.headers(), "HX-Request": "true"}
    )
    html_page(swap)
    leaks.extend(scanner.find(SURFACE, "an HTMX swap", whole(swap)))
    kit.client.cookies.clear()
    assert_no_leaks(leaks)
    assert fingerprints > 0


def test_markup_in_stored_text_renders_as_text_on_every_page(kit: Kit) -> None:
    use_tables(kit)
    raw: list[dict[str, Any]] = [
        {"_id": f"p{number}", "name": text, "description": text}
        for number, text in enumerate(PAYLOADS)
    ]
    seed(kit, {WLAN: raw}, controller=PAYLOADS[0])
    for path in ("/history", "/history/1", "/configuration", f"/configuration/1?resource={WLAN}"):
        text = html_page(page(kit, path))
        for payload in MARKUP:
            assert payload not in text, path
        for attrs in Tags(text).attrs("a"):
            assert not (attrs.get("href") or "").lower().startswith("javascript:"), path
    configuration = page(kit, "/configuration/1", resource=WLAN).text
    history = page(kit, "/history/1").text
    for text in (configuration, history):
        assert str(escape(PAYLOADS[0])) in text


# ---- roles ------------------------------------------------------------------------------------


def test_the_pages_offer_run_now_to_an_operator_and_edit_to_an_admin(kit: Kit) -> None:
    two_snapshots(kit)
    with kit.store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (2, 'office-unifi', 'unifi')"
        )
    kit.app.state.scheduler = object()  # read by the pages only; no run is started here
    try:
        for path in ("/history/2", "/configuration/2"):
            viewer = Tags(html_page(page(kit, path, "viewer")))
            assert viewer.forms() == set(), path
            assert "/sources/2/edit" not in viewer.hrefs(), path
            operator = Tags(html_page(page(kit, path, "operator")))
            assert operator.forms() == {"/sources/2/run"}, path
            run = [a for a in operator.attrs("input") if a.get("name") == "csrf_token"]
            assert run and all(a.get("value") for a in run), path
            admin = Tags(html_page(page(kit, path, "admin")))
            assert "/sources/2/edit" in admin.hrefs(), path
        # a push source is never run, whatever the role
        for path in ("/history/1", "/configuration/1"):
            assert "/sources/1/run" not in Tags(html_page(page(kit, path, "admin"))).forms()
    finally:
        kit.app.state.scheduler = None


def test_without_a_scheduler_nobody_is_offered_run_now(kit: Kit) -> None:
    with kit.store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (2, 'office-unifi', 'unifi')"
        )
    use_tables(kit)
    for path in ("/history/2", "/configuration/2"):
        text = html_page(page(kit, path, "admin"))
        assert Tags(text).forms() == set(), path
        assert "No reading yet" in text, path


# ---- states, navigation, HTMX -----------------------------------------------------------------


def test_the_pickers_link_both_pages_and_mark_the_navigation(kit: Kit) -> None:
    two_snapshots(kit)
    for path, other in (("/history", "/configuration/1"), ("/configuration", "/history/1")):
        text = html_page(page(kit, path))
        tags = Tags(text)
        assert {f"{path}/1", other} <= tags.hrefs(), path
        assert {"href": path, "aria-current": "page"} in tags.attrs("a"), path
    for path, nav in (("/history/1", "/history"), ("/configuration/1", "/configuration")):
        tags = Tags(html_page(page(kit, path)))
        assert {"href": nav, "aria-current": "page"} in tags.attrs("a"), path


def test_a_source_without_a_reading_shows_the_empty_states(kit: Kit) -> None:
    use_tables(kit)
    for path in ("/history/1", "/configuration/1"):
        text = html_page(page(kit, path))
        assert "No reading yet" in text, path
        assert 'id="config-browser"' not in text, path


def test_a_search_without_a_match_says_so_and_offers_to_clear_it(kit: Kit) -> None:
    two_snapshots(kit)
    text = html_page(page(kit, "/configuration/1", resource=WLAN, q="nothing like this"))
    assert "No object matches" in text
    assert f"/configuration/1?resource={WLAN}" in Tags(text).hrefs()


def test_the_configuration_pager_keeps_the_resource_and_the_search(kit: Kit) -> None:
    use_tables(kit)
    seed(kit, {WLAN: [plain_lab(number, 100 + number) for number in range(51)]})
    first = Tags(html_page(page(kit, "/configuration/1", resource=WLAN, q="lab")))
    assert f"/configuration/1?resource={WLAN}&q=lab&page=2" in first.hrefs()
    second = html_page(page(kit, "/configuration/1", resource=WLAN, q="lab", page="2"))
    assert "Showing 51 to 51 of 51 objects" in second
    assert f"/configuration/1?resource={WLAN}&q=lab" in Tags(second).hrefs()  # page 1


def test_an_htmx_request_of_the_configuration_gets_the_page(kit: Kit) -> None:
    two_snapshots(kit)
    headers = {**kit.new_session("viewer").headers(), "HX-Request": "true"}
    response = kit.client.get("/configuration/1", headers=headers, params={"resource": WLAN})
    kit.client.cookies.clear()
    text = html_page(response)
    assert 'id="config-browser"' in text and 'aria-current="page"' in text


def test_a_damaged_store_is_the_designed_error_page_with_a_retry(kit: Kit) -> None:
    two_snapshots(kit)
    with kit.store.write() as connection:
        connection.execute(sa.update(snapshots).values(manifest_zstd=b"CANARY-junk"))
    text = html_page(page(kit, "/configuration/1"), 500)
    assert "The stored configuration cannot be read" in text
    assert {"method": "get", "action": "/configuration/1"} in Tags(text).attrs("form")
    assert "CANARY" not in text
    # the history reads rows, not manifests, so it still shows the readings
    assert "ledger__word" in html_page(page(kit, "/history/1"))


def test_an_unknown_source_is_the_designed_not_found_page(kit: Kit) -> None:
    for path in ("/history/99999", "/configuration/99999"):
        assert "Page not found" in html_page(page(kit, path), 404), path
