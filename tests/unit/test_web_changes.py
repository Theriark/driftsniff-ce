"""The change list and the change detail (P10-T6, frontend slice) through the real application.

Acceptance of the plan, each with its test here:

1. XSS payloads in notes, names and enrichments render escaped:
   ``test_payloads_in_notes_names_and_enrichments_render_escaped_on_both_pages``;
2. every item shows its rule id and rationale:
   ``test_every_item_shows_its_rule_id_and_its_rationale``;
3. acknowledging twice keeps both rows: ``test_acknowledging_twice_keeps_both_rows``.

The other tests cover the list (filters, the severity floor, sort, the pager, the empty states,
the mutes under the table), the role rules (a viewer sees no control and is refused on every
post), notes, mutes and unmutes, the refused texts, the JSON answers and the 503 without the
service. Changes are written straight into the tables, the way the run pipeline writes them.
Everything is synthetic; the password starts with CANARY-.
"""

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from httpx import Response

from driftsniff.changes.actions import ACK_COMMENT_MAX_CHARS, NOTE_MAX_CHARS
from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    acknowledgements,
    audit_events,
    change_events,
    change_items,
    enrichments,
    notes,
    path_mutes,
    snapshots,
    sources,
)
from driftsniff.main import create_app
from driftsniff.secrets.keys import MasterKey
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.change_pages import ChangePages

ORIGIN = "http://testserver"
MASTER = MasterKey(bytes(range(32)))
CORRECT = "CANARY-correct horse battery"  # noqa: S105
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
STAMP = "2026-10-23T11:05:00Z"
BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
# The payloads of the security suite (tests/security/test_xss.py), with a canary each.
PAYLOADS = (
    "<script>alert('CANARY-xss-0')</script>",
    '"><img src=x onerror=alert("CANARY-xss-1")>',
    "<svg onload=alert('CANARY-xss-2')>",
    "javascript:alert(1) CANARY-xss-3",
    "{{7*7}} ${7*7} CANARY-xss-4",
)
FINGERPRINT_BEFORE = "fp1:0a1b2c3d:" + "ab12cd34ef56" * 2 + "ab12cd34"
FINGERPRINT_AFTER = "fp1:0a1b2c3d:" + "ff00cd34ef56" * 2 + "ab12cd34"


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

    def joined(self) -> str:
        return " ".join(" ".join(self.text).split())


@dataclass
class World:
    client: TestClient
    store: Database
    auth: AuthService
    pages: ChangePages
    user_ids: dict[str, int] = field(default_factory=dict)
    sessions: dict[str, dict[str, str]] = field(default_factory=dict)

    def headers(self, role: str = "operator", *, html: bool = True) -> dict[str, str]:
        """A session of ``role`` with its CSRF value and the origin, as a browser or a script."""
        if role not in self.sessions:
            response = self.client.post("/login", data={"username": role, "password": CORRECT})
            assert response.status_code == 303, response.text
            match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
            assert match is not None
            self.client.cookies.clear()
            principal = self.auth.authenticate(match.group(1))
            assert principal is not None
            self.sessions[role] = {
                "Cookie": f"{SESSION_COOKIE}={match.group(1)}",
                "X-CSRF-Token": principal.csrf_token,
                "Origin": ORIGIN,
            }
        return {**self.sessions[role], **(BROWSER if html else {})}

    def get(self, path: str, role: str = "operator", *, html: bool = True) -> Response:
        return self.client.get(path, headers=self.headers(role, html=html))

    def post(
        self,
        path: str,
        data: Mapping[str, Any] | None = None,
        role: str = "operator",
        *,
        html: bool = True,
        json: Mapping[str, Any] | None = None,
    ) -> Response:
        headers = self.headers(role, html=html)
        return self.client.post(path, data=data, json=json, headers=headers)


def make_world(store: Database, *, with_service: bool = True) -> World:
    auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    user_ids = {
        role: auth.create_user(role, CORRECT, role) for role in ("viewer", "operator", "admin")
    }
    pages = ChangePages(store, clock=lambda: NOW)
    app = create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN, "DRIFTSNIFF_ENVIRONMENT_LABEL": "Test"}),
        master_key=MASTER,
        auth=auth,
        change_pages=pages if with_service else None,
    )
    client = TestClient(app, base_url=ORIGIN, follow_redirects=False)
    return World(client, store, auth, pages, user_ids)


@pytest.fixture
def world(store: Database) -> Iterator[World]:
    built = make_world(store)
    with built.client:
        yield built


# ---- what the run pipeline would have written ------------------------------------------------


def add_event(
    store: Database,
    *,
    items: Sequence[Mapping[str, Any]] = (),
    source_id: int = 1,
    severity: str = "high",
    status: str = "open",
    created_at: str = STAMP,
    summary: str | None = None,
) -> int:
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
        event_id: int = connection.execute(
            sa.insert(change_events)
            .values(
                source_id=source_id,
                snapshot_id=snapshot_id,
                window_start="2026-10-23T11:00:00Z",
                window_end=created_at,
                max_severity=severity,
                item_count=len(items),
                summary=summary or f"{len(items)} changes",
                rule_pack_version="pack-1",
                status=status,
                created_at=created_at,
            )
            .returning(change_events.c.id)
        ).scalar_one()
        for item in items:
            row = {
                "event_id": event_id,
                "resource": "networks",
                "object_name_at_time": None,
                "change_kind": "modified",
                "path": "name",
                "field_class": "config",
                "severity": "low",
                "rule_id": "rule-1",
                "rationale": "A name is cosmetic.",
                "before_value": "Guest",
                "after_value": "Visitors",
                **item,
            }
            connection.execute(sa.insert(change_items).values(**row))
    return event_id


def item_ids(store: Database, event_id: int) -> list[int]:
    with store.read() as connection:
        rows = connection.execute(
            sa.select(change_items.c.id)
            .where(change_items.c.event_id == event_id)
            .order_by(change_items.c.id)
        ).all()
    return [int(row[0]) for row in rows]


def rows_of(store: Database, table: sa.Table) -> list[Any]:
    with store.read() as connection:
        return list(connection.execute(sa.select(table).order_by(table.c.id)).all())


def actions_of(store: Database, prefix: str) -> list[str]:
    """The audit actions that start with ``prefix``, oldest first (the fixture users add
    ``user.created`` rows of their own)."""
    return [
        str(row.action)
        for row in rows_of(store, audit_events)
        if str(row.action).startswith(prefix)
    ]


def add_second_source(store: Database, name: str = "office-xo") -> int:
    with store.write() as connection:
        return int(
            connection.execute(
                sa.insert(sources).values(name=name, type="push").returning(sources.c.id)
            ).scalar_one()
        )


def add_enrichment(store: Database, event_id: int, user_id: int, text: str, number: int) -> None:
    """An enrichment of ``event_id`` whose label, summary and data are ``text``; ``number`` keeps
    the token row of each call unique."""
    with store.write() as connection:
        token_id = connection.execute(
            sa.text(
                "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, scopes) "
                "VALUES (:user_id, 'canary', :prefix, :hash, '[]') RETURNING id"
            ),
            {"user_id": user_id, "prefix": f"CANARY-{number}", "hash": f"canary-hash-{number}"},
        ).scalar_one()
        connection.execute(
            sa.insert(enrichments).values(
                event_id=event_id,
                token_id=token_id,
                provider_label=text,
                summary=text,
                payload={"html": text, text: [text]},
                created_at=STAMP,
            )
        )


def assert_page(response: Response, status: int = 200) -> Parsed:
    """A page that keeps the two policy rules and labels every field."""
    assert response.status_code == status, response.text[:500]
    assert response.headers["content-type"].startswith("text/html")
    parsed = Parsed(response.text)
    for tag, attrs in parsed.tags:
        assert "style" not in attrs, f"<{tag}> carries a style attribute"
        assert not [name for name in attrs if name.startswith("on")], f"<{tag}> has a handler"
    labelled = {attrs.get("for") for attrs in parsed.find("label")}
    for tag in ("input", "textarea", "select"):
        for attrs in parsed.find(tag):
            if attrs.get("type") != "hidden":
                assert attrs.get("id") in labelled or attrs.get("aria-label"), f"{tag} {attrs}"
    return parsed


def page(world: World, path: str, role: str = "operator", status: int = 200) -> tuple[str, Parsed]:
    """A page as a given role: its HTML and its parsed form, after the policy checks."""
    response = world.get(path, role=role)
    return response.text, assert_page(response, status)


def list_rows(html: str) -> list[str]:
    """The text of every body row of the change table."""
    body = html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    return [Parsed("<tr" + part).joined() for part in body.split("<tr")[1:]]


def change_links(html: str) -> list[int]:
    return [int(found) for found in re.findall(r'href="/changes/(\d+)"', html)]


# ---- acceptance 1: payloads render escaped ------------------------------------------------------


def plant_payloads(world: World) -> int:
    """A change whose names, rationale, source, notes, comments, enrichments and mute reason
    hold markup."""
    items = tuple(
        {"path": f"net.{number}", "object_name_at_time": text, "rationale": text}
        for number, text in enumerate(PAYLOADS)
    )
    event_id = add_event(world.store, items=items, summary=PAYLOADS[0])
    with world.store.write() as connection:
        connection.execute(sa.update(sources).where(sources.c.id == 1).values(name=PAYLOADS[1]))
    for number, text in enumerate(PAYLOADS):
        assert world.post(f"/changes/{event_id}/notes", {"note": text}).status_code == 303
        posted = world.post(f"/changes/{event_id}/acknowledge", {"comment": text})
        assert posted.status_code == 303
        add_enrichment(world.store, event_id, world.user_ids["admin"], text, number)
    first = item_ids(world.store, event_id)[0]
    muted = world.post(
        f"/changes/items/{first}/mute", {"reason": PAYLOADS[0], "event": str(event_id)}
    )
    assert muted.status_code == 303
    return event_id


def test_payloads_in_notes_names_and_enrichments_render_escaped_on_both_pages(
    world: World,
) -> None:
    event_id = plant_payloads(world)
    for path in ("/changes", "/changes?muted=1", f"/changes/{event_id}"):
        html, _parsed = page(world, path)
        # no payload is markup on the page: the three markup payloads are absent as typed,
        # the tags they carry never open (page() also fails on any on* attribute), and no
        # template syntax was evaluated; the escaped text may still read onerror=
        for text in PAYLOADS[:3]:
            assert text not in html, path
        for tag in ("<script>", "<img src=x", "<svg onload"):
            assert tag not in html, (path, tag)
        assert "&lt;script&gt;alert(&#39;CANARY-xss-0&#39;)&lt;/script&gt;" in html, path
        assert " 49 " not in html, path
    detail, _parsed = page(world, f"/changes/{event_id}")
    # the template payload sits in names, notes and enrichments, which only the detail shows
    assert "{{7*7}} ${7*7} CANARY-xss-4" in detail
    # every planted text came back, escaped: the source name, the object names and the
    # rationales (the items), the notes, the comments, the enrichment labels and summaries and
    # the attached data; the mute reason sits under the list
    for canary in ("CANARY-xss-0", "CANARY-xss-1", "CANARY-xss-2", "CANARY-xss-3", "CANARY-xss-4"):
        assert detail.count(canary) >= 5, canary
    assert "&#34;&gt;&lt;img src=x onerror=alert(&#34;CANARY-xss-1&#34;)&gt;" in detail
    assert "&lt;svg onload=alert(&#39;CANARY-xss-2&#39;)&gt;" in detail
    assert "\\u003cscript\\u003e" in detail  # the attached data is JSON text, not markup
    listing, _parsed = page(world, "/changes")
    assert "&#34;&gt;&lt;img src=x onerror=alert(&#34;CANARY-xss-1&#34;)&gt;" in listing
    assert listing.count("&lt;script&gt;alert(&#39;CANARY-xss-0&#39;)&lt;/script&gt;") >= 2
    # the JSON answers carry the text unchanged, as JSON
    answer = world.get(f"/changes/{event_id}", html=False)
    assert answer.status_code == 200
    assert answer.headers["content-type"].startswith("application/json")
    assert answer.json()["change"]["notes"][0]["body"] == PAYLOADS[0]
    assert answer.json()["change"]["groups"][0]["object_name"] == PAYLOADS[0]


# ---- acceptance 2: every item shows its rule id and rationale -----------------------------------


def test_every_item_shows_its_rule_id_and_its_rationale(world: World) -> None:
    items = (
        {"path": "security", "rule_id": "unifi.wifi.security_downgrade", "rationale": "Open."},
        {
            "path": "passphrase",
            "field_class": "secret",
            "severity": "critical",
            "rule_id": "unifi.wifi.secret_changed",
            "rationale": "A secret changed.",
            "before_value": None,
            "after_value": None,
            "before_fp": FINGERPRINT_BEFORE,
            "after_fp": FINGERPRINT_AFTER,
        },
        {"path": "name", "rule_id": None, "rationale": None},
        {
            "path": "order",
            "change_kind": "moved",
            "severity": "high",
            "rule_id": "unifi.firewall.order_moved",
            "rationale": "A policy above a deny can allow what the deny stopped.",
            "before_value": None,
            "after_value": None,
            "order_detail": {
                "key": "Allow IoT",
                "from_after": "Block guest",
                "from_before": None,
                "to_after": None,
                "to_before": "Deny IoT",
                "summary": "Allow IoT moved",
            },
        },
    )
    event_id = add_event(world.store, items=items, severity="critical")
    html, parsed = page(world, f"/changes/{event_id}", role="viewer")
    text = parsed.joined()
    for rule_id, rationale in (
        ("unifi.wifi.security_downgrade", "Open."),
        ("unifi.wifi.secret_changed", "A secret changed."),
        ("unrated", "No rule rationale was stored with this item."),
        ("unifi.firewall.order_moved", "A policy above a deny can allow what the deny stopped."),
    ):
        assert f"rule {rule_id}" in text, rule_id
        assert rationale in text, rationale
    assert text.count("Why is this rated") == 4
    assert "Why is this rated critical?" in text and "Why is this rated low?" in text
    # the evidence of each kind: the marked difference, the fingerprints, the move in words
    assert "Security changed" in text and "Before Guest After Visitors" in text
    assert "<mark>Guest</mark>" in html and "<mark>Visitors</mark>" in html
    assert "secret changed, fingerprint ab12 cd34 ef56 to ff00 cd34 ef56" in text
    assert "ab12cd34ef56ab12cd34ef56" not in html
    assert "Allow IoT moved from after Block guest to before Deny IoT." in text
    assert "Detected between 11:00 and 11:05 UTC today" in text
    assert "4 items in 1 object" in text
    # a viewer sees the evidence and no control
    assert 'action="/changes/' not in html and "Mute this path" not in html
    assert "Nobody has acknowledged this change yet" in text


# ---- acceptance 3: acknowledging twice keeps both rows ------------------------------------------


def test_acknowledging_twice_keeps_both_rows(world: World) -> None:
    event_id = add_event(world.store, items=({"path": "name"},))
    first = world.post(f"/changes/{event_id}/acknowledge", {"comment": "seen, expected"})
    assert first.status_code == 303
    assert first.headers["location"] == f"/changes/{event_id}?notice=acknowledged#acknowledge"
    second = world.post(f"/changes/{event_id}/acknowledge", {"comment": ""}, role="admin")
    assert second.status_code == 303
    rows = rows_of(world.store, acknowledgements)
    assert [(row.user_id, row.comment) for row in rows] == [
        (world.user_ids["operator"], "seen, expected"),
        (world.user_ids["admin"], ""),
    ]
    assert rows_of(world.store, change_events)[0].status == "acknowledged"
    assert actions_of(world.store, "change.") == ["change.acknowledged", "change.acknowledged"]
    _html, parsed = page(world, f"/changes/{event_id}?notice=acknowledged")
    text = parsed.joined()
    assert "Change acknowledged" in text
    assert "seen, expected operator, just now" in text
    assert "Acknowledged without a comment admin, just now" in text
    assert "Acknowledge again" in text
    listing = list_rows(world.get("/changes").text)
    assert len(listing) == 1 and "Acknowledged" in listing[0]
    assert "2 acknowledgements" in listing[0]
    # a script gets the row it made
    third = world.post(
        f"/changes/{event_id}/acknowledge", json={"comment": "by script"}, html=False
    )
    assert third.status_code == 201 and third.json()["acknowledgement"]["comment"] == "by script"
    assert len(rows_of(world.store, acknowledgements)) == 3


# ---- the list ------------------------------------------------------------------------------------


def test_the_empty_list_sends_to_the_sources_and_a_filter_that_matches_nothing_says_so(
    world: World,
) -> None:
    _html, parsed = page(world, "/changes", role="viewer")
    text = parsed.joined()
    assert "No changes yet" in text and "See the sources" in text
    assert {"class": "btn btn--primary", "href": "/sources"} in parsed.find("a")
    add_event(world.store, items=({"path": "name"},))
    nothing = page(world, "/changes?q=zzz", role="viewer")[1].joined()
    assert "No change matches these filters" in nothing and "Clear the filters" in nothing
    assert "No changes yet" not in nothing


def test_the_list_filters_sorts_and_pages(world: World) -> None:
    other = add_second_source(world.store)
    low = add_event(
        world.store,
        items=({"path": "name", "object_name_at_time": "Guest"},),
        severity="low",
        created_at="2026-10-20T08:00:00Z",
        summary="Network Guest renamed",
    )
    high = add_event(
        world.store,
        items=({"path": "security", "severity": "high", "resource": "unifi-wifi-broadcasts"},),
        severity="high",
        created_at="2026-10-21T08:00:00Z",
        summary="WiFi security changed",
    )
    critical = add_event(
        world.store,
        items=({"path": "action", "severity": "critical", "resource": "unifi-firewall-policies"},),
        severity="critical",
        status="acknowledged",
        source_id=other,
        created_at="2026-10-22T08:00:00Z",
        summary="Policy removed",
    )
    html, parsed = page(world, "/changes", role="viewer")
    assert change_links(html)[:3] == [critical, high, low]
    assert "3 changes" in parsed.joined()
    assert change_links(world.get("/changes?sort=oldest").text)[:3] == [low, high, critical]
    assert change_links(world.get("/changes?sort=severity").text)[:3] == [critical, high, low]
    assert change_links(world.get("/changes?status=open").text)[:2] == [high, low]
    assert change_links(world.get("/changes?status=acknowledged").text)[:1] == [critical]
    # the severity floor of the select, and a dashboard link whose set is not a floor
    assert change_links(world.get("/changes?min=high").text)[:2] == [critical, high]
    _html, floor = page(world, "/changes?severity=critical&severity=high")
    assert {"value": "high", "selected": None} in floor.find("option")
    _html, exact = page(world, "/changes?severity=low")
    assert {"value": "exact", "selected": None} in exact.find("option")
    assert {"type": "hidden", "name": "severity", "value": "low"} in exact.find("input")
    assert "Low only" in exact.joined()
    assert change_links(world.get("/changes?min=exact&severity=low").text)[:1] == [low]
    assert change_links(world.get("/changes?min=&severity=low").text)[:3] == [critical, high, low]
    assert change_links(world.get(f"/changes?source={other}").text)[:1] == [critical]
    assert change_links(world.get("/changes?resource=unifi-wifi-broadcasts").text)[:1] == [high]
    assert change_links(world.get("/changes?q=guest").text)[:1] == [low]
    assert change_links(world.get("/changes?from=2026-10-21&to=2026-10-21").text)[:1] == [high]
    # the hint names the filters in force; the selects list the sources and the resources seen
    _html, hint = page(world, f"/changes?status=open&source={other}&resource=networks")
    assert "No changes match: open, source office-xo, networks." in hint.joined()
    assert "Firewall policies" in hint.joined() and "office-xo" in hint.joined()
    # the column heads carry the sort links and the state
    heads = {attrs.get("aria-sort") for attrs in page(world, "/changes")[1].find("th")}
    assert "descending" in heads
    ascending = page(world, "/changes?sort=oldest")[1].find("th")
    assert any(attrs.get("aria-sort") == "ascending" for attrs in ascending)


def test_the_list_pages_by_fifty_with_a_pager_that_keeps_the_filters(world: World) -> None:
    for number in range(53):
        add_event(world.store, created_at=f"2026-10-22T08:{number:02d}:00Z", severity="low")
    html, first = page(world, "/changes?min=low")
    assert len(list_rows(html)) == 50
    assert "Showing 1 to 50 of 53" in first.joined()
    links = {attrs.get("href") for attrs in first.find("a")}
    next_link = "/changes?severity=critical&severity=high&severity=medium&severity=low&page=2"
    assert next_link in links
    html, second = page(world, next_link)
    assert "Showing 51 to 53 of 53" in second.joined()
    assert len(list_rows(html)) == 3
    assert [attrs for attrs in second.find("span") if attrs.get("aria-current") == "page"]
    past = world.get("/changes?page=99")
    assert "Showing 51 to 53 of 53" in Parsed(past.text).joined()
    answer = world.get("/changes?page=2", html=False)
    assert answer.status_code == 200
    assert (answer.json()["page"], answer.json()["pages"], answer.json()["total"]) == (2, 2, 53)
    assert len(answer.json()["changes"]) == 3


def test_the_viewer_sees_no_control_and_is_refused_on_every_post(world: World) -> None:
    event_id = add_event(world.store, items=({"path": "name"},))
    item_id = item_ids(world.store, event_id)[0]
    assert world.post(f"/changes/items/{item_id}/mute", {"event": str(event_id)}).status_code == 303
    html, listing = page(world, "/changes?muted=1", role="viewer")
    assert "Unmute" not in listing.joined() and "Muted paths, 1" in listing.joined()
    assert "/mutes/" not in html and 'action="/changes/' not in html
    html, detail = page(world, f"/changes/{event_id}", role="viewer")
    assert 'action="/changes/' not in html and "Mute this path" not in html
    assert "Muted: hidden from the change list" in detail.joined()
    mute_id = int(rows_of(world.store, path_mutes)[0].id)
    posts: tuple[tuple[str, dict[str, str]], ...] = (
        (f"/changes/{event_id}/acknowledge", {"comment": "x"}),
        (f"/changes/{event_id}/notes", {"note": "x"}),
        (f"/changes/items/{item_id}/mute", {"reason": "x"}),
        (f"/mutes/{mute_id}/remove", {}),
    )
    before = (
        len(rows_of(world.store, acknowledgements)),
        len(rows_of(world.store, notes)),
        len(rows_of(world.store, path_mutes)),
    )
    for path, data in posts:
        refused = world.post(path, data, role="viewer")
        assert refused.status_code == 403, path
        assert "Your role does not allow this" in refused.text
        assert world.post(path, json=data, role="viewer", html=False).status_code == 403, path
    after = (
        len(rows_of(world.store, acknowledgements)),
        len(rows_of(world.store, notes)),
        len(rows_of(world.store, path_mutes)),
    )
    assert after == before
    # the operator's page has the controls
    html, _operator = page(world, f"/changes/{event_id}")
    assert f'action="/changes/{event_id}/acknowledge"' in html
    assert f'action="/changes/{event_id}/notes"' in html


# ---- notes ---------------------------------------------------------------------------------------


def test_a_note_is_kept_and_an_empty_or_too_long_one_is_refused_with_the_field_marked(
    world: World,
) -> None:
    event_id = add_event(world.store, items=({"path": "name"},))
    saved = world.post(f"/changes/{event_id}/notes", {"note": "  Restore requested.  "})
    assert saved.status_code == 303
    assert saved.headers["location"] == f"/changes/{event_id}?notice=note-added#notes"
    _html, saved_page = page(world, f"/changes/{event_id}?notice=note-added")
    assert "Note saved" in saved_page.joined()
    assert "Restore requested. operator, just now" in saved_page.joined()
    empty = world.post(f"/changes/{event_id}/notes", {"note": "   "})
    refused = assert_page(empty, 422)
    assert "Write the note first." in refused.joined()
    assert any(attrs.get("aria-invalid") == "true" for attrs in refused.find("textarea"))
    long = world.post(f"/changes/{event_id}/notes", {"note": "x" * (NOTE_MAX_CHARS + 1)})
    assert long.status_code == 422
    assert f"Keep the note under {NOTE_MAX_CHARS:,} characters." in Parsed(long.text).joined()
    assert "x" * 100 in long.text  # the typed text stays in the field
    control = world.post(f"/changes/{event_id}/notes", {"note": "bad \x07 text"})
    assert control.status_code == 422 and "control characters" in control.text
    assert len(rows_of(world.store, notes)) == 1
    comment = world.post(
        f"/changes/{event_id}/acknowledge", {"comment": "y" * (ACK_COMMENT_MAX_CHARS + 1)}
    )
    assert comment.status_code == 422
    assert f"Keep the comment under {ACK_COMMENT_MAX_CHARS:,} characters." in comment.text
    script = world.post(f"/changes/{event_id}/notes", json={"note": ""}, html=False)
    assert script.status_code == 422 and script.json() == {"detail": "Write the note first."}
    listed = world.get("/changes").text
    assert "1 note" in Parsed(listed).joined()


# ---- mutes ---------------------------------------------------------------------------------------


def test_a_mute_hides_the_change_from_the_list_and_an_unmute_shows_it_again(
    world: World,
) -> None:
    event_id = add_event(
        world.store, items=({"path": "tlsVerify", "resource": "servers"},), summary="TLS off"
    )
    item_id = item_ids(world.store, event_id)[0]
    muted = world.post(
        f"/changes/items/{item_id}/mute", {"reason": "lab noise", "event": str(event_id)}
    )
    assert muted.status_code == 303
    assert muted.headers["location"] == f"/changes/{event_id}?notice=muted"
    mute = rows_of(world.store, path_mutes)[0]
    assert (mute.resource, mute.path_pattern, mute.reason) == ("servers", "tlsVerify", "lab noise")
    html, detail = page(world, f"/changes/{event_id}?notice=muted")
    assert "Path muted" in detail.joined() and "1 muted item" in detail.joined()
    assert "Muted: hidden from the change list" in detail.joined()
    assert "/changes/items/" not in html  # no second mute form for a muted item
    html, listing = page(world, "/changes")
    assert change_links(html) == []
    assert "1 change hidden by mutes" in listing.joined()
    assert "Muted paths, 1" in listing.joined() and "lab noise" in listing.joined()
    assert "Servers tlsVerify" in listing.joined()
    html, included = page(world, "/changes?muted=1")
    assert change_links(html) == [event_id]
    assert "Muted changes are included" in included.joined()
    again = world.post(
        f"/changes/items/{item_id}/mute", {"reason": "twice", "event": str(event_id)}
    )
    assert again.headers["location"] == f"/changes/{event_id}?notice=mute-exists"
    assert len(rows_of(world.store, path_mutes)) == 1
    removed = world.post(f"/mutes/{mute.id}/remove", {"next": "/changes?status=open"})
    assert removed.status_code == 303
    assert removed.headers["location"] == "/changes?status=open&notice=unmuted"
    assert rows_of(world.store, path_mutes) == []
    html, back = page(world, "/changes?status=open&notice=unmuted")
    assert "Mute removed" in back.joined() and change_links(html) == [event_id]
    assert "Muted paths" not in back.joined()
    elsewhere = world.post(f"/mutes/{mute.id}/remove", {"next": "https://evil.example/"})
    assert elsewhere.status_code == 404  # gone, and never a redirect off the site
    assert actions_of(world.store, "mute.") == ["mute.added", "mute.removed"]


def test_a_critical_item_cannot_be_muted_and_the_page_says_so(world: World) -> None:
    event_id = add_event(
        world.store,
        items=({"path": "action", "severity": "critical"}, {"path": "name"}),
        severity="critical",
    )
    critical, cosmetic = item_ids(world.store, event_id)
    html, parsed = page(world, f"/changes/{event_id}")
    assert "Not offered: a critical item cannot be muted." in parsed.joined()
    assert f'action="/changes/items/{cosmetic}/mute"' in html
    assert f'action="/changes/items/{critical}/mute"' not in html
    refused = world.post(f"/changes/items/{critical}/mute", {"reason": "", "event": str(event_id)})
    problem = assert_page(refused, 409)
    assert "This path was not muted" in problem.joined()
    assert "A critical item cannot be muted. Nothing was changed." in problem.joined()
    assert rows_of(world.store, path_mutes) == []
    script = world.post(f"/changes/items/{critical}/mute", json={}, html=False)
    assert script.status_code == 409 and "critical" in script.json()["detail"]
    without_event = world.post(f"/changes/items/{critical}/mute", {"reason": ""})
    assert without_event.status_code == 409
    ok = world.post(f"/changes/items/{cosmetic}/mute", {"event": "not-a-number"})
    assert ok.status_code == 303 and ok.headers["location"] == "/changes?notice=muted"
    scripted = world.post(f"/changes/items/{cosmetic}/mute", json={"reason": "x"}, html=False)
    assert scripted.status_code == 200 and scripted.json()["created"] is False


# ---- unknown ids, the navigation and the missing service -----------------------------------------


def test_an_unknown_change_item_or_mute_is_not_found(world: World) -> None:
    missing = world.get("/changes/99999")
    assert missing.status_code == 404 and "Page not found" in missing.text
    assert world.get("/changes/99999", html=False).status_code == 404
    for path, data in (
        ("/changes/99999/acknowledge", {"comment": ""}),
        ("/changes/99999/notes", {"note": "x"}),
        ("/changes/items/99999/mute", {"reason": ""}),
        ("/mutes/99999/remove", {"next": ""}),
    ):
        assert world.post(path, data).status_code == 404, path
        assert world.post(path, json=data, html=False).status_code == 404, path
    # an id outside the range is not a route parameter at all
    assert world.get("/changes/0", html=False).status_code == 422
    assert world.get("/changes/abc", html=False).status_code == 422


def test_the_changes_entry_of_the_navigation_is_current_on_both_pages(world: World) -> None:
    event_id = add_event(world.store, items=({"path": "name"},), summary="Network renamed")
    for path in ("/changes", f"/changes/{event_id}"):
        _html, parsed = page(world, path, role="viewer")
        current = [attrs.get("href") for attrs in parsed.find("a") if attrs.get("aria-current")]
        assert current == ["/changes"], path
    html, detail = page(world, f"/changes/{event_id}", role="viewer")
    assert "<title>Network renamed, driftsniff</title>" in html
    crumbs = [attrs for attrs in detail.find("nav") if attrs.get("aria-label") == "Breadcrumb"]
    assert crumbs and "Changes / lab-controller / Change 1" in detail.joined()


def test_without_the_service_the_pages_answer_503(store: Database) -> None:
    world = make_world(store, with_service=False)
    with world.client:
        assert world.get("/changes", html=False).status_code == 503
        assert world.get("/changes/1", html=False).status_code == 503
        assert world.post("/changes/1/notes", json={"note": "x"}, html=False).status_code == 503
