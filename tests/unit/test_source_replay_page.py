"""The Change Replay on the source page (UI revision WP4c, THE-1197) through the real application.

- Every role that reads the source page (viewer, operator, admin) gets the same replay: the cells
  are the stored change items of the source counted per UTC day and resource type, the same
  ``ReplayService`` value ``GET /sources/{id}/replay`` answers with.
- ``replay_days`` picks the window (7, 30 or 90 days); anything else is the 30-day default.
- A page drawn again after a refused action (the typed-name delete) still holds the replay.
- Without the replay service the section says so; the rest of the page is unchanged.
- The page loads the replay script from its own origin and holds no inline script or style.

Everything is synthetic: the source is the store fixture's push source and the items are plain
inserts, the way the run pipeline writes them.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from httpx import Response

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import change_events, change_items, snapshots
from driftsniff.main import create_app
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.service import SourceService
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.replay import ReplayService
from driftsniff.web.source_pages import SourcePages

ORIGIN = "http://testserver"
MASTER = MasterKey(bytes(range(32)))
CORRECT = "CANARY-correct horse battery"
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
ROLES = ("viewer", "operator", "admin")


def add_event(store: Database, created_at: str, items: list[tuple[str, str]]) -> None:
    """An event of source 1 made at ``created_at``, with one item per (resource, severity)."""
    with store.write() as connection:
        snapshot_id = connection.execute(
            sa.insert(snapshots)
            .values(
                source_id=1,
                taken_at=created_at,
                manifest_hash="m",
                manifest_zstd=b"x",
                normaliser_version=1,
            )
            .returning(snapshots.c.id)
        ).scalar_one()
        event_id = connection.execute(
            sa.insert(change_events)
            .values(
                source_id=1,
                snapshot_id=snapshot_id,
                window_start=created_at,
                window_end=created_at,
                max_severity="critical",
                item_count=len(items),
                summary="CANARY-summary-never-shown",
                rule_pack_version="pack-1",
                created_at=created_at,
            )
            .returning(change_events.c.id)
        ).scalar_one()
        for resource, severity in items:
            connection.execute(
                sa.insert(change_items).values(
                    event_id=event_id,
                    resource=resource,
                    change_kind="changed",
                    path="CANARY-path-never-shown",
                    field_class="config",
                    severity=severity,
                )
            )


@dataclass
class Site:
    client: TestClient
    auth: AuthService
    sessions: dict[str, dict[str, str]] = field(default_factory=dict)

    def headers(self, role: str) -> dict[str, str]:
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
        return {**self.sessions[role], **BROWSER}

    def get(self, path: str, role: str = "viewer") -> Response:
        return self.client.get(path, headers=self.headers(role))


def build(store: Database, *, replay: bool = True) -> Site:
    auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    for role in ROLES:
        auth.create_user(role, CORRECT, role)
    service = SourceService(store, CredentialCipher.from_master(MASTER))
    app = create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}),
        master_key=MASTER,
        auth=auth,
        sources=SourcePages(store, service, clock=lambda: NOW),
        replay=ReplayService(store, clock=lambda: NOW) if replay else None,
    )
    return Site(TestClient(app, base_url=ORIGIN, follow_redirects=False), auth)


@pytest.fixture
def site(store: Database) -> Iterator[Site]:
    add_event(store, "2026-10-20T09:00:00Z", [("vms", "critical"), ("vms", "medium")])
    add_event(store, "2026-10-23T08:00:00Z", [("networks", "low")])
    add_event(store, "2026-09-01T08:00:00Z", [("networks", "high")])  # outside 30 days
    built = build(store)
    with built.client:
        yield built


def cell_links(text: str) -> list[str]:
    return re.findall(r'<a class="replay-cell[^"]*" href="([^"]+)"', text)


@pytest.mark.parametrize("role", ROLES)
def test_every_role_that_reads_the_page_gets_the_same_replay(site: Site, role: str) -> None:
    response = site.get("/sources/1", role)
    assert response.status_code == 200
    text = response.text
    assert 'id="replay"' in text and "Change replay" in text
    links = cell_links(text)
    assert links == [
        "/changes?source=1&amp;resource=vms&amp;from=2026-10-20&amp;to=2026-10-20&amp;muted=1",
        "/changes?source=1&amp;resource=networks&amp;from=2026-10-23&amp;to=2026-10-23&amp;muted=1",
    ]
    assert "2 change items (1 critical, 1 medium)</title>" in text
    # counts, days and names only: nothing an item stored about the configuration
    assert "CANARY-" not in text
    assert 'aria-current="true">30 days' in text


def test_the_window_comes_from_replay_days_and_falls_back_to_thirty(site: Site) -> None:
    week = site.get("/sources/1?replay_days=7").text
    assert 'aria-current="true">7 days' in week
    assert len(cell_links(week)) == 2
    quarter = site.get("/sources/1?replay_days=90").text
    assert 'aria-current="true">90 days' in quarter
    assert len(cell_links(quarter)) == 3  # the September item is inside 90 days
    for odd in ("8", "abc", "-7", "9999999"):
        assert 'aria-current="true">30 days' in site.get(f"/sources/1?replay_days={odd}").text


def test_a_page_drawn_again_after_a_refused_delete_still_holds_the_replay(site: Site) -> None:
    headers = site.headers("admin")
    response = site.client.post("/sources/1/delete", data={"confirm": "wrong"}, headers=headers)
    assert response.status_code == 422
    assert len(cell_links(response.text)) == 2


def test_without_the_service_the_section_says_so(store: Database) -> None:
    built = build(store, replay=False)
    with built.client:
        response = built.get("/sources/1")
    assert response.status_code == 200
    assert "The change replay is not available on this installation" in response.text
    assert cell_links(response.text) == []


def test_a_source_without_items_shows_the_empty_replay(store: Database) -> None:
    built = build(store)
    with built.client:
        text = built.get("/sources/1").text
    assert "Nothing to replay in the last 30 days" in text
    assert cell_links(text) == []


def test_the_page_loads_the_script_from_its_own_origin_and_inlines_nothing(site: Site) -> None:
    text = site.get("/sources/1").text
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", text, re.S)
    assert ' src="/static/replay.js" defer' in [attrs for attrs, _ in scripts]
    assert all(body.strip() == "" for _, body in scripts)
    assert re.search(r"<[a-z][^>]*\sstyle=", text) is None
    served = site.client.get("/static/replay.js")
    assert served.status_code == 200
    assert "javascript" in served.headers["content-type"]
    assert site.client.get("/static/replay.css").status_code == 200
