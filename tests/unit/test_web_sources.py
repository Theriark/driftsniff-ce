"""The sources pages (P10-T5) through the real application.

Acceptance of the plan, each with its test here:

1. the credential is never present in any rendered page or response body (canary):
   ``test_the_credential_never_comes_back_in_any_page_or_answer``;
2. coverage rows match the stored rows for every status:
   ``test_coverage_rows_match_the_stored_rows_for_every_status``;
3. delete needs the typed name: ``test_delete_needs_the_typed_name``.

The other tests cover the list, the role checks, the forms of the three types, the TLS
confirmation rule, test connection (which stores nothing), run now (refused inside 30 seconds)
and enable or disable. A fake collector stands in for the controllers and a fake scheduler for
the run loop; everything is synthetic and every secret starts with ``CANARY-``.
"""

import hashlib
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from httpx import Response

from driftsniff.collectors.base import Collector, FetchResult, ResourceSpec
from driftsniff.collectors.xo.resources import COLLECTIONS
from driftsniff.config import Settings
from driftsniff.core.canonical import JsonValue
from driftsniff.db.engine import Database
from driftsniff.db.tables import audit_events, resource_coverage, runs, sources
from driftsniff.main import create_app
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.probe import ProbeTarget
from driftsniff.sources.scheduler import RunNowResult, RunNowStatus, Scheduler
from driftsniff.sources.service import SourceService
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.routes_sources import PUSH_NOTICES
from driftsniff.web.source_pages import SourcePages

ORIGIN = "http://testserver"
MASTER = MasterKey(bytes(range(32)))
CORRECT = "CANARY-correct horse battery"
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
STAMP = "2026-10-23T11:00:00Z"
EARLIER = "2026-10-20T09:30:00Z"
BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
UNIFI_CANARY = "CANARY-7e57c0de7e57c0de7e57c0de"
XO_CANARY = "CANARY-a11ce0a11ce0a11ce0a11ce0"
TYPED_CONFIRMATION = "CANARY-not the sentence"
# The forms of the shell on every signed-in page: sign out, and the top bar change search.
SHELL_FORMS = {"/logout", "/changes"}
OBJECTS: Sequence[Mapping[str, JsonValue]] = ({"id": "a"}, {"id": "b"})


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


class CoverageRows(HTMLParser):
    """The cell texts of every body row of the coverage tables of a page."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.rows: list[list[str]] = []
        self._depth = 0
        self._in_body = False
        self._cell: list[str] | None = None
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = dict(attrs).get("class") or ""
        if tag == "table" and "coverage-table" in classes:
            self._depth += 1
        elif self._depth and tag == "tbody":
            self._in_body = True
        elif self._in_body and tag == "tr":
            self.rows.append([])
        elif self._in_body and tag in ("th", "td"):
            self._cell = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("th", "td") and self._cell is not None:
            self.rows[-1].append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tbody":
            self._in_body = False
        elif tag == "table" and self._depth:
            self._depth -= 1

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)


class FakeCollector(Collector):
    """A controller with three resources: 200 with two objects, 403 and 404."""

    def __init__(self, target: ProbeTarget) -> None:
        self.target = target

    def probe(self) -> str | None:
        return "10.1.84"

    def resources(self) -> Sequence[ResourceSpec]:
        return [ResourceSpec("unifi-sites"), ResourceSpec("unifi-dns-policies"), ResourceSpec("x")]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        if spec.name == "unifi-sites":
            return FetchResult.success(OBJECTS)
        if spec.name == "unifi-dns-policies":
            return FetchResult.failure("forbidden", "the controller refused this", status="403")
        return FetchResult.failure("not_available", "not on this version", status="404")


class FakeScheduler:
    """The parts of the scheduler the routes use; ``answer`` is what run now says."""

    def __init__(self) -> None:
        self.answer = RunNowResult(RunNowStatus.STARTED)
        self.asked: list[int] = []
        self.synced = 0

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def sync(self) -> None:
        self.synced += 1

    def run_now(self, source_id: int) -> RunNowResult:
        self.asked.append(source_id)
        return self.answer


@dataclass
class World:
    client: TestClient
    store: Database
    auth: AuthService
    service: SourceService
    pages: SourcePages
    scheduler: FakeScheduler
    targets: list[ProbeTarget] = field(default_factory=list)
    sessions: dict[str, dict[str, str]] = field(default_factory=dict)
    bodies: list[str] = field(default_factory=list)

    def headers(self, role: str = "admin", *, html: bool = True) -> dict[str, str]:
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

    def get(self, path: str, role: str = "admin", *, html: bool = True) -> Response:
        response = self.client.get(path, headers=self.headers(role, html=html))
        self.bodies.append(response.text + " ".join(response.headers.values()))
        return response

    def post(
        self,
        path: str,
        data: Mapping[str, Any] | None = None,
        role: str = "admin",
        *,
        html: bool = True,
        extra: Mapping[str, str] | None = None,
        json: Mapping[str, Any] | None = None,
    ) -> Response:
        headers = {**self.headers(role, html=html), **(extra or {})}
        response = self.client.post(path, data=data, json=json, headers=headers)
        self.bodies.append(response.text + " ".join(response.headers.values()))
        return response


def make_world(store: Database, *, probe: bool = True, scheduler: bool = True) -> World:
    auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    for role in ("viewer", "operator", "admin"):
        auth.create_user(role, CORRECT, role)
    service = SourceService(store, CredentialCipher.from_master(MASTER))
    targets: list[ProbeTarget] = []

    def factory(target: ProbeTarget) -> Collector:
        targets.append(target)
        return FakeCollector(target)

    pages = SourcePages(store, service, probe_factory=factory if probe else None, clock=lambda: NOW)
    fake = FakeScheduler()
    app = create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN, "DRIFTSNIFF_ENVIRONMENT_LABEL": "Test"}),
        master_key=MASTER,
        auth=auth,
        sources=pages,
        scheduler=cast(Scheduler, fake) if scheduler else None,
    )
    client = TestClient(app, base_url=ORIGIN, follow_redirects=False)
    return World(client, store, auth, service, pages, fake, targets)


@pytest.fixture
def world(store: Database) -> Iterator[World]:
    built = make_world(store)
    with built.client:
        yield built


def unifi_form(**changes: Any) -> dict[str, Any]:
    form: dict[str, Any] = {
        "full_form": "1",
        "type": "unifi",
        "name": "branch-gw",
        "base_url": "https://controller.example",
        "credential": UNIFI_CANARY,
        "interval_minutes": "10",
        "tls_mode": "verify",
        "resource": ["unifi-sites", "unifi-networks", "unifi-firewall-policies"],
    }
    form.update(changes)
    return form


def add_unifi(world: World, **changes: Any) -> int:
    response = world.post("/sources/new", unifi_form(**changes))
    assert response.status_code == 303, response.text[:500]
    match = re.fullmatch(r"/sources/(\d+)\?notice=created", response.headers["location"])
    assert match is not None
    return int(match.group(1))


def count_rows(store: Database) -> dict[str, int]:
    """How many rows the tables a test connection must never write hold."""
    counts: dict[str, int] = {}
    with store.read() as connection:
        for table in (sources, runs, resource_coverage, audit_events):
            query = sa.select(sa.func.count()).select_from(table)
            counts[table.name] = int(connection.execute(query).scalar_one())
    return counts


def assert_page(response: Response, status: int = 200) -> Parsed:
    assert response.status_code == status, response.text[:500]
    assert response.headers["content-type"].startswith("text/html")
    parsed = Parsed(response.text)
    for tag, attrs in parsed.tags:
        assert "style" not in attrs, f"<{tag}> carries a style attribute"
    labelled = {attrs.get("for") for attrs in parsed.find("label")}
    for tag in ("input", "textarea", "select"):
        for attrs in parsed.find(tag):
            if attrs.get("type") != "hidden":
                assert attrs.get("id") in labelled, f"unlabelled {tag} {attrs}"
    return parsed


# ---- acceptance 1: the credential never comes back ----------------------------------------


def test_the_credential_never_comes_back_in_any_page_or_answer(world: World) -> None:
    source_id = add_unifi(world)
    assert world.service.credential_for_collector(source_id) == UNIFI_CANARY.encode("utf-8")
    xo = world.post(
        "/sources/new",
        {**unifi_form(type="xo", name="pool-a", credential=XO_CANARY), "resource": "vms"},
    )
    assert xo.status_code == 303
    created = world.post(
        "/sources/new",
        json={
            "type": "unifi",
            "name": "by-script",
            "base_url": "https://other.example",
            "credential": UNIFI_CANARY,
        },
        html=False,
    )
    assert created.status_code == 201 and created.json()["source"]["has_credential"] is True
    # every page and answer a user can reach about these sources
    for path in ("/sources", f"/sources/{source_id}", f"/sources/{source_id}/edit", "/"):
        assert world.get(path).status_code == 200, path
    assert world.get("/sources", html=False).status_code == 200
    assert world.get(f"/sources/{source_id}", html=False).status_code == 200
    # a refused form comes back without the credential it was sent with
    refused = world.post("/sources/new", unifi_form(name="second", interval_minutes="0"))
    assert refused.status_code == 422
    assert 'value="CANARY' not in refused.text
    edit_refused = world.post(
        f"/sources/{source_id}/edit", unifi_form(credential=XO_CANARY, name="")
    )
    assert edit_refused.status_code == 422
    # test connection with a typed credential and with the stored one, as HTMX and as a page
    htmx = {"HX-Request": "true"}
    assert world.post("/sources/test", unifi_form(), extra=htmx).status_code == 200
    assert world.post("/sources/test", unifi_form()).status_code == 200
    assert world.post(f"/sources/{source_id}/test", unifi_form(credential="")).status_code == 200
    assert world.post("/sources/test", json=unifi_form(), html=False).status_code == 200
    assert world.targets[-2].credential == UNIFI_CANARY.encode("utf-8")
    for body in world.bodies:
        for secret in (UNIFI_CANARY, XO_CANARY):
            assert secret not in body
            assert secret.removeprefix("CANARY-") not in body


# ---- acceptance 2: coverage rows ------------------------------------------------------------


def test_coverage_rows_match_the_stored_rows_for_every_status(world: World) -> None:
    view = world.service.create(
        name="pool-a",
        source_type="xo",
        actor="test",
        base_url="https://xo.example",
        credential=XO_CANARY,
        options={"resources_off": ["pifs"]},
    )
    stored = [
        ("vms", "200", STAMP, None, 7),
        ("hosts", "403", EARLIER, STAMP, 4),
        ("pools", "404", None, STAMP, 0),
        ("srs", "error", EARLIER, STAMP, 3),
        ("servers", "200", STAMP, None, 2),
        ("vifs", "502", None, STAMP, 0),
    ]
    with world.store.write() as connection:
        for resource, status, last_ok, stale, count in stored:
            connection.execute(
                sa.insert(resource_coverage).values(
                    source_id=view.id,
                    resource=resource,
                    last_status=status,
                    last_ok_at=last_ok,
                    stale_since=stale,
                    object_count=count,
                )
            )
    # the panel model equals the stored rows, field by field
    rows = {row.resource: row for row in world.pages.detail(view.id).coverage}
    for resource, status, last_ok, stale, count in stored:
        row = rows[resource]
        assert (row.status, row.object_count) == (status, count), resource
        assert row.last_ok_at == (None if last_ok is None else datetime.fromisoformat(last_ok))
        assert row.stale_since == (None if stale is None else datetime.fromisoformat(stale))
    assert [rows[name].kind for name in ("vms", "hosts", "pools", "srs", "vifs")] == [
        "ok",
        "stale",
        "unsupported",
        "failing",
        "failing",
    ]
    assert rows["pifs"].status == "off" and rows["groups"].status == ""
    assert rows["servers"].hidden_by_xo == ("password", "token")
    assert list(rows) == list(COLLECTIONS)
    # and the page prints them
    response = world.get(f"/sources/{view.id}", role="viewer")
    assert_page(response)
    printed = {cells[0]: cells for cells in CoverageRows(response.text).rows}
    assert printed["Virtual machines"][1:3] == ["200", "7"]
    assert printed["Hosts"][1:3] == ["403, stale", "4"]
    assert printed["Pools"][1:3] == ["404, not on this version", "0"]
    assert printed["Storage repositories"][1:3] == ["Error", "3"]
    assert printed["Virtual interfaces"][1:3] == ["HTTP 502", "0"]
    assert printed["Physical interfaces"][1:3] == ["Off", "none"]
    assert printed["Groups"][1:3] == ["Not read yet", "none"]
    servers = next(key for key in printed if key.startswith("Servers"))
    assert "Hidden by XO: password, token, changes not observable" in servers
    assert 'datetime="2026-10-23T11:00:00Z"' in response.text  # stale since, as a time
    assert "Stale since" in " ".join(printed["Hosts"])


# ---- acceptance 3: delete needs the typed name ---------------------------------------------


def test_delete_needs_the_typed_name(world: World) -> None:
    source_id = add_unifi(world)
    for typed in ("", "branch", "BRANCH-GW", "branch-gw2"):
        response = world.post(f"/sources/{source_id}/delete", {"confirm": typed})
        parsed = assert_page(response, 422)
        assert "Type the name of the source exactly" in parsed.joined()
        field_attrs = next(a for a in parsed.find("input") if a.get("name") == "confirm")
        assert field_attrs.get("aria-invalid") == "true"
    refused = world.post(f"/sources/{source_id}/delete", json={"confirm": "x"}, html=False)
    assert refused.status_code == 422
    assert world.service.get(source_id).name == "branch-gw"
    as_operator = world.post(f"/sources/{source_id}/delete", {"confirm": "branch-gw"}, "operator")
    assert as_operator.status_code == 403
    deleted = world.post(f"/sources/{source_id}/delete", {"confirm": " branch-gw "})
    assert deleted.status_code == 303 and deleted.headers["location"] == "/sources?notice=deleted"
    assert world.get(f"/sources/{source_id}").status_code == 404
    page = assert_page(world.get("/sources?notice=deleted"))
    assert "Source deleted" in page.joined()
    with world.store.read() as connection:
        actions = connection.execute(sa.select(audit_events.c.action)).scalars().all()
    assert "source.delete" in actions
    assert world.scheduler.synced >= 2  # after the create and after the delete


# ---- the list and the roles -----------------------------------------------------------------


def test_the_list_shows_status_flags_last_check_version_and_drift_line(world: World) -> None:
    source_id = add_unifi(
        world, tls_mode="insecure", tls_confirmation="I understand the risk", name="lab-gw"
    )
    xo = world.service.create(
        name="pool-a",
        source_type="xo",
        actor="test",
        base_url="https://xo.example",
        credential=XO_CANARY,
        options={"credential_expires_on": (NOW + timedelta(days=5)).date().isoformat()},
    )
    with world.store.write() as connection:
        connection.execute(
            sa.update(sources)
            .where(sources.c.id == source_id)
            .values(last_checked_at=STAMP, controller_version="10.1.84", state="unsupported")
        )
        connection.execute(
            sa.insert(runs).values(
                source_id=source_id, started_at=STAMP, finished_at=STAMP, status="ok"
            )
        )
    parsed = assert_page(world.get("/sources", role="viewer"))
    text = parsed.joined()
    for expected in ("lab-gw", "pool-a", "Insecure TLS", "Unsupported", "Credential expiring"):
        assert expected in text, expected
    assert "10.1.84" in text and "No check yet" in text
    hrefs = {a.get("href") for a in parsed.find("a")}
    assert {f"/sources/{source_id}", f"/sources/{xo.id}", "/sources/1"} <= hrefs
    assert "/sources/new" not in hrefs  # a viewer cannot add
    strips = [svg for svg in parsed.find("svg") if svg.get("role") == "img"]
    assert len(strips) == 3  # the two sources and the push source of the store fixture
    admin = assert_page(world.get("/sources"))
    assert {"class": "btn btn--primary", "href": "/sources/new"} in admin.find("a")
    listed = world.get("/sources", html=False).json()["sources"]
    assert [entry["name"] for entry in listed] == ["lab-controller", "lab-gw", "pool-a"]
    keys = {key for entry in listed for key in entry}
    assert keys - {"has_credential"} == {key for key in keys if "credential" not in key}


def test_an_empty_list_offers_add_source_only_to_an_admin(world: World) -> None:
    with world.store.write() as connection:
        connection.execute(sa.delete(sources))
    admin = assert_page(world.get("/sources"))
    assert {"class": "btn btn--primary", "href": "/sources/new"} in admin.find("a")
    assert "Nothing to watch yet" in admin.joined()
    viewer = assert_page(world.get("/sources", role="viewer"))
    assert "/sources/new" not in {a.get("href") for a in viewer.find("a")}
    assert "An admin adds the sources" in viewer.joined()


def test_the_empty_dashboard_tells_a_viewer_who_adds_sources(world: World) -> None:
    viewer = assert_page(world.get("/", role="viewer"))
    assert "/sources/new" not in {a.get("href") for a in viewer.find("a")}
    assert "An admin adds the sources" in viewer.joined()
    operator = assert_page(world.get("/", role="operator"))
    assert "/sources/new" not in {a.get("href") for a in operator.find("a")}
    admin = assert_page(world.get("/"))
    assert {"class": "btn btn--primary", "href": "/sources/new"} in admin.find("a")


def test_only_an_admin_opens_the_forms_and_changes_a_source(world: World) -> None:
    source_id = add_unifi(world)
    for role in ("viewer", "operator"):
        assert world.get("/sources/new", role=role).status_code == 403
        assert world.get(f"/sources/{source_id}/edit", role=role).status_code == 403
        assert world.post("/sources/new", unifi_form(name="x"), role).status_code == 403
        assert world.post(f"/sources/{source_id}/disable", {}, role).status_code == 403
    viewer = assert_page(world.get(f"/sources/{source_id}", role="viewer"))
    actions = {attrs.get("action") for attrs in viewer.find("form")} - SHELL_FORMS
    assert actions == set()
    operator = assert_page(world.get(f"/sources/{source_id}", role="operator"))
    actions = {attrs.get("action") for attrs in operator.find("form")} - SHELL_FORMS
    assert actions == {f"/sources/{source_id}/run"}
    admin = assert_page(world.get(f"/sources/{source_id}"))
    actions = {attrs.get("action") for attrs in admin.find("form")} - SHELL_FORMS
    assert actions == {
        f"/sources/{source_id}/run",
        f"/sources/{source_id}/disable",
        f"/sources/{source_id}/delete",
    }
    assert world.get("/sources/99999").status_code == 404


def test_the_navigation_shows_only_pages_that_exist(world: World) -> None:
    parsed = assert_page(world.get("/sources"))
    nav = {a.get("href") for a in parsed.find("a")}
    assert "/sources" in nav and "/changes" in nav  # Changes came back with P10-T6
    assert "/history" in nav and "/configuration" in nav  # and these two with P10-T7
    assert "/settings" in nav  # and Settings with P10-T8, for an admin only
    viewer = assert_page(world.get("/sources", role="viewer"))
    assert "/settings" not in {a.get("href") for a in viewer.find("a")}


def test_the_source_page_links_to_its_history_and_its_configuration(world: World) -> None:
    source_id = add_unifi(world)
    for role in ("viewer", "operator", "admin"):
        parsed = assert_page(world.get(f"/sources/{source_id}", role=role))
        hrefs = {a.get("href") for a in parsed.find("a")}
        assert f"/history/{source_id}" in hrefs, role
        assert f"/configuration/{source_id}" in hrefs, role


# ---- the forms ------------------------------------------------------------------------------


def test_adding_a_unifi_source_stores_the_form_values(world: World) -> None:
    form = assert_page(world.get("/sources/new"))
    names = {attrs.get("name") for attrs in form.find("input")}
    assert {"name", "base_url", "credential", "interval_minutes", "tls_mode", "resource"} <= names
    credential = next(a for a in form.find("input") if a.get("name") == "credential")
    assert credential.get("type") == "password" and "value" not in credential
    source_id = add_unifi(world)
    view = world.service.get(source_id)
    assert (view.name, view.type) == ("branch-gw", "unifi")
    assert view.base_url == "https://controller.example"
    off = view.options["resources_off"]
    assert isinstance(off, list) and "unifi-sites" not in off and "unifi-devices" in off
    assert view.options["interval_seconds"] == 600 and "tls_mode" not in view.options
    page = assert_page(world.get(f"/sources/{source_id}?notice=created"))
    text = page.joined()
    assert "Source added" in text and "Every 10 minutes" in text
    assert "Stored encrypted, never shown again" in text
    assert "3 of 14 resources on" in text


def test_an_xo_form_with_every_resource_ticked_passes_the_csrf_check(world: World) -> None:
    headers = world.headers()
    form = {
        **unifi_form(type="xo", name="pool-a", credential=XO_CANARY),
        "credential_expires_on": "2026-11-30",
        "resource": list(COLLECTIONS),
        "csrf_token": headers.pop("X-CSRF-Token"),
    }
    response = world.client.post("/sources/new", data=form, headers=headers)
    assert response.status_code == 303, response.text[:300]
    source_id = int(response.headers["location"].split("/")[2].split("?")[0])
    view = world.service.get(source_id)
    assert "resources_off" not in view.options
    assert view.options["credential_expires_on"] == "2026-11-30"
    edit = assert_page(world.get(f"/sources/{source_id}/edit"))
    expiry = next(a for a in edit.find("input") if a.get("name") == "credential_expires_on")
    assert expiry.get("value") == "2026-11-30"


def test_form_errors_are_marked_on_their_fields_and_nothing_is_stored(world: World) -> None:
    before = count_rows(world.store)
    response = world.post(
        "/sources/new",
        unifi_form(
            name="",
            base_url="",
            credential="",
            interval_minutes="90",
            tls_mode="pinned",
            resource=[],
        ),
    )
    parsed = assert_page(response, 422)
    invalid = {a.get("name") for a in parsed.find("input") if a.get("aria-invalid") == "true"}
    assert {"name", "base_url", "credential", "interval_minutes", "tls_pin"} <= invalid
    assert "Turn on at least one resource." in parsed.joined()
    assert count_rows(world.store) == before
    xo = world.post(
        "/sources/new", unifi_form(type="xo", name="pool", credential_expires_on="31/12/2026")
    )
    assert "Enter the date as YYYY-MM-DD." in assert_page(xo, 422).joined()
    unknown = world.post("/sources/new", unifi_form(type="ldap"))
    assert unknown.status_code == 422


def test_a_taken_name_is_refused_on_the_name_field(world: World) -> None:
    add_unifi(world)
    response = world.post("/sources/new", unifi_form())
    parsed = assert_page(response, 409)
    assert "Another source already has this name." in parsed.joined()
    as_json = world.post("/sources/new", json=unifi_form(), html=False)
    assert as_json.status_code == 409


def test_insecure_tls_needs_the_typed_confirmation(world: World) -> None:
    before = count_rows(world.store)
    refused = world.post(
        "/sources/new", unifi_form(tls_mode="insecure", tls_confirmation=TYPED_CONFIRMATION)
    )
    parsed = assert_page(refused, 422)
    confirm = next(a for a in parsed.find("input") if a.get("name") == "tls_confirmation")
    assert confirm.get("aria-invalid") == "true" and "value" not in confirm
    assert TYPED_CONFIRMATION not in refused.text
    assert count_rows(world.store) == before
    source_id = add_unifi(world, tls_mode="insecure", tls_confirmation="I understand the risk")
    view = world.service.get(source_id)
    assert view.options["tls_mode"] == "insecure" and view.options["insecure"] is True
    page = assert_page(world.get(f"/sources/{source_id}"))
    assert "Certificate checks are off for this source" in page.joined()
    with world.store.read() as connection:
        actions = connection.execute(sa.select(audit_events.c.action)).scalars().all()
    assert "source.tls_insecure_enabled" in actions
    # an already insecure source is saved again without the sentence
    again = world.post(f"/sources/{source_id}/edit", unifi_form(tls_mode="insecure", credential=""))
    assert again.status_code == 303
    # switching it back to verify drops the flag
    back = world.post(f"/sources/{source_id}/edit", unifi_form(tls_mode="verify", credential=""))
    assert back.status_code == 303
    assert "insecure" not in world.service.get(source_id).options


def test_editing_keeps_the_stored_credential_when_the_field_is_empty(world: World) -> None:
    source_id = add_unifi(world)
    form = assert_page(world.get(f"/sources/{source_id}/edit"))
    credential = next(a for a in form.find("input") if a.get("name") == "credential")
    assert "value" not in credential
    name = next(a for a in form.find("input") if a.get("name") == "name")
    assert name.get("value") == "branch-gw"
    saved = world.post(f"/sources/{source_id}/edit", unifi_form(name="branch-gw-2", credential=""))
    assert saved.status_code == 303 and saved.headers["location"].endswith("?notice=saved")
    assert world.service.credential_for_collector(source_id) == UNIFI_CANARY.encode("utf-8")
    world.post(f"/sources/{source_id}/edit", unifi_form(credential=XO_CANARY))
    assert world.service.credential_for_collector(source_id) == XO_CANARY.encode("utf-8")
    # a script that sends only the name keeps every other value
    renamed = world.post(f"/sources/{source_id}/edit", json={"name": "renamed"}, html=False)
    assert renamed.status_code == 200
    view = world.service.get(source_id)
    assert view.name == "renamed" and view.options["interval_seconds"] == 600
    assert "unifi-devices" in cast(list[str], view.options["resources_off"])


def test_a_push_source_declares_fields_and_shows_its_sender_key_once(world: World) -> None:
    form = assert_page(world.get("/sources/new?type=push"))
    assert {a.get("name") for a in form.find("input")} & {"credential", "base_url"} == set()
    created = world.post(
        "/sources/new",
        {"full_form": "1", "type": "push", "name": "netbox", "push_fields": "networks: _id, name"},
    )
    assert created.status_code == 303
    source_id = int(created.headers["location"].split("/")[2].split("?")[0])
    assert world.service.get(source_id).options == {"push_fields": {"networks": ["_id", "name"]}}
    made = assert_page(world.post(f"/sources/{source_id}/push-key", {}))
    key_input = next(a for a in made.find("input") if a.get("name") == "push_key")
    key = str(key_input.get("value"))
    target = world.service.push_target(source_id)
    assert target is not None and target.key_hash == hashlib.sha256(key.encode()).hexdigest()
    later = world.get(f"/sources/{source_id}")
    assert key not in later.text and "Made; only its SHA-256 is stored" in later.text
    assert key not in world.get(f"/sources/{source_id}/edit").text
    assert world.post(f"/sources/{source_id}/run", {}, "operator").status_code == 409
    bad = world.post(
        "/sources/new",
        {"full_form": "1", "type": "push", "name": "x", "push_fields": "networks"},
    )
    assert bad.status_code == 422


# ---- test connection ------------------------------------------------------------------------


def test_test_connection_shows_version_and_coverage_and_stores_nothing(world: World) -> None:
    before = count_rows(world.store)
    response = world.post("/sources/test", unifi_form(), extra={"HX-Request": "true"})
    assert response.status_code == 200
    assert not response.text.startswith("<!doctype html>")  # only the panel
    parsed = Parsed(response.text)
    assert "The controller answered" in parsed.joined()
    assert "Version 10.1.84. 1 of 3 resources answered 200. Nothing was stored." in parsed.joined()
    printed = CoverageRows(response.text).rows
    assert [cells[1:3] for cells in printed] == [
        ["200", "2"],
        ["403", "0"],
        ["404, not on this version", "none"],
    ]
    assert count_rows(world.store) == before
    target = world.targets[-1]
    assert (target.source_type, target.base_url) == ("unifi", "https://controller.example")
    assert target.options["interval_seconds"] == 600
    # without JavaScript the whole form comes back with the result
    page = assert_page(world.post("/sources/test", unifi_form()))
    assert "The controller answered" in page.joined()
    name = next(a for a in page.find("input") if a.get("name") == "name")
    assert name.get("value") == "branch-gw"
    # a form that cannot be tested says why, in the panel
    broken = world.post("/sources/test", unifi_form(base_url=""), extra={"HX-Request": "true"})
    assert broken.status_code == 200 and "Fix the form before the test" in broken.text
    assert count_rows(world.store) == before
    assert world.post("/sources/test", unifi_form(), "operator").status_code == 403


def test_test_connection_of_a_stored_source_uses_the_stored_credential(world: World) -> None:
    source_id = add_unifi(world)
    response = world.post(f"/sources/{source_id}/test", unifi_form(credential="", base_url=""))
    assert_page(response)
    target = world.targets[-1]
    assert target.credential == UNIFI_CANARY.encode("utf-8")
    assert target.base_url == "https://controller.example"


def test_test_connection_says_when_it_is_not_available(store: Database) -> None:
    world = make_world(store, probe=False)
    with world.client:
        form = assert_page(world.get("/sources/new"))
        assert "Not available on this installation yet." in form.joined()
        buttons = form.find("button")
        test = next(b for b in buttons if b.get("aria-describedby") == "test-unavailable")
        assert "disabled" in test
        panel = world.post("/sources/test", unifi_form(), extra={"HX-Request": "true"})
        assert panel.status_code == 200 and "not available on this installation" in panel.text
        page = assert_page(world.post("/sources/test", unifi_form()), 503)
        assert "Test connection is not available on this installation yet" in page.joined()
        assert world.post("/sources/test", json=unifi_form(), html=False).status_code == 503


# ---- run now, enable and disable ------------------------------------------------------------


def test_run_now_starts_a_run_or_says_why_not(world: World) -> None:
    source_id = add_unifi(world)
    started = world.post(f"/sources/{source_id}/run", {}, "operator")
    assert started.status_code == 303
    assert started.headers["location"] == f"/sources/{source_id}?notice=run-started"
    assert world.scheduler.asked == [source_id]
    world.scheduler.answer = RunNowResult(RunNowStatus.TOO_SOON, 12.3)
    too_soon = world.post(f"/sources/{source_id}/run", {}, "operator")
    parsed = assert_page(too_soon, 429)
    assert too_soon.headers["retry-after"] == "13"
    assert "A run was started less than 30 seconds ago" in parsed.joined()
    assert "Wait 13 seconds, then run this source again." in parsed.joined()
    as_json = world.post(f"/sources/{source_id}/run", {}, "operator", html=False)
    assert as_json.status_code == 429
    world.scheduler.answer = RunNowResult(RunNowStatus.ALREADY_RUNNING)
    assert world.post(f"/sources/{source_id}/run", {}, "operator").status_code == 409
    world.scheduler.answer = RunNowResult(RunNowStatus.STARTED)
    assert world.post(f"/sources/{source_id}/run", {}, "operator", html=False).status_code == 202
    assert world.post(f"/sources/{source_id}/run", {}, "viewer").status_code == 403
    world.service.set_enabled(source_id, False, actor="test")
    disabled = world.post(f"/sources/{source_id}/run", {}, "operator")
    assert "This source is disabled" in assert_page(disabled, 409).joined()


def test_run_now_without_a_scheduler_says_runs_are_not_scheduled(store: Database) -> None:
    world = make_world(store, scheduler=False)
    with world.client:
        source_id = add_unifi(world)
        response = world.post(f"/sources/{source_id}/run", {}, "operator")
        text = assert_page(response, 503).joined()
        assert "Runs are not scheduled on this installation yet" in text


def test_without_a_scheduler_the_pages_promise_no_check(store: Database) -> None:
    world = make_world(store, scheduler=False)
    with world.client:
        source_id = add_unifi(world)
        for notice in ("created", "saved", "enabled"):
            page = assert_page(world.get(f"/sources/{source_id}?notice={notice}", "operator"))
            text = page.joined()
            assert "Checks are not scheduled on this installation yet" in text
            assert "within one interval" not in text
            assert "on its interval" not in text
            assert "The next check of this source" not in text
        buttons = page.find("button")
        run = next(b for b in buttons if b.get("aria-describedby") == "runs-unscheduled")
        assert "btn--unavailable" in (run.get("class") or "")
        assert "disabled" in run
        assert {"id": "runs-unscheduled", "class": "quiet"} in page.find("p")


def add_push(world: World) -> int:
    created = world.post(
        "/sources/new",
        {"full_form": "1", "type": "push", "name": "netbox", "push_fields": "networks: _id, name"},
    )
    assert created.status_code == 303
    return int(created.headers["location"].split("/")[2].split("?")[0])


@pytest.mark.parametrize("scheduler", [True, False])
def test_a_push_source_page_speaks_of_pushes_not_checks(store: Database, scheduler: bool) -> None:
    world = make_world(store, scheduler=scheduler)
    with world.client:
        source_id = add_push(world)
        for notice, (title, line) in PUSH_NOTICES.items():
            text = assert_page(world.get(f"/sources/{source_id}?notice={notice}", "admin")).joined()
            assert title in text and line in text, notice
            assert "not scheduled" not in text and "interval" not in text, notice
        page = assert_page(world.get(f"/sources/{source_id}", "admin"))
        text = page.joined()
        assert "Nothing pushed yet" in text
        assert "Not pushed yet" in text and "No push has carried this resource yet." in text
        assert "A 404 means" not in text and "No run has read" not in text
        assert f"/sources/{source_id}/run" not in {f.get("action") for f in page.find("form")}


def test_the_coverage_table_grows_with_the_page(world: World) -> None:
    source_id = add_unifi(world)
    page = assert_page(world.get(f"/sources/{source_id}"))
    classes = [div.get("class") or "" for div in page.find("div")]
    assert [c for c in classes if "table-wrap" in c] == ["table-wrap table-wrap--full"]


def test_with_a_scheduler_the_source_page_names_the_first_check(world: World) -> None:
    source_id = add_unifi(world)
    page = assert_page(world.get(f"/sources/{source_id}?notice=created", "operator"))
    text = page.joined()
    assert "Its first check runs within one interval; coverage fills in." in text
    assert "Checks are not scheduled" not in text
    assert all(b.get("aria-describedby") != "runs-unscheduled" for b in page.find("button"))


def test_a_refused_submit_puts_focus_on_its_reason(world: World) -> None:
    source_id = add_unifi(world)
    form = assert_page(world.post("/sources/new", unifi_form(name="")), 422)
    focused = [attrs for _, attrs in form.tags if "autofocus" in attrs]
    assert len(focused) == 1 and focused[0].get("tabindex") == "-1"
    assert "Fix the field marked below, then try again." in form.joined()
    detail = assert_page(world.post(f"/sources/{source_id}/delete", {"confirm": "wrong"}), 422)
    focused = [attrs for _, attrs in detail.tags if "autofocus" in attrs]
    assert [attrs.get("id") for attrs in focused] == ["confirm-name"]


def test_disable_and_enable_change_the_source_and_tell_the_scheduler(world: World) -> None:
    source_id = add_unifi(world)
    synced = world.scheduler.synced
    disabled = world.post(f"/sources/{source_id}/disable", {})
    assert disabled.headers["location"] == f"/sources/{source_id}?notice=disabled"
    assert world.service.get(source_id).enabled is False
    page = assert_page(world.get(f"/sources/{source_id}?notice=disabled"))
    assert "Source disabled" in page.joined()
    assert f"/sources/{source_id}/run" not in {a.get("action") for a in page.find("form")}
    enabled = world.post(f"/sources/{source_id}/enable", {}, html=False)
    assert enabled.status_code == 200 and enabled.json()["source"]["enabled"] is True
    assert world.scheduler.synced == synced + 2
