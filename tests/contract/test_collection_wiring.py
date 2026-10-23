"""The collection side of ``serve`` against fake controllers (P10, THE-978).

The real pieces are wired the way ``serve`` wires them (``sources.wiring.build_collection``): the
source service, the collector factory, the run pipeline with its notifier and the scheduler. A
fake Xen Orchestra and a fake UniFi controller on localhost stand in for the systems. Every
credential is a synthetic ``CANARY-`` value. The checks:

* run now stores a snapshot, through the real sources pages;
* a scheduled run fires without anyone asking;
* the resources turned off are never requested, by a run, a scheduled run or a test connection;
* test connection reads, stores nothing and works with the stored credential;
* the scheduler follows create, disable, enable and delete;
* a change tells the notifier after the run is committed;
* a source without a usable collector leaves a failed run that says why;
* no credential is in any page, answer, log line or database file.
"""

import asyncio
import logging
import re
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from httpx import Response

from driftsniff.config import Settings
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.main import create_app
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.scheduler import Scheduler
from driftsniff.sources.wiring import Collection, build_collection
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.source_pages import SourcePages

from . import fake_xo
from .fake_unifi import CANARY_HEADER, Scenario, fake_unifi

ORIGIN = "http://testserver"
MASTER = MasterKey(bytes(range(32)))
PASSWORD = "CANARY-correct horse battery"  # noqa: S105 - a test canary, not a credential
BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
WAIT_SECONDS = 20.0


def latest_possible(low: float, high: float) -> float:
    """The longest wait the scheduler may draw, so no scheduled run fires during a test."""
    return high


@dataclass
class Bench:
    """The application over a real database, signed in as an admin."""

    client: TestClient
    store: Database
    collection: Collection
    scheduler: Scheduler
    events: list[int]
    folder: Path
    headers: dict[str, str]
    bodies: list[str] = field(default_factory=list)

    def post(
        self, path: str, data: Mapping[str, object] | None = None, *, htmx: bool = False
    ) -> Response:
        headers = {**self.headers, **BROWSER}
        if htmx:
            headers["HX-Request"] = "true"
        response = self.client.post(path, data=data, headers=headers)
        self.bodies.append(response.text + " ".join(response.headers.values()))
        return response

    def add_xo(self, url: str, resources: list[str], name: str = "pool-a") -> int:
        response = self.post("/sources/new", xo_form(url, resources, name))
        assert response.status_code == 303, response.text[:300]
        match = re.fullmatch(r"/sources/(\d+)\?notice=created", response.headers["location"])
        assert match is not None
        return int(match.group(1))

    def wait_for_run(self, source_id: int) -> sa.Row[tuple[object, ...]]:
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:
            finished = [row for row in run_rows(self.store, source_id) if row.status is not None]
            if finished:
                return finished[0]
            time.sleep(0.05)
        raise AssertionError("no run finished in time")


def xo_form(url: str, resources: list[str], name: str = "pool-a") -> dict[str, object]:
    return {
        "full_form": "1",
        "type": "xo",
        "name": name,
        "base_url": url,
        "allow_plain_http": "1",
        "credential": fake_xo.CANARY_TOKEN,
        "interval_minutes": "60",
        "tls_mode": "verify",
        "resource": resources,
    }


def run_rows(store: Database, source_id: int) -> list[sa.Row[tuple[object, ...]]]:
    with store.read() as connection:
        return list(
            connection.execute(
                sa.select(tables.runs)
                .where(tables.runs.c.source_id == source_id)
                .order_by(tables.runs.c.id)
            )
        )


def count(store: Database, table: sa.Table, source_id: int | None = None) -> int:
    query = sa.select(sa.func.count()).select_from(table)
    if source_id is not None:
        query = query.where(table.c.source_id == source_id)
    with store.read() as connection:
        return int(connection.execute(query).scalar_one())


def covered(store: Database, source_id: int) -> set[str]:
    with store.read() as connection:
        rows = connection.execute(
            sa.select(tables.resource_coverage.c.resource).where(
                tables.resource_coverage.c.source_id == source_id
            )
        )
        return {str(row.resource) for row in rows}


def xo_collections_requested(server: fake_xo.FakeXo) -> set[str]:
    """The collections the fake Xen Orchestra was asked for (not the root, not the credential)."""
    names = {request.path[len(fake_xo.PREFIX) :].strip("/") for request in server.requests}
    return names - {"", fake_xo.TOKENS}


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Database]:
    database = Database(database_path(tmp_path))
    try:
        upgrade_to_head(database)
        yield database
    finally:
        database.close()


@pytest.fixture
def events() -> list[int]:
    return []


@pytest.fixture
def collection(store: Database, tmp_path: Path, events: list[int]) -> Collection:
    return build_collection(store, MASTER, tmp_path, notifier=events.append)


@pytest.fixture
def bench(
    store: Database, collection: Collection, events: list[int], tmp_path: Path
) -> Iterator[Bench]:
    auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    auth.create_user("admin", PASSWORD, "admin")
    scheduler = Scheduler(
        collection.service,
        collection.pipeline,
        collection.factory.for_source,
        uniform=latest_possible,
    )
    app = create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}),
        master_key=MASTER,
        scheduler=scheduler,
        auth=auth,
        sources=SourcePages(store, collection.service, probe_factory=collection.factory.for_target),
    )
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        response = client.post("/login", data={"username": "admin", "password": PASSWORD})
        assert response.status_code == 303, response.text
        match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
        assert match is not None
        client.cookies.clear()
        principal = auth.authenticate(match.group(1))
        assert principal is not None
        headers = {
            "Cookie": f"{SESSION_COOKIE}={match.group(1)}",
            "X-CSRF-Token": principal.csrf_token,
            "Origin": ORIGIN,
        }
        yield Bench(client, store, collection, scheduler, events, tmp_path, headers)


def assert_no_credential(bench: Bench, secret: str, caplog: pytest.LogCaptureFixture) -> None:
    """The secret is in no page or answer, no log line and no byte of the database."""
    assert all(secret not in body for body in bench.bodies)
    assert secret not in caplog.text
    database = database_path(bench.folder)
    for path in (database, Path(f"{database}-wal")):
        if path.exists():
            assert secret.encode("utf-8") not in path.read_bytes()


# -- run now ------------------------------------------------------------------------------------


def test_run_now_stores_a_snapshot_and_reads_only_the_resources_left_on(
    bench: Bench, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    scenario = fake_xo.Scenario(
        objects={
            "vms": [{"id": "vm-1", "name_label": "web"}],
            "hosts": [{"id": "host-1", "name_label": "xcp1"}],
        }
    )
    with fake_xo.fake_xo(scenario) as server:
        source_id = bench.add_xo(server.url, ["vms", "hosts"])
        assert source_id in bench.scheduler.scheduled()
        response = bench.post(f"/sources/{source_id}/run")
        assert response.status_code == 303, response.text[:300]
        assert response.headers["location"] == f"/sources/{source_id}?notice=run-started"
        run = bench.wait_for_run(source_id)
        requested = xo_collections_requested(server)
    assert (run.status, bool(run.stored_new_snapshot)) == ("ok", True)
    assert count(bench.store, tables.snapshots, source_id) == 1
    assert requested == {"vms", "hosts"}
    assert covered(bench.store, source_id) == {"vms", "hosts"}
    page = bench.client.get(f"/sources/{source_id}", headers={**bench.headers, **BROWSER})
    bench.bodies.append(page.text)
    assert page.status_code == 200
    assert_no_credential(bench, fake_xo.CANARY_TOKEN, caplog)


# -- test connection ----------------------------------------------------------------------------


def test_test_connection_reads_only_the_resources_left_on_and_stores_nothing(
    bench: Bench, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    scenario = fake_xo.Scenario(objects={"vms": [{"id": "vm-1", "name_label": "web"}]})
    with fake_xo.fake_xo(scenario) as server:
        response = bench.post("/sources/test", xo_form(server.url, ["vms"]), htmx=True)
        assert response.status_code == 200, response.text[:300]
        assert xo_collections_requested(server) == {"vms"}
        assert all(
            request.cookie == f"authenticationToken={fake_xo.CANARY_TOKEN}"
            for request in server.requests
        )
    for table in (tables.sources, tables.runs, tables.snapshots, tables.resource_coverage):
        assert count(bench.store, table) == 0
    assert_no_credential(bench, fake_xo.CANARY_TOKEN, caplog)


def test_test_connection_of_a_stored_source_uses_the_stored_credential(
    bench: Bench, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with fake_xo.fake_xo(fake_xo.Scenario(objects={"vms": [{"id": "vm-1"}]})) as server:
        source_id = bench.add_xo(server.url, ["vms", "hosts"])
        # The credential field is left empty: the page must use the stored one.
        response = bench.post(f"/sources/{source_id}/test", {"name": "pool-a"}, htmx=True)
        assert response.status_code == 200, response.text[:300]
        assert xo_collections_requested(server) == {"vms", "hosts"}
        assert server.requests
        assert all(
            request.cookie == f"authenticationToken={fake_xo.CANARY_TOKEN}"
            for request in server.requests
        )
    assert count(bench.store, tables.runs) == 0
    assert_no_credential(bench, fake_xo.CANARY_TOKEN, caplog)


# -- the scheduler follows the sources ----------------------------------------------------------


def test_the_scheduler_follows_create_disable_enable_and_delete(bench: Bench) -> None:
    source_id = bench.add_xo("https://203.0.113.10:8443", ["vms"])
    assert bench.scheduler.scheduled() == {source_id}
    assert bench.post(f"/sources/{source_id}/disable").status_code == 303
    assert bench.scheduler.scheduled() == frozenset()
    assert bench.post(f"/sources/{source_id}/enable").status_code == 303
    assert bench.scheduler.scheduled() == {source_id}
    refused = bench.post(f"/sources/{source_id}/delete", {"confirm": "not the name"})
    assert refused.status_code == 422
    assert bench.scheduler.scheduled() == {source_id}
    deleted = bench.post(f"/sources/{source_id}/delete", {"confirm": "pool-a"})
    assert deleted.status_code == 303
    assert bench.scheduler.scheduled() == frozenset()


# -- a scheduled run ----------------------------------------------------------------------------


class FirstWaitOnly:
    """The wait of the first cycle returns at once; every later wait lasts until it is cancelled."""

    def __init__(self) -> None:
        self.waits: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)
        if len(self.waits) > 1:
            await asyncio.Event().wait()


def test_a_scheduled_run_fires_and_never_requests_the_resources_turned_off(
    store: Database, collection: Collection, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    scenario = Scenario(objects={"networks": [{"id": "n1", "name": "LAN"}]})
    with fake_unifi(scenario) as server:
        view = collection.service.create(
            name="gateway",
            source_type="unifi",
            actor="admin",
            base_url=server.url,
            credential=CANARY_HEADER,
            options={
                "allow_plain_http": True,
                "interval_seconds": 60,
                "resources_off": ["unifi-wans", "unifi-vpn-servers"],
            },
        )
        sleeper = FirstWaitOnly()
        scheduler = Scheduler(
            collection.service,
            collection.pipeline,
            collection.factory.for_source,
            sleep=sleeper,
            uniform=lambda low, high: 0.0,
        )

        async def scenario_run() -> None:
            await scheduler.start()
            try:
                deadline = time.monotonic() + WAIT_SECONDS
                while time.monotonic() < deadline:
                    if any(row.status is not None for row in run_rows(store, view.id)):
                        return
                    await asyncio.sleep(0.05)
            finally:
                await scheduler.stop()

        asyncio.run(scenario_run())
        networks = server.requests_for("/networks")
        turned_off = server.requests_for("/wans") + server.requests_for("/vpn/servers")
    (run,) = [row for row in run_rows(store, view.id) if row.status is not None]
    assert (run.status, bool(run.stored_new_snapshot)) == ("ok", True)
    assert count(store, tables.snapshots, view.id) == 1
    assert sleeper.waits[0] == 0.0
    assert networks
    assert turned_off == []
    assert CANARY_HEADER not in caplog.text


# -- the notifier -------------------------------------------------------------------------------


def test_a_change_tells_the_notifier_after_the_run_is_committed(
    store: Database, collection: Collection, events: list[int]
) -> None:
    scenario = fake_xo.Scenario(objects={"hosts": [{"id": "host-1", "name_label": "xcp1"}]})
    with fake_xo.fake_xo(scenario) as server:
        view = collection.service.create(
            name="pool-a",
            source_type="xo",
            actor="admin",
            base_url=server.url,
            credential=fake_xo.CANARY_TOKEN,
            options={"allow_plain_http": True, "resources_off": ["vms"]},
        )
        first = collection.pipeline.run(view.id, collection.factory.for_source(view))
        assert (first.status, first.event_id, events) == ("ok", None, [])
        server.scenario.objects["hosts"] = [{"id": "host-1", "name_label": "xcp2"}]
        second = collection.pipeline.run(view.id, collection.factory.for_source(view))
    assert second.status == "ok"
    assert second.event_id is not None
    assert events == [second.event_id]
    assert count(store, tables.change_events, view.id) == 1


# -- a source that cannot get a collector -------------------------------------------------------


def test_a_source_without_a_usable_collector_leaves_a_failed_run_that_says_why(
    store: Database, collection: Collection
) -> None:
    view = collection.service.create(
        name="pool-a",
        source_type="xo",
        actor="admin",
        base_url="https://203.0.113.10:8443",
        credential=fake_xo.CANARY_TOKEN,
        options={"tls_mode": "ca_file", "tls_ca_file": "missing.pem"},
    )
    report = collection.pipeline.run(view.id, collection.factory.for_source(view))
    assert (report.status, report.error_class) == ("failed", "not_started")
    (row,) = run_rows(store, view.id)
    assert row.status == "failed"
    assert row.error_summary == "the CA file does not exist in the CA folder"
    assert fake_xo.CANARY_TOKEN not in str(row)
