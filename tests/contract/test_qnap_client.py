"""The QNAP collector against a fake NAS on localhost.

Covered: sign in by POST with the encoded password (never in a URL), reads with the session,
sign out after the run, a bad password, 2-step accounts, an expired session, a refused (non-admin)
read, hostile XML (document type declaration, entities) refused, HTTP faults, and two full
pipeline runs with configuration drift and the expected severities.

The names the fake serves are unverified (docs/vendor-notes/qnap.md).
"""

import base64
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, ERROR_HTTP, CollectorError, ResourceSpec
from driftsniff.collectors.qnap.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_TWO_STEP,
    ERROR_UNAUTHORIZED,
    QnapClient,
)
from driftsniff.collectors.qnap.resources import RESOURCES
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_qnap import CANARY_PASSWORD, LOGIN, LOGOUT, USER, FakeQnap, Scenario, fake_qnap

BILLION_LAUGHS = (
    b'<?xml version="1.0"?><!DOCTYPE QDocRoot [<!ENTITY a "aaaaaaaaaa">'
    b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
    b"<QDocRoot><authPassed>1</authPassed><volumeList><volume><volumeValue>1</volumeValue>"
    b"<volumeLabel>&c;</volumeLabel></volume></volumeList></QDocRoot>"
)
XXE = (
    b'<?xml version="1.0"?><!DOCTYPE QDocRoot [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    b"<QDocRoot><authPassed>1</authPassed><hostname>&x;</hostname></QDocRoot>"
)
SOURCE_ID = 1


def client_for(server: FakeQnap, password: str = CANARY_PASSWORD) -> QnapClient:
    return QnapClient(server.url, USER, password, allow_plain_http=True)


@contextmanager
def connected(scenario: Scenario | None = None) -> Iterator[tuple[FakeQnap, QnapClient]]:
    with fake_qnap(scenario) as server:
        client = client_for(server)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(scenario: Scenario | None = None) -> Iterator[tuple[FakeQnap, QnapClient]]:
    with connected(scenario) as (server, client):
        client.probe()
        yield server, client


def fetch(client: QnapClient, name: str) -> list[dict[str, Any]]:
    result = client.fetch(ResourceSpec(name))
    assert result.ok, (result.error_class, result.error_text)
    return [dict(item) for item in result.objects]


# -- sign in, reads, sign out -----------------------------------------------------------------


def test_the_probe_signs_in_by_post_and_reports_the_firmware() -> None:
    with connected() as (server, client):
        assert client.probe() == "5.1.4"
        login, read = server.requests
    assert (login.method, login.path, login.query) == ("POST", LOGIN, "")
    form = parse_qs(login.body)
    assert form["user"] == [USER]
    assert form["pwd"] == [base64.b64encode(CANARY_PASSWORD.encode()).decode()]
    assert read.method == "GET"
    assert parse_qs(read.query)["sid"] == ["s0000001"]


def test_the_password_never_travels_in_a_url_and_the_session_ends() -> None:
    encoded = base64.b64encode(CANARY_PASSWORD.encode()).decode()
    with fake_qnap() as server:
        client = client_for(server)
        client.probe()
        for name in RESOURCES:
            assert client.fetch(ResourceSpec(name)).ok
        client.close()
        for request in server.requests:
            assert CANARY_PASSWORD not in request.query + request.path + request.body
            assert encoded not in request.query + request.path
        last = server.requests[-1]
        assert (last.method, last.path) == ("GET", LOGOUT)
        assert parse_qs(last.query) == {"logout": ["1"], "sid": ["s0000001"]}
        assert server.open_sessions == set()


def test_every_resource_has_a_type_table_and_is_listed_in_order() -> None:
    with probed() as (_, client):
        assert [spec.name for spec in client.resources()] == list(RESOURCES)


def test_a_shared_document_is_read_once_per_run() -> None:
    with probed() as (server, client):
        for name in RESOURCES:
            client.fetch(ResourceSpec(name))
        paths = [request.path for request in server.requests]
    assert paths.count("/cgi-bin/management/manaRequest.cgi") == 1
    assert paths.count("/cgi-bin/management/chartReq.cgi") == 1


def test_the_objects_keep_only_configuration() -> None:
    with probed() as (_, client):
        (system,) = fetch(client, "qnap-system")
        interfaces = fetch(client, "qnap-network-interfaces")
        volumes = fetch(client, "qnap-volumes")
        shares = fetch(client, "qnap-shared-folders")
        (web,) = fetch(client, "qnap-web-services")
        apps = fetch(client, "qnap-apps")
    assert system == {
        "id": "system",
        "hostname": "nas-lab-01",
        "model": "TS-464",
        "firmware": {"version": "5.1.4", "build": "20231128", "patch": "0"},
        "timezone": "(GMT+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna",
        "dnsServers": ["192.0.2.53", "198.51.100.53"],
    }
    assert [item["ifname"] for item in interfaces] == ["eth0", "eth1"]
    assert interfaces[0] == {
        "ifname": "eth0",
        "dname": "Adapter 1",
        "eth_ip": "192.0.2.10",
        "eth_mask": "255.255.255.0",
        "eth_mac": "00:08:9b:00:00:01",
        "eth_usage": "STATIC",
        "eth_max_speed": "2500",
        "eth_ipv6_enable": "0",
        "dns": ["192.0.2.53", "198.51.100.53"],
    }
    assert [(item["volumeValue"], item["volumeLabel"]) for item in volumes] == [
        ("1", "DataVol1"),
        ("2", "Scratch"),
    ]
    assert "freeSize" not in volumes[0] and "volumeStatus" not in volumes[0]
    assert volumes[0]["volumeDisks"] == "1,2,3,4"
    assert [(item["sharename"], item["volumeValue"]) for item in shares] == [
        ("Backups", "1"),
        ("Container", "2"),
        ("Public", "1"),
        ("homes", "1"),
    ]
    assert all("used_size" not in item for item in shares)
    assert web["forceSSL"] == "1" and web["id"] == "web"
    assert [item["name"] for item in apps] == ["HybridBackup", "container-station"]
    assert "status" not in apps[0] and "task_info" not in apps[0]


def test_a_fetch_before_the_probe_is_refused() -> None:
    with connected() as (_, client), pytest.raises(CollectorError) as caught:
        client.fetch(ResourceSpec("qnap-system"))
    assert caught.value.error_class == ERROR_NOT_PROBED


# -- refusals ---------------------------------------------------------------------------------


def test_a_bad_password_is_unauthorized_with_a_fixed_text() -> None:
    with fake_qnap() as server:
        client = client_for(server, "CANARY-wrng-001")
        with pytest.raises(CollectorError) as caught:
            client.probe()
        client.close()
        assert server.open_sessions == set()
        assert [request.method for request in server.requests] == ["POST"]
    assert caught.value.error_class == ERROR_UNAUTHORIZED
    assert not caught.value.retryable
    assert "CANARY" not in str(caught.value)


def test_a_two_step_account_is_not_supported() -> None:
    with connected(Scenario(two_step=True)) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_TWO_STEP


def test_an_expired_session_signs_in_once_more_and_repeats_the_read() -> None:
    with probed(Scenario(expire_after=1)) as (server, client):
        # The probe's read used the session; the fake has now ended it.
        objects = fetch(client, "qnap-apps")
        methods = [request.method for request in server.requests]
        sids = [parse_qs(request.query).get("sid") for request in server.requests]
    assert [item["name"] for item in objects] == ["HybridBackup", "container-station"]
    assert methods == ["POST", "GET", "GET", "POST", "GET"]
    assert sids[2] == ["s0000001"] and sids[4] == ["s0000002"]


def test_a_read_refused_with_a_fresh_session_is_forbidden_coverage() -> None:
    with probed(Scenario(refused={"apps"})) as (server, client):
        result = client.fetch(ResourceSpec("qnap-apps"))
        logins = [request for request in server.requests if request.method == "POST"]
    assert (result.ok, result.error_class, result.status) == (False, ERROR_FORBIDDEN, "403")
    assert len(logins) == 2
    assert "s000000" not in (result.error_text or "")


def test_a_login_interface_that_is_missing_is_no_api() -> None:
    with connected(Scenario(status={"login": 404})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_NO_API


# -- hostile and broken answers ---------------------------------------------------------------


@pytest.mark.parametrize("body", [BILLION_LAUGHS, XXE], ids=["entity-expansion", "external-entity"])
def test_a_document_type_declaration_is_refused(body: bytes) -> None:
    with probed(Scenario(raw={"disk_usage": body})) as (_, client):
        result = client.fetch(ResourceSpec("qnap-volumes"))
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)
    assert result.error_text == "the answer holds a document type declaration, which is refused"


def test_a_hostile_login_answer_stops_the_probe() -> None:
    with connected(Scenario(raw={"login": XXE})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_NO_API


@pytest.mark.parametrize(
    "body",
    [b"<html>login</html>", b"<QDocRoot><a>", b"", b"{}"],
    ids=["html", "cut", "empty", "json"],
)
def test_an_answer_that_is_not_a_qnap_document_fails_that_resource(body: bytes) -> None:
    with probed(Scenario(raw={"apps": body})) as (_, client):
        result = client.fetch(ResourceSpec("qnap-apps"))
        other = client.fetch(ResourceSpec("qnap-volumes"))
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)
    assert other.ok


def test_duplicate_keys_fail_the_resource() -> None:
    scenario = Scenario()
    scenario.shares.append({"name": "Public", "volume": "2"})
    with probed(scenario) as (_, client):
        result = client.fetch(ResourceSpec("qnap-shared-folders"))
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


@pytest.mark.parametrize(
    ("status", "error_class", "retryable"),
    [(404, ERROR_NOT_AVAILABLE, False), (500, ERROR_HTTP, True), (403, ERROR_FORBIDDEN, False)],
)
def test_http_faults_of_a_read(status: int, error_class: str, retryable: bool) -> None:
    with probed(Scenario(status={"apps": status})) as (_, client):
        result = client.fetch(ResourceSpec("qnap-apps"))
    assert (result.ok, result.error_class, result.retryable) == (False, error_class, retryable)
    assert "sid" not in (result.error_text or "")


def test_a_failed_sign_out_is_ignored() -> None:
    with fake_qnap(Scenario(status={"logout": 500})) as server:
        client = client_for(server)
        client.probe()
        client.close()


# -- two runs through the pipeline ------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.second = 0

    def __call__(self) -> str:
        self.second += 1
        moment = datetime(2026, 11, 12, 9, 0, 0, tzinfo=UTC) + timedelta(seconds=self.second)
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    store = Database(database_path(tmp_path))
    try:
        upgrade_to_head(store)
        with store.write() as connection:
            connection.exec_driver_sql(
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-nas', 'qnap')"
            )
        yield store
    finally:
        store.close()


@pytest.fixture
def pipeline(database: Database) -> RunPipeline:
    return RunPipeline(
        database,
        RuleEngine(load_rules()),
        Fingerprinter(bytes(range(32)), "0a1b2c3d"),
        clock=Clock(),
    )


def collect(pipeline: RunPipeline, server: FakeQnap) -> RunReport:
    return pipeline.run(SOURCE_ID, client_for(server))


def change_items(database: Database) -> set[tuple[object, ...]]:
    with database.read() as connection:
        rows = connection.execute(sa.select(tables.change_items))
        return {(row.resource, row.change_kind, row.path, row.severity) for row in rows}


def test_volatile_values_raise_nothing_and_drift_gets_its_severity(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_qnap() as server:
        first = collect(pipeline, server)
        assert first.status == "ok"
        server.scenario.tick += 1  # uptime, temperatures, counters and sizes move
        quiet = collect(pipeline, server)
        assert (quiet.status, quiet.event_id) == ("ok", None)
        assert change_items(database) == set()
        server.mutate()
        second = collect(pipeline, server)
        assert server.open_sessions == set()
    assert second.status == "ok" and second.event_id is not None
    assert change_items(database) == {
        ("qnap-web-services", "modified", "forceSSL", "high"),
        ("qnap-system", "modified", "dnsServers.0", "high"),
        ("qnap-system", "removed", "dnsServers.1", "high"),
        ("qnap-system", "modified", "hostname", "low"),
        ("qnap-shared-folders", "added", "", "medium"),
        ("qnap-apps", "added", "", "medium"),
    }
