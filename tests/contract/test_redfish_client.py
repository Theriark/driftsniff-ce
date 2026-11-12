"""The Redfish client against a fake BMC on localhost, and two runs through the pipeline.

The fake serves the DMTF Redfish property names (docs/vendor-notes/redfish.md); it is not a lab
BMC. The last group runs the whole pipeline on a migrated database: a first read, then a read
after :meth:`Scenario.drift`, gives the expected change items and severities, and no secret the
fake serves (nor the password or the session token) is ever stored in clear or logged.
"""

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError, ResourceSpec
from driftsniff.collectors.redfish.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NO_SESSION,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    RedfishClient,
)
from driftsniff.collectors.redfish.resources import RESOURCES
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.factory import build_collector
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_redfish import (
    ACCOUNT_PASSWORD,
    BIOS_PASSWORD,
    FIRMWARE_VERSION,
    LDAP_PASSWORD,
    PASSWORD,
    ROOT,
    SESSIONS,
    SNMP_COMMUNITY,
    SUBSCRIPTION_CONTEXT,
    TOKEN_PREFIX,
    USERNAME,
    FakeRedfish,
    Scenario,
    fake_redfish,
)

SECRETS = (
    PASSWORD,
    TOKEN_PREFIX,
    SNMP_COMMUNITY,
    SUBSCRIPTION_CONTEXT,
    BIOS_PASSWORD,
    ACCOUNT_PASSWORD,
    LDAP_PASSWORD,
)
SOURCE_ID = 1


@contextmanager
def connected(
    scenario: Scenario | None = None, password: str = PASSWORD, **options: Any
) -> Iterator[tuple[FakeRedfish, RedfishClient]]:
    with fake_redfish(scenario) as server:
        client = RedfishClient(server.url, USERNAME, password, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(scenario: Scenario | None = None) -> Iterator[tuple[FakeRedfish, RedfishClient]]:
    with connected(scenario) as (server, client):
        client.probe()
        yield server, client


def read_all(client: RedfishClient) -> dict[str, Any]:
    return {spec.name: client.fetch(spec) for spec in client.resources()}


# -- probe and session ------------------------------------------------------------------------


def test_a_probe_reads_the_root_signs_in_and_reports_the_bmc_firmware() -> None:
    with connected() as (server, client):
        assert client.probe() == f"Contoso Contoso BMC {FIRMWARE_VERSION} (Redfish 1.17.0)"
        first, login = server.requests[:2]
        assert (first.method, first.path, first.token) == ("GET", f"{ROOT}/", None)
        assert (login.method, login.path, login.token) == ("POST", SESSIONS, None)
        assert json.loads(login.body) == {"UserName": USERNAME, "Password": PASSWORD}
        assert login.authorization is None


def test_the_session_is_deleted_when_the_client_closes() -> None:
    with connected() as (server, client):
        client.probe()
        assert len(server.scenario.sessions) == 1
        client.close()
        assert server.scenario.sessions == {}
        assert server.requests[-1].method == "DELETE"
        assert server.requests[-1].path == f"{SESSIONS}/1"


def test_a_second_probe_ends_the_first_session() -> None:
    with connected() as (server, client):
        client.probe()
        client.probe()
        assert list(server.scenario.sessions) == [f"{SESSIONS}/2"]


def test_a_session_without_location_is_not_deleted_and_nothing_fails() -> None:
    with connected(Scenario(location=False)) as (server, client):
        client.probe()
        client.close()
        assert not any(request.method == "DELETE" for request in server.requests)


@pytest.mark.parametrize("password", ["wrong", PASSWORD + "x"])
def test_a_wrong_password_is_unauthorized_and_never_echoed(password: str) -> None:
    with connected(Scenario(echo=True), password) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
        assert password not in str(caught.value)
        assert [request.method for request in server.requests] == ["GET", "POST"]


@pytest.mark.parametrize("status", [404, 405])
def test_a_bmc_without_sessions_is_no_session(status: int) -> None:
    with connected(Scenario(status={SESSIONS: status})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_NO_SESSION


@pytest.mark.parametrize(
    "scenario",
    [
        Scenario(status={f"{ROOT}/": 404}),
        Scenario(raw={f"{ROOT}/": b"<html>"}),
        Scenario(raw={f"{ROOT}/": b'{"Name": "not redfish"}'}),
    ],
)
def test_a_server_that_is_not_redfish_is_no_api(scenario: Scenario) -> None:
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_a_blocked_address_is_refused_before_any_request() -> None:
    with connected(resolver=lambda host: ["169.254.169.254"]) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == "blocked_address"
        assert server.requests == []


def test_fetching_before_the_probe_is_refused() -> None:
    with connected() as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.fetch(ResourceSpec("redfish-systems"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize(("user", "password"), [("", "x"), ("a\nb", "x"), ("user", "")])
def test_a_blank_user_name_or_password_is_refused(user: str, password: str) -> None:
    with pytest.raises(ValueError):
        RedfishClient("https://bmc.example.invalid", user, password)


# -- reading ----------------------------------------------------------------------------------


def test_every_resource_is_read_with_the_token_and_the_password_travels_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    with connected() as (server, client):
        client.probe()
        results = read_all(client)
        client.close()
        requests = list(server.requests)
    assert all(result.ok for result in results.values()), results
    assert list(results) == list(RESOURCES)
    token = f"{TOKEN_PREFIX}01"
    for request in requests[2:]:
        assert request.method in ("GET", "DELETE")
        assert request.token == token
        assert request.authorization is None
        assert request.query == ""
        assert PASSWORD.encode() not in request.body
    assert sum(PASSWORD.encode() in request.body for request in requests) == 1
    gets = [request.path for request in requests if request.method == "GET"]
    assert len(gets) == len(set(gets)), "every document is read once per run"
    assert PASSWORD not in caplog.text and token not in caplog.text


def test_objects_are_cleaned_keyed_and_sorted_whatever_order_the_bmc_sends() -> None:
    with probed() as (_, client):
        straight = read_all(client)
    with probed(Scenario(reverse=True)) as (_, client):
        reversed_ = read_all(client)
    assert {k: list(v.objects) for k, v in straight.items()} == {
        k: list(v.objects) for k, v in reversed_.items()
    }
    (system,) = straight["redfish-systems"].objects
    assert system["SecureBoot"]["SecureBootEnable"] is True
    assert "Bios" not in system and "@odata.etag" not in system
    assert "BootSourceOverrideTarget@Redfish.AllowableValues" not in system["Boot"]
    accounts = [item["UserName"] for item in straight["redfish-accounts"].objects]
    assert accounts == ["admin", "driftsniff", "operator"]  # the empty slot is not an account
    bios = {item["Attribute"]: item for item in straight["redfish-bios"].objects}
    assert bios["ProcVirtualization"] == {
        "ObjectKey": "1/ProcVirtualization",
        "System": "1",
        "Attribute": "ProcVirtualization",
        "value": "Enabled",
    }
    assert "value" not in bios["AdminPassword"]
    (network,) = straight["redfish-network-protocol"].objects
    assert network["Manager"] == "1"
    (interface,) = straight["redfish-manager-interfaces"].objects
    assert interface["ObjectKey"] == "1/1"
    (certificate,) = straight["redfish-certificates"].objects
    assert certificate["Uri"] == f"{ROOT}/Managers/1/NetworkProtocol/HTTPS/Certificates/1"
    firmware = [item["Id"] for item in straight["redfish-firmware"].objects]
    assert firmware == ["BIOS", "BMC"]


def test_a_service_the_root_does_not_link_is_not_available_and_never_requested() -> None:
    scenario = Scenario()
    del scenario.docs[f"{ROOT}/"]["CertificateService"]
    with probed(scenario) as (server, client):
        result = client.fetch(ResourceSpec("redfish-certificates"))
        assert not any("Certificate" in request.path for request in server.requests)
    assert (result.ok, result.status, result.error_class) == (False, "404", ERROR_NOT_AVAILABLE)


@pytest.mark.parametrize(
    ("status", "error_class"), [(403, ERROR_FORBIDDEN), (404, ERROR_NOT_AVAILABLE)]
)
def test_a_refused_member_gives_the_coverage_status(status: int, error_class: str) -> None:
    path = f"{ROOT}/AccountService/Accounts/4"
    with probed(Scenario(status={path: status})) as (_, client):
        result = client.fetch(ResourceSpec("redfish-accounts"))
    assert (result.ok, result.status, result.error_class) == (False, str(status), error_class)


def test_a_server_error_is_retryable() -> None:
    with probed(Scenario(status={f"{ROOT}/UpdateService/FirmwareInventory": 503})) as (_, client):
        result = client.fetch(ResourceSpec("redfish-firmware"))
    assert (result.ok, result.status) == (False, "503")
    assert result.retryable


@pytest.mark.parametrize(
    ("path", "body", "resource"),
    [
        (
            "/Systems",
            b'{"Members": [{"@odata.id": "https://elsewhere.invalid/x"}]}',
            "redfish-systems",
        ),
        ("/Systems", b'{"Members": [{"@odata.id": "/redfish/v1/../../etc"}]}', "redfish-systems"),
        ("/Systems", b'{"Members": {}}', "redfish-systems"),
        ("/Systems/1/Bios", b'{"Id": "Bios"}', "redfish-bios"),
        ("/Managers/1", b'{"Name": "no id"}', "redfish-managers"),
        ("/UpdateService/FirmwareInventory", b"[]", "redfish-firmware"),
        (
            "/AccountService",
            b'{"Accounts": {"@odata.id": "/redfish/v1/x?y=1"}}',
            "redfish-accounts",
        ),
    ],
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(
    path: str, body: bytes, resource: str
) -> None:
    with probed(Scenario(raw={ROOT + path: body})) as (server, client):
        result = client.fetch(ResourceSpec(resource))
        assert not any(
            "elsewhere" in request.path or ".." in request.path for request in server.requests
        )
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


def test_an_unknown_resource_is_never_requested() -> None:
    with probed() as (server, client):
        before = len(server.requests)
        result = client.fetch(ResourceSpec("vms"))
        assert result.error_class == ERROR_UNKNOWN_RESOURCE
        assert len(server.requests) == before


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
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-bmc', 'redfish')"
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


def collect(pipeline: RunPipeline, server: FakeRedfish) -> RunReport:
    client = RedfishClient(server.url, USERNAME, PASSWORD, allow_plain_http=True)
    return pipeline.run(SOURCE_ID, client)


def items(database: Database) -> list[tuple[str, str, str, str, str | None]]:
    with database.read() as connection:
        rows = connection.execute(sa.select(tables.change_items))
        return sorted(
            (row.resource, row.change_kind, row.path, row.severity, row.rule_id) for row in rows
        )


def stored_text(database: Database) -> str:
    """Every value the database holds, state bodies decompressed, as one text."""
    parts: list[str] = []
    with database.read() as connection:
        for table in tables.metadata.sorted_tables:
            for row in connection.execute(sa.select(table)):
                for value in row:
                    if isinstance(value, bytes):
                        with suppress(Exception):  # not every byte column is a state body
                            value = decompress_bytes(value, MAX_STATE_BYTES)
                        parts.append(value.decode("utf-8", errors="replace"))
                    else:
                        parts.append(str(value))
    return "\n".join(parts)


def test_volatile_changes_alone_report_nothing(database: Database, pipeline: RunPipeline) -> None:
    with fake_redfish() as server:
        first = collect(pipeline, server)
        server.scenario.tick()
        second = collect(pipeline, server)
        assert server.scenario.sessions == {}  # every run deleted its session
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.event_id) == ("ok", None)
    assert items(database) == []


def test_a_drift_between_two_reads_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_redfish() as server:
        first = collect(pipeline, server)
        assert first.status == "ok"
        server.scenario.drift()
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    assert items(database) == [
        ("redfish-accounts", "added", "", "critical", "builtin.floor.added"),
        (
            "redfish-network-protocol",
            "modified",
            "IPMI.ProtocolEnabled",
            "critical",
            "redfish.network.ipmi_on",
        ),
        (
            "redfish-network-protocol",
            "modified",
            "NTP.NTPServers.0",
            "medium",
            "redfish.network.ntp_servers",
        ),
        (
            "redfish-network-protocol",
            "modified",
            "SSH.ProtocolEnabled",
            "high",
            "redfish.network.ssh_on",
        ),
        ("redfish-systems", "modified", "Description", "low", "redfish.systems.description"),
    ]


def test_more_helpers_give_their_severities(database: Database, pipeline: RunPipeline) -> None:
    with fake_redfish() as server:
        collect(pipeline, server)
        server.scenario.set_secure_boot(False)
        server.scenario.set_role(4, "Administrator")
        server.scenario.set_firmware("2.15.0")
        server.scenario.set_bios("SriovGlobalEnable", "Enabled")
        server.scenario.set_subscription_destination("https://other.example.invalid/events")
        collect(pipeline, server)
    found = {
        (resource, path): (severity, rule) for resource, _, path, severity, rule in items(database)
    }
    assert found == {
        ("redfish-systems", "SecureBoot.SecureBootEnable"): (
            "critical",
            "redfish.systems.secure_boot_off",
        ),
        ("redfish-accounts", "RoleId"): ("critical", "redfish.accounts.role_to_admin"),
        ("redfish-managers", "FirmwareVersion"): ("medium", "redfish.managers.firmware"),
        ("redfish-firmware", "Version"): ("medium", "redfish.firmware.version"),
        ("redfish-bios", "value"): ("medium", "redfish.bios.value"),
        ("redfish-event-subscriptions", "Destination"): (
            "high",
            "redfish.subscriptions.destination",
        ),
    }


def test_no_secret_is_stored_in_clear_or_logged(
    database: Database, pipeline: RunPipeline, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with fake_redfish() as server:
        collect(pipeline, server)
        server.scenario.drift()
        server.scenario.set_bios("AdminPassword", "CANARY-redfish-bios-01")
        collect(pipeline, server)
    text = stored_text(database)
    assert "srv-01.example.invalid" in text  # the states are in the text that was searched
    for secret in (*SECRETS, "CANARY-redfish-bios-01"):
        assert secret not in text, secret
        assert secret not in caplog.text, secret


def test_the_factory_builds_the_client_from_the_user_name_option() -> None:
    with fake_redfish() as server:
        options: dict[str, object] = {"username": USERNAME, "allow_plain_http": True}
        collector = build_collector("redfish", server.url, PASSWORD.encode(), options)
        try:
            assert isinstance(collector, RedfishClient)
            assert collector.probe() is not None
        finally:
            collector.close()
        assert server.scenario.sessions == {}
