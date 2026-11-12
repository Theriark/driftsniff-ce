"""The Proxmox VE client against a fake Proxmox VE on localhost, and two runs through the pipeline.

The fake serves the shapes read from the Proxmox VE API schema and sources
(docs/vendor-notes/proxmox.md); it is not a lab Proxmox. The last group runs the whole pipeline on a
migrated database: a first read, then a read after :meth:`Scenario.drift`, gives the expected
change items and severities, and no secret the fake serves is ever stored or logged in clear.
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError, ResourceSpec
from driftsniff.collectors.proxmox import resources as res
from driftsniff.collectors.proxmox.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_TOO_MANY_GUESTS,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    ProxmoxClient,
)
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.factory import build_collector
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_proxmox import (
    API_TOKEN,
    CI_PASSWORD,
    OIDC_CLIENT_KEY,
    SECRETS,
    VERSION,
    FakeProxmox,
    Scenario,
    fake_proxmox,
)

SOURCE_ID = 1


@contextmanager
def connected(
    scenario: Scenario | None = None, token: str = API_TOKEN, **options: Any
) -> Iterator[tuple[FakeProxmox, ProxmoxClient]]:
    with fake_proxmox(scenario) as server:
        client = ProxmoxClient(server.url, token, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(scenario: Scenario | None = None) -> Iterator[tuple[FakeProxmox, ProxmoxClient]]:
    with connected(scenario) as (server, client):
        client.probe()
        yield server, client


def read_all(client: ProxmoxClient) -> dict[str, Any]:
    return {spec.name: client.fetch(spec) for spec in client.resources()}


def objects(results: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return list(results[name].objects)


# -- probe ------------------------------------------------------------------------------------


def test_a_probe_reads_the_version_with_the_token() -> None:
    with connected() as (server, client):
        assert client.probe() == VERSION
        assert [request.path for request in server.requests] == ["/api2/json/version"]
        assert server.requests[0].authorization == f"PVEAPIToken={API_TOKEN}"


@pytest.mark.parametrize(
    "token", ["driftsniff@pve!audit=CANARY-proxmox-wrong", "other@pve!audit=CANARY-proxmox-x"]
)
def test_an_unknown_token_is_unauthorized_and_never_echoed(token: str) -> None:
    with connected(Scenario(echo_key=True), token) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
    assert token not in str(caught.value)
    assert "CANARY" not in str(caught.value)


def test_a_forbidden_version_is_forbidden() -> None:
    with connected(Scenario(status={"version": 403})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_FORBIDDEN


@pytest.mark.parametrize(
    "scenario",
    [
        Scenario(status={"version": 501}),
        Scenario(raw={"version": b"<html>"}),
        Scenario(raw={"version": b'{"version": "8.3.2"}'}),
    ],
)
def test_a_server_that_is_not_proxmox_is_no_api(scenario: Scenario) -> None:
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_an_unreadable_version_text_is_reported_as_none() -> None:
    with connected(Scenario(raw={"version": b'{"data": {"version": "<b>"}}'})) as (_, client):
        assert client.probe() is None


def test_a_blocked_address_is_refused_before_any_request() -> None:
    with connected(resolver=lambda host: ["169.254.169.254"]) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == "blocked_address"
        assert server.requests == []


def test_fetching_before_the_probe_is_refused() -> None:
    with connected() as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.fetch(ResourceSpec(res.RESOURCE_USERS))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize(
    "token",
    [
        "",
        "CANARY-proxmox-00",
        "user@pve=CANARY",
        "user@pve!tok",
        "user@pve!tok=a b",
        "café@pve!t=x",
    ],
)
def test_a_token_of_the_wrong_form_is_refused_without_echo(token: str) -> None:
    with pytest.raises(ValueError, match="user@realm!tokenid=secret") as caught:
        ProxmoxClient("https://pve.example.invalid:8006", token)
    assert "CANARY" not in str(caught.value)


# -- reading ----------------------------------------------------------------------------------


def test_every_resource_is_read_with_get_and_only_the_header_carries_the_token() -> None:
    with probed() as (server, client):
        results = read_all(client)
    assert all(result.ok for result in results.values()), {
        name: result.error_text for name, result in results.items() if not result.ok
    }
    assert list(results) == [resource.name for resource in res.RESOURCES]
    for request in server.requests:
        assert request.method == "GET"
        assert request.path.startswith("/api2/json/")
        assert request.authorization == f"PVEAPIToken={API_TOKEN}"
        assert request.cookie is None
        assert "CANARY" not in request.path + request.query
    configs = sorted(r.path for r in server.requests if r.path.endswith("/config"))
    assert configs == [
        "/api2/json/nodes/pve1/config",
        "/api2/json/nodes/pve1/lxc/200/config",
        "/api2/json/nodes/pve1/qemu/100/config",
        "/api2/json/nodes/pve2/config",
        "/api2/json/nodes/pve2/qemu/101/config",
    ]


def test_objects_are_reshaped_and_sorted_whatever_order_proxmox_sends() -> None:
    with probed() as (_, client):
        straight = read_all(client)
    with probed(Scenario(reverse=True)) as (_, client):
        reversed_ = read_all(client)
    assert {k: list(v.objects) for k, v in straight.items()} == {
        k: list(v.objects) for k, v in reversed_.items()
    }
    vms = objects(straight, res.RESOURCE_VMS)
    assert [vm["vmid"] for vm in vms] == [100, 101]
    assert vms[1]["node"] == "pve2"
    assert vms[1]["net[n]"] == [
        {"slot": "net0", "value": "virtio=BC:24:11:00:01:01,bridge=vmbr0,tag=20"},
        {"slot": "net1", "value": "virtio=BC:24:11:00:01:02,bridge=vmbr1"},
    ]
    assert "net0" not in vms[1]
    (container,) = objects(straight, res.RESOURCE_CONTAINERS)
    assert (container["vmid"], container["mp[n]"][0]["slot"]) == (200, "mp0")
    nodes = objects(straight, res.RESOURCE_NODES)
    assert nodes[1]["acmedomain[n]"] == [
        {"slot": "acmedomain0", "value": "domain=pve2.example.invalid"}
    ]
    assert nodes[0]["ssl_fingerprint"] == "AA:BB:CC:01"
    (options,) = objects(straight, res.RESOURCE_FIREWALL_OPTIONS)
    assert (options["id"], options["enable"]) == ("cluster", 1)
    rules = objects(straight, res.RESOURCE_FIREWALL_RULES)
    assert [rule["id"] for rule in rules] == [
        "cluster/0",
        "cluster/1",
        "cluster/2",
        "group/webservers/0",
        "group/webservers/1",
    ]
    (ipset,) = objects(straight, res.RESOURCE_FIREWALL_IPSETS)
    assert {entry["cidr"] for entry in ipset["entries"]} == {"192.0.2.5", "192.0.2.6"}
    users = objects(straight, res.RESOURCE_USERS)
    assert users[1]["groups"] == ["operators"] and "tokens" not in users[0]
    (token,) = objects(straight, res.RESOURCE_TOKENS)
    assert (token["id"], token["privsep"]) == ("driftsniff@pve!audit", 1)
    roles = objects(straight, res.RESOURCE_ROLES)
    assert roles[1]["privs"] == ["VM.Audit", "VM.PowerMgmt"]
    admins = objects(straight, res.RESOURCE_ADMIN_ACL)
    assert [entry["id"] for entry in admins] == ["/|user|root@pam|Administrator"]
    assert len(objects(straight, res.RESOURCE_ACL)) == 2
    realms = {realm["realm"]: realm for realm in objects(straight, res.RESOURCE_REALMS)}
    assert realms["corp"]["bind_dn"] == "cn=pve,dc=example,dc=invalid"
    (pool,) = objects(straight, res.RESOURCE_POOLS)
    assert pool["members"] == ["qemu/100", "storage/pve1/local"]


@pytest.mark.parametrize("code", [404, 501])
def test_a_missing_resource_is_not_available(code: int) -> None:
    with probed(Scenario(status={"cluster/sdn/zones": code})) as (_, client):
        result = client.fetch(ResourceSpec(res.RESOURCE_SDN_ZONES))
    assert (result.ok, result.status, result.error_class) == (False, "404", ERROR_NOT_AVAILABLE)
    assert not result.retryable


def test_a_refused_resource_is_forbidden() -> None:
    with probed(Scenario(status={"access/acl": 403})) as (_, client):
        result = client.fetch(ResourceSpec(res.RESOURCE_ADMIN_ACL))
    assert (result.ok, result.status, result.error_class) == (False, "403", ERROR_FORBIDDEN)


def test_a_guest_config_that_cannot_be_read_fails_the_resource() -> None:
    with probed(Scenario(status={"nodes/{node}/qemu/{vmid}/config": 500})) as (_, client):
        vms = client.fetch(ResourceSpec(res.RESOURCE_VMS))
        containers = client.fetch(ResourceSpec(res.RESOURCE_CONTAINERS))
    assert (vms.ok, vms.status, vms.retryable) == (False, "500", True)
    assert containers.ok


def test_more_guests_than_the_limit_fail_the_resource_before_reading_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(res, "MAX_GUESTS", 1)
    with probed() as (server, client):
        result = client.fetch(ResourceSpec(res.RESOURCE_VMS))
        assert not any("/qemu/" in request.path for request in server.requests)
    assert (result.ok, result.error_class) == (False, ERROR_TOO_MANY_GUESTS)


@pytest.mark.parametrize(
    ("key", "body", "name"),
    [
        ("storage", b"[]", res.RESOURCE_STORAGE),
        ("storage", b'{"data": {}}', res.RESOURCE_STORAGE),
        ("storage", b'{"data": [{"type": "dir"}]}', res.RESOURCE_STORAGE),
        ("access/roles", b'{"data": [{"roleid": "A"}, {"roleid": "A"}]}', res.RESOURCE_ROLES),
        ("cluster/options", b'{"data": []}', res.RESOURCE_CLUSTER_OPTIONS),
        ("access/acl", b'{"data": [{"path": "/"}]}', res.RESOURCE_ACL),
        ("cluster/firewall/rules", b'{"data": [{"action": "DROP"}]}', res.RESOURCE_FIREWALL_RULES),
        ("nodes", b'{"data": [{"node": "../../access"}]}', res.RESOURCE_NODES),
        (
            "cluster/resources",
            b'{"data": [{"type": "qemu", "vmid": 9, "node": "a/b"}]}',
            res.RESOURCE_VMS,
        ),
    ],
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(key: str, body: bytes, name: str) -> None:
    with probed(Scenario(raw={key: body})) as (server, client):
        result = client.fetch(ResourceSpec(name))
        assert not any(".." in request.path or "a/b" in request.path for request in server.requests)
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


def test_an_unknown_resource_is_never_requested() -> None:
    with probed() as (server, client):
        result = client.fetch(ResourceSpec("vms"))
        assert result.error_class == ERROR_UNKNOWN_RESOURCE
        assert len(server.requests) == 1


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
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-proxmox', 'proxmox')"
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


def collect(pipeline: RunPipeline, server: FakeProxmox) -> RunReport:
    return pipeline.run(SOURCE_ID, ProxmoxClient(server.url, API_TOKEN, allow_plain_http=True))


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
    with fake_proxmox() as server:
        first = collect(pipeline, server)
        server.scenario.tick()
        second = collect(pipeline, server)
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.event_id) == ("ok", None)
    assert items(database) == []


def test_a_drift_between_two_reads_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_proxmox() as server:
        first = collect(pipeline, server)
        assert first.status == "ok"
        server.scenario.drift()
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    assert items(database) == [
        ("proxmox-admin-acl", "added", "", "critical", "builtin.floor.added"),
        ("proxmox-backup-jobs", "modified", "enabled", "high", "proxmox.backup_jobs.disabled"),
        (
            "proxmox-firewall-options",
            "modified",
            "enable",
            "critical",
            "proxmox.firewall_options.disabled",
        ),
        ("proxmox-users", "added", "", "high", "builtin.floor.added"),
        ("proxmox-vms", "modified", "cipassword", "high", "proxmox.vms.ci_password"),
        ("proxmox-vms", "modified", "name", "low", "proxmox.vms.name"),
        ("proxmox-vms", "modified", "net[n]", "medium", "proxmox.vms.network"),
    ]


def test_a_new_token_and_an_administrator_grant_to_it(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_proxmox() as server:
        collect(pipeline, server)
        server.scenario.add_token("ops@pve", "automation", privsep=0)
        server.scenario.grant_acl("/vms", "group", "operators", "PVEAuditor")
        collect(pipeline, server)
    assert items(database) == [
        ("proxmox-acl", "added", "", "high", "builtin.floor.added"),
        ("proxmox-tokens", "added", "", "high", "builtin.floor.added"),
    ]


def test_no_secret_the_fake_serves_is_stored_or_logged_in_clear(
    database: Database, pipeline: RunPipeline, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with fake_proxmox() as server:
        collect(pipeline, server)
        server.scenario.drift()
        collect(pipeline, server)
    text = stored_text(database)
    assert "web-01b" in text  # the states are in the text that was searched
    assert CI_PASSWORD not in text and OIDC_CLIENT_KEY not in text
    for secret in SECRETS:
        assert secret not in text, secret
        assert secret not in caplog.text, secret


def test_the_factory_builds_the_client_from_the_whole_token() -> None:
    collector = build_collector(
        "proxmox", "https://pve.example.invalid:8006", API_TOKEN.encode("utf-8"), {}
    )
    try:
        assert isinstance(collector, ProxmoxClient)
    finally:
        collector.close()
