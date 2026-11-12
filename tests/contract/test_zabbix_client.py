"""The Zabbix client against a fake Zabbix on localhost, and two runs through the pipeline.

The fake serves the shapes read from the Zabbix manual (docs/vendor-notes/zabbix.md); it is not a
lab Zabbix. The last group runs the whole pipeline on a migrated database: a first read, then a
read after a mutation of the fake, gives the expected change items and severities, and no secret
the fake serves is ever stored in clear or written to a log.
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
from driftsniff.collectors.zabbix.client import (
    ERROR_API_ERROR,
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_TOO_MANY,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    ERROR_UNSUPPORTED_VERSION,
    ZabbixClient,
)
from driftsniff.collectors.zabbix.resources import RESOURCES
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_zabbix import (
    ADMIN_TOKEN,
    LIMITED_TOKEN,
    SECRETS,
    VERSION,
    FakeZabbix,
    Scenario,
    fake_zabbix,
)

LIMITED_DENIED = (
    "zabbix-media-types",
    "zabbix-user-roles",
    "zabbix-proxies",
    "zabbix-authentication",
)
SUPPORTED = ("6.0.30", "6.2.9", "6.4.21", "7.0.5", "7.2.4", "8.0.0")
SOURCE_ID = 1


@contextmanager
def connected(
    scenario: Scenario | None = None, token: str = ADMIN_TOKEN, **options: Any
) -> Iterator[tuple[FakeZabbix, ZabbixClient]]:
    with fake_zabbix(scenario) as server:
        client = ZabbixClient(server.url, token, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(
    scenario: Scenario | None = None, token: str = ADMIN_TOKEN, **options: Any
) -> Iterator[tuple[FakeZabbix, ZabbixClient]]:
    with connected(scenario, token, **options) as (server, client):
        client.probe()
        yield server, client


def read_all(client: ZabbixClient) -> dict[str, Any]:
    return {spec.name: client.fetch(spec) for spec in client.resources()}


# -- probe ------------------------------------------------------------------------------------


def test_a_probe_reads_the_version_without_the_token_then_checks_the_token() -> None:
    with connected() as (server, client):
        assert client.probe() == VERSION
        first, second = server.requests
    assert (first.path, first.rpc_method) == ("/zabbix/api_jsonrpc.php", "apiinfo.version")
    assert first.authorization is None and first.auth_member is None
    assert second.rpc_method == "hostgroup.get"
    assert second.authorization == f"Bearer {ADMIN_TOKEN}"
    assert second.content_type == "application/json-rpc"


@pytest.mark.parametrize("version", SUPPORTED)
def test_the_token_travels_where_each_version_wants_it(version: str) -> None:
    with probed(Scenario(version=version)) as (server, client):
        results = read_all(client)
    assert all(result.ok for result in results.values()), results
    for request in server.requests[1:]:
        if version.startswith(("6.0", "6.2")):
            assert (request.auth_member, request.authorization) == (ADMIN_TOKEN, None)
        else:
            assert (request.auth_member, request.authorization) == (None, f"Bearer {ADMIN_TOKEN}")
        assert ADMIN_TOKEN not in request.path + request.query
        assert request.http_method == "POST"


def test_an_address_that_names_the_endpoint_is_used_as_it_is() -> None:
    with fake_zabbix() as server:
        client = ZabbixClient(f"{server.url}/api_jsonrpc.php", ADMIN_TOKEN, allow_plain_http=True)
        try:
            client.probe()
        finally:
            client.close()
        assert {request.path for request in server.requests} == {"/zabbix/api_jsonrpc.php"}


@pytest.mark.parametrize("token", ["CANARY-zabbix-99", ADMIN_TOKEN + "x"])
def test_an_unknown_token_is_unauthorized_and_never_echoed(token: str) -> None:
    with connected(Scenario(echo_key=True), token) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
    assert token not in str(caught.value)


def test_a_version_below_six_is_unsupported() -> None:
    with connected(Scenario(version="5.4.12")) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert len(server.requests) == 1
    assert caught.value.error_class == ERROR_UNSUPPORTED_VERSION
    assert "5.4" in str(caught.value)


@pytest.mark.parametrize(
    "scenario",
    [
        Scenario(status={"apiinfo.version": 404}),
        Scenario(raw={"apiinfo.version": b"<html>"}),
        Scenario(raw={"apiinfo.version": b'{"jsonrpc": "2.0", "result": "<b>", "id": 1}'}),
        Scenario(errors={"apiinfo.version": (-32601, "Method not found.", "")}),
    ],
)
def test_a_server_that_is_not_zabbix_is_no_api(scenario: Scenario) -> None:
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
            client.fetch(ResourceSpec("zabbix-users"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize("token", ["", "with space", "café"])
def test_a_token_a_header_cannot_carry_is_refused(token: str) -> None:
    with pytest.raises(ValueError, match="API token"):
        ZabbixClient("https://zabbix.example.invalid/zabbix", token)


# -- reading ----------------------------------------------------------------------------------


def test_every_resource_is_read_with_its_get_method_and_config_fields_only() -> None:
    with probed() as (server, client):
        results = read_all(client)
    assert all(result.ok for result in results.values()), results
    assert list(results) == [resource.name for resource in RESOURCES]
    methods = [request.rpc_method for request in server.requests]
    assert all(method is not None and method.endswith((".get", ".version")) for method in methods)
    users = next(r for r in server.requests if r.rpc_method == "user.get")
    assert "passwd" not in users.params["output"]
    hosts = list(results["zabbix-hosts"].objects)
    assert [host["hostid"] for host in hosts] == ["10084", "10601", "10602"]  # no discovered host
    assert "maintenance_status" not in hosts[0]
    macros = {macro["macro"]: macro for macro in hosts[1]["macros"]}
    assert "value" not in macros["{$DB.PASSWORD}"]  # Zabbix never returns it
    assert macros["{$API.KEY}"]["value"] == "secret/web:api-key"
    triggers = list(results["zabbix-triggers"].objects)
    assert [trigger["triggerid"] for trigger in triggers] == ["23001", "23101", "23102"]
    assert "value" not in triggers[1] and "lastchange" not in triggers[1]
    (authentication,) = results["zabbix-authentication"].objects
    assert authentication["id"] == "authentication"
    users_read = list(results["zabbix-users"].objects)
    assert users_read[0]["role"] == {"type": "3"}


def test_hosts_and_triggers_are_listed_by_id_then_read_in_chunks() -> None:
    with probed(chunk_size=2) as (server, client):
        result = client.fetch(ResourceSpec("zabbix-hosts"))
    assert result.ok
    calls = [r.params for r in server.requests if r.rpc_method == "host.get"]
    assert calls[0] == {
        "output": ["hostid"],
        "filter": {"flags": "0"},
        "sortfield": "hostid",
        "limit": 100_001,
    }
    assert [call["hostids"] for call in calls[1:]] == [["10084", "10601"], ["10602"]]


def test_more_objects_than_the_limit_fail_the_resource_instead_of_storing_part() -> None:
    with probed(max_objects=2) as (_, client):
        result = client.fetch(ResourceSpec("zabbix-hosts"))
    assert (result.ok, result.error_class) == (False, ERROR_TOO_MANY)


def test_version_differences_are_reshaped_to_one_form() -> None:
    with probed(Scenario(version="6.0.30")) as (server, client):
        old = read_all(client)
    with probed(Scenario(version="7.0.5")) as (_, client):
        new = read_all(client)
    for name in ("zabbix-host-groups", "zabbix-templates", "zabbix-triggers", "zabbix-users"):
        assert list(old[name].objects) == list(new[name].objects), name
    old_host = list(old["zabbix-hosts"].objects)[2]
    assert old_host["hostgroups"] == [{"groupid": "22", "name": "Databases"}]
    assert old_host["proxy_hostid"] == "10701"
    old_group = list(old["zabbix-user-groups"].objects)[3]
    assert (
        old_group["hostgroup_rights"]
        == list(new["zabbix-user-groups"].objects)[3]["hostgroup_rights"]
    )
    selects = next(r for r in server.requests if r.rpc_method == "usergroup.get").params
    assert "selectRights" in selects and "selectHostGroupRights" not in selects


def test_objects_are_sorted_whatever_order_zabbix_sends() -> None:
    with probed() as (_, client):
        straight = read_all(client)
    with probed(Scenario(reverse=True)) as (_, client):
        reversed_ = read_all(client)
    assert {k: list(v.objects) for k, v in straight.items()} == {
        k: list(v.objects) for k, v in reversed_.items()
    }


def test_a_limited_token_gets_403_on_super_admin_resources_and_reads_the_rest() -> None:
    with probed(token=LIMITED_TOKEN) as (_, client):
        results = read_all(client)
    for name, result in results.items():
        if name in LIMITED_DENIED:
            assert (result.ok, result.status, result.error_class) == (False, "403", ERROR_FORBIDDEN)
        else:
            assert result.ok, name


def test_an_unknown_method_is_not_available() -> None:
    errors = {"proxy.get": (-32601, "Method not found.", 'Incorrect API "proxy".')}
    with probed(Scenario(errors=errors)) as (_, client):
        result = client.fetch(ResourceSpec("zabbix-proxies"))
    assert (result.ok, result.status, result.error_class) == (False, "404", ERROR_NOT_AVAILABLE)


def test_another_api_error_shows_its_code_and_never_its_text() -> None:
    errors = {"action.get": (-32500, "Application error.", "SQL statement CANARY-zabbix-sql-00")}
    with probed(Scenario(errors=errors)) as (_, client):
        result = client.fetch(ResourceSpec("zabbix-actions"))
    assert (result.ok, result.error_class) == (False, ERROR_API_ERROR)
    assert "-32500" in (result.error_text or "")
    assert "CANARY" not in (result.error_text or "")


def test_a_server_error_is_retryable() -> None:
    with probed(Scenario(status={"trigger.get": 502})) as (_, client):
        result = client.fetch(ResourceSpec("zabbix-triggers"))
    assert (result.ok, result.status) == (False, "502")
    assert result.retryable


@pytest.mark.parametrize(
    ("method", "body"),
    [
        ("template.get", b'{"jsonrpc": "2.0", "result": [], "id": 99}'),
        ("template.get", b'{"jsonrpc": "1.0", "result": [], "id": 3}'),
        ("action.get", b'{"jsonrpc": "2.0", "result": {}, "id": 3}'),
        ("role.get", b'{"jsonrpc": "2.0", "result": [{"name": "no id"}], "id": 3}'),
        ("authentication.get", b'{"jsonrpc": "2.0", "result": [], "id": 3}'),
    ],
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(method: str, body: bytes) -> None:
    name = {
        "template.get": "zabbix-templates",
        "action.get": "zabbix-actions",
        "role.get": "zabbix-user-roles",
        "authentication.get": "zabbix-authentication",
    }[method]
    with probed(Scenario(raw={method: body})) as (_, client):
        result = client.fetch(ResourceSpec(name))
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


def test_an_unknown_resource_is_never_requested() -> None:
    with probed() as (server, client):
        result = client.fetch(ResourceSpec("hosts"))
        assert result.error_class == ERROR_UNKNOWN_RESOURCE
        assert len(server.requests) == 2


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
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-zabbix', 'zabbix')"
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


def collect(pipeline: RunPipeline, server: FakeZabbix) -> RunReport:
    return pipeline.run(SOURCE_ID, ZabbixClient(server.url, ADMIN_TOKEN, allow_plain_http=True))


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
    with fake_zabbix() as server:
        first = collect(pipeline, server)
        server.scenario.tick()
        second = collect(pipeline, server)
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.event_id) == ("ok", None)
    assert items(database) == []


def test_the_standard_drift_gives_one_change_of_each_severity(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_zabbix() as server:
        assert collect(pipeline, server).status == "ok"
        server.scenario.drift()
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    assert items(database) == [
        ("zabbix-hosts", "modified", "description", "low", "zabbix.hosts.description"),
        ("zabbix-hosts", "modified", "status", "medium", "zabbix.hosts.status"),
        ("zabbix-triggers", "modified", "status", "high", "zabbix.triggers.disabled"),
        ("zabbix-users", "modified", "role.type", "critical", "zabbix.users.super_admin"),
        ("zabbix-users", "modified", "roleid", "high", "zabbix.users.role"),
    ]


def test_every_mutation_helper_gives_its_rule(database: Database, pipeline: RunPipeline) -> None:
    with fake_zabbix() as server:
        assert collect(pipeline, server).status == "ok"
        scenario = server.scenario
        scenario.unlink_template("10601", "10563")
        scenario.set_host_macro("10084", "{$CPU.UTIL.CRIT}", "95")
        scenario.set_action_status("3", "1")
        scenario.set_media_parameter("40", "Token", "CANARY-zabbix-webhook-01")
        scenario.set_authentication("passwd_min_length", "8")
        assert collect(pipeline, server).status == "ok"
    assert items(database) == [
        ("zabbix-actions", "modified", "status", "high", "zabbix.actions.disabled"),
        (
            "zabbix-authentication",
            "modified",
            "passwd_min_length",
            "critical",
            "zabbix.authentication.any",
        ),
        ("zabbix-hosts", "modified", "macros", "medium", "zabbix.hosts.macros"),
        ("zabbix-hosts", "removed", "parentTemplates", "medium", "zabbix.hosts.templates"),
        ("zabbix-media-types", "modified", "parameters", "high", "zabbix.media_types.any"),
    ]


def test_no_secret_the_fake_holds_is_stored_in_clear_or_logged(
    database: Database, pipeline: RunPipeline, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with fake_zabbix() as server:
        collect(pipeline, server)
        server.scenario.drift()
        server.scenario.set_media_parameter("40", "Token", "CANARY-zabbix-webhook-01")
        collect(pipeline, server)
    text = stored_text(database)
    assert "web-01.example.invalid" in text  # the states are in the text that was searched
    for secret in (*SECRETS, "CANARY-zabbix-webhook-01"):
        assert secret not in text, secret
        assert secret not in caplog.text, secret
