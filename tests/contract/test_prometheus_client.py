"""The Prometheus client against a fake Prometheus on localhost, and two runs through the pipeline.

The fake serves the shapes of the Prometheus documentation (docs/vendor-notes/prometheus.md); it is
not a lab Prometheus. The last group runs the whole pipeline on a migrated database: a first read,
then a read after :meth:`Scenario.drift`, gives the expected change items and severities, and no
secret the fake serves is ever stored in clear.
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
from driftsniff.collectors.prometheus.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    PrometheusClient,
)
from driftsniff.collectors.prometheus.resources import RESOURCES
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_prometheus import (
    AZURE_SECRET,
    TENANT_HEADER,
    TOKEN,
    URL_PASSWORD,
    VERSION,
    FakePrometheus,
    Scenario,
    fake_prometheus,
)

SECRETS = (TOKEN, TENANT_HEADER, URL_PASSWORD, AZURE_SECRET)
SOURCE_ID = 1


@contextmanager
def connected(
    scenario: Scenario | None = None, token: str = TOKEN, **options: Any
) -> Iterator[tuple[FakePrometheus, PrometheusClient]]:
    with fake_prometheus(scenario) as server:
        client = PrometheusClient(server.url, token, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(scenario: Scenario | None = None) -> Iterator[tuple[FakePrometheus, PrometheusClient]]:
    with connected(scenario) as (server, client):
        client.probe()
        yield server, client


def read_all(client: PrometheusClient) -> dict[str, Any]:
    return {spec.name: client.fetch(spec) for spec in client.resources()}


# -- probe ------------------------------------------------------------------------------------


def test_a_probe_reads_the_build_info_with_the_bearer_token() -> None:
    with connected() as (server, client):
        assert client.probe() == VERSION
        (request,) = server.requests
    assert request.path == "/api/v1/status/buildinfo"
    assert request.authorization == f"Bearer {TOKEN}"


def test_a_wrong_token_is_unauthorized_and_never_echoed() -> None:
    with connected(token="CANARY-wrng-0") as (_, client):  # noqa: S106 - a test canary
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
    assert "CANARY-wrng-0" not in str(caught.value)


def test_a_server_without_auth_ignores_the_token() -> None:
    unused = "CANARY-unused-00"  # noqa: S105 - a test canary
    with connected(Scenario(require_token=False), unused) as (_, client):
        assert client.probe() == VERSION
        assert all(result.ok for result in read_all(client).values())


def test_a_forbidden_build_info_is_forbidden() -> None:
    with connected(Scenario(status={"buildinfo": 403})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_FORBIDDEN


@pytest.mark.parametrize(
    "scenario",
    [
        Scenario(status={"buildinfo": 404}),
        Scenario(raw={"buildinfo": b"<html>"}),
        Scenario(raw={"buildinfo": b'{"version": "3.5.0"}'}),
    ],
)
def test_a_server_that_is_not_prometheus_is_no_api(scenario: Scenario) -> None:
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_an_unreadable_version_is_reported_as_none() -> None:
    body = b'{"status": "success", "data": {"version": "<b>"}}'
    with connected(Scenario(raw={"buildinfo": body})) as (_, client):
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
            client.fetch(ResourceSpec("prometheus-flags"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize("token", ["", "with space", "café"])
def test_a_token_a_header_cannot_carry_is_refused(token: str) -> None:
    with pytest.raises(ValueError, match="bearer token"):
        PrometheusClient("https://prometheus.example.invalid", token)


# -- reading ----------------------------------------------------------------------------------


def test_every_resource_is_read_from_three_gets_and_only_the_header_carries_the_token() -> None:
    with probed() as (server, client):
        results = read_all(client)
    assert all(result.ok for result in results.values()), results
    assert list(results) == [resource.name for resource in RESOURCES]
    assert [(r.method, r.path, r.query) for r in server.requests] == [
        ("GET", "/api/v1/status/buildinfo", ""),
        ("GET", "/api/v1/status/config", ""),
        ("GET", "/api/v1/status/flags", ""),
        ("GET", "/api/v1/rules", "exclude_alerts=true"),
    ]
    for request in server.requests:
        assert request.authorization == f"Bearer {TOKEN}" and request.cookie is None
        assert TOKEN not in request.path + request.query
    assert results["prometheus-global"].bytes_fetched > 0
    assert results["prometheus-scrape-jobs"].bytes_fetched == 0  # the same answer, kept


def test_the_configuration_becomes_keyed_objects() -> None:
    with probed() as (_, client):
        results = read_all(client)
    (settings,) = results["prometheus-global"].objects
    assert settings["id"] == "global"
    assert settings["global"]["external_labels"] == [
        {"name": "env", "value": "lab"},
        {"name": "site", "value": "lab-01"},
    ]
    assert settings["rule_files"] == ["/etc/prometheus/rules/*.yml"]
    jobs = list(results["prometheus-scrape-jobs"].objects)
    assert [job["id"] for job in jobs] == ["blackbox", "node", "prometheus"]
    assert jobs[0]["params"] == [{"name": "module", "value": ["http_2xx"]}]
    assert jobs[0]["basic_auth"] == {"username": "probe", "password": "<secret>"}
    assert jobs[1]["static_configs"][0]["labels"] == [{"name": "rack", "value": "a1"}]
    (alerting,) = results["prometheus-alerting"].objects
    assert alerting["alertmanagers"][0]["static_configs"] == [{"targets": ["192.0.2.20:9093"]}]
    targets = list(results["prometheus-remote-write"].objects)
    assert [target["id"] for target in targets] == [
        "https://metrics-user:<secret>@mimir.example.invalid/api/v1/push",
        "longterm",
    ]
    (flags,) = results["prometheus-flags"].objects
    assert (flags["id"], flags["web_enable_admin_api"]) == ("flags", "false")


def test_the_rules_become_groups_alerting_rules_and_recording_rules() -> None:
    with probed() as (_, client):
        results = read_all(client)
    (group,) = results["prometheus-rule-groups"].objects
    assert group["id"] == "/etc/prometheus/rules/node.yml / node"
    assert "rules" not in group
    alerts = list(results["prometheus-alerting-rules"].objects)
    assert [rule["name"] for rule in alerts] == ["DiskAlmostFull", "NodeDown"]
    assert alerts[1]["labels"] == [{"name": "severity", "value": "critical"}]
    assert alerts[1]["group"] == "node" and "alerts" not in alerts[1]
    (recording,) = results["prometheus-recording-rules"].objects
    assert recording["id"].endswith(" / instance:node_cpu:rate5m")


def test_a_missing_answer_is_not_available_for_its_resources_only() -> None:
    with probed(Scenario(status={"rules": 404})) as (_, client):
        results = read_all(client)
    for name, result in results.items():
        if name.endswith(("-rule-groups", "-alerting-rules", "-recording-rules")):
            assert (result.status, result.error_class) == ("404", ERROR_NOT_AVAILABLE), name
        else:
            assert result.ok, name


def test_a_server_error_is_retryable() -> None:
    with probed(Scenario(status={"config": 503})) as (_, client):
        result = client.fetch(ResourceSpec("prometheus-scrape-jobs"))
    assert (result.ok, result.status, result.retryable) == (False, "503", True)


@pytest.mark.parametrize(
    ("route", "body", "name"),
    [
        ("config", b'{"status": "success", "data": {}}', "prometheus-global"),
        ("config", b'{"status": "success", "data": {"yaml": "a: [b"}}', "prometheus-global"),
        ("config", b'{"status": "success", "data": {"yaml": "- 1"}}', "prometheus-global"),
        (
            "config",
            b'{"status": "success", "data": {"yaml": "scrape_configs: [{scheme: http}]"}}',
            "prometheus-scrape-jobs",
        ),
        (
            "config",
            b'{"status": "success", "data": {"yaml": '
            b'"scrape_configs: [{job_name: a}, {job_name: a}]"}}',
            "prometheus-scrape-jobs",
        ),
        ("flags", b'{"status": "error", "data": {}}', "prometheus-flags"),
        ("flags", b'{"status": "success", "data": []}', "prometheus-flags"),
        (
            "rules",
            b'{"status": "success", "data": {"groups": [{"name": "x"}]}}',
            "prometheus-rule-groups",
        ),
    ],
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(route: str, body: bytes, name: str) -> None:
    with probed(Scenario(raw={route: body})) as (_, client):
        result = client.fetch(ResourceSpec(name))
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


def test_an_alias_bomb_is_refused_without_expanding() -> None:
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    lines += [f"a{n}: &a{n} [*a{n - 1}, *a{n - 1}, *a{n - 1}, *a{n - 1}]" for n in range(1, 20)]
    text = "\\n".join(lines)
    body = ('{"status": "success", "data": {"yaml": "' + text + '"}}').encode()
    with probed(Scenario(raw={"config": body})) as (_, client):
        result = client.fetch(ResourceSpec("prometheus-global"))
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
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-prometheus', 'prometheus')"
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


def collect(pipeline: RunPipeline, server: FakePrometheus) -> RunReport:
    return pipeline.run(SOURCE_ID, PrometheusClient(server.url, TOKEN, allow_plain_http=True))


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
    with fake_prometheus() as server:
        first = collect(pipeline, server)
        server.scenario.tick()
        second = collect(pipeline, server)
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.event_id) == ("ok", None)
    assert items(database) == []


def test_a_drift_between_two_reads_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_prometheus() as server:
        first = collect(pipeline, server)
        assert first.status == "ok"
        server.scenario.drift()
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    assert items(database) == [
        (
            "prometheus-alerting-rules",
            "modified",
            "query",
            "medium",
            "prometheus.alerting_rules.query",
        ),
        (
            "prometheus-flags",
            "modified",
            "web_enable_admin_api",
            "critical",
            "prometheus.flags.admin_api",
        ),
        (
            "prometheus-scrape-jobs",
            "modified",
            "scrape_interval",
            "low",
            "prometheus.scrape_jobs.scrape_interval",
        ),
        ("prometheus-scrape-jobs", "removed", "", "high", "builtin.floor.removed"),
    ]


def test_other_mutations_give_their_severities(database: Database, pipeline: RunPipeline) -> None:
    with fake_prometheus() as server:
        collect(pipeline, server)
        server.scenario.set_retention("30d")
        server.scenario.delete_alert_rule("NodeDown")
        server.scenario.set_remote_write_url(0, "https://other.example.invalid/api/v1/push")
        collect(pipeline, server)
    found = {(row[0], row[1], row[2], row[3]) for row in items(database)}
    assert found == {
        ("prometheus-flags", "modified", "storage_tsdb_retention_time", "medium"),
        ("prometheus-alerting-rules", "removed", "", "high"),
        ("prometheus-remote-write", "removed", "", "high"),
        ("prometheus-remote-write", "added", "", "high"),
    }


def test_no_secret_the_fake_serves_is_stored_or_logged_in_clear(
    database: Database, pipeline: RunPipeline, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with fake_prometheus() as server:
        collect(pipeline, server)
        server.scenario.drift()
        server.scenario.set_remote_write_url(0, "https://other.example.invalid/api/v1/push")
        collect(pipeline, server)
    text = stored_text(database)
    assert "lab-01" in text  # the states are in the text that was searched
    for secret in SECRETS:
        assert secret not in text, secret
        assert secret not in caplog.text, secret
