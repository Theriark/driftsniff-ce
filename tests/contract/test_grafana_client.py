"""The Grafana client against a fake Grafana on localhost, and two runs through the pipeline.

The fake serves the shapes read from the Grafana HTTP API documentation
(docs/vendor-notes/grafana.md); it is not a lab Grafana. The last group runs the whole pipeline on
a migrated database: a first read, then a read after :meth:`Scenario.drift`, gives the expected
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
from driftsniff.collectors.grafana import client as grafana_client
from driftsniff.collectors.grafana.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    WARNING_TOO_MANY_DASHBOARDS,
    GrafanaClient,
)
from driftsniff.collectors.grafana.resources import RESOURCES
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_grafana import (
    ADMIN_TOKEN,
    DATASOURCE_PASSWORD,
    HOOK_PASSWORD,
    HOOK_URL,
    NEW_HOOK_URL,
    VERSION,
    VIEWER_TOKEN,
    FakeGrafana,
    Scenario,
    fake_grafana,
)

ADMIN_ONLY = (
    "grafana-datasources",
    "grafana-folder-permissions",
    "grafana-alert-rules",
    "grafana-contact-points",
    "grafana-notification-policies",
    "grafana-org-users",
    "grafana-teams",
    "grafana-service-accounts",
)
SECRETS = (ADMIN_TOKEN, DATASOURCE_PASSWORD, HOOK_PASSWORD, HOOK_URL, NEW_HOOK_URL)
SOURCE_ID = 1


@contextmanager
def connected(
    scenario: Scenario | None = None, token: str = ADMIN_TOKEN, **options: Any
) -> Iterator[tuple[FakeGrafana, GrafanaClient]]:
    with fake_grafana(scenario) as server:
        client = GrafanaClient(server.url, token, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(
    scenario: Scenario | None = None, token: str = ADMIN_TOKEN
) -> Iterator[tuple[FakeGrafana, GrafanaClient]]:
    with connected(scenario, token) as (server, client):
        client.probe()
        yield server, client


def read_all(client: GrafanaClient) -> dict[str, Any]:
    return {spec.name: client.fetch(spec) for spec in client.resources()}


# -- probe ------------------------------------------------------------------------------------


def test_a_probe_reads_the_version_then_proves_the_token() -> None:
    with connected() as (server, client):
        assert client.probe() == VERSION
        assert [(r.path, r.authorization) for r in server.requests] == [
            ("/api/health", None),
            ("/api/org", f"Bearer {ADMIN_TOKEN}"),
        ]


@pytest.mark.parametrize("token", ["wrong-token", VIEWER_TOKEN + "x"])
def test_an_unknown_token_is_unauthorized_and_never_echoed(token: str) -> None:
    with connected(Scenario(echo_key=True), token) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
    assert token not in str(caught.value)


def test_a_forbidden_org_is_forbidden() -> None:
    with connected(Scenario(status={"org": 403})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_FORBIDDEN


@pytest.mark.parametrize(
    "scenario",
    [
        Scenario(status={"health": 404}),
        Scenario(raw={"health": b"<html>"}),
        Scenario(raw={"org": b"[]"}),
    ],
)
def test_a_server_that_is_not_grafana_is_no_api(scenario: Scenario) -> None:
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_a_hidden_version_is_reported_as_none() -> None:
    with connected(Scenario(raw={"health": b'{"database": "ok"}'})) as (_, client):
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
            client.fetch(ResourceSpec("grafana-org-users"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize("token", ["", "with space", "café"])
def test_a_token_a_header_cannot_carry_is_refused(token: str) -> None:
    with pytest.raises(ValueError, match="service account token"):
        GrafanaClient("https://grafana.example.invalid", token)


# -- reading ----------------------------------------------------------------------------------


def test_every_resource_is_read_with_get_and_only_the_header_carries_the_token() -> None:
    with probed() as (server, client):
        results = read_all(client)
    assert all(result.ok for result in results.values()), results
    assert list(results) == [resource.name for resource in RESOURCES]
    for request in server.requests[1:]:
        assert request.method == "GET"
        assert request.authorization == f"Bearer {ADMIN_TOKEN}"
        assert request.cookie is None
        assert ADMIN_TOKEN not in request.path + request.query
    paths = [r.path for r in server.requests]
    assert [p for p in paths if p.startswith("/api/dashboards/")] == [
        "/api/dashboards/uid/dash-hosts",
        "/api/dashboards/uid/dash-links",
        "/api/dashboards/uid/dash-stock",
    ]
    assert [p for p in paths if p.endswith("/permissions")] == [
        "/api/folders/fold-biz/permissions",
        "/api/folders/fold-net/permissions",
        "/api/folders/fold-ops/permissions",
    ]


def test_objects_are_shaped_and_sorted_whatever_order_grafana_sends() -> None:
    with probed() as (_, client):
        straight = read_all(client)
    with probed(Scenario(reverse=True)) as (_, client):
        reversed_ = read_all(client)
    assert {k: list(v.objects) for k, v in straight.items()} == {
        k: list(v.objects) for k, v in reversed_.items()
    }
    (dashboard, *_) = straight["grafana-dashboards"].objects
    assert (dashboard["uid"], dashboard["title"], dashboard["folderUid"]) == (
        "dash-hosts",
        "Host overview",
        "fold-ops",
    )
    assert dashboard["dashboard"]["panels"][0]["title"] == "CPU"
    folders = {item["uid"]: item for item in straight["grafana-folders"].objects}
    assert folders["fold-net"]["folderUid"] == "fold-ops"
    permissions = {item["uid"]: item for item in straight["grafana-folder-permissions"].objects}
    assert permissions["fold-ops"]["permissions"] == [
        {"subject": "role:Editor", "permission": 2, "userLogin": "", "team": "", "role": "Editor"},
        {"subject": "role:Viewer", "permission": 1, "userLogin": "", "team": "", "role": "Viewer"},
        {"subject": "team:1", "permission": 4, "userLogin": "", "team": "sre", "role": ""},
    ]
    (policies,) = straight["grafana-notification-policies"].objects
    assert (policies["id"], policies["receiver"]) == ("policies", "ops mail")
    sources = {item["uid"]: item for item in straight["grafana-datasources"].objects}
    assert sources["pg-inventory"]["secureJsonFields"] == {"password": True}
    assert sources["pg-inventory"]["password"] == ""


def test_a_viewer_gets_403_on_admin_only_resources_and_reads_the_rest() -> None:
    with probed(token=VIEWER_TOKEN) as (_, client):
        results = read_all(client)
    for name, result in results.items():
        if name in ADMIN_ONLY:
            assert (result.ok, result.status, result.error_class) == (False, "403", ERROR_FORBIDDEN)
        else:
            assert result.ok, name


def test_paged_lists_are_read_to_the_end(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grafana_client, "SEARCH_PAGE_SIZE", 2)
    scenario = Scenario()
    scenario.add_team(3, "contractors")
    with probed(scenario) as (server, client):
        teams = client.fetch(ResourceSpec("grafana-teams"))
        folders = client.fetch(ResourceSpec("grafana-folders"))
    assert [item["id"] for item in teams.objects] == [1, 2, 3]
    assert len(folders.objects) == 3
    team_queries = [r.query for r in server.requests if r.path == "/api/teams/search"]
    assert team_queries == ["perpage=2&page=1", "perpage=2&page=2"]


def test_dashboards_past_the_bound_are_left_with_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grafana_client, "MAX_DASHBOARDS", 2)
    with probed() as (server, client):
        result = client.fetch(ResourceSpec("grafana-dashboards"))
    assert result.ok
    assert result.warning_class == WARNING_TOO_MANY_DASHBOARDS
    assert [item["uid"] for item in result.objects] == ["dash-hosts", "dash-links"]
    assert not any(r.path.endswith("/dash-stock") for r in server.requests)


def test_a_missing_resource_is_not_available() -> None:
    with probed(Scenario(status={"policies": 404})) as (_, client):
        result = client.fetch(ResourceSpec("grafana-notification-policies"))
    assert (result.ok, result.status, result.error_class) == (False, "404", ERROR_NOT_AVAILABLE)


def test_a_dashboard_that_cannot_be_read_fails_the_dashboards_resource() -> None:
    with probed(Scenario(status={"dashboard": 500})) as (_, client):
        result = client.fetch(ResourceSpec("grafana-dashboards"))
    assert (result.ok, result.status) == (False, "500")
    assert result.retryable


def test_folder_permissions_a_folder_admin_may_not_read_are_forbidden() -> None:
    with probed(Scenario(status={"folder_permissions": 403})) as (_, client):
        result = client.fetch(ResourceSpec("grafana-folder-permissions"))
    assert (result.ok, result.error_class) == (False, ERROR_FORBIDDEN)


@pytest.mark.parametrize(
    ("key", "body", "name"),
    [
        ("datasources", b"{}", "grafana-datasources"),
        ("datasources", b'[{"name": "no uid"}]', "grafana-datasources"),
        ("policies", b"[]", "grafana-notification-policies"),
        ("teams", b'{"teams": 3}', "grafana-teams"),
        ("dashboard", b'{"meta": {}}', "grafana-dashboards"),
        ("folder_permissions", b'[{"permission": 1}]', "grafana-folder-permissions"),
    ],
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(key: str, body: bytes, name: str) -> None:
    with probed(Scenario(raw={key: body})) as (_, client):
        result = client.fetch(ResourceSpec(name))
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


def test_an_unknown_resource_is_never_requested() -> None:
    with probed() as (server, client):
        result = client.fetch(ResourceSpec("vms"))
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
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-grafana', 'grafana')"
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


def collect(pipeline: RunPipeline, server: FakeGrafana) -> RunReport:
    return pipeline.run(SOURCE_ID, GrafanaClient(server.url, ADMIN_TOKEN, allow_plain_http=True))


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
    with fake_grafana() as server:
        first = collect(pipeline, server)
        server.scenario.tick()
        second = collect(pipeline, server)
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.event_id) == ("ok", None)
    assert items(database) == []


def test_a_drift_between_two_reads_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_grafana() as server:
        first = collect(pipeline, server)
        assert first.status == "ok"
        server.scenario.drift()
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    assert items(database) == [
        ("grafana-alert-rules", "modified", "isPaused", "high", "grafana.alert_rules.paused"),
        ("grafana-contact-points", "modified", "settings", "high", "builtin.floor.modified"),
        (
            "grafana-dashboards",
            "modified",
            "dashboard.panels.0.title",
            "low",
            "grafana.dashboards.any",
        ),
        ("grafana-datasources", "modified", "url", "high", "grafana.datasources.url"),
        ("grafana-org-users", "modified", "role", "critical", "grafana.org_users.role_to_admin"),
        ("grafana-teams", "added", "", "medium", "grafana.teams.any"),
    ]


def test_no_secret_the_fake_serves_is_stored_or_logged_in_clear(
    database: Database, pipeline: RunPipeline, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with fake_grafana() as server:
        collect(pipeline, server)
        server.scenario.drift()
        collect(pipeline, server)
    text = stored_text(database)
    assert "Host overview" in text  # the states are in the text that was searched
    logged = "\n".join(record.getMessage() for record in caplog.records)
    for secret in SECRETS:
        assert secret not in text, secret
        assert secret not in logged, secret
