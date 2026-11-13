"""The Checkmk client against a fake Checkmk site on localhost, and two runs through the pipeline.

The fake serves the shapes read from the Checkmk source (docs/vendor-notes/checkmk.md); it is not
a lab Checkmk. The last group runs the whole pipeline on a migrated database: a first read, then a
read after :meth:`Scenario.drift`, gives the expected change items and severities, and no secret
the fake serves or stores is ever stored in clear or logged.
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
from driftsniff.collectors.checkmk.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    CheckmkClient,
)
from driftsniff.collectors.checkmk.resources import RESOURCES
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.factory import build_collector
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_checkmk import (
    API,
    AUTOMATION_SECRET,
    AUTOMATION_USER,
    IPMI_PASSWORD,
    READER_DENIED,
    READER_SECRET,
    READER_USER,
    SNMP_AUTH_PASSWORD,
    SNMP_COMMUNITY,
    SNMP_PRIVACY_PASSWORD,
    STORED_PASSWORD,
    VERSION,
    WEBHOOK_URL,
    FakeCheckmk,
    Scenario,
    fake_checkmk,
)

SECRETS = (
    AUTOMATION_SECRET,
    IPMI_PASSWORD,
    SNMP_AUTH_PASSWORD,
    SNMP_COMMUNITY,
    SNMP_PRIVACY_PASSWORD,
    STORED_PASSWORD,
    WEBHOOK_URL,
    "CANARY-checkmk-06",
    "CANARY-checkmk-08",
    "CANARY-checkmk-09",
)
READER_DENIED_RESOURCES = {
    "users": "checkmk-users",
    "contact_groups": "checkmk-contact-groups",
    "passwords": "checkmk-passwords",
}
SOURCE_ID = 1


@contextmanager
def connected(
    scenario: Scenario | None = None,
    user: str = AUTOMATION_USER,
    secret: str = AUTOMATION_SECRET,
    **options: Any,
) -> Iterator[tuple[FakeCheckmk, CheckmkClient]]:
    with fake_checkmk(scenario) as server:
        client = CheckmkClient(server.url, user, secret, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(
    scenario: Scenario | None = None, user: str = AUTOMATION_USER, secret: str = AUTOMATION_SECRET
) -> Iterator[tuple[FakeCheckmk, CheckmkClient]]:
    with connected(scenario, user, secret) as (server, client):
        client.probe()
        yield server, client


def read_all(client: CheckmkClient) -> dict[str, Any]:
    return {spec.name: client.fetch(spec) for spec in client.resources()}


# -- probe ------------------------------------------------------------------------------------


def test_a_probe_reads_the_version_with_the_bearer_header() -> None:
    with connected() as (server, client):
        assert client.probe() == VERSION
        (request,) = server.requests
    assert request.path == f"{API}/version"
    assert request.authorization == f"Bearer {AUTOMATION_USER} {AUTOMATION_SECRET}"


@pytest.mark.parametrize(
    ("user", "secret"),
    [(AUTOMATION_USER, "CANARY-wrng-0"), ("nobody", AUTOMATION_SECRET)],
)
def test_a_refused_user_or_secret_is_unauthorized_and_never_echoed(user: str, secret: str) -> None:
    with connected(Scenario(echo_credentials=True), user, secret) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
    assert secret not in str(caught.value)


def test_a_forbidden_version_is_forbidden() -> None:
    with connected(Scenario(status={"version": 403})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_FORBIDDEN


@pytest.mark.parametrize(
    "scenario",
    [
        Scenario(status={"version": 404}),
        Scenario(raw={"version": b"<html>"}),
        Scenario(raw={"version": b'{"site": "mysite"}'}),
    ],
)
def test_a_server_that_is_not_checkmk_is_no_api(scenario: Scenario) -> None:
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_a_wrong_site_name_is_no_api() -> None:
    with fake_checkmk() as server:
        client = CheckmkClient(
            server.url.replace("/mysite", "/othersite"),
            AUTOMATION_USER,
            AUTOMATION_SECRET,
            allow_plain_http=True,
        )
        with pytest.raises(CollectorError) as caught:
            client.probe()
        client.close()
    assert caught.value.error_class == ERROR_NO_API


def test_a_2_5_community_version_is_read() -> None:
    # Checkmk 2.5.0p14 names its edition in full (lab site, 2026-11-13).
    body = b'{"versions": {"checkmk": "2.5.0p14.community"}, "edition": "community"}'
    with connected(Scenario(raw={"version": body})) as (_, client):
        assert client.probe() == "2.5.0p14.community"


def test_an_unreadable_version_text_is_reported_as_none() -> None:
    body = b'{"versions": {"checkmk": "<b>"}}'
    with connected(Scenario(raw={"version": body})) as (_, client):
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
            client.fetch(ResourceSpec("checkmk-users"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize(
    ("user", "secret"),
    [("", "x"), ("with space", "x"), ("automation", ""), ("automation", "two words"), ("é", "x")],
)
def test_a_user_or_secret_a_header_cannot_carry_is_refused(user: str, secret: str) -> None:
    with pytest.raises(ValueError, match="header"):
        CheckmkClient("https://checkmk.example.invalid/mysite", user, secret)


def test_the_factory_builds_the_client_from_the_user_name_option() -> None:
    with fake_checkmk() as server:
        collector = build_collector(
            "checkmk",
            server.url,
            AUTOMATION_SECRET.encode(),
            {"username": AUTOMATION_USER, "allow_plain_http": True},
        )
        try:
            assert collector.probe() == VERSION
        finally:
            collector.close()


# -- reading ----------------------------------------------------------------------------------


def test_every_resource_is_read_with_get_and_only_the_header_carries_the_secret() -> None:
    with probed() as (server, client):
        results = read_all(client)
    assert all(result.ok for result in results.values()), results
    assert list(results) == [resource.name for resource in RESOURCES]
    for request in server.requests:
        assert request.method == "GET"
        assert request.authorization == f"Bearer {AUTOMATION_USER} {AUTOMATION_SECRET}"
        assert request.cookie is None
        assert AUTOMATION_SECRET not in request.path + request.query
    queries = {r.path.removeprefix(API): r.query for r in server.requests}
    assert queries["/domain-types/host_config/collections/all"] == "effective_attributes=false"
    assert queries["/domain-types/folder_config/collections/all"] == "recursive=true"
    counts = {name: len(result.objects) for name, result in results.items()}
    assert counts == {
        "checkmk-hosts": 4,
        "checkmk-folders": 4,
        "checkmk-host-groups": 2,
        "checkmk-service-groups": 1,
        "checkmk-contact-groups": 3,
        "checkmk-users": 5,
        "checkmk-time-periods": 2,
        "checkmk-passwords": 1,
        "checkmk-notification-rules": 2,
    }


def test_objects_are_reshaped_and_sorted_whatever_order_checkmk_sends() -> None:
    with probed() as (_, client):
        straight = read_all(client)
    with probed(Scenario(reverse=True)) as (_, client):
        reversed_ = read_all(client)
    assert {k: list(v.objects) for k, v in straight.items()} == {
        k: list(v.objects) for k, v in reversed_.items()
    }
    hosts = {item["id"]: item for item in straight["checkmk-hosts"].objects}
    assert list(hosts) == ["db-01", "printer-01", "switch-core", "web-01"]
    web = hosts["web-01"]
    assert "links" not in web and "extensions" not in web and "domainType" not in web
    assert web["title"] == "Web server 1" and web["folder"] == "/servers/linux"
    assert web["attributes"]["labels"] == [
        {"key": "env", "value": "prod"},
        {"key": "os", "value": "linux"},
    ]
    assert web["attributes"]["tags"] == [
        {"group": "agent", "value": "cmk-agent"},
        {"group": "criticality", "value": "prod"},
    ]
    assert "tag_agent" not in web["attributes"]
    folders = [item["id"] for item in straight["checkmk-folders"].objects]
    assert folders == ["~", "~network", "~servers", "~servers~linux"]
    rules = list(straight["checkmk-notification-rules"].objects)
    plugin = rules[1]["rule_config"]["notification_method"]["notify_plugin"]
    assert plugin["plugin_name"] == "slack"
    passwords = list(straight["checkmk-passwords"].objects)
    assert STORED_PASSWORD not in repr(passwords)


def test_a_reader_without_permissions_gets_forbidden_coverage_and_reads_the_rest() -> None:
    with probed(user=READER_USER, secret=READER_SECRET) as (_, client):
        results = read_all(client)
    denied = {READER_DENIED_RESOURCES[name] for name in READER_DENIED}
    for name, result in results.items():
        if name in denied:
            assert (result.ok, result.status, result.error_class) == (False, "401", ERROR_FORBIDDEN)
            assert READER_SECRET not in (result.error_text or "")
        else:
            assert result.ok, name


@pytest.mark.parametrize("status", [403, 401])
def test_a_refused_resource_is_forbidden(status: int) -> None:
    with probed(Scenario(status={"passwords": status})) as (_, client):
        result = client.fetch(ResourceSpec("checkmk-passwords"))
    assert (result.ok, result.status, result.error_class) == (False, str(status), ERROR_FORBIDDEN)


def test_a_missing_resource_is_not_available() -> None:
    with probed(Scenario(status={"notification_rules": 404})) as (_, client):
        result = client.fetch(ResourceSpec("checkmk-notification-rules"))
    assert (result.ok, result.status, result.error_class) == (False, "404", ERROR_NOT_AVAILABLE)


def test_a_server_error_is_retryable() -> None:
    with probed(Scenario(status={"hosts": 502})) as (_, client):
        result = client.fetch(ResourceSpec("checkmk-hosts"))
    assert (result.ok, result.status) == (False, "502")
    assert result.retryable


@pytest.mark.parametrize(
    "body",
    [b"[]", b'{"value": {}}', b'{"value": [{"title": "no id"}]}', b'{"value": [{"id": 3}]}'],
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(body: bytes) -> None:
    with probed(Scenario(raw={"hosts": body})) as (_, client):
        result = client.fetch(ResourceSpec("checkmk-hosts"))
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


def test_an_unknown_resource_is_never_requested() -> None:
    with probed() as (server, client):
        result = client.fetch(ResourceSpec("checkmk-rules"))
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
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-checkmk', 'checkmk')"
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


def collect(pipeline: RunPipeline, server: FakeCheckmk) -> RunReport:
    client = CheckmkClient(server.url, AUTOMATION_USER, AUTOMATION_SECRET, allow_plain_http=True)
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
    with fake_checkmk() as server:
        first = collect(pipeline, server)
        server.scenario.tick()
        second = collect(pipeline, server)
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.event_id) == ("ok", None)
    assert items(database) == []


def test_a_drift_between_two_reads_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_checkmk() as server:
        first = collect(pipeline, server)
        assert first.status == "ok"
        server.scenario.drift()
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    assert items(database) == [
        ("checkmk-contact-groups", "modified", "title", "medium", "checkmk.contact_groups.any"),
        ("checkmk-folders", "modified", "attributes.tags", "medium", "checkmk.folders.attributes"),
        ("checkmk-hosts", "modified", "attributes.labels", "low", "checkmk.hosts.labels"),
        ("checkmk-hosts", "removed", "", "high", "checkmk.hosts.any"),
        ("checkmk-users", "added", "roles", "critical", "checkmk.users.roles_admin"),
        ("checkmk-users", "modified", "disable_login", "high", "checkmk.users.login_enabled"),
    ]


def test_a_changed_snmp_community_is_high_and_shown_as_a_fingerprint(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_checkmk() as server:
        collect(pipeline, server)
        server.scenario.set_snmp_community("switch-core", "CANARY-checkmk-10")
        collect(pipeline, server)
    with database.read() as connection:
        (row,) = connection.execute(sa.select(tables.change_items))
    assert (row.path, row.severity, row.field_class) == (
        "attributes.snmp_community",
        "high",
        "secret",
    )
    assert row.before_value is None and row.after_value is None
    assert row.before_fp and row.after_fp and row.before_fp != row.after_fp


def test_no_secret_is_stored_in_clear_or_logged(
    database: Database, pipeline: RunPipeline, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with fake_checkmk() as server:
        collect(pipeline, server)
        server.scenario.drift()
        server.scenario.set_snmp_community("switch-core", "CANARY-checkmk-10")
        collect(pipeline, server)
    text = stored_text(database)
    assert "web-01" in text  # the states are in the text that was searched
    for secret in (*SECRETS, "CANARY-checkmk-10"):
        assert secret not in text, secret
        assert secret not in caplog.text, secret
