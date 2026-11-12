"""The Portainer client against a fake Portainer on localhost, and two runs through the pipeline.

The fake serves the shapes read from the Portainer source (docs/vendor-notes/portainer.md); it is
not a lab Portainer. The last group runs the whole pipeline on a migrated database: a first read,
then a read after :meth:`Scenario.drift`, gives the expected change items and severities, and no
secret the fake serves is ever stored in clear.
"""

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError, ResourceSpec
from driftsniff.collectors.portainer.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    PortainerClient,
)
from driftsniff.collectors.portainer.resources import RESOURCES
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_portainer import (
    ADMIN_TOKEN,
    AGENT_SECRET,
    DB_PASSWORD,
    EDGE_KEY,
    GIT_PASSWORD,
    REGISTRY_TOKEN,
    STANDARD_TOKEN,
    VERSION,
    FakePortainer,
    Scenario,
    fake_portainer,
)

ADMIN_ONLY = ("portainer-edge-groups", "portainer-team-memberships", "portainer-settings")
SECRETS = (ADMIN_TOKEN, AGENT_SECRET, DB_PASSWORD, EDGE_KEY, GIT_PASSWORD, REGISTRY_TOKEN)
SOURCE_ID = 1


@contextmanager
def connected(
    scenario: Scenario | None = None, token: str = ADMIN_TOKEN, **options: Any
) -> Iterator[tuple[FakePortainer, PortainerClient]]:
    with fake_portainer(scenario) as server:
        client = PortainerClient(server.url, token, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(
    scenario: Scenario | None = None, token: str = ADMIN_TOKEN
) -> Iterator[tuple[FakePortainer, PortainerClient]]:
    with connected(scenario, token) as (server, client):
        client.probe()
        yield server, client


def read_all(client: PortainerClient) -> dict[str, Any]:
    return {spec.name: client.fetch(spec) for spec in client.resources()}


# -- probe ------------------------------------------------------------------------------------


def test_a_probe_reads_the_version_with_the_token() -> None:
    with connected() as (server, client):
        assert client.probe() == VERSION
        assert [request.path for request in server.requests] == ["/api/system/version"]


@pytest.mark.parametrize("token", ["ptr_wrong", STANDARD_TOKEN + "x"])
def test_an_unknown_token_is_unauthorized_and_never_echoed(token: str) -> None:
    with connected(Scenario(echo_key=True), token) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
    assert token not in str(caught.value)


def test_a_forbidden_version_is_forbidden() -> None:
    with connected(Scenario(status={"version": 403})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_FORBIDDEN


@pytest.mark.parametrize(
    "scenario", [Scenario(status={"version": 404}), Scenario(raw={"version": b"<html>"})]
)
def test_a_server_that_is_not_portainer_is_no_api(scenario: Scenario) -> None:
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_an_unreadable_version_text_is_reported_as_none() -> None:
    with connected(Scenario(raw={"version": b'{"ServerVersion": "<b>"}'})) as (_, client):
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
            client.fetch(ResourceSpec("portainer-users"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize("key", ["", "with space", "café"])
def test_a_key_a_header_cannot_carry_is_refused(key: str) -> None:
    with pytest.raises(ValueError, match="access token"):
        PortainerClient("https://portainer.example.invalid", key)


# -- reading ----------------------------------------------------------------------------------


def test_every_resource_is_read_with_get_and_only_the_header_carries_the_token() -> None:
    with probed() as (server, client):
        results = read_all(client)
    assert all(result.ok for result in results.values()), results
    assert list(results) == [resource.name for resource in RESOURCES]
    for request in server.requests:
        assert request.method == "GET"
        assert request.api_key == ADMIN_TOKEN
        assert request.authorization is None and request.cookie is None
        assert ADMIN_TOKEN not in request.path + request.query
    stack_files = [r.path for r in server.requests if r.path.endswith("/file")]
    assert stack_files == ["/api/stacks/1/file", "/api/stacks/2/file", "/api/stacks/3/file"]
    endpoints = next(r for r in server.requests if r.path == "/api/endpoints")
    assert endpoints.query == "excludeSnapshots=true"


def test_objects_are_reshaped_and_sorted_whatever_order_portainer_sends() -> None:
    with probed() as (_, client):
        straight = read_all(client)
    with probed(Scenario(reverse=True)) as (_, client):
        reversed_ = read_all(client)
    assert {k: list(v.objects) for k, v in straight.items()} == {
        k: list(v.objects) for k, v in reversed_.items()
    }
    environments = list(straight["portainer-environments"].objects)
    assert [item["Id"] for item in environments] == [1, 2, 3]
    assert environments[0]["TeamAccessPolicies"] == [{"TeamId": 1, "RoleId": 0}]
    assert "Snapshots" not in environments[0]
    tags = list(straight["portainer-tags"].objects)
    assert tags[0]["Endpoints"] == [1, 2]
    registries = list(straight["portainer-registries"].objects)
    assert registries[1]["RegistryAccesses"] == [
        {
            "EnvironmentId": 2,
            "UserAccessPolicies": [{"UserId": 3, "RoleId": 0}],
            "TeamAccessPolicies": [],
            "Namespaces": [],
        }
    ]
    (settings,) = straight["portainer-settings"].objects
    assert settings["Id"] == "settings"
    stacks = list(straight["portainer-stacks"].objects)
    assert stacks[2]["StackFileContent"].startswith("services:")


def test_a_standard_token_gets_403_on_admin_only_resources_and_reads_the_rest() -> None:
    with probed(token=STANDARD_TOKEN) as (_, client):
        results = read_all(client)
    for name, result in results.items():
        if name in ADMIN_ONLY:
            assert (result.ok, result.status, result.error_class) == (False, "403", ERROR_FORBIDDEN)
        else:
            assert result.ok, name


def test_a_missing_resource_is_not_available() -> None:
    with probed(Scenario(status={"edge_groups": 404})) as (_, client):
        result = client.fetch(ResourceSpec("portainer-edge-groups"))
    assert (result.ok, result.status, result.error_class) == (False, "404", ERROR_NOT_AVAILABLE)


def test_a_stack_file_that_cannot_be_read_fails_the_stacks_resource() -> None:
    with probed(Scenario(status={"stack_file": 500})) as (_, client):
        result = client.fetch(ResourceSpec("portainer-stacks"))
    assert (result.ok, result.status) == (False, "500")
    assert result.retryable


@pytest.mark.parametrize(
    ("key", "body"),
    [
        ("endpoints", b"{}"),
        ("endpoints", b'[{"Name": "no id"}]'),
        ("tags", b'[{"ID": true}]'),
        ("settings", b"[]"),
        ("stack_file", b'{"StackFileContent": 7}'),
    ],
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(key: str, body: bytes) -> None:
    name = {
        "endpoints": "portainer-environments",
        "tags": "portainer-tags",
        "settings": "portainer-settings",
        "stack_file": "portainer-stacks",
    }[key]
    with probed(Scenario(raw={key: body})) as (_, client):
        result = client.fetch(ResourceSpec(name))
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
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-portainer', 'portainer')"
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


def collect(pipeline: RunPipeline, server: FakePortainer) -> RunReport:
    return pipeline.run(SOURCE_ID, PortainerClient(server.url, ADMIN_TOKEN, allow_plain_http=True))


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
    with fake_portainer() as server:
        first = collect(pipeline, server)
        server.scenario.tick()
        second = collect(pipeline, server)
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.event_id) == ("ok", None)
    assert items(database) == []


def test_a_drift_between_two_reads_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_portainer() as server:
        first = collect(pipeline, server)
        assert first.status == "ok"
        server.scenario.drift()
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    assert items(database) == [
        ("portainer-registries", "modified", "URL", "high", "portainer.registries.url"),
        (
            "portainer-settings",
            "modified",
            "AuthenticationMethod",
            "critical",
            "portainer.settings.authentication_method",
        ),
        ("portainer-stacks", "modified", "Env", "high", "portainer.stacks.env"),
        ("portainer-tags", "modified", "Name", "low", "portainer.tags.name"),
        ("portainer-users", "modified", "Role", "critical", "portainer.users.role_to_admin"),
    ]


def test_no_secret_the_fake_serves_is_stored_in_clear(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_portainer() as server:
        collect(pipeline, server)
        server.scenario.drift()
        collect(pipeline, server)
    text = stored_text(database)
    assert "lab-agent" in text  # the states are in the text that was searched
    for secret in (*SECRETS, "CANARY-db-password-0002"):
        assert secret not in text, secret
