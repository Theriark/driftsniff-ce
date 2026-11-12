"""The UniFi Protect client against a fake Protect on localhost, and two runs through the pipeline.

The fake serves the shapes of Ubiquiti's OpenAPI document (docs/vendor-notes/unifi_protect.md); it
is not a lab console. The last group runs the whole pipeline on a migrated database: a first read,
then a read after :meth:`Scenario.drift`, gives the expected change items and severities, and the
API key is never stored or logged.
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
from driftsniff.collectors.unifi.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
)
from driftsniff.collectors.unifi_protect.client import ProtectClient
from driftsniff.collectors.unifi_protect.resources import RESOURCES
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_unifi_protect import API_KEY, BASE, VERSION, FakeProtect, Scenario, fake_protect

SOURCE_ID = 1
NAMES = {
    "nvrs": "protect-nvr",
    "cameras": "protect-cameras",
    "viewers": "protect-viewers",
    "liveviews": "protect-liveviews",
    "chimes": "protect-chimes",
    "lights": "protect-lights",
    "sensors": "protect-sensors",
}


@contextmanager
def connected(
    scenario: Scenario | None = None, key: str = API_KEY, **options: Any
) -> Iterator[tuple[FakeProtect, ProtectClient]]:
    with fake_protect(scenario) as server:
        client = ProtectClient(server.url, key, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(scenario: Scenario | None = None) -> Iterator[tuple[FakeProtect, ProtectClient]]:
    with connected(scenario) as (server, client):
        client.probe()
        yield server, client


def read_all(client: ProtectClient) -> dict[str, Any]:
    return {spec.name: client.fetch(spec) for spec in client.resources()}


# -- probe ------------------------------------------------------------------------------------


def test_a_probe_reads_the_version_with_the_key() -> None:
    with connected() as (server, client):
        assert client.probe() == VERSION
        assert [request.path for request in server.requests] == [f"{BASE}/meta/info"]


@pytest.mark.parametrize("key", ["CANARY-unifi_protect-01", API_KEY + "x"])
def test_an_unknown_key_is_unauthorized_and_never_echoed(key: str) -> None:
    with connected(Scenario(echo_key=True), key) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
    assert key not in str(caught.value)


def test_a_forbidden_info_call_is_forbidden() -> None:
    with connected(Scenario(status={"info": 403})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
    assert caught.value.error_class == ERROR_FORBIDDEN


@pytest.mark.parametrize(
    "scenario",
    [
        Scenario(status={"info": 404}),
        Scenario(raw={"info": b"<html>"}),
        Scenario(raw={"info": b'{"version": "7.2.105"}'}),
    ],
)
def test_a_console_without_protect_is_no_api(scenario: Scenario) -> None:
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_an_unreadable_version_text_is_reported_as_none() -> None:
    with connected(Scenario(raw={"info": b'{"applicationVersion": "<b>"}'})) as (_, client):
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
            client.fetch(ResourceSpec("protect-cameras"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize("key", ["", "with space", "café"])
def test_a_key_a_header_cannot_carry_is_refused(key: str) -> None:
    with pytest.raises(ValueError, match="API key"):
        ProtectClient("https://protect.example.invalid", key)


# -- reading ----------------------------------------------------------------------------------


def test_every_resource_is_read_with_get_and_only_the_header_carries_the_key() -> None:
    with probed() as (server, client):
        results = read_all(client)
    assert all(result.ok for result in results.values()), results
    assert list(results) == [resource.name for resource in RESOURCES]
    assert [request.path for request in server.requests] == [
        f"{BASE}/meta/info",
        *(f"{BASE}{resource.path}" for resource in RESOURCES),
    ]
    for request in server.requests:
        assert request.method == "GET"
        assert request.api_key == API_KEY
        assert request.authorization is None and request.cookie is None
        assert request.query == ""


def test_objects_are_sorted_whatever_order_protect_sends() -> None:
    with probed() as (_, client):
        straight = read_all(client)
    with probed(Scenario(reverse=True)) as (_, client):
        reversed_ = read_all(client)
    assert {k: list(v.objects) for k, v in straight.items()} == {
        k: list(v.objects) for k, v in reversed_.items()
    }
    cameras = list(straight["protect-cameras"].objects)
    assert [item["id"] for item in cameras] == ["camera-0001", "camera-0002", "camera-0003"]
    (nvr,) = straight["protect-nvr"].objects
    assert nvr["id"] == "nvr-0001"
    assert len(straight["protect-sensors"].objects) == 2


@pytest.mark.parametrize(
    ("route", "status", "error_class"),
    [
        ("sensors", 404, ERROR_NOT_AVAILABLE),
        ("lights", 403, ERROR_FORBIDDEN),
    ],
)
def test_a_missing_or_forbidden_resource_keeps_its_status(
    route: str, status: int, error_class: str
) -> None:
    with probed(Scenario(status={route: status})) as (_, client):
        result = client.fetch(ResourceSpec(NAMES[route]))
    assert (result.ok, result.status, result.error_class) == (False, str(status), error_class)


def test_a_server_error_is_retryable() -> None:
    with probed(Scenario(status={"cameras": 502})) as (_, client):
        result = client.fetch(ResourceSpec("protect-cameras"))
    assert (result.ok, result.status) == (False, "502")
    assert result.retryable


@pytest.mark.parametrize(
    ("route", "body"),
    [
        ("cameras", b"{}"),
        ("cameras", b'[{"name": "no id"}]'),
        ("chimes", b'[{"id": 7}]'),
        ("viewers", b'[{"id": ""}]'),
        ("nvrs", b"[1]"),
        ("lights", b"[[]]"),
    ],
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(route: str, body: bytes) -> None:
    with probed(Scenario(raw={route: body})) as (_, client):
        result = client.fetch(ResourceSpec(NAMES[route]))
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


def test_an_unknown_resource_is_never_requested() -> None:
    with probed() as (server, client):
        result = client.fetch(ResourceSpec("unifi-networks"))
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
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-protect', 'unifi_protect')"
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


def collect(pipeline: RunPipeline, server: FakeProtect) -> RunReport:
    return pipeline.run(SOURCE_ID, ProtectClient(server.url, API_KEY, allow_plain_http=True))


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
    with fake_protect() as server:
        first = collect(pipeline, server)
        server.scenario.tick()
        second = collect(pipeline, server)
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.event_id) == ("ok", None)
    assert items(database) == []


def test_a_drift_between_two_reads_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_protect() as server:
        first = collect(pipeline, server)
        assert first.status == "ok"
        server.scenario.drift()
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    assert items(database) == [
        ("protect-cameras", "modified", "isMicEnabled", "medium", "protect.cameras.microphone_on"),
        ("protect-cameras", "modified", "name", "low", "protect.cameras.name"),
        (
            "protect-cameras",
            "removed",
            "",
            "high",
            "builtin.floor.removed",
        ),
        (
            "protect-cameras",
            "removed",
            "smartDetectSettings.objectTypes",
            "high",
            "protect.cameras.smart_detect_object_removed",
        ),
        (
            "protect-sensors",
            "modified",
            "alarmSettings.isEnabled",
            "critical",
            "protect.sensors.alarm_off",
        ),
    ]


def test_the_key_is_never_stored_or_logged(
    database: Database, pipeline: RunPipeline, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with fake_protect(Scenario(echo_key=True)) as server:
        collect(pipeline, server)
        server.scenario.drift()
        server.scenario.status["sensors"] = 500
        collect(pipeline, server)
    text = stored_text(database)
    assert "Front porch" in text  # the states are in the text that was searched
    assert API_KEY not in text
    assert API_KEY not in caplog.text
