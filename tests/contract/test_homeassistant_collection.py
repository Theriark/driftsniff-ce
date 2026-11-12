"""The Home Assistant collector through the whole run pipeline, against the fake API.

Two reads of the synthetic system (``tests/fixtures/homeassistant/system.json``) with the fake
changed in between, collected by the real client into a migrated database with the shipped rules:

* state changing (sensor readings, last triggered, a running script, integration state, the
  version and loaded components) gives no change item at all;
* the configuration changes of the fixture give the change items and severities a person should
  see (the ``drift`` list of the fixture names them);
* the inline credential of an automation and the home location never reach the database in clear;
* a resource the token may not read keeps its objects and is not reported as removed.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.homeassistant.client import HomeAssistantClient
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_homeassistant import (
    CANARY_TOKEN,
    FakeHomeAssistant,
    apply_drift,
    apply_volatile,
    error,
    fake_homeassistant,
)
from .unifi_bands import SOURCE_ID, change_item_rows, coverage_rows, make_pipeline


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    store = Database(database_path(tmp_path))
    upgrade_to_head(store)
    with store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (1, 'home-lab-01', 'homeassistant')"
        )
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def pipeline(database: Database) -> RunPipeline:
    return make_pipeline(database)


def collect(pipeline: RunPipeline, server: FakeHomeAssistant) -> RunReport:
    client = HomeAssistantClient(server.url, CANARY_TOKEN, allow_plain_http=True)
    return pipeline.run(SOURCE_ID, client)


def items(database: Database) -> list[dict[str, Any]]:
    return [
        {
            "resource": row.resource,
            "path": row.path,
            "severity": row.severity,
            "rule_id": row.rule_id,
            "before": row.before_value,
            "after": row.after_value,
            "after_fp": row.after_fp,
        }
        for row in change_item_rows(database)
    ]


def database_text(database: Database) -> str:
    """Every value of every table, as one text."""
    with database.read() as connection:
        names = [
            row[0]
            for row in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        ]
        rows = [
            repr(tuple(row))
            for name in names
            for row in connection.exec_driver_sql(f'SELECT * FROM "{name}"')  # noqa: S608
        ]
    return "\n".join(rows)


def test_state_changes_produce_no_change_item(database: Database, pipeline: RunPipeline) -> None:
    with fake_homeassistant() as server:
        first = collect(pipeline, server)
        apply_volatile(server.scenario.commands)
        second = collect(pipeline, server)
    assert (first.status, second.status) == ("ok", "ok")
    assert items(database) == []


def test_configuration_drift_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_homeassistant() as server:
        collect(pipeline, server)
        expected = apply_drift(server.scenario.commands)
        apply_volatile(server.scenario.commands)
        report = collect(pipeline, server)
    assert report.status == "ok"
    found = items(database)
    for expect in expected:
        matches = [
            item
            for item in found
            if item["resource"] == expect["resource"] and item["path"] == expect["path"]
        ]
        assert matches, expect
        assert {item["severity"] for item in matches} == {expect["severity"]}, (expect, matches)
        assert {item["rule_id"] for item in matches} == {expect["rule_id"]}
    assert {(item["resource"], item["path"]) for item in found} == {
        (expect["resource"], expect["path"]) for expect in expected
    }
    assert {item["severity"] for item in found} == {"low", "medium", "high", "critical"}


def test_secrets_are_never_stored_in_clear(database: Database, pipeline: RunPipeline) -> None:
    with fake_homeassistant() as server:
        collect(pipeline, server)
        apply_drift(server.scenario.commands)
        collect(pipeline, server)
    actions = [item for item in items(database) if item["path"] == "config.actions"]
    assert len(actions) == 1
    assert actions[0]["before"] is None and actions[0]["after"] is None and actions[0]["after_fp"]
    text = database_text(database)
    assert "CANARY-homeassistant" not in text
    assert "38.7" not in text and "-9.1" not in text


def test_a_forbidden_resource_keeps_its_objects(database: Database, pipeline: RunPipeline) -> None:
    with fake_homeassistant() as server:
        collect(pipeline, server)
        server.scenario.errors["config/auth/list"] = error("unauthorized", "Unauthorized")
        report = collect(pipeline, server)
    assert report.status == "partial"
    row = coverage_rows(database)["homeassistant-users"]
    assert (row.last_status, row.object_count) == ("403", 3)
    assert items(database) == []
