"""The TrueNAS collector through the whole run pipeline, against the fake API.

Two reads of the synthetic system (``tests/fixtures/truenas/system.json``) with the fake changed in
between, collected by the real client into a migrated database with the shipped rules:

* run state changing (pool usage and health, a scrub, service pids, task and job state, link state,
  password age) gives no change item at all;
* the configuration changes of the fixture give the change items and severities a person should
  see (the ``drift`` list of the fixture names them);
* a resource the credential may not read keeps its objects and is not reported as removed.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.truenas.client import TruenasClient
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_truenas import (
    CANARY_CREDENTIAL,
    ERROR_ACCESS_DENIED,
    FakeTruenas,
    apply_drift,
    apply_volatile,
    fake_truenas,
)
from .unifi_bands import SOURCE_ID, change_item_rows, coverage_rows, make_pipeline


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    store = Database(database_path(tmp_path))
    upgrade_to_head(store)
    with store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (1, 'nas-lab-01', 'truenas')"
        )
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def pipeline(database: Database) -> RunPipeline:
    return make_pipeline(database)


def collect(pipeline: RunPipeline, server: FakeTruenas) -> RunReport:
    client = TruenasClient(server.url, CANARY_CREDENTIAL, allow_plain_http=True)
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


def test_run_state_changes_produce_no_change_item(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_truenas() as server:
        first = collect(pipeline, server)
        apply_volatile(server.scenario.methods)
        second = collect(pipeline, server)
    assert (first.status, second.status) == ("ok", "ok")
    assert items(database) == []


def test_configuration_drift_gives_the_expected_changes_and_severities(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_truenas() as server:
        collect(pipeline, server)
        expected = apply_drift(server.scenario.methods)
        apply_volatile(server.scenario.methods)
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
        if expect["rule_id"] is not None:
            assert {item["rule_id"] for item in matches} == {expect["rule_id"]}
    resources = {item["resource"] for item in found}
    assert resources == {expect["resource"] for expect in expected}


def test_a_changed_cloud_secret_is_shown_as_a_fingerprint_only(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_truenas() as server:
        collect(pipeline, server)
        apply_drift(server.scenario.methods)
        collect(pipeline, server)
    secret = [item for item in items(database) if item["path"] == "provider.secret_access_key"]
    assert len(secret) == 1
    assert secret[0]["before"] is None and secret[0]["after"] is None
    assert secret[0]["after_fp"]
    assert "SYNTHETIC-secret" not in repr(items(database))


def test_a_forbidden_resource_keeps_its_objects(database: Database, pipeline: RunPipeline) -> None:
    with fake_truenas() as server:
        collect(pipeline, server)
        server.scenario.errors["user.query"] = ERROR_ACCESS_DENIED
        server.scenario.methods["user.query"] = []
        report = collect(pipeline, server)
    assert report.status == "partial"
    row = coverage_rows(database)["truenas-users"]
    assert (row.last_status, row.object_count) == ("403", 3)
    assert items(database) == []
