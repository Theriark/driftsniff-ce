"""Tests for the Development-only synthetic changes (docs/dev-fixture.md).

The tests run the real run pipeline with the shipped rules on a migrated database; no network is
involved.
"""

import logging
import re
from pathlib import Path

import pytest
import sqlalchemy as sa
import uvicorn

from driftsniff import devfixture
from driftsniff.cli import main
from driftsniff.config import Settings
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.devfixture import (
    FIXTURE_SOURCE_NAME,
    PUSH_FIELDS,
    STEPS,
    seed_fixture_at_startup,
)
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.service import SourceService

DEV_URL = "https://ce-dev-driftsniff.theriark.dev"
MASTER = MasterKey(bytes(range(32)))
SEVERITIES = {"low", "medium", "high", "critical"}


def settings_for(url: str, label: str = "") -> Settings:
    env = {"DRIFTSNIFF_BASE_URL": url}
    if label:
        env["DRIFTSNIFF_ENVIRONMENT_LABEL"] = label
    return Settings.from_env(env)


def count(database: Database, table: sa.Table) -> int:
    with database.read() as connection:
        return int(connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one())


def fixture_source_id(database: Database) -> int:
    with database.read() as connection:
        query = sa.select(tables.sources.c.id).where(tables.sources.c.name == FIXTURE_SOURCE_NAME)
        return int(connection.execute(query).scalar_one())


def test_a_development_start_makes_labelled_changes_of_every_severity(store: Database) -> None:
    report = seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    assert report is not None
    assert (report.created, report.removed) == (True, False)
    assert report.pushed == len(STEPS) == 4
    assert report.events == 3  # the first document is the baseline
    source_id = fixture_source_id(store)
    with store.read() as connection:
        source = connection.execute(
            sa.select(tables.sources).where(tables.sources.c.id == source_id)
        ).one()
        events = (
            connection.execute(
                sa.select(tables.change_events.c.max_severity).where(
                    tables.change_events.c.source_id == source_id
                )
            )
            .scalars()
            .all()
        )
        items = connection.execute(
            sa.select(tables.change_items.c.resource, tables.change_items.c.severity)
            .join(tables.change_events)
            .where(tables.change_events.c.source_id == source_id)
        ).all()
    assert source.type == "push"
    assert source.push_token_hash is None  # no sender key: nothing can push, no credential made
    assert source.options["push_fields"] == PUSH_FIELDS
    assert {"critical", "medium"} <= set(events)
    assert {item.severity for item in items} == SEVERITIES
    assert len({item.resource for item in items}) >= 5


def test_the_existing_source_of_the_site_is_left_alone(store: Database) -> None:
    seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    with store.read() as connection:
        other = connection.execute(sa.select(tables.sources).where(tables.sources.c.id == 1)).one()
        other_runs = connection.execute(
            sa.select(sa.func.count()).select_from(tables.runs).where(tables.runs.c.source_id == 1)
        ).scalar_one()
    assert other.name == "lab-controller"
    assert other_runs == 0
    assert fixture_source_id(store) != 1


def test_a_second_start_changes_nothing(store: Database, caplog: pytest.LogCaptureFixture) -> None:
    seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    before = [
        count(store, table)
        for table in (tables.sources, tables.runs, tables.snapshots, tables.change_events)
    ]
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    report = seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    assert report is not None
    assert (report.created, report.removed, report.pushed, report.events) == (False, False, 0, 0)
    after = [
        count(store, table)
        for table in (tables.sources, tables.runs, tables.snapshots, tables.change_events)
    ]
    assert after == before
    assert "already present" in caplog.text


def test_a_start_after_an_interrupted_run_only_runs_the_missing_steps(
    store: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = SourceService(store, CredentialCipher.from_master(MASTER))
    real = devfixture.STEPS
    monkeypatch.setattr(devfixture, "STEPS", real[:2])
    first = seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    assert first is not None
    assert (first.pushed, first.events) == (2, 1)
    monkeypatch.setattr(devfixture, "STEPS", real)
    second = seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    assert second is not None
    assert (second.created, second.pushed, second.events) == (False, 2, 2)
    assert [view.name for view in service.list_sources()].count(FIXTURE_SOURCE_NAME) == 1
    assert count(store, tables.change_events) == 3


def test_deleting_the_source_removes_it_and_a_later_start_does_not_make_it_again(
    store: Database, caplog: pytest.LogCaptureFixture
) -> None:
    seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    service = SourceService(store, CredentialCipher.from_master(MASTER))
    service.delete(fixture_source_id(store), actor="admin")
    assert count(store, tables.change_events) == 0
    caplog.set_level(logging.DEBUG)
    report = seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    assert report is not None
    assert (report.removed, report.pushed) == (True, 0)
    assert FIXTURE_SOURCE_NAME not in [view.name for view in service.list_sources()]
    assert "removed earlier" in caplog.text


@pytest.mark.parametrize(
    "url",
    [
        "https://ce-stg-driftsniff.theriark.dev",
        "https://ee-dev-driftsniff.theriark.dev",
        "https://driftsniff.theriark.dev",
        "https://ce-dev-driftsniff.example.com",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
)
def test_it_never_seeds_a_stage_production_or_local_address(
    url: str, store: Database, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    assert seed_fixture_at_startup(settings_for(url), store, MASTER) is None
    assert count(store, tables.sources) == 1
    assert count(store, tables.runs) == 0
    assert "fixture" not in caplog.text


def test_it_never_seeds_another_environment_badge(store: Database) -> None:
    assert seed_fixture_at_startup(settings_for(DEV_URL, label="Stage"), store, MASTER) is None
    assert count(store, tables.sources) == 1


def test_it_survives_a_database_failure(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    database = Database(database_path(tmp_path))  # not migrated: there are no tables
    try:
        assert seed_fixture_at_startup(settings_for(DEV_URL), database, MASTER) is None
    finally:
        database.close()
    assert "not seeded" in caplog.text


def test_it_sends_no_notification_and_stores_no_secret(
    store: Database, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    seed_fixture_at_startup(settings_for(DEV_URL), store, MASTER)
    assert count(store, tables.notification_deliveries) == 0
    with store.read() as connection:
        stored = "\n".join(
            str(row)
            for table in (tables.change_items, tables.runs, tables.audit_events)
            for row in connection.execute(sa.select(table))
        )
    assert "CANARY" not in stored
    assert "CANARY" not in caplog.text


def test_every_value_of_the_fixture_is_synthetic() -> None:
    text = repr(devfixture._documents())
    ids = re.findall(r"'id': '([^']+)'", text)
    assert ids
    assert all(value.startswith("fx-") for value in ids)
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)  # no address at all
    for domain in re.findall(r"'domain': '([^']+)'", text):
        assert domain.endswith(".fixture.example")
    for secret in re.findall(r"'(?:passphrase|preSharedKey|sharedSecret)': '([^']+)'", text):
        assert secret.startswith("CANARY-")


def test_serve_on_a_development_address_seeds_the_fixture_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: None)
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    monkeypatch.setenv("DRIFTSNIFF_BASE_URL", DEV_URL)
    assert main(["serve"]) == 0
    assert main(["serve"]) == 0
    database = Database(database_path(data_dir))
    try:
        assert count(database, tables.change_events) == 3
        assert count(database, tables.sources) == 1
    finally:
        database.close()


def test_serve_on_stage_does_not_seed_the_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: None)
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    monkeypatch.setenv("DRIFTSNIFF_BASE_URL", "https://ce-stg-driftsniff.theriark.dev")
    assert main(["serve"]) == 0
    database = Database(database_path(data_dir))
    try:
        assert count(database, tables.sources) == 0
    finally:
        database.close()
