"""Retention (sources/retention.py): old events, thinned manifests, collected states, daily job.

Rows are written with the real storage functions (``store_if_changed``) and plain inserts, on a
migrated database. The clock is a parameter and a fake ``sleep``, so no test waits for 03:30.
"""

import asyncio
import itertools
import logging
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Final

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    ManifestError,
    build_manifest,
    latest_snapshot,
    load_manifest,
    resolve_current_state,
    resolve_manifest,
    store_if_changed,
)
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    acknowledgements,
    api_tokens,
    audit_events,
    change_events,
    change_items,
    enrichments,
    notes,
    notification_channel,
    notification_deliveries,
    object_states,
    settings,
    snapshots,
    users,
)
from driftsniff.main import create_app
from driftsniff.sources.retention import (
    ACTION_RETENTION_RUN,
    DEFAULT_RETENTION_DAYS,
    RETENTION_DAYS_SETTING,
    RetentionJob,
    RetentionResult,
    retention_days,
    run_retention,
    seconds_until_next_run,
)

NOW: Final = datetime(2026, 10, 20, 3, 30, tzinfo=UTC)
CANARY: Final = "CANARY-retention-0001"
WAIT_SECONDS: Final = 10.0
SECOND_SOURCE: Final = 2
VLANS: Final = itertools.count(101)

CHILD_TABLES: Final = (
    change_items,
    acknowledgements,
    notes,
    enrichments,
    notification_deliveries,
)


def days_ago(days: int, *, hour: int | None = None) -> str:
    moment = NOW - timedelta(days=days)
    if hour is not None:
        moment = moment.replace(hour=hour, minute=0)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def add_snapshot(store: Database, taken_at: str, *, source_id: int = 1) -> int:
    """Store a manifest with one new state (the vlan of n1 is new every time)."""
    resources = {
        "networks": CollectedResource(
            [
                CollectedObject("n1", {"_id": "n1", "vlan": next(VLANS)}, "Lab"),
                CollectedObject("n2", {"_id": "n2", "vlan": 30}, "Guest"),
            ]
        )
    }
    manifest = build_manifest(resources, controller_version="10.0.1")
    with store.write() as connection:
        outcome = store_if_changed(connection, source_id, manifest, taken_at=taken_at)
    assert outcome.snapshot_id is not None
    return outcome.snapshot_id


def add_event(
    store: Database,
    created_at: str,
    *,
    snapshot_id: int,
    previous_snapshot_id: int | None = None,
) -> int:
    with store.write() as connection:
        return connection.execute(
            sa.insert(change_events)
            .values(
                source_id=1,
                snapshot_id=snapshot_id,
                previous_snapshot_id=previous_snapshot_id,
                window_start=created_at,
                window_end=created_at,
                max_severity="low",
                item_count=1,
                summary="a change",
                rule_pack_version="pack-r1",
                created_at=created_at,
            )
            .returning(change_events.c.id)
        ).scalar_one()


def add_parents(store: Database) -> tuple[int, int, int]:
    """A user, an API token and a notification channel; returns their ids."""
    with store.write() as connection:
        user_id = connection.execute(
            sa.insert(users)
            .values(username="retention-admin", password_hash="x", role="admin", created_at="t")
            .returning(users.c.id)
        ).scalar_one()
        token_id = connection.execute(
            sa.insert(api_tokens)
            .values(
                user_id=user_id,
                name="enricher",
                token_prefix="dst_",
                token_hash="t" * 64,
                scopes=["enrich"],
            )
            .returning(api_tokens.c.id)
        ).scalar_one()
        channel_id = connection.execute(
            sa.insert(notification_channel)
            .values(type="webhook", config_ciphertext="c")
            .returning(notification_channel.c.id)
        ).scalar_one()
    return user_id, token_id, channel_id


def add_children(store: Database, event_id: int, parents: tuple[int, int, int]) -> None:
    """One row in every table that hangs on a change event."""
    user_id, token_id, channel_id = parents
    with store.write() as connection:
        connection.execute(
            sa.insert(change_items).values(
                event_id=event_id,
                resource="networks",
                change_kind="modified",
                path="vlan",
                field_class="config",
                severity="low",
            )
        )
        connection.execute(
            sa.insert(acknowledgements).values(
                event_id=event_id, user_id=user_id, comment="seen", created_at="t"
            )
        )
        connection.execute(
            sa.insert(notes).values(event_id=event_id, user_id=user_id, body="n", created_at="t")
        )
        connection.execute(
            sa.insert(enrichments).values(
                event_id=event_id,
                token_id=token_id,
                provider_label="helper",
                summary="a summary",
                created_at="t",
            )
        )
        connection.execute(
            sa.insert(notification_deliveries).values(
                event_id=event_id,
                channel_id=channel_id,
                attempt=1,
                status="sent",
                created_at="t",
            )
        )


def count(store: Database, table: sa.Table) -> int:
    with store.read() as connection:
        return connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()


def ids(store: Database, table: sa.Table) -> list[int]:
    with store.read() as connection:
        return list(connection.execute(sa.select(table.c.id).order_by(table.c.id)).scalars())


def set_window(store: Database, value: str) -> None:
    with store.write() as connection:
        connection.execute(
            sa.insert(settings).values(workspace_id=1, key=RETENTION_DAYS_SETTING, value=value)
        )


@pytest.fixture
def two_sources(store: Database) -> Database:
    with store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (2, 'second-controller', 'push')"
        )
    return store


# --- the window of change events --------------------------------------------------------------


def test_events_older_than_the_window_go_with_everything_that_hangs_on_them(
    store: Database,
) -> None:
    snapshot = add_snapshot(store, days_ago(2))
    old = add_event(store, days_ago(366), snapshot_id=snapshot)
    edge = add_event(store, days_ago(364), snapshot_id=snapshot)
    recent = add_event(store, days_ago(1), snapshot_id=snapshot)
    parents = add_parents(store)
    add_children(store, old, parents)
    add_children(store, recent, parents)
    assert [count(store, table) for table in CHILD_TABLES] == [2, 2, 2, 2, 2]

    result = run_retention(store, now=NOW)

    assert result.retention_days == DEFAULT_RETENTION_DAYS == 365
    assert result.events_deleted == 1
    assert ids(store, change_events) == [edge, recent]
    assert [count(store, table) for table in CHILD_TABLES] == [1, 1, 1, 1, 1]
    with store.read() as connection:
        owners = connection.execute(sa.select(change_items.c.event_id)).scalars().all()
    assert owners == [recent]


def test_the_window_is_the_stored_setting(store: Database) -> None:
    snapshot = add_snapshot(store, days_ago(2))
    add_event(store, days_ago(40), snapshot_id=snapshot)
    twenty = add_event(store, days_ago(20), snapshot_id=snapshot)
    set_window(store, "30")

    result = run_retention(store, now=NOW)

    assert result.retention_days == 30
    assert result.events_deleted == 1
    assert ids(store, change_events) == [twenty]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30", 30),
        ("90", 90),
        (" 365 ", 365),
        ("29", 365),
        ("366", 365),
        ("0", 365),
        ("-30", 365),
        ("abc", 365),
        ("", 365),
        ("1e2", 365),
        ("９０", 365),
        ("9" * 5000, 365),
    ],
)
def test_the_window_is_30_to_365_and_anything_else_means_365(
    store: Database, value: str, expected: int
) -> None:
    set_window(store, value)
    with store.read() as connection:
        assert retention_days(connection) == expected


def test_without_a_setting_the_window_is_365_and_nothing_is_logged(
    store: Database, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING), store.read() as connection:
        assert retention_days(connection) == 365
    assert [item for item in caplog.records if item.name.startswith("driftsniff")] == []


def test_an_invalid_setting_is_logged_without_its_value(
    store: Database, caplog: pytest.LogCaptureFixture
) -> None:
    set_window(store, CANARY)
    with caplog.at_level(logging.WARNING), store.read() as connection:
        assert retention_days(connection) == 365
    assert RETENTION_DAYS_SETTING in caplog.text
    assert CANARY not in caplog.text


# --- thinning ---------------------------------------------------------------------------------


def test_old_manifests_are_thinned_to_the_last_of_each_day_and_recent_ones_stay(
    store: Database,
) -> None:
    morning = add_snapshot(store, days_ago(100, hour=8))
    noon = add_snapshot(store, days_ago(100, hour=12))
    night = add_snapshot(store, days_ago(100, hour=23))
    next_day = add_snapshot(store, days_ago(99, hour=9))
    edge_a = add_snapshot(store, days_ago(89, hour=1))
    edge_b = add_snapshot(store, days_ago(89, hour=2))
    recent_a = add_snapshot(store, days_ago(5, hour=1))
    recent_b = add_snapshot(store, days_ago(5, hour=2))

    result = run_retention(store, now=NOW)

    kept = ids(store, snapshots)
    assert result.snapshots_thinned == 2
    assert kept == [night, next_day, edge_a, edge_b, recent_a, recent_b]
    assert morning not in kept
    assert noon not in kept


def test_thinning_is_per_source(two_sources: Database) -> None:
    a_early = add_snapshot(two_sources, days_ago(100, hour=8))
    b_late = add_snapshot(two_sources, days_ago(100, hour=20), source_id=SECOND_SOURCE)
    a_late = add_snapshot(two_sources, days_ago(100, hour=22))
    b_early = add_snapshot(two_sources, days_ago(100, hour=6), source_id=SECOND_SOURCE)

    result = run_retention(two_sources, now=NOW)

    kept = ids(two_sources, snapshots)
    assert result.snapshots_thinned == 2
    assert kept == [b_late, a_late]
    assert a_early not in kept
    assert b_early not in kept


def test_a_manifest_a_retained_event_points_to_is_never_removed(store: Database) -> None:
    before = add_snapshot(store, days_ago(100, hour=7))
    after = add_snapshot(store, days_ago(100, hour=8))
    unrelated = add_snapshot(store, days_ago(100, hour=9))
    last = add_snapshot(store, days_ago(100, hour=10))
    add_event(store, days_ago(100, hour=8), snapshot_id=after, previous_snapshot_id=before)

    result = run_retention(store, now=NOW)

    kept = ids(store, snapshots)
    assert result.events_deleted == 0
    assert result.snapshots_thinned == 1
    assert kept == [before, after, last]
    assert unrelated not in kept


def test_a_manifest_of_a_deleted_event_is_thinned_in_the_same_run(store: Database) -> None:
    first = add_snapshot(store, days_ago(400, hour=8))
    second = add_snapshot(store, days_ago(400, hour=9))
    add_event(store, days_ago(400, hour=9), snapshot_id=second, previous_snapshot_id=first)

    result = run_retention(store, now=NOW)

    assert (result.events_deleted, result.snapshots_thinned) == (1, 1)
    assert ids(store, snapshots) == [second]


def test_the_newest_manifest_of_an_idle_source_is_kept_and_still_resolves(
    store: Database,
) -> None:
    only = add_snapshot(store, days_ago(200, hour=5))
    with store.read() as connection:
        before = resolve_current_state(connection, 1)

    result = run_retention(store, now=NOW)

    assert result.snapshots_thinned == 0
    assert ids(store, snapshots) == [only]
    with store.read() as connection:
        assert resolve_current_state(connection, 1) == before


# --- states -----------------------------------------------------------------------------------


def test_unreferenced_states_are_collected_and_referenced_ones_stay(store: Database) -> None:
    for hour in (1, 2, 3):
        add_snapshot(store, days_ago(100, hour=hour))
    last = add_snapshot(store, days_ago(100, hour=4))
    recent = add_snapshot(store, days_ago(2))
    assert count(store, object_states) == 6  # five distinct n1 states and the shared n2

    result = run_retention(store, now=NOW)

    assert result.snapshots_thinned == 3
    assert result.states_removed == 3
    assert result.freed_bytes > 0
    assert count(store, object_states) == 3
    with store.read() as connection:
        for snapshot_id in (last, recent):
            row = connection.execute(
                sa.select(snapshots.c.manifest_hash, snapshots.c.manifest_zstd).where(
                    snapshots.c.id == snapshot_id
                )
            ).one()
            manifest = load_manifest(row.manifest_zstd, row.manifest_hash)
            resolved = resolve_manifest(connection, manifest)
            assert set(resolved["networks"]) == {"n1", "n2"}
        newest = latest_snapshot(connection, 1)
    assert newest is not None
    assert newest.snapshot_id == recent


def test_a_run_with_nothing_to_do_changes_no_history(store: Database) -> None:
    add_snapshot(store, days_ago(3))
    snapshot = add_snapshot(store, days_ago(2))
    add_event(store, days_ago(1), snapshot_id=snapshot)

    result = run_retention(store, now=NOW)

    assert result == RetentionResult(365, 0, 0, 0, 0)
    assert count(store, snapshots) == 2
    assert count(store, change_events) == 1


def test_the_run_writes_one_audit_event_with_counts_only(store: Database) -> None:
    snapshot = add_snapshot(store, days_ago(2))
    add_event(store, days_ago(500), snapshot_id=snapshot)

    run_retention(store, now=NOW)

    with store.read() as connection:
        rows = connection.execute(
            sa.select(audit_events).where(audit_events.c.action == ACTION_RETENTION_RUN)
        ).all()
    assert len(rows) == 1
    assert rows[0].actor == "system"
    assert rows[0].at == "2026-10-20T03:30:00Z"
    assert rows[0].detail == {
        "retention_days": 365,
        "events_deleted": 1,
        "snapshots_thinned": 0,
        "states_removed": 0,
        "freed_bytes": 0,
    }


def test_a_damaged_manifest_stops_the_collection_before_any_state_is_deleted(
    store: Database,
) -> None:
    for hour in (1, 2):
        add_snapshot(store, days_ago(100, hour=hour))
    victim = add_snapshot(store, days_ago(100, hour=3))
    states = count(store, object_states)
    with store.write() as connection:
        connection.execute(
            sa.update(snapshots).where(snapshots.c.id == victim).values(manifest_hash="0" * 64)
        )

    with pytest.raises(ManifestError, match="recorded hash"):
        run_retention(store, now=NOW)

    assert count(store, object_states) == states


# --- the daily job ----------------------------------------------------------------------------

PLUS_TWO: Final = timezone(timedelta(hours=2))


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (datetime(2026, 10, 20, 0, 0, tzinfo=UTC), 3.5 * 3600),
        (datetime(2026, 10, 20, 3, 29, 59, tzinfo=UTC), 1.0),
        (datetime(2026, 10, 20, 3, 30, tzinfo=UTC), 24 * 3600.0),
        (datetime(2026, 10, 20, 3, 30, 1, tzinfo=UTC), 24 * 3600.0 - 1),
        (datetime(2026, 10, 20, 23, 59, 59, tzinfo=UTC), 3.5 * 3600 + 1),
        (datetime(2026, 12, 31, 12, 0, tzinfo=UTC), 15.5 * 3600),
        (datetime(2026, 10, 20, 5, 0, tzinfo=PLUS_TWO), 1800.0),
    ],
)
def test_the_next_run_is_the_next_0330_utc(now: datetime, expected: float) -> None:
    assert seconds_until_next_run(now) == pytest.approx(expected)


class Sleeper:
    """A fake ``sleep``: records the wait, returns at once, blocks for good at wait ``stop_at``."""

    def __init__(self, stop_at: int) -> None:
        self.stop_at = stop_at
        self.waits: list[float] = []
        self.reached = asyncio.Event()
        self._never = asyncio.Event()

    async def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)
        if len(self.waits) >= self.stop_at:
            self.reached.set()
            await self._never.wait()
        await asyncio.sleep(0)


def run_async(test: Callable[[], Coroutine[Any, Any, None]]) -> None:
    asyncio.run(asyncio.wait_for(test(), timeout=60))


def drive(job: RetentionJob, sleeper: Sleeper) -> None:
    """Start the job, wait until its sleeper has reached its last wait, stop it."""

    async def scenario() -> None:
        await job.start()
        await job.start()  # a second start does nothing
        try:
            await asyncio.wait_for(sleeper.reached.wait(), WAIT_SECONDS)
        finally:
            await job.stop()

    run_async(scenario)


def test_the_job_sleeps_until_0330_then_runs_and_sleeps_again(store: Database) -> None:
    snapshot = add_snapshot(store, days_ago(2))
    add_event(store, days_ago(500), snapshot_id=snapshot)
    clock = datetime(2026, 10, 20, 2, 0, tzinfo=UTC)
    sleeper = Sleeper(2)

    drive(RetentionJob(store, now=lambda: clock, sleep=sleeper), sleeper)

    assert sleeper.waits == [5400.0, 5400.0]
    assert count(store, change_events) == 0
    assert count(store, audit_events) == 1


def test_a_failed_run_is_logged_by_class_and_the_loop_goes_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class Broken(Database):
        def __init__(self) -> None:
            pass

        def write(self) -> Any:
            raise RuntimeError(CANARY)

    sleeper = Sleeper(3)
    with caplog.at_level(logging.ERROR):
        drive(RetentionJob(Broken(), now=lambda: NOW, sleep=sleeper), sleeper)
    assert len(sleeper.waits) == 3
    assert "RuntimeError" in caplog.text
    assert CANARY not in caplog.text


def test_run_once_returns_the_result(store: Database) -> None:
    job = RetentionJob(store, now=lambda: NOW, sleep=Sleeper(1))
    results: list[RetentionResult | None] = []

    async def scenario() -> None:
        results.append(await job.run_once())

    run_async(scenario)
    assert results == [RetentionResult(365, 0, 0, 0, 0)]


def test_stop_without_start_and_start_after_stop_do_nothing(store: Database) -> None:
    sleeper = Sleeper(1)
    job = RetentionJob(store, now=lambda: NOW, sleep=sleeper)

    async def scenario() -> None:
        await job.stop()
        await job.start()
        await asyncio.sleep(0)

    run_async(scenario)
    assert sleeper.waits == []


def test_the_application_starts_and_stops_the_retention_job(store: Database) -> None:
    job = RetentionJob(store, now=lambda: NOW, sleep=Sleeper(1))
    with TestClient(create_app(retention=job)) as client:
        assert client.get("/healthz").status_code == 200
        assert job._task is not None
    assert job._task is None


def test_the_application_runs_without_a_retention_job() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/healthz").status_code == 200
