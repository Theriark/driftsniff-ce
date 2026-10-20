"""Growth and bookkeeping tests for core/collection.py: store on change, nothing more."""

from datetime import UTC, datetime, timedelta
from typing import Literal

import sqlalchemy as sa

from driftsniff.core.canonical import JsonValue
from driftsniff.core.collection import CollectionResult, record_collection
from driftsniff.core.runs import start_run
from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    Manifest,
    build_manifest,
    gc_unreferenced_states,
    latest_snapshot,
    resolve_current_state,
)
from driftsniff.db import tables
from driftsniff.db.engine import Database

SOURCE_ID = 1
START = datetime(2026, 10, 20, 8, 0, 0, tzinfo=UTC)
OBJECT_COUNT = 12
CONTROLLER = "10.0.1"


def at(second: int) -> str:
    return (START + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%SZ")


def objects_for(revision: int) -> dict[str, CollectedResource]:
    """Twelve networks; the last one carries the revision, so each revision is one change."""
    networks = []
    for number in range(OBJECT_COUNT):
        fields: dict[str, JsonValue] = {"_id": f"n{number}", "vlan": 100 + number, "dhcp": True}
        if number == OBJECT_COUNT - 1:
            fields["comment"] = f"revision {revision}"
        networks.append(CollectedObject(f"n{number}", fields, f"Network {number}"))
    return {"networks": CollectedResource(networks)}


def run_once(
    database: Database,
    manifest: Manifest,
    second: int,
    *,
    bytes_fetched: int = 5000,
    status: Literal["ok", "partial"] = "ok",
) -> CollectionResult:
    with database.write() as connection:
        run_id = start_run(connection, SOURCE_ID, at(second))
        return record_collection(
            connection,
            source_id=SOURCE_ID,
            run_id=run_id,
            manifest=manifest,
            bytes_fetched=bytes_fetched,
            finished_at=at(second + 1),
            status=status,
        )


def count(database: Database, table: sa.Table) -> int:
    with database.read() as connection:
        return connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()


def source_row(database: Database) -> sa.Row[tuple[object, ...]]:
    with database.read() as connection:
        return connection.execute(sa.select(tables.sources)).one()


def test_1000_identical_runs_store_one_snapshot_and_no_new_state(store: Database) -> None:
    for number in range(1000):
        manifest = build_manifest(objects_for(0), controller_version=CONTROLLER)
        result = run_once(store, manifest, number * 2)
        assert result.snapshot.stored is (number == 0)
    assert count(store, tables.snapshots) == 1
    assert count(store, tables.object_states) == OBJECT_COUNT
    assert count(store, tables.runs) == 1000
    with store.read() as connection:
        stored_flags = connection.execute(
            sa.select(tables.runs.c.stored_new_snapshot).order_by(tables.runs.c.id)
        ).scalars()
        flags = list(stored_flags)
        later = connection.execute(
            sa.select(
                sa.func.sum(tables.runs.c.new_state_bytes),
                sa.func.sum(tables.runs.c.manifest_bytes),
            ).where(tables.runs.c.id > 1)
        ).one()
    assert flags == [True] + [False] * 999
    assert tuple(later) == (0, 0)


def test_1000_runs_with_5_changes_store_six_snapshots(store: Database) -> None:
    change_runs = {100, 300, 500, 700, 900}
    revision = 0
    for number in range(1000):
        if number in change_runs:
            revision += 1
        manifest = build_manifest(objects_for(revision), controller_version=CONTROLLER)
        run_once(store, manifest, number * 2)
    assert revision == 5
    assert count(store, tables.snapshots) == 6
    assert count(store, tables.object_states) == OBJECT_COUNT + 5
    assert count(store, tables.runs) == 1000
    with store.read() as connection:
        kinds = connection.execute(
            sa.select(tables.snapshots.c.kind).order_by(tables.snapshots.c.id)
        ).scalars()
        assert list(kinds) == ["baseline"] + ["normal"] * 5
        resolved = resolve_current_state(connection, SOURCE_ID)
        newest = latest_snapshot(connection, SOURCE_ID)
    expected = build_manifest(objects_for(5), controller_version=CONTROLLER)
    assert resolved is not None
    assert resolved["networks"]["n11"]["comment"] == "revision 5"
    assert newest is not None
    assert newest.manifest.manifest_hash == expected.manifest_hash
    # Older snapshots still refer to the superseded states, so garbage collection keeps them.
    with store.write() as connection:
        assert gc_unreferenced_states(connection).removed_count == 0


def test_a_run_without_change_only_moves_the_checked_time_and_writes_a_run_record(
    store: Database,
) -> None:
    manifest = build_manifest(objects_for(0), controller_version=CONTROLLER)
    first = run_once(store, manifest, 0)
    all_objects = sa.select(tables.objects)
    with store.read() as connection:
        before = connection.execute(all_objects).all()
    second = run_once(store, manifest, 60, bytes_fetched=4321)
    assert first.snapshot.stored is True
    assert first.object_changes is not None
    assert first.object_changes.added == OBJECT_COUNT
    assert second.snapshot.stored is False
    assert second.object_changes is None
    assert count(store, tables.snapshots) == 1
    assert count(store, tables.object_states) == OBJECT_COUNT
    with store.read() as connection:
        assert connection.execute(all_objects).all() == before
        run = connection.execute(
            sa.select(tables.runs).order_by(tables.runs.c.id.desc()).limit(1)
        ).one()
    assert run.started_at == at(60)
    assert run.finished_at == at(61)
    assert run.status == "ok"
    assert run.object_count == manifest.object_count
    assert run.bytes_fetched == 4321
    assert run.stored_new_snapshot == 0
    assert (run.new_state_bytes, run.manifest_bytes) == (0, 0)
    source = source_row(store)
    assert source.last_checked_at == at(61)
    assert source.last_success_at == at(61)


def test_the_run_record_logs_the_bytes_a_change_added(store: Database) -> None:
    first = run_once(store, build_manifest(objects_for(0), controller_version=CONTROLLER), 0)
    second = run_once(store, build_manifest(objects_for(1), controller_version=CONTROLLER), 60)
    with store.read() as connection:
        runs = connection.execute(sa.select(tables.runs).order_by(tables.runs.c.id)).all()
        state_bytes = connection.execute(
            sa.select(sa.func.sum(sa.func.length(tables.object_states.c.body_zstd)))
        ).scalar_one()
        manifest_bytes = connection.execute(
            sa.select(sa.func.sum(sa.func.length(tables.snapshots.c.manifest_zstd)))
        ).scalar_one()
    assert [run.stored_new_snapshot for run in runs] == [1, 1]
    assert runs[0].new_state_bytes == first.snapshot.new_state_bytes > 0
    assert runs[1].new_state_bytes == second.snapshot.new_state_bytes > 0
    assert runs[1].new_state_bytes < runs[0].new_state_bytes
    assert runs[0].manifest_bytes == first.snapshot.manifest_bytes > 0
    # What the runs report is what the database really holds.
    assert sum(run.new_state_bytes for run in runs) == state_bytes
    assert sum(run.manifest_bytes for run in runs) == manifest_bytes
    assert second.object_changes is not None
    assert (second.object_changes.added, second.object_changes.removed) == (0, 0)


def test_a_partial_run_does_not_count_as_a_success(store: Database) -> None:
    manifest = build_manifest(objects_for(0), controller_version=CONTROLLER)
    run_once(store, manifest, 0)
    run_once(store, manifest, 60, status="partial")
    source = source_row(store)
    assert source.last_checked_at == at(61)
    assert source.last_success_at == at(1)
    with store.read() as connection:
        status = connection.execute(
            sa.select(tables.runs.c.status).order_by(tables.runs.c.id.desc()).limit(1)
        ).scalar_one()
    assert status == "partial"


def test_the_controller_version_is_kept_on_the_source(store: Database) -> None:
    run_once(store, build_manifest(objects_for(0), controller_version="10.0.1"), 0)
    assert source_row(store).controller_version == "10.0.1"
    run_once(store, build_manifest(objects_for(0), controller_version="10.0.2"), 60)
    assert source_row(store).controller_version == "10.0.2"
    run_once(store, build_manifest(objects_for(0), controller_version=None), 120)
    assert source_row(store).controller_version == "10.0.2"


def test_objects_follow_the_stored_snapshots(store: Database) -> None:
    run_once(store, build_manifest(objects_for(0), controller_version=CONTROLLER), 0)
    shrunk = objects_for(0)
    shrunk["networks"] = CollectedResource(list(shrunk["networks"].objects[:-1]))
    result = run_once(store, build_manifest(shrunk, controller_version=CONTROLLER), 60)
    assert result.object_changes is not None
    assert result.object_changes.removed == 1
    with store.read() as connection:
        removed = connection.execute(
            sa.select(tables.objects.c.object_key).where(tables.objects.c.removed_at.is_not(None))
        ).scalars()
        assert list(removed) == ["n11"]
