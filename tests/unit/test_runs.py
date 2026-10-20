"""Tests for core/runs.py: the run record and the sizes written into it."""

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from driftsniff.core.runs import finish_run, start_run
from driftsniff.db import tables
from driftsniff.db.engine import Database

T1 = "2026-10-20T10:00:00Z"
T2 = "2026-10-20T10:00:09Z"


def test_a_run_is_open_until_it_is_finished(store: Database) -> None:
    with store.write() as connection:
        run_id = start_run(connection, 1, T1)
    with store.read() as connection:
        row = connection.execute(sa.select(tables.runs)).one()
    assert row.id == run_id
    assert (row.source_id, row.started_at, row.finished_at, row.status) == (1, T1, None, None)
    assert (row.bytes_fetched, row.new_state_bytes, row.manifest_bytes) == (0, 0, 0)
    assert row.stored_new_snapshot == 0


def test_finish_run_records_the_sizes(store: Database) -> None:
    with store.write() as connection:
        run_id = start_run(connection, 1, T1)
        finish_run(
            connection,
            run_id,
            finished_at=T2,
            status="ok",
            object_count=12,
            bytes_fetched=4096,
            stored_new_snapshot=True,
            new_state_bytes=300,
            manifest_bytes=120,
        )
    with store.read() as connection:
        row = connection.execute(sa.select(tables.runs)).one()
    assert row.finished_at == T2
    assert row.status == "ok"
    assert row.object_count == 12
    assert row.bytes_fetched == 4096
    assert row.stored_new_snapshot == 1
    assert (row.new_state_bytes, row.manifest_bytes) == (300, 120)
    assert (row.error_class, row.error_summary) == (None, None)


def test_a_failed_run_keeps_its_error(store: Database) -> None:
    with store.write() as connection:
        run_id = start_run(connection, 1, T1)
        finish_run(
            connection,
            run_id,
            finished_at=T2,
            status="failed",
            error_class="timeout",
            error_summary="no answer in 30 s",
        )
    with store.read() as connection:
        row = connection.execute(sa.select(tables.runs)).one()
    assert (row.status, row.error_class, row.error_summary) == (
        "failed",
        "timeout",
        "no answer in 30 s",
    )


def test_an_unknown_status_is_refused(store: Database) -> None:
    with store.write() as connection:
        run_id = start_run(connection, 1, T1)
        with pytest.raises(ValueError, match="unknown run status"):
            finish_run(connection, run_id, finished_at=T2, status="done")


def test_finishing_a_run_that_does_not_exist_is_refused(store: Database) -> None:
    with store.write() as connection, pytest.raises(LookupError, match="run 99"):
        finish_run(connection, 99, finished_at=T2, status="ok")


def test_a_run_needs_an_existing_source(store: Database) -> None:
    with (
        pytest.raises(IntegrityError, match="FOREIGN KEY"),
        store.write() as connection,
    ):
        start_run(connection, 42, T1)
