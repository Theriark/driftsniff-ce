"""Tests for the SQLite engine: WAL, foreign keys, one writer, up to four readers."""

import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, closing
from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError

from driftsniff.db.engine import (
    BUSY_TIMEOUT_MS,
    DATABASE_FILE_NAME,
    MAX_READ_CONNECTIONS,
    Database,
    database_path,
)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(database_path(tmp_path))
    try:
        yield db
    finally:
        db.close()


def test_database_path_is_inside_the_data_dir(tmp_path: Path) -> None:
    assert database_path(tmp_path) == tmp_path / DATABASE_FILE_NAME


def test_wal_mode_is_on_for_the_writer_and_the_readers(database: Database) -> None:
    with database.write() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
    with database.read() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"


def test_wal_mode_is_stored_in_the_file(database: Database) -> None:
    with closing(sqlite3.connect(database.path)) as raw:
        assert raw.execute("PRAGMA journal_mode").fetchone() == ("wal",)


def test_connection_settings(database: Database) -> None:
    for context in (database.write, database.read):
        with context() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            timeout = connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one()
            assert timeout == BUSY_TIMEOUT_MS == 5000
            assert connection.exec_driver_sql("PRAGMA synchronous").scalar_one() == 1  # NORMAL


def test_readers_cannot_write(database: Database) -> None:
    with database.write() as connection:
        connection.exec_driver_sql("CREATE TABLE t (x INTEGER)")
    with database.read() as connection, pytest.raises(OperationalError, match="readonly"):
        connection.exec_driver_sql("INSERT INTO t (x) VALUES (1)")


def test_write_commits_and_a_reader_sees_it(database: Database) -> None:
    with database.write() as connection:
        connection.exec_driver_sql("CREATE TABLE t (x INTEGER)")
        connection.exec_driver_sql("INSERT INTO t (x) VALUES (7)")
    with database.read() as connection:
        assert connection.exec_driver_sql("SELECT x FROM t").scalar_one() == 7


def test_write_rolls_back_changes_and_ddl_on_error(database: Database) -> None:
    with database.write() as connection:
        connection.exec_driver_sql("CREATE TABLE kept (x INTEGER)")
    with pytest.raises(RuntimeError), database.write() as connection:
        connection.exec_driver_sql("INSERT INTO kept (x) VALUES (1)")
        connection.exec_driver_sql("CREATE TABLE lost (x INTEGER)")
        raise RuntimeError("boom")
    with database.read() as connection:
        count = connection.exec_driver_sql("SELECT count(*) FROM kept").scalar_one()
        tables = {
            name
            for (name,) in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert count == 0
    assert "lost" not in tables


def test_an_open_reader_does_not_block_the_writer(database: Database) -> None:
    with database.write() as connection:
        connection.exec_driver_sql("CREATE TABLE t (x INTEGER)")
    with database.read() as reader:
        assert reader.exec_driver_sql("SELECT count(*) FROM t").scalar_one() == 0
        with database.write() as connection:
            connection.exec_driver_sql("INSERT INTO t (x) VALUES (1)")
        # The reader keeps its snapshot until its block ends.
        assert reader.exec_driver_sql("SELECT count(*) FROM t").scalar_one() == 0
    with database.read() as reader:
        assert reader.exec_driver_sql("SELECT count(*) FROM t").scalar_one() == 1


def test_there_is_one_writer_at_a_time(database: Database) -> None:
    guard = threading.Lock()
    state = {"active": 0, "most": 0}

    def work() -> None:
        with database.write():
            with guard:
                state["active"] += 1
                state["most"] = max(state["most"], state["active"])
            time.sleep(0.05)
            with guard:
                state["active"] -= 1

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert state["most"] == 1


def test_up_to_four_read_connections_are_open_at_once(database: Database) -> None:
    assert MAX_READ_CONNECTIONS == 4
    with ExitStack() as stack:
        connections = [stack.enter_context(database.read()) for _ in range(MAX_READ_CONNECTIONS)]
        raw = {id(connection.connection.dbapi_connection) for connection in connections}
    assert len(raw) == MAX_READ_CONNECTIONS
