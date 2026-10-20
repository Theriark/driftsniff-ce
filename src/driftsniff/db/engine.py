"""SQLite engine: WAL mode, foreign keys, one writer and a small pool of readers.

The application has a single writer. Every write goes through Database.write(), which holds one
process-wide lock, so writers never wait on each other inside SQLite. Reads go through
Database.read(), which hands out at most four connections, each one read only.
"""

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import URL, Connection, Engine, create_engine, event
from sqlalchemy.pool import QueuePool

DATABASE_FILE_NAME = "driftsniff.db"
BUSY_TIMEOUT_MS = 5000
MAX_READ_CONNECTIONS = 4


def database_path(data_dir: Path) -> Path:
    """Return the database file inside the data directory."""
    return data_dir / DATABASE_FILE_NAME


def _make_engine(path: Path, *, writer: bool) -> Engine:
    engine = create_engine(
        URL.create("sqlite+pysqlite", database=str(path)),
        poolclass=QueuePool,
        pool_size=1 if writer else MAX_READ_CONNECTIONS,
        max_overflow=0,
        pool_timeout=BUSY_TIMEOUT_MS / 1000,
        connect_args={"timeout": BUSY_TIMEOUT_MS / 1000, "check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _configure(dbapi_connection: sqlite3.Connection, _record: object) -> None:
        # The driver must not open transactions on its own: begin() below issues BEGIN, so
        # DDL and data changes of one block commit or roll back together.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        try:
            if writer:
                cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            cursor.execute("PRAGMA synchronous=NORMAL")
            if not writer:
                cursor.execute("PRAGMA query_only=ON")
        finally:
            cursor.close()

    @event.listens_for(engine, "begin")
    def _begin(connection: Connection) -> None:
        # The writer takes the write lock up front so a transaction never fails half way
        # through while upgrading from a read lock.
        connection.exec_driver_sql("BEGIN IMMEDIATE" if writer else "BEGIN")

    return engine


class Database:
    """One SQLite file with a single writer connection and up to four read connections."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._write_lock = threading.Lock()
        self._writer = _make_engine(path, writer=True)
        self._readers = _make_engine(path, writer=False)
        # Open the writer first: it creates the file and switches it to WAL before any reader
        # connects. The setting is stored in the file, so it survives a restart.
        with self._writer.connect():
            pass

    @contextmanager
    def write(self) -> Iterator[Connection]:
        """Yield the writer connection inside a transaction.

        The transaction commits when the block ends and rolls back when it raises. Only one
        thread can be inside this block at a time.
        """
        with self._write_lock, self._writer.begin() as connection:
            yield connection

    @contextmanager
    def read(self) -> Iterator[Connection]:
        """Yield a read-only connection; the snapshot lasts until the block ends."""
        with self._readers.connect() as connection:
            yield connection

    def close(self) -> None:
        """Close every connection (the last one checkpoints the WAL file)."""
        self._readers.dispose()
        self._writer.dispose()
