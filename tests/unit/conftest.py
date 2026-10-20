"""Fixtures shared by the store tests: a migrated database with one push source."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head

SOURCE_ID = 1


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Database]:
    """A database migrated to the newest revision, with one source (id 1) and nothing else."""
    database = Database(database_path(tmp_path))
    try:
        upgrade_to_head(database)
        with database.write() as connection:
            connection.exec_driver_sql(
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-controller', 'push')"
            )
        yield database
    finally:
        database.close()
