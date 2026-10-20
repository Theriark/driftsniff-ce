"""Tests for the schema, the migrations and the refusal of a database from a newer version."""

import os
import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
import sqlalchemy as sa
import uvicorn
from alembic import command
from sqlalchemy.exc import IntegrityError

from driftsniff.cli import main
from driftsniff.db import migrate, tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import (
    DatabaseTooNewError,
    check_not_newer,
    current_revisions,
    head_revision,
    upgrade_to_head,
)

SRC = Path(__file__).resolve().parents[2] / "src"
TOP_LEVEL_TABLES = {
    "users",
    "sources",
    "path_mutes",
    "notification_channel",
    "audit_events",
    "settings",
}


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(database_path(tmp_path))
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def migrated(database: Database) -> Database:
    upgrade_to_head(database)
    return database


def stamp_unknown_revision(data_dir: Path, revision: str = "9999_from_the_future") -> None:
    """Write an alembic_version row the way a newer version of the application would."""
    with closing(sqlite3.connect(database_path(data_dir))) as raw:
        raw.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)")
        raw.execute("INSERT INTO alembic_version (version_num) VALUES (?)", (revision,))
        raw.commit()


def metadata_index_columns(index: sa.Index) -> tuple[str, ...]:
    """Column names in order; a text expression such as 'taken_at DESC' counts as its column."""
    return tuple(str(expression).split()[0].split(".")[-1] for expression in index.expressions)


def schema_from_database(connection: sa.Connection) -> dict[str, dict[str, object]]:
    inspector = sa.inspect(connection)
    schema: dict[str, dict[str, object]] = {}
    for name in inspector.get_table_names():
        if name == "alembic_version":
            continue
        schema[name] = {
            "columns": {c["name"]: c["nullable"] for c in inspector.get_columns(name)},
            "primary_key": sorted(inspector.get_pk_constraint(name)["constrained_columns"]),
            "indexes": {
                (i["name"], tuple(i["column_names"]), bool(i["unique"]))
                for i in inspector.get_indexes(name)
            },
            "uniques": {tuple(u["column_names"]) for u in inspector.get_unique_constraints(name)},
            "foreign_keys": {
                (
                    tuple(fk["constrained_columns"]),
                    fk["referred_table"],
                    tuple(fk["referred_columns"]),
                )
                for fk in inspector.get_foreign_keys(name)
            },
        }
    return schema


def schema_from_metadata() -> dict[str, dict[str, object]]:
    schema: dict[str, dict[str, object]] = {}
    for name, table in tables.metadata.tables.items():
        schema[name] = {
            "columns": {column.name: column.nullable for column in table.columns},
            "primary_key": sorted(column.name for column in table.primary_key.columns),
            "indexes": {
                (index.name, metadata_index_columns(index), bool(index.unique))
                for index in table.indexes
            },
            "uniques": {
                tuple(column.name for column in constraint.columns)
                for constraint in table.constraints
                if isinstance(constraint, sa.UniqueConstraint)
            },
            "foreign_keys": {
                (
                    tuple(column.name for column in constraint.columns),
                    constraint.referred_table.name,
                    tuple(element.column.name for element in constraint.elements),
                )
                for constraint in table.constraints
                if isinstance(constraint, sa.ForeignKeyConstraint)
            },
        }
    return schema


def test_the_schema_has_every_table_of_the_report() -> None:
    assert set(tables.metadata.tables) == {
        "workspaces",
        "users",
        "api_tokens",
        "sources",
        "runs",
        "resource_coverage",
        "objects",
        "object_states",
        "snapshots",
        "change_events",
        "change_items",
        "acknowledgements",
        "notes",
        "enrichments",
        "path_mutes",
        "notification_channel",
        "notification_deliveries",
        "audit_events",
        "settings",
    }


def test_top_level_tables_carry_workspace_id_defaulting_to_one() -> None:
    carrying = {name for name, t in tables.metadata.tables.items() if "workspace_id" in t.c}
    assert carrying == TOP_LEVEL_TABLES
    for name in carrying:
        column = tables.metadata.tables[name].c.workspace_id
        assert column.nullable is False
        assert str(column.server_default.arg) == "1"  # type: ignore[union-attr]


def test_migrate_creates_every_table_and_index(migrated: Database) -> None:
    with migrated.read() as connection:
        actual = schema_from_database(connection)
    expected = schema_from_metadata()
    assert set(actual) == set(expected)
    for name in expected:
        assert actual[name] == expected[name], name


def test_the_report_indexes_exist(migrated: Database) -> None:
    with migrated.read() as connection:
        inspector = sa.inspect(connection)
        indexes = {
            (name, index["name"])
            for name in inspector.get_table_names()
            for index in inspector.get_indexes(name)
        }
    assert {
        ("change_events", "ix_change_events_source_created"),
        ("change_events", "ix_change_events_severity_status"),
        ("change_items", "ix_change_items_event"),
        ("change_items", "ix_change_items_object"),
        ("snapshots", "ix_snapshots_source_taken"),
        ("objects", "uq_objects_source_resource_key"),
    } <= indexes


def test_migrate_records_the_head_revision_and_is_repeatable(migrated: Database) -> None:
    assert head_revision() == "0002"
    assert current_revisions(migrated) == ("0002",)
    assert upgrade_to_head(migrated) == "0002"
    assert current_revisions(migrated) == ("0002",)


def test_migration_0002_adds_the_size_columns_to_existing_runs(database: Database) -> None:
    config = migrate._config()
    with database.write() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001")
    with database.write() as connection:
        connection.exec_driver_sql("INSERT INTO sources (id, name, type) VALUES (1, 's', 'push')")
        connection.exec_driver_sql(
            "INSERT INTO runs (source_id, started_at, bytes_fetched) "
            "VALUES (1, '2026-10-20T00:00:00Z', 7)"
        )
    assert current_revisions(database) == ("0001",)
    assert upgrade_to_head(database) == "0002"
    with database.read() as connection:
        row = connection.exec_driver_sql(
            "SELECT bytes_fetched, new_state_bytes, manifest_bytes FROM runs"
        ).one()
    assert tuple(row) == (7, 0, 0)


def test_migrate_inserts_the_single_workspace(migrated: Database) -> None:
    with migrated.read() as connection:
        rows = connection.exec_driver_sql("SELECT id, name FROM workspaces").all()
    assert [tuple(row) for row in rows] == [(1, "default")]


def test_a_new_top_level_row_lands_in_workspace_one(migrated: Database) -> None:
    with migrated.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO users (username, password_hash, role, created_at) "
            "VALUES ('ada', 'x', 'admin', '2026-10-20T00:00:00Z')"
        )
    with migrated.read() as connection:
        row = connection.exec_driver_sql("SELECT workspace_id, disabled FROM users").one()
    assert tuple(row) == (1, 0)


def test_a_foreign_key_violation_is_rejected(migrated: Database) -> None:
    with (
        pytest.raises(IntegrityError, match="FOREIGN KEY"),
        migrated.write() as connection,
    ):
        connection.exec_driver_sql(
            "INSERT INTO runs (source_id, started_at) VALUES (999, '2026-10-20T00:00:00Z')"
        )
    with pytest.raises(IntegrityError, match="FOREIGN KEY"), migrated.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO users (workspace_id, username, password_hash, role, created_at) "
            "VALUES (42, 'bob', 'x', 'viewer', '2026-10-20T00:00:00Z')"
        )


def test_a_check_constraint_is_enforced(migrated: Database) -> None:
    with pytest.raises(IntegrityError, match="CHECK"), migrated.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO users (username, password_hash, role, created_at) "
            "VALUES ('eve', 'x', 'superuser', '2026-10-20T00:00:00Z')"
        )


def test_deleting_a_source_removes_its_dependent_rows(migrated: Database) -> None:
    with migrated.write() as connection:
        connection.exec_driver_sql("INSERT INTO sources (id, name, type) VALUES (1, 's', 'push')")
        connection.exec_driver_sql(
            "INSERT INTO runs (source_id, started_at) VALUES (1, '2026-10-20T00:00:00Z')"
        )
    with migrated.write() as connection:
        connection.exec_driver_sql("DELETE FROM sources WHERE id = 1")
    with migrated.read() as connection:
        assert connection.exec_driver_sql("SELECT count(*) FROM runs").scalar_one() == 0


def test_wal_mode_is_on_after_migrate(migrated: Database) -> None:
    with closing(sqlite3.connect(migrated.path)) as raw:
        assert raw.execute("PRAGMA journal_mode").fetchone() == ("wal",)


def test_a_database_from_a_newer_version_is_refused(tmp_path: Path) -> None:
    stamp_unknown_revision(tmp_path)
    database = Database(database_path(tmp_path))
    try:
        with pytest.raises(DatabaseTooNewError, match="9999_from_the_future"):
            check_not_newer(database)
        with pytest.raises(DatabaseTooNewError, match="newer"):
            upgrade_to_head(database)
        with database.read() as connection:
            names = set(sa.inspect(connection).get_table_names())
    finally:
        database.close()
    # Nothing was changed in the refused database.
    assert names == {"alembic_version"}


def test_migrate_command_exits_with_code_3_on_a_newer_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stamp_unknown_revision(tmp_path)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path))
    assert main(["migrate"]) == 3
    error = capsys.readouterr().err
    assert "newer" in error
    assert "9999_from_the_future" in error


def test_serve_exits_with_code_3_before_starting_on_a_newer_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def must_not_run(app: object, **kwargs: object) -> None:
        raise AssertionError("the server must not start on a newer database")

    stamp_unknown_revision(tmp_path)
    monkeypatch.setattr(uvicorn, "run", must_not_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path))
    assert main(["serve"]) == 3


def test_the_process_exit_code_is_3_on_a_newer_database(tmp_path: Path) -> None:
    stamp_unknown_revision(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "driftsniff", "migrate"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC), "DRIFTSNIFF_DATA_DIR": str(tmp_path)},
        timeout=60,
        check=False,
    )
    assert result.returncode == 3
    assert "newer" in result.stderr


def test_migrate_command_creates_the_database_and_can_run_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    assert main(["migrate"]) == 0
    assert main(["migrate"]) == 0
    assert "revision 0002" in capsys.readouterr().out
    assert database_path(data_dir).is_file()


def test_migrate_command_reports_an_unusable_data_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(blocker / "data"))
    assert main(["migrate"]) == 1
    assert "database error" in capsys.readouterr().err
