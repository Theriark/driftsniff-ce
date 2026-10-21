"""The database backup (db/backup.py) and the ``backup`` command.

The source database is left open with its recent writes still in the write-ahead log, as a
running application would have it, so the tests show that the copy is a consistent online copy.
"""

import shutil
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import pytest

from driftsniff.cli import main
from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    build_manifest,
    resolve_current_state,
    store_if_changed,
)
from driftsniff.db import backup as backup_module
from driftsniff.db.backup import (
    KEY_WARNING,
    BackupError,
    backup_database,
    default_backup_path,
    integrity_problems,
)
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head

CANARY: Final = "CANARY-backup-0001"
TAKEN_AT: Final = "2026-10-20T10:00:00Z"


def fill(database: Database) -> None:
    resources = {
        "networks": CollectedResource(
            [
                CollectedObject("n1", {"_id": "n1", "name": "Lab", "vlan": 20}, "Lab"),
                CollectedObject("n2", {"_id": "n2", "name": "Guest", "vlan": 30}, "Guest"),
            ]
        )
    }
    manifest = build_manifest(resources, controller_version="10.0.1")
    with database.write() as connection:
        store_if_changed(connection, 1, manifest, taken_at=TAKEN_AT)


def test_the_backup_is_a_checked_single_file_with_the_data_of_the_original(
    store: Database, tmp_path: Path
) -> None:
    fill(store)
    target = tmp_path / "out" / "copy.db"

    result = backup_database(store.path, target)

    assert result.path == target
    assert result.size_bytes == target.stat().st_size > 0
    assert integrity_problems(target) == []
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [item.name for item in target.parent.iterdir()] == ["copy.db"]
    with store.read() as connection:
        original = resolve_current_state(connection, 1)
    assert original is not None
    assert original["networks"]["n1"]["vlan"] == 20

    restored = tmp_path / "restored"
    restored.mkdir()
    shutil.copy(target, database_path(restored))
    database = Database(database_path(restored))
    try:
        with database.read() as connection:
            assert resolve_current_state(connection, 1) == original
    finally:
        database.close()


def test_the_backup_works_while_the_application_holds_the_database_open(
    store: Database, tmp_path: Path
) -> None:
    fill(store)
    assert Path(f"{store.path}-wal").exists()  # the recent write is still in the log
    target = tmp_path / "copy.db"

    backup_database(store.path, target)

    connection = sqlite3.connect(target)
    try:
        assert connection.execute("SELECT count(*) FROM snapshots").fetchone() == (1,)
    finally:
        connection.close()


def test_a_backup_never_overwrites_an_existing_file(store: Database, tmp_path: Path) -> None:
    target = tmp_path / "copy.db"
    target.write_bytes(CANARY.encode())

    with pytest.raises(BackupError, match="already exists"):
        backup_database(store.path, target)

    assert target.read_bytes() == CANARY.encode()


def test_a_backup_never_follows_a_link_at_the_target(store: Database, tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(CANARY.encode())
    link = tmp_path / "copy.db"
    link.symlink_to(victim)

    with pytest.raises(BackupError, match="already exists"):
        backup_database(store.path, link)

    assert victim.read_bytes() == CANARY.encode()
    assert link.is_symlink()


def test_a_missing_database_is_refused_and_nothing_is_created(tmp_path: Path) -> None:
    target = tmp_path / "out" / "copy.db"

    with pytest.raises(BackupError, match="no database"):
        backup_database(tmp_path / "missing.db", target)

    assert not target.parent.exists()


def test_a_file_that_is_not_a_database_leaves_no_backup_behind(tmp_path: Path) -> None:
    source = tmp_path / "driftsniff.db"
    source.write_bytes(b"this is not a database " * 200)
    target = tmp_path / "copy.db"

    with pytest.raises(BackupError, match="backup failed"):
        backup_database(source, target)

    assert not target.exists()


def test_a_copy_that_fails_its_integrity_check_is_removed(
    store: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup_module, "integrity_problems", lambda path: ["row 1 is damaged"])
    target = tmp_path / "copy.db"

    with pytest.raises(BackupError, match="integrity check: row 1 is damaged"):
        backup_database(store.path, target)

    assert not target.exists()


def test_integrity_problems_reports_a_damaged_file(store: Database, tmp_path: Path) -> None:
    fill(store)
    target = tmp_path / "copy.db"
    backup_database(store.path, target)
    data = bytearray(target.read_bytes())
    for offset in range(len(data) // 2, len(data)):
        data[offset] = 0xFF
    target.write_bytes(bytes(data))

    assert integrity_problems(target) != []


def test_the_default_path_is_a_time_stamped_file_in_the_backups_folder() -> None:
    now = datetime(2026, 10, 20, 3, 30, 5, tzinfo=UTC)
    assert default_backup_path(Path("/data"), now) == Path(
        "/data/backups/driftsniff-20261020T033005Z.db"
    )


# --- the command ------------------------------------------------------------------------------


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "data"
    directory.mkdir()
    seeded = Database(database_path(directory))
    try:
        upgrade_to_head(seeded)
        with seeded.write() as connection:
            connection.exec_driver_sql(
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-controller', 'push')"
            )
        fill(seeded)
    finally:
        seeded.close()
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(directory))
    return directory


def test_the_command_writes_the_file_and_warns_about_the_key_volume(
    data_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "backup.db"

    assert main(["backup", str(target)]) == 0

    output = capsys.readouterr().out
    assert str(target) in output
    assert "integrity check passed" in output
    assert KEY_WARNING in output
    assert "key volume" in output
    assert integrity_problems(target) == []


def test_the_command_refuses_an_existing_target(
    data_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "backup.db"
    assert main(["backup", str(target)]) == 0
    first = target.read_bytes()
    capsys.readouterr()

    assert main(["backup", str(target)]) == 1

    assert "already exists" in capsys.readouterr().err
    assert target.read_bytes() == first


def test_the_command_without_a_target_writes_into_the_backups_folder(data_dir: Path) -> None:
    assert main(["backup"]) == 0

    written = list((data_dir / "backups").iterdir())
    assert len(written) == 1
    assert written[0].name.startswith("driftsniff-")
    assert written[0].suffix == ".db"
    assert integrity_problems(written[0]) == []


def test_the_command_fails_cleanly_without_a_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "empty"))

    assert main(["backup", str(tmp_path / "backup.db")]) == 1

    assert "no database" in capsys.readouterr().err
    assert not (tmp_path / "backup.db").exists()
