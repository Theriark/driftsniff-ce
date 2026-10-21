"""Database backup: a consistent copy made with the SQLite online backup API.

``backup_database`` copies the live database to a file that must not exist yet, then runs
``PRAGMA integrity_check`` on the copy. The source is only read, so the application can keep
running: in WAL mode a reader does not block the writer, and the copy is one consistent snapshot
that includes what is still in the write-ahead log. The target is created exclusively with mode
0600 (it holds encrypted credentials and fingerprints), is never overwritten, and is removed again
when the copy or the check fails, so a file that exists after a successful call is a good backup.
The copy is a single file with no ``-wal`` or ``-shm`` neighbour.

The master key is not in the database and is not part of the backup (``KEY_WARNING``).
"""

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

BACKUP_DIR_NAME: Final = "backups"
BUSY_TIMEOUT_SECONDS: Final = 5.0
KEY_WARNING: Final = (
    "the key volume is NOT part of this backup: back it up separately and keep it apart from "
    "the database backup. A restored database without its master key cannot decrypt the stored "
    "credentials, and the application will not start."
)


class BackupError(Exception):
    """The backup could not be made; the message says why."""


@dataclass(frozen=True, slots=True)
class BackupResult:
    """The backup that was written."""

    path: Path
    size_bytes: int


def default_backup_path(data_dir: Path, now: datetime) -> Path:
    """``<data dir>/backups/driftsniff-<UTC time>.db`` for a backup without an explicit target."""
    return data_dir / BACKUP_DIR_NAME / f"driftsniff-{now.strftime('%Y%m%dT%H%M%SZ')}.db"


def _create_target(target: Path) -> None:
    """Create the empty target file; refuse an existing file or link of that name."""
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError:
        raise BackupError(
            f"{target} already exists: a backup never overwrites a file, choose another name"
        ) from None
    os.close(descriptor)


def _copy(source: Path, target: Path) -> None:
    source_uri = source.resolve().as_uri() + "?mode=rw"
    reader = sqlite3.connect(source_uri, uri=True, timeout=BUSY_TIMEOUT_SECONDS)
    try:
        reader.execute("PRAGMA query_only=ON")
        writer = sqlite3.connect(target)
        try:
            reader.backup(writer)
            # One self-contained file: the copy keeps the WAL flag of the source otherwise.
            writer.execute("PRAGMA journal_mode=DELETE")
        finally:
            writer.close()
    finally:
        reader.close()


def integrity_problems(path: Path) -> list[str]:
    """The lines ``PRAGMA integrity_check`` reports for the file; empty when it is intact."""
    connection = sqlite3.connect(path)
    try:
        rows = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
    except sqlite3.DatabaseError as error:
        # A badly damaged file can make the check itself fail instead of listing problems.
        return [str(error)]
    finally:
        connection.close()
    return [] if rows == ["ok"] else rows


def backup_database(source: Path, target: Path) -> BackupResult:
    """Copy the database at ``source`` to the new file ``target`` and check the copy.

    Raises ``BackupError`` when the source is missing, the target exists, the copy fails or the
    integrity check finds a problem; in every case no file is left behind at ``target`` unless it
    already existed (and was then not touched).
    """
    if not source.is_file():
        raise BackupError(f"there is no database at {source}")
    try:
        _create_target(target)
    except OSError as error:
        raise BackupError(f"cannot create {target}: {error.strerror or 'file error'}") from None
    try:
        _copy(source, target)
        problems = integrity_problems(target)
        if problems:
            raise BackupError(f"the copy failed its integrity check: {'; '.join(problems[:3])}")
        size_bytes = target.stat().st_size
    except BackupError:
        target.unlink(missing_ok=True)
        raise
    except (sqlite3.Error, OSError) as error:
        target.unlink(missing_ok=True)
        raise BackupError(f"the backup failed: {error}") from None
    return BackupResult(target, size_bytes)
