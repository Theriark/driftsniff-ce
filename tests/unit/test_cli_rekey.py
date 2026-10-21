"""The rekey command: new key, credentials re-encrypted, lost-key mode and refusals."""

import stat
from pathlib import Path

import pytest
import sqlalchemy as sa

from driftsniff.cli import main
from driftsniff.config import ConfigError, Settings
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.db.tables import audit_events, sources
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey

OLD_MATERIAL = bytes(range(32))
NEW_MATERIAL = bytes(reversed(range(32)))
CANARY = b"CANARY-password-0001"


def rekey_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_old_key: bool = True
) -> tuple[Path, Path]:
    """A migrated database with one credential made with the old key; returns both key files."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database = Database(database_path(data_dir))
    try:
        upgrade_to_head(database)
        sealed = CredentialCipher.from_master(MasterKey(OLD_MATERIAL)).encrypt(1, CANARY)
        with database.write() as connection:
            connection.execute(
                sa.insert(sources).values(
                    id=1,
                    name="lab",
                    type="push",
                    credential_ciphertext=sealed.ciphertext,
                    key_id=sealed.key_id,
                )
            )
    finally:
        database.close()
    old_key = tmp_path / "old" / "old.key"
    old_key.parent.mkdir()
    old_key.write_bytes(OLD_MATERIAL)
    old_key.chmod(0o400)
    key_file = tmp_path / "keys" / "master.key"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(key_file))
    monkeypatch.delenv("DRIFTSNIFF_OLD_KEY_FILE", raising=False)
    if with_old_key:
        monkeypatch.setenv("DRIFTSNIFF_OLD_KEY_FILE", str(old_key))
    return key_file, old_key


def stored_source(tmp_path: Path) -> tuple[str, str]:
    database = Database(database_path(tmp_path / "data"))
    try:
        with database.read() as connection:
            row = connection.execute(
                sa.select(sources.c.credential_ciphertext, sources.c.key_id)
            ).one()
        return str(row[0]), str(row[1])
    finally:
        database.close()


def audit_actions(tmp_path: Path) -> list[str]:
    database = Database(database_path(tmp_path / "data"))
    try:
        with database.read() as connection:
            rows = connection.execute(sa.select(audit_events.c.action).order_by(audit_events.c.id))
            return [str(action) for action in rows.scalars()]
    finally:
        database.close()


def test_rekey_creates_the_new_key_and_re_encrypts_the_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key_file, _ = rekey_setup(tmp_path, monkeypatch)
    assert main(["rekey"]) == 0
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o400
    new = MasterKey(key_file.read_bytes())
    ciphertext, key_id = stored_source(tmp_path)
    assert key_id == new.key_id
    assert CredentialCipher.from_master(new).decrypt(1, ciphertext, key_id) == CANARY
    output = capsys.readouterr().out
    assert "re-encrypted 1 credential(s)" in output
    assert CANARY.decode() not in output


def test_rekey_uses_an_existing_new_key_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key_file, _ = rekey_setup(tmp_path, monkeypatch)
    key_file.parent.mkdir()
    key_file.write_bytes(NEW_MATERIAL)
    key_file.chmod(0o400)
    assert main(["rekey"]) == 0
    assert key_file.read_bytes() == NEW_MATERIAL
    assert stored_source(tmp_path)[1] == MasterKey(NEW_MATERIAL).key_id


def test_rekey_needs_the_old_key_file_or_the_lost_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key_file, _ = rekey_setup(tmp_path, monkeypatch, with_old_key=False)
    assert main(["rekey"]) == 1
    assert "DRIFTSNIFF_OLD_KEY_FILE" in capsys.readouterr().err
    assert not key_file.exists()


def test_rekey_refuses_the_old_key_file_together_with_the_lost_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key_file, _ = rekey_setup(tmp_path, monkeypatch)
    assert main(["rekey", "--old-key-lost"]) == 1
    assert "not both" in capsys.readouterr().err
    assert not key_file.exists()


def test_rekey_with_a_missing_old_key_file_stops_and_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, old_key = rekey_setup(tmp_path, monkeypatch)
    before = stored_source(tmp_path)
    old_key.unlink()
    assert main(["rekey"]) == 1
    assert "not found" in capsys.readouterr().err
    assert stored_source(tmp_path) == before


def test_rekey_refuses_the_same_key_as_old_and_new(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, old_key = rekey_setup(tmp_path, monkeypatch)
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(old_key))
    before = stored_source(tmp_path)
    assert main(["rekey"]) == 1
    assert "same key" in capsys.readouterr().err
    assert stored_source(tmp_path) == before


def test_a_second_rekey_is_refused_while_the_first_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rekey_setup(tmp_path, monkeypatch)
    assert main(["rekey"]) == 0
    capsys.readouterr()
    assert main(["rekey"]) == 1
    assert "already in progress" in capsys.readouterr().err


def test_rekey_with_a_lost_old_key_writes_one_event_and_keeps_the_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key_file, _ = rekey_setup(tmp_path, monkeypatch, with_old_key=False)
    before = stored_source(tmp_path)
    assert main(["rekey", "--old-key-lost"]) == 0
    assert key_file.exists()
    assert audit_actions(tmp_path) == ["baseline_reestablished"]
    assert stored_source(tmp_path) == before
    assert "enter them again" in capsys.readouterr().out


def test_rekey_on_a_database_that_is_not_migrated_fails_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "missing" / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    monkeypatch.delenv("DRIFTSNIFF_OLD_KEY_FILE", raising=False)
    assert main(["rekey", "--old-key-lost"]) == 1
    assert "rekey failed" in capsys.readouterr().err


def test_the_old_key_file_setting_is_optional() -> None:
    assert Settings.from_env({}).old_key_file is None
    settings = Settings.from_env({"DRIFTSNIFF_OLD_KEY_FILE": "/run/keys/old.key"})
    assert settings.old_key_file == Path("/run/keys/old.key")


def test_a_blank_old_key_file_setting_is_refused() -> None:
    with pytest.raises(ConfigError, match="OLD_KEY_FILE"):
        Settings.from_env({"DRIFTSNIFF_OLD_KEY_FILE": " "})
