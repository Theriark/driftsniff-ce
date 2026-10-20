"""Master key management: derivation, key id, file mode, atomic creation, refusal, no overwrite."""

import base64
import hashlib
import hmac
import logging
import os
import stat
import threading
import time
import traceback
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from driftsniff.db.engine import Database
from driftsniff.secrets import keys
from driftsniff.secrets.keys import (
    EXIT_KEY_MISSING,
    EXIT_KEY_UNUSABLE,
    KEY_BYTES,
    MasterKey,
    MasterKeyError,
    MasterKeyInvalidError,
    MasterKeyMissingError,
    ensure_master_key,
    fingerprints_in_use,
    load_master_key,
    mark_fingerprints_in_use,
    mark_fingerprints_in_use_in,
    master_key_or_exit,
)

TEST_MATERIAL = bytes(range(KEY_BYTES))
LABELS = (
    "driftsniff/fingerprint/v1",
    "driftsniff/credential/v1",
    "driftsniff/session/v1",
    "driftsniff/webhook/v1",
)


@pytest.fixture(autouse=True)
def no_settle_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """A key file that is too short is re-read a few times; tests need not wait for that."""
    monkeypatch.setattr(keys, "_SETTLE_DELAY_SECONDS", 0.0)


def _write_key(path: Path, material: bytes = TEST_MATERIAL) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(material)
    path.chmod(0o400)


def _hkdf_with_library(material: bytes, label: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label.encode())
    return hkdf.derive(material)


def _hkdf_with_hmac(material: bytes, label: str) -> bytes:
    """RFC 5869 by hand for one output block: extract with a zero salt, then expand."""
    prk = hmac.new(bytes(32), material, hashlib.sha256).digest()
    return hmac.new(prk, label.encode() + b"\x01", hashlib.sha256).digest()


def test_four_derived_keys_differ() -> None:
    derived = MasterKey(TEST_MATERIAL).derived_keys()
    values = {derived.fingerprint, derived.credential, derived.session, derived.webhook}
    assert len(values) == 4
    assert all(len(value) == 32 for value in values)
    assert TEST_MATERIAL not in values


@pytest.mark.parametrize("label", LABELS)
def test_derivation_matches_the_cryptography_library(label: str) -> None:
    assert MasterKey(TEST_MATERIAL).derive(label) == _hkdf_with_library(TEST_MATERIAL, label)


@pytest.mark.parametrize("label", LABELS)
def test_derivation_matches_plain_hmac(label: str) -> None:
    assert MasterKey(TEST_MATERIAL).derive(label) == _hkdf_with_hmac(TEST_MATERIAL, label)


def test_derived_keys_use_the_documented_labels() -> None:
    master = MasterKey(TEST_MATERIAL)
    derived = master.derived_keys()
    assert derived.fingerprint == _hkdf_with_library(TEST_MATERIAL, LABELS[0])
    assert derived.credential == _hkdf_with_library(TEST_MATERIAL, LABELS[1])
    assert derived.session == _hkdf_with_library(TEST_MATERIAL, LABELS[2])
    assert derived.webhook == _hkdf_with_library(TEST_MATERIAL, LABELS[3])


def test_different_master_keys_give_different_derived_keys() -> None:
    other = MasterKey(bytes(reversed(TEST_MATERIAL)))
    assert other.derive(LABELS[0]) != MasterKey(TEST_MATERIAL).derive(LABELS[0])


def test_key_id_is_the_first_eight_hex_characters_of_the_sha256() -> None:
    key_id = MasterKey(TEST_MATERIAL).key_id
    assert key_id == hashlib.sha256(TEST_MATERIAL).hexdigest()[:8]
    assert len(key_id) == 8


@pytest.mark.parametrize("size", [0, 31, 33, 64])
def test_a_master_key_needs_exactly_32_bytes(size: int) -> None:
    with pytest.raises(MasterKeyInvalidError):
        MasterKey(bytes(size))


def test_first_start_creates_a_key_with_mode_0400(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "master.key"
    master = ensure_master_key(path, fingerprints_exist=False)
    content = path.read_bytes()
    assert len(content) == 32
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert master.key_id == hashlib.sha256(content).hexdigest()[:8]
    assert master.derive(LABELS[0]) == _hkdf_with_library(content, LABELS[0])


def test_new_keys_are_random(tmp_path: Path) -> None:
    first = ensure_master_key(tmp_path / "a" / "master.key", fingerprints_exist=False)
    second = ensure_master_key(tmp_path / "b" / "master.key", fingerprints_exist=False)
    assert first.key_id != second.key_id


def test_an_existing_key_is_loaded_and_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    _write_key(path)
    before = path.stat()
    for fingerprints_exist in (False, True):
        master = ensure_master_key(path, fingerprints_exist=fingerprints_exist)
        assert master.key_id == MasterKey(TEST_MATERIAL).key_id
    assert path.read_bytes() == TEST_MATERIAL
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert stat.S_IMODE(path.stat().st_mode) == 0o400


def test_a_second_start_uses_the_key_of_the_first(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    first = ensure_master_key(path, fingerprints_exist=False)
    second = ensure_master_key(path, fingerprints_exist=False)
    assert first.key_id == second.key_id


def test_missing_key_with_fingerprints_is_refused_and_not_created(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "master.key"
    with pytest.raises(MasterKeyMissingError, match="never creates a replacement"):
        ensure_master_key(path, fingerprints_exist=True)
    assert not path.exists()
    assert not path.parent.exists()


def test_fingerprint_marker_defaults_to_false_and_is_idempotent(store: Database) -> None:
    assert fingerprints_in_use(store) is False
    mark_fingerprints_in_use(store)
    mark_fingerprints_in_use(store)
    assert fingerprints_in_use(store) is True


def test_the_flag_is_part_of_the_transaction_that_sets_it(store: Database) -> None:
    with pytest.raises(RuntimeError, match="rollback"):
        with store.write() as connection:
            mark_fingerprints_in_use_in(connection)
            raise RuntimeError("rollback")
    assert fingerprints_in_use(store) is False
    with store.write() as connection:
        mark_fingerprints_in_use_in(connection)
        mark_fingerprints_in_use_in(connection)
    assert fingerprints_in_use(store) is True


def test_startup_exits_with_code_4_when_the_key_is_missing(
    store: Database, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "keys" / "master.key"
    mark_fingerprints_in_use(store)
    with pytest.raises(SystemExit) as raised:
        master_key_or_exit(path, store)
    assert raised.value.code == EXIT_KEY_MISSING == 4
    assert "never creates a replacement" in capsys.readouterr().err
    assert not path.exists()


def test_startup_creates_the_key_when_no_fingerprint_exists(
    store: Database, tmp_path: Path
) -> None:
    path = tmp_path / "keys" / "master.key"
    master = master_key_or_exit(path, store)
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert master.key_id == hashlib.sha256(path.read_bytes()).hexdigest()[:8]


def test_startup_uses_the_existing_key_when_fingerprints_exist(
    store: Database, tmp_path: Path
) -> None:
    path = tmp_path / "master.key"
    _write_key(path)
    mark_fingerprints_in_use(store)
    assert master_key_or_exit(path, store).key_id == MasterKey(TEST_MATERIAL).key_id


@pytest.mark.parametrize("size", [0, 31, 33])
def test_a_key_file_of_the_wrong_size_is_refused_and_kept(tmp_path: Path, size: int) -> None:
    path = tmp_path / "master.key"
    material = os.urandom(size)
    _write_key(path, material)
    for fingerprints_exist in (False, True):
        with pytest.raises(MasterKeyInvalidError, match="exactly 32 bytes") as raised:
            ensure_master_key(path, fingerprints_exist=fingerprints_exist)
        assert material.hex() not in str(raised.value) or size == 0
    assert path.read_bytes() == material


def test_startup_exits_with_code_1_for_an_unusable_key(
    store: Database, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "master.key"
    _write_key(path, b"short")
    with pytest.raises(SystemExit) as raised:
        master_key_or_exit(path, store)
    assert raised.value.code == EXIT_KEY_UNUSABLE
    assert "exactly 32 bytes" in capsys.readouterr().err
    assert path.read_bytes() == b"short"


def test_startup_exits_with_code_1_when_the_key_cannot_be_created(
    store: Database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_descriptor: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", fail)
    path = tmp_path / "keys" / "master.key"
    with pytest.raises(SystemExit) as raised:
        master_key_or_exit(path, store)
    assert raised.value.code == EXIT_KEY_UNUSABLE
    assert "cannot create master key file" in capsys.readouterr().err
    assert not path.exists()


def test_a_dangling_symbolic_link_is_refused_and_its_target_not_created(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.key"
    path = tmp_path / "master.key"
    path.symlink_to(target)
    with pytest.raises(MasterKeyInvalidError):
        ensure_master_key(path, fingerprints_exist=False)
    assert not target.exists()


def test_a_symbolic_link_to_a_real_key_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real.key"
    _write_key(target)
    path = tmp_path / "master.key"
    path.symlink_to(target)
    with pytest.raises(MasterKeyInvalidError):
        load_master_key(path)


def test_a_directory_in_place_of_the_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    path.mkdir()
    with pytest.raises(MasterKeyInvalidError, match="cannot read"):
        ensure_master_key(path, fingerprints_exist=False)


def test_a_named_pipe_in_place_of_the_key_is_refused_without_blocking(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    os.mkfifo(path)
    with pytest.raises(MasterKeyInvalidError, match="not a regular file"):
        load_master_key(path)


# --- key file mode -----------------------------------------------------------------------


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_a_key_file_with_an_allowed_mode_loads(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "master.key"
    _write_key(path)
    path.chmod(mode)
    assert load_master_key(path).key_id == MasterKey(TEST_MATERIAL).key_id


@pytest.mark.parametrize(
    "mode", [0o640, 0o644, 0o440, 0o660, 0o604, 0o700, 0o500, 0o755, 0o777, 0o666]
)
def test_a_key_file_with_any_other_mode_is_refused_and_kept(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "master.key"
    _write_key(path)
    path.chmod(mode)
    for fingerprints_exist in (False, True):
        with pytest.raises(MasterKeyInvalidError, match="0400 or 0600") as raised:
            ensure_master_key(path, fingerprints_exist=fingerprints_exist)
        assert f"{mode:04o}" in str(raised.value)
    assert path.read_bytes() == TEST_MATERIAL
    assert stat.S_IMODE(path.stat().st_mode) == mode


def test_startup_exits_with_code_1_for_a_key_file_others_can_read(
    store: Database, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "master.key"
    _write_key(path)
    path.chmod(0o644)
    mark_fingerprints_in_use(store)
    with pytest.raises(SystemExit) as raised:
        master_key_or_exit(path, store)
    assert raised.value.code == EXIT_KEY_UNUSABLE
    assert "0400 or 0600" in capsys.readouterr().err


# --- atomic creation ---------------------------------------------------------------------


def test_a_failed_write_leaves_no_partial_key_and_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_descriptor: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", fail)
    path = tmp_path / "master.key"
    with pytest.raises(OSError, match="disk full"):
        ensure_master_key(path, fingerprints_exist=False)
    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


def test_creation_publishes_the_complete_key_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "keys" / "master.key"
    seen: list[tuple[int, int]] = []
    real_link = os.link

    def spy(source: Path, destination: Path) -> None:
        seen.append((os.stat(source).st_size, stat.S_IMODE(os.stat(source).st_mode)))
        assert not destination.exists()
        real_link(source, destination)

    monkeypatch.setattr(os, "link", spy)
    ensure_master_key(path, fingerprints_exist=False)
    assert seen == [(32, 0o400)]
    assert [item.name for item in path.parent.iterdir()] == ["master.key"]


def test_a_file_system_without_hard_links_still_gets_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(source: Path, destination: Path) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "link", refuse)
    path = tmp_path / "keys" / "master.key"
    master = ensure_master_key(path, fingerprints_exist=False)
    assert master.key_id == hashlib.sha256(path.read_bytes()).hexdigest()[:8]
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert [item.name for item in path.parent.iterdir()] == ["master.key"]


def test_the_loser_of_a_race_removes_its_temporary_file_and_uses_the_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "master.key"

    def winner_first(source: Path, destination: Path) -> None:
        _write_key(Path(destination))
        raise FileExistsError(str(destination))

    monkeypatch.setattr(os, "link", winner_first)
    master = ensure_master_key(path, fingerprints_exist=False)
    assert master.key_id == MasterKey(TEST_MATERIAL).key_id
    assert path.read_bytes() == TEST_MATERIAL
    assert [item.name for item in tmp_path.iterdir()] == ["master.key"]


def test_a_key_created_by_another_process_in_the_meantime_is_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "master.key"

    def other_process_won(target: Path) -> MasterKey:
        _write_key(target)
        raise FileExistsError(str(target))

    monkeypatch.setattr(keys, "_create_key_file", other_process_won)
    master = ensure_master_key(path, fingerprints_exist=False)
    assert master.key_id == MasterKey(TEST_MATERIAL).key_id
    assert path.read_bytes() == TEST_MATERIAL


def test_a_key_that_is_still_being_written_is_waited_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "master.key"
    _write_key(path, TEST_MATERIAL[:10])
    sleeps: list[float] = []

    def finish_writing(seconds: float) -> None:
        sleeps.append(seconds)
        path.chmod(0o600)
        path.write_bytes(TEST_MATERIAL)
        path.chmod(0o400)

    monkeypatch.setattr(time, "sleep", finish_writing)
    master = ensure_master_key(path, fingerprints_exist=True)
    assert master.key_id == MasterKey(TEST_MATERIAL).key_id
    assert len(sleeps) == 1


def _start_together(path: Path, count: int) -> tuple[list[str], list[Exception]]:
    """Run ensure_master_key in ``count`` threads that are released at the same moment."""
    barrier = threading.Barrier(count)
    key_ids: list[str] = []
    errors: list[Exception] = []

    def start() -> None:
        try:
            barrier.wait(timeout=30)
            key_ids.append(ensure_master_key(path, fingerprints_exist=False).key_id)
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=start) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    return key_ids, errors


def test_processes_that_start_together_agree_on_one_key(tmp_path: Path) -> None:
    for round_number in range(20):
        path = tmp_path / f"round{round_number}" / "master.key"
        key_ids, errors = _start_together(path, 8)
        assert errors == []
        assert len(key_ids) == 8
        assert set(key_ids) == {hashlib.sha256(path.read_bytes()).hexdigest()[:8]}
        assert len(path.read_bytes()) == 32
        assert [item.name for item in path.parent.iterdir()] == ["master.key"]


# --- nothing leaks -----------------------------------------------------------------------


def _forms(material: bytes) -> list[str]:
    """Every way the bytes could be printed, and the first half of the hex form."""
    return [
        material.hex(),
        material.hex()[:16],
        base64.b64encode(material).decode(),
        base64.urlsafe_b64encode(material).decode(),
        repr(material),
    ]


def _failures(tmp_path: Path, material: bytes) -> list[Exception]:
    """One error of each kind, raised while the master key and a short key file exist."""
    short = tmp_path / "short" / "master.key"
    _write_key(short, material[:31])
    loose = tmp_path / "loose" / "master.key"
    _write_key(loose, material)
    loose.chmod(0o644)
    missing = tmp_path / "missing" / "master.key"
    errors: list[Exception] = []
    for target, fingerprints_exist in ((short, False), (loose, True), (missing, True)):
        try:
            ensure_master_key(target, fingerprints_exist=fingerprints_exist)
        except MasterKeyError as error:
            errors.append(error)
    return errors


def test_no_key_material_in_repr_errors_logs_output_or_tracebacks(
    store: Database,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "keys" / "master.key"
    with caplog.at_level(logging.DEBUG):
        master = ensure_master_key(path, fingerprints_exist=False)
        derived = master.derived_keys()
        material = path.read_bytes()
        errors = _failures(tmp_path, material)
        for target in (tmp_path / "short" / "master.key", tmp_path / "loose" / "master.key"):
            with pytest.raises(SystemExit):
                master_key_or_exit(target, store)
    assert len(errors) == 3
    visible = [repr(master), repr(derived), str(derived)]
    for error in errors:
        visible.append(str(error))
        visible.append(repr(error))
        visible.append("".join(traceback.format_exception(error)))
    captured = capsys.readouterr()
    visible.extend([caplog.text, captured.out, captured.err])
    forbidden = _forms(material) + _forms(material[:31])
    for purpose_key in (derived.fingerprint, derived.credential, derived.session, derived.webhook):
        forbidden.extend(_forms(purpose_key))
    for text in visible:
        for form in forbidden:
            assert form not in text
    assert master.key_id in repr(master)
