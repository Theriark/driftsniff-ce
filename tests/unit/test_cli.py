"""Tests for the command line interface."""

import hashlib
import logging
import os
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI

from driftsniff.cli import COMMANDS, main
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.secrets.keys import mark_fingerprints_in_use
from driftsniff.secrets.redact import RedactingFilter
from driftsniff.sources.retention import RetentionJob
from driftsniff.web.auth import (
    AuthService,
    SetupCodeError,
    SetupUnavailableError,
    make_password_hasher,
)

CHEAP_HASHER = make_password_hasher(memory_kib=8, time_cost=1)
SRC = Path(__file__).resolve().parents[2] / "src"


@contextmanager
def health_server(status: int, body: bytes) -> Iterator[int]:
    """Serve a fixed answer on an ephemeral local port and yield the port."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return None

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(autouse=True)
def clean_root_log_filters() -> Iterator[None]:
    """serve installs the log filter on the root handlers; do not leave it for other tests."""
    yield
    for handler in logging.getLogger().handlers:
        for item in list(handler.filters):
            if isinstance(item, RedactingFilter):
                handler.removeFilter(item)


def database_with_a_fingerprint(data_dir: Path) -> None:
    """A migrated database in which the first fingerprint has been stored."""
    data_dir.mkdir(parents=True, exist_ok=True)
    database = Database(database_path(data_dir))
    try:
        upgrade_to_head(database)
        mark_fingerprints_in_use(database)
    finally:
        database.close()


def test_there_are_six_commands() -> None:
    expected = {"serve", "migrate", "backup", "rekey", "create-admin-code", "healthcheck"}
    assert set(COMMANDS) == expected


def test_help_lists_the_six_commands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    for command in COMMANDS:
        assert command in output


def test_python_dash_m_help_lists_the_six_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "driftsniff", "--help"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
        timeout=60,
        check=False,
    )
    assert result.returncode == 0
    for command in COMMANDS:
        assert command in result.stdout


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert "0.1.0.dev0" in capsys.readouterr().out


def test_unknown_command_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["bogus"])
    assert exit_info.value.code == 2


def test_no_command_exits_with_code_2() -> None:
    assert main([]) == 2


def test_create_admin_code_prints_a_code_that_works_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    assert main(["create-admin-code"]) == 0
    output = capsys.readouterr().out
    match = re.search(r"setup code: ([A-Z2-9]{4}(?:-[A-Z2-9]{4}){3})", output)
    assert match is not None
    database = Database(database_path(tmp_path / "data"))
    try:
        auth = AuthService(database, hasher=CHEAP_HASHER)
        grant = auth.complete_setup(match.group(1), "ada", "a long enough password", "127.0.0.1")
        assert grant.principal.role == "admin"
        with pytest.raises(SetupUnavailableError):
            auth.complete_setup(match.group(1), "bob", "another long password", "127.0.0.1")
    finally:
        database.close()


def test_create_admin_code_replaces_an_earlier_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    assert main(["create-admin-code"]) == 0
    first = capsys.readouterr().out
    assert main(["create-admin-code"]) == 0
    second = capsys.readouterr().out
    assert first != second
    old_code = re.search(r"setup code: (\S+)", first)
    assert old_code is not None
    database = Database(database_path(tmp_path / "data"))
    try:
        auth = AuthService(database, hasher=CHEAP_HASHER)
        with pytest.raises(SetupCodeError):
            auth.complete_setup(old_code.group(1), "ada", "a long enough password", "127.0.0.1")
    finally:
        database.close()


def test_create_admin_code_refuses_when_an_admin_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    assert main(["migrate"]) == 0
    database = Database(database_path(data_dir))
    try:
        AuthService(database, hasher=CHEAP_HASHER).create_user(
            "ada", "a long enough password", "admin"
        )
    finally:
        database.close()
    capsys.readouterr()
    assert main(["create-admin-code"]) == 1
    captured = capsys.readouterr()
    assert "admin already exists" in captured.err
    assert "setup code" not in captured.out


def test_create_admin_code_reports_a_newer_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with closing(sqlite3.connect(database_path(data_dir))) as raw:
        raw.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)")
        raw.execute("INSERT INTO alembic_version (version_num) VALUES ('9999_from_the_future')")
        raw.commit()
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    assert main(["create-admin-code"]) == 3
    assert "newer" in capsys.readouterr().err


def test_serve_prints_the_setup_code_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run(app: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    assert main(["serve"]) == 0
    first = capsys.readouterr().out
    assert re.search(r"first-run setup code \(shown once\): [A-Z2-9]{4}(-[A-Z2-9]{4}){3}", first)
    assert main(["serve"]) == 0
    assert "setup code" not in capsys.readouterr().out


def test_serve_gives_the_app_the_sign_in_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apps: list[FastAPI] = []

    def fake_run(app: FastAPI, **kwargs: object) -> None:
        apps.append(app)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    assert main(["serve"]) == 0
    assert isinstance(apps[0].state.auth, AuthService)


def test_serve_passes_the_settings_to_uvicorn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[dict[str, object]] = []

    def fake_run(app: object, **kwargs: object) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_PORT", "9500")
    monkeypatch.setenv("DRIFTSNIFF_TRUSTED_PROXY", "true")
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    assert main(["serve"]) == 0
    assert len(calls) == 1
    assert calls[0]["port"] == 9500
    assert calls[0]["proxy_headers"] is True
    assert calls[0]["access_log"] is False


def test_serve_creates_the_master_key_and_gives_it_to_the_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apps: list[FastAPI] = []

    def fake_run(app: FastAPI, **kwargs: object) -> None:
        apps.append(app)

    key_file = tmp_path / "keys" / "master.key"
    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(key_file))
    assert main(["serve"]) == 0
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o400
    expected_id = hashlib.sha256(key_file.read_bytes()).hexdigest()[:8]
    assert len(apps) == 1
    assert apps[0].state.master_key.key_id == expected_id


def test_serve_gives_the_app_the_daily_retention_job(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apps: list[FastAPI] = []

    def fake_run(app: FastAPI, **kwargs: object) -> None:
        apps.append(app)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    assert main(["serve"]) == 0
    assert len(apps) == 1
    assert isinstance(apps[0].state.retention, RetentionJob)


def test_serve_installs_the_log_filter(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(app: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    assert main(["serve"]) == 0
    filters = [item for handler in logging.getLogger().handlers for item in handler.filters]
    assert any(isinstance(item, RedactingFilter) for item in filters)


def test_serve_exits_with_code_4_when_fingerprints_exist_and_the_key_is_gone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[object] = []

    def fake_run(app: object, **kwargs: object) -> None:
        calls.append(app)

    key_file = tmp_path / "keys" / "master.key"
    database_with_a_fingerprint(tmp_path / "data")
    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(key_file))
    with pytest.raises(SystemExit) as raised:
        main(["serve"])
    assert raised.value.code == 4
    assert "never creates a replacement" in capsys.readouterr().err
    assert not key_file.exists()
    assert calls == []


def test_serve_exits_with_code_1_for_a_key_file_others_can_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[object] = []

    def fake_run(app: object, **kwargs: object) -> None:
        calls.append(app)

    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    key_file.write_bytes(bytes(range(32)))
    key_file.chmod(0o644)
    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(key_file))
    with pytest.raises(SystemExit) as raised:
        main(["serve"])
    assert raised.value.code == 1
    assert "0400 or 0600" in capsys.readouterr().err
    assert calls == []


def test_serve_exits_with_code_4_end_to_end(tmp_path: Path) -> None:
    key_file = tmp_path / "keys" / "master.key"
    database_with_a_fingerprint(tmp_path / "data")
    result = subprocess.run(
        [sys.executable, "-m", "driftsniff", "serve"],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHONPATH": str(SRC),
            "DRIFTSNIFF_DATA_DIR": str(tmp_path / "data"),
            "DRIFTSNIFF_KEY_FILE": str(key_file),
            "DRIFTSNIFF_PORT": str(unused_port()),
        },
        timeout=120,
        check=False,
    )
    assert result.returncode == 4
    assert "never creates a replacement" in result.stderr
    assert not key_file.exists()


def test_serve_and_healthcheck_reject_a_bad_port(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_PORT", "abc")
    assert main(["serve"]) == 1
    assert main(["healthcheck"]) == 1
    assert "DRIFTSNIFF_PORT" in capsys.readouterr().err


def test_healthcheck_succeeds_when_the_server_reports_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    with health_server(200, b'{"status": "ok", "version": "test"}') as port:
        monkeypatch.setenv("DRIFTSNIFF_PORT", str(port))
        assert main(["healthcheck"]) == 0


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (500, b'{"status": "ok"}'),
        (200, b'{"status": "down"}'),
        (200, b"not json"),
        (200, b'["ok"]'),
    ],
)
def test_healthcheck_fails_on_a_bad_answer(
    status: int, body: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    with health_server(status, body) as port:
        monkeypatch.setenv("DRIFTSNIFF_PORT", str(port))
        assert main(["healthcheck"]) == 1


def test_healthcheck_fails_when_nothing_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DRIFTSNIFF_PORT", str(unused_port()))
    assert main(["healthcheck"]) == 1
