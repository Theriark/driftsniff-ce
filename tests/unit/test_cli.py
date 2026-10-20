"""Tests for the command line interface."""

import os
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import uvicorn

from driftsniff.cli import COMMANDS, main

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


@pytest.mark.parametrize("command", ["migrate", "backup", "rekey", "create-admin-code"])
def test_later_phase_commands_say_not_implemented(
    command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([command]) == 2
    assert "not implemented yet" in capsys.readouterr().err


def test_serve_passes_the_settings_to_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_run(app: object, **kwargs: object) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_PORT", "9500")
    monkeypatch.setenv("DRIFTSNIFF_TRUSTED_PROXY", "true")
    assert main(["serve"]) == 0
    assert len(calls) == 1
    assert calls[0]["port"] == 9500
    assert calls[0]["proxy_headers"] is True
    assert calls[0]["access_log"] is False


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
