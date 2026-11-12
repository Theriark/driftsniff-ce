"""A fake Home Assistant WebSocket API on localhost for the contract tests.

It is meant to be ported to the company Mock Platform as the Dev/Stage simulation of Home
Assistant, so it speaks the real wire protocol and does not import driftsniff: the WebSocket framing
below is its own (RFC 6455, server side), independent of the client in
``collectors/truenas/websocket.py``.

Surface (docs/vendor-notes/homeassistant.md has the sources):

* ``GET /api/websocket`` with ``Upgrade: websocket`` answers ``101``; any other path is ``404``.
* The server sends ``{"type": "auth_required", "ha_version"}``. The client sends
  ``{"type": "auth", "access_token"}``; the answer is ``{"type": "auth_ok", "ha_version"}``, or
  ``{"type": "auth_invalid", "message"}`` and the connection is closed.
* Commands are ``{"id", "type", ...}``; answers are ``{"id", "type": "result", "success": true,
  "result"}`` or ``{"id", "type": "result", "success": false, "error": {"code", "message"}}``.
  ``ping`` answers ``{"id", "type": "pong"}``. An unknown command is ``unknown_command``.
* ``automation/config`` and ``script/config`` take ``entity_id`` and answer ``{"config": ...}``
  (``not_found`` for an unknown entity). With ``Scenario(admin=False)`` they and
  ``config/auth/list`` answer ``unauthorized``, as for a token of a user who is no administrator.

The synthetic system lives in ``tests/fixtures/homeassistant/system.json``: ``commands`` (the
results), ``drift`` (configuration changes with the changes a person should see) and ``volatile``
(state that changes on a real system without anyone touching the configuration).
:func:`set_field`, :func:`apply_drift` and :func:`apply_volatile` change a scenario in place.
"""

import base64
import copy
import hashlib
import json
import struct
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "homeassistant" / "system.json"
API_PATH = "/api/websocket"
HA_VERSION = "2026.11.0"
CANARY_TOKEN = "CANARY-homeassistant-00"  # noqa: S105 - a test canary, not a credential
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ADMIN_COMMANDS = frozenset({"config/auth/list", "automation/config", "script/config"})
KEY_FIELDS = {
    "config_entries/get": "entry_id",
    "config/auth/list": "id",
    "config/area_registry/list": "area_id",
    "config/entity_registry/list": "id",
    "lovelace/dashboards/list": "url_path",
    "get_states": "entity_id",
}


def load_system() -> dict[str, Any]:
    """The whole fixture: ``commands``, ``drift`` and ``volatile``."""
    data: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return data


def system_commands() -> dict[str, Any]:
    """A fresh copy of the results of every command of the synthetic system."""
    return copy.deepcopy(load_system()["commands"])


def error(code: str, message: str) -> dict[str, Any]:
    """The ``error`` of a failed result."""
    return {"code": code, "message": message}


@dataclass(frozen=True, slots=True)
class Call:
    """One command the server received (the ``auth`` message is not a command)."""

    type: str
    fields: dict[str, Any]


@dataclass
class Scenario:
    """What the fake Home Assistant serves and which faults it simulates.

    ``admin`` false refuses the administrator commands; ``errors`` answers a command with that
    error; ``delay`` waits before answering; ``upgrade_status`` answers the upgrade with that HTTP
    status; ``event_before`` sends an unrelated event before every answer; ``fragment`` splits every
    answer into three frames; ``close_on`` closes the connection instead of answering.
    """

    token: str = CANARY_TOKEN
    admin: bool = True
    commands: dict[str, Any] = field(default_factory=system_commands)
    errors: dict[str, dict[str, Any]] = field(default_factory=dict)
    delay: dict[str, float] = field(default_factory=dict)
    upgrade_status: int | None = None
    event_before: bool = False
    fragment: bool = False
    close_on: set[str] = field(default_factory=set)


def _find(commands: dict[str, Any], command: str, key: Any) -> dict[str, Any]:
    result = commands[command]
    if key is None:
        return cast("dict[str, Any]", result)
    if isinstance(result, dict):
        return cast("dict[str, Any]", result[key])
    for item in result:
        if item.get(KEY_FIELDS[command]) == key:
            return cast("dict[str, Any]", item)
    raise KeyError(key)


def set_field(commands: dict[str, Any], command: str, key: Any, path: str, value: Any) -> None:
    """Set ``path`` (dot separated) of the object ``key`` in the result of ``command``."""
    target = _find(commands, command, key)
    *parents, last = path.split(".")
    for part in parents:
        target = target.setdefault(part, {})
    target[last] = copy.deepcopy(value)


def apply_drift(commands: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply every configuration change of the fixture; returns the changes a person should see.

    One low (an area renamed), medium (an automation's actions changed, an automation turned
    off), one high (the external URL) and one critical change (a user made administrator).
    """
    expected: list[dict[str, Any]] = []
    for change in load_system()["drift"]:
        set_field(commands, change["command"], change["id"], change["path"], change["value"])
        expected.extend(change["expect"])
    return expected


def apply_volatile(commands: dict[str, Any]) -> None:
    """Change state only: sensor readings, run state, last triggered, integration state."""
    for change in load_system()["volatile"]:
        set_field(commands, change["command"], change["id"], change["path"], change["value"])


# -- the server ---------------------------------------------------------------------------------


class _Closed(Exception):
    """The client closed the connection or broke the protocol."""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _plain(self, status: int) -> None:
        body = b"refused"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        server = cast("_Server", self.server)
        scenario = server.scenario
        server.upgrades.append(dict(self.headers.items()))
        if self.path != API_PATH:
            self._plain(404)
            return
        if scenario.upgrade_status is not None:
            self._plain(scenario.upgrade_status)
            return
        key = self.headers.get("Sec-WebSocket-Key")
        if self.headers.get("Upgrade", "").lower() != "websocket" or not key:
            self._plain(400)
            return
        digest = hashlib.sha1((key + _GUID).encode()).digest()  # noqa: S324 - RFC 6455
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", base64.b64encode(digest).decode())
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True
        try:
            self._serve(server)
        except (_Closed, OSError):
            return

    # -- framing (server side) --

    def _read_exact(self, count: int) -> bytes:
        data = self.rfile.read(count)
        if len(data) != count:
            raise _Closed
        return data

    def _read_message(self) -> str:
        parts: list[bytes] = []
        while True:
            first, second = self._read_exact(2)
            opcode = first & 0x0F
            if not second & 0x80:
                raise _Closed  # a client frame must be masked
            length = second & 0x7F
            if length == 126:
                (length,) = struct.unpack("!H", self._read_exact(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", self._read_exact(8))
            key = self._read_exact(4)
            payload = bytes(b ^ key[i % 4] for i, b in enumerate(self._read_exact(length)))
            if opcode == 0x8:
                self._send_frame(0x8, payload[:2])
                raise _Closed
            if opcode in (0x9, 0xA):
                if opcode == 0x9:
                    self._send_frame(0xA, payload)
                continue
            parts.append(payload)
            if first & 0x80:
                return b"".join(parts).decode("utf-8")

    def _send_frame(self, opcode: int, payload: bytes, *, fin: bool = True) -> None:
        length = len(payload)
        head = 0x80 if fin else 0
        if length < 126:
            header = struct.pack("!BB", head | opcode, length)
        elif length < 1 << 16:
            header = struct.pack("!BBH", head | opcode, 126, length)
        else:
            header = struct.pack("!BBQ", head | opcode, 127, length)
        self.wfile.write(header + payload)
        self.wfile.flush()

    def _send_json(self, message: Any, *, fragment: bool = False) -> None:
        data = json.dumps(message).encode("utf-8")
        if not fragment or len(data) < 3:
            self._send_frame(0x1, data)
            return
        third = len(data) // 3
        self._send_frame(0x1, data[:third], fin=False)
        self._send_frame(0x0, data[third : 2 * third], fin=False)
        self._send_frame(0x0, data[2 * third :])

    # -- the Home Assistant protocol --

    def _serve(self, server: "_Server") -> None:
        self._send_json({"type": "auth_required", "ha_version": HA_VERSION})
        auth = json.loads(self._read_message())
        server.auth_messages.append(auth)
        if auth.get("type") != "auth" or auth.get("access_token") != server.scenario.token:
            self._send_json({"type": "auth_invalid", "message": "Invalid access token or password"})
            self._send_frame(0x8, struct.pack("!H", 1000))
            raise _Closed
        self._send_json({"type": "auth_ok", "ha_version": HA_VERSION})
        while True:
            request = json.loads(self._read_message())
            scenario = server.scenario
            command = request.get("type")
            fields = {k: v for k, v in request.items() if k not in ("id", "type")}
            server.calls.append(Call(command, fields))
            time.sleep(scenario.delay.get(command, 0.0))
            if command in scenario.close_on:
                raise _Closed
            answer = self._answer(scenario, request.get("id"), command, fields)
            if scenario.event_before:
                self._send_json(
                    {"id": 0, "type": "event", "event": {"event_type": "state_changed"}}
                )
            self._send_json(answer, fragment=scenario.fragment)

    @staticmethod
    def _answer(scenario: Scenario, call_id: Any, command: Any, fields: dict[str, Any]) -> Any:
        if command == "ping":
            return {"id": call_id, "type": "pong"}
        failure: dict[str, Any] | None = scenario.errors.get(command)
        result: Any = None
        if failure is None and not scenario.admin and command in ADMIN_COMMANDS:
            failure = error("unauthorized", "Unauthorized")
        elif failure is None and command not in scenario.commands:
            failure = error("unknown_command", "Unknown command.")
        elif failure is None and command in ("automation/config", "script/config"):
            result = scenario.commands[command].get(fields.get("entity_id"))
            if result is None:
                failure = error("not_found", "Entity not found")
        elif failure is None:
            result = scenario.commands[command]
        if failure is not None:
            return {"id": call_id, "type": "result", "success": False, "error": failure}
        return {"id": call_id, "type": "result", "success": True, "result": result}


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.calls: list[Call] = []
        self.upgrades: list[dict[str, str]] = []
        self.auth_messages: list[dict[str, Any]] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeHomeAssistant:
    """A running fake Home Assistant."""

    def __init__(self, server: _Server) -> None:
        self._server = server

    @property
    def url(self) -> str:
        """The base address, plain http on a free local port."""
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    @property
    def scenario(self) -> Scenario:
        """The scenario being served; a test may change it between runs."""
        return self._server.scenario

    @property
    def calls(self) -> list[Call]:
        """Every command received, in order."""
        return self._server.calls

    @property
    def upgrades(self) -> list[dict[str, str]]:
        """The headers of every HTTP request (the WebSocket upgrades)."""
        return self._server.upgrades

    @property
    def auth_messages(self) -> list[dict[str, Any]]:
        """Every ``auth`` message received, in order."""
        return self._server.auth_messages

    def commands_sent(self) -> list[str]:
        """The types of the commands received, in order."""
        return [call.type for call in self._server.calls]


@contextmanager
def fake_homeassistant(scenario: Scenario | None = None) -> Iterator[FakeHomeAssistant]:
    """Serve ``scenario`` (the synthetic system when None) on a free local port."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeHomeAssistant(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
