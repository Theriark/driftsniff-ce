"""A fake TrueNAS JSON-RPC 2.0 WebSocket API on localhost for the contract tests.

It is meant to be ported to the company Mock Platform as the Dev/Stage simulation of TrueNAS, so
it speaks the real wire protocol and does not import driftsniff: the WebSocket framing below is its
own (RFC 6455, server side), independent of the client in ``collectors/truenas/websocket.py``.

Surface (docs/vendor-notes/truenas.md has the sources):

* ``GET /api/current`` with ``Upgrade: websocket`` answers ``101`` and then JSON-RPC 2.0 text
  messages. Any other path is ``404``.
* ``auth.login_ex`` with ``{"mechanism": "API_KEY_PLAIN", "username", "api_key"}`` answers
  ``{"response_type": "SUCCESS"}`` or ``{"response_type": "AUTH_ERR"}``. Before a successful sign
  in every other call answers error ``-32001`` with ``errname`` ``ENOTAUTHENTICATED``.
* Every method in :attr:`Scenario.methods` answers its stored result (``*.query`` lists,
  ``*.config`` objects, ``system.version`` text). An unknown method answers ``-32601``
  (method not found).

The synthetic system lives in ``tests/fixtures/truenas/system.json``: ``methods`` (the results),
``drift`` (configuration changes with the change a person should see) and ``volatile`` (run state
that changes on a real system without anyone touching the configuration). :func:`set_field`,
:func:`apply_drift` and :func:`apply_volatile` change a scenario in place so a second read sees it.
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

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "truenas" / "system.json"
API_PATH = "/api/current"
CANARY_USER = "driftsniff"
CANARY_KEY = "7-CANARY-nas-00"  # a test canary, not a credential
CANARY_CREDENTIAL = f"{CANARY_USER}:{CANARY_KEY}"
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

ERROR_NOT_AUTHENTICATED = {
    "code": -32001,
    "message": "Method call error",
    "data": {"error": 13, "errname": "ENOTAUTHENTICATED", "reason": "Not authenticated"},
}
ERROR_ACCESS_DENIED = {
    "code": -32001,
    "message": "Method call error",
    "data": {"error": 13, "errname": "EACCES", "reason": "Not authorized"},
}
ERROR_METHOD_NOT_FOUND = {"code": -32601, "message": "Method not found"}


def load_system() -> dict[str, Any]:
    """The whole fixture: ``methods``, ``drift`` and ``volatile``."""
    data: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return data


def system_methods() -> dict[str, Any]:
    """A fresh copy of the results of every method of the synthetic system."""
    return copy.deepcopy(load_system()["methods"])


@dataclass(frozen=True, slots=True)
class Call:
    """One JSON-RPC call the server received."""

    method: str
    params: Any
    authenticated: bool


@dataclass
class Scenario:
    """What the fake TrueNAS serves and which faults it simulates.

    ``errors`` answers a method with that JSON-RPC error; ``delay`` waits before answering;
    ``upgrade_status`` answers the WebSocket upgrade with that HTTP status instead of 101;
    ``event_before`` sends an unrelated notification before every answer; ``ping_before`` sends a
    ping first; ``fragment`` splits every answer into three frames; ``close_on`` closes the
    connection instead of answering that method; ``login_response`` replaces SUCCESS.
    """

    username: str = CANARY_USER
    api_key: str = CANARY_KEY
    methods: dict[str, Any] = field(default_factory=system_methods)
    errors: dict[str, dict[str, Any]] = field(default_factory=dict)
    delay: dict[str, float] = field(default_factory=dict)
    upgrade_status: int | None = None
    event_before: bool = False
    ping_before: bool = False
    fragment: bool = False
    close_on: set[str] = field(default_factory=set)
    login_response: str = "SUCCESS"
    bad_accept: bool = False


def _find(items: Any, key: Any) -> dict[str, Any]:
    if isinstance(items, dict):
        return items
    for item in items:
        if item.get("id") == key:
            return cast("dict[str, Any]", item)
    raise KeyError(key)


def set_field(methods: dict[str, Any], method: str, key: Any, path: str, value: Any) -> None:
    """Set ``path`` (dot separated) of the object ``key`` in the result of ``method``."""
    target = _find(methods[method], key)
    *parents, last = path.split(".")
    for part in parents:
        target = target.setdefault(part, {})
    target[last] = copy.deepcopy(value)


def apply_drift(methods: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply every configuration change of the fixture; returns the changes a person should see."""
    expected = []
    for change in load_system()["drift"]:
        set_field(methods, change["method"], change["id"], change["path"], change["value"])
        expected.append(change["expect"])
    return expected


def apply_volatile(methods: dict[str, Any]) -> None:
    """Change the run state of the system (usage, health, service state, task state, ...)."""
    for change in load_system()["volatile"]:
        set_field(methods, change["method"], change["id"], change["path"], change["value"])


# -- the server ---------------------------------------------------------------------------------


class _Closed(Exception):
    """The client closed the connection or broke the protocol."""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _plain(self, status: int) -> None:
        body = b'{"error": "refused"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
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
        accept = base64.b64encode(digest).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", "wrong" if scenario.bad_accept else accept)
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

    def _send_text(self, text: str, *, fragment: bool) -> None:
        data = text.encode("utf-8")
        if not fragment or len(data) < 3:
            self._send_frame(0x1, data)
            return
        third = len(data) // 3
        self._send_frame(0x1, data[:third], fin=False)
        self._send_frame(0x0, data[third : 2 * third], fin=False)
        self._send_frame(0x0, data[2 * third :])

    # -- JSON-RPC --

    def _serve(self, server: "_Server") -> None:
        authenticated = False
        while True:
            request = json.loads(self._read_message())
            scenario = server.scenario
            method = request.get("method")
            params = request.get("params", [])
            server.calls.append(Call(method, params, authenticated))
            time.sleep(scenario.delay.get(method, 0.0))
            if method in scenario.close_on:
                raise _Closed
            answer: dict[str, Any] = {"jsonrpc": "2.0", "id": request.get("id")}
            if method == "auth.login_ex":
                answer["result"] = self._login(scenario, params)
                authenticated = answer["result"]["response_type"] == "SUCCESS"
            elif not authenticated:
                answer["error"] = ERROR_NOT_AUTHENTICATED
            elif method in scenario.errors:
                answer["error"] = scenario.errors[method]
            elif method in scenario.methods:
                answer["result"] = scenario.methods[method]
            else:
                answer["error"] = ERROR_METHOD_NOT_FOUND
            if scenario.ping_before:
                self._send_frame(0x9, b"hb")
            if scenario.event_before:
                event = {"jsonrpc": "2.0", "method": "collection_update", "params": {}}
                self._send_text(json.dumps(event), fragment=False)
            self._send_text(json.dumps(answer), fragment=scenario.fragment)

    @staticmethod
    def _login(scenario: Scenario, params: Any) -> dict[str, Any]:
        options = params[0] if isinstance(params, list) and params else {}
        good = (
            isinstance(options, dict)
            and options.get("mechanism") == "API_KEY_PLAIN"
            and options.get("username") == scenario.username
            and options.get("api_key") == scenario.api_key
        )
        if not good:
            return {"response_type": "AUTH_ERR"}
        return {"response_type": scenario.login_response, "user_info": None}


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.calls: list[Call] = []
        self.upgrades: list[dict[str, str]] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeTruenas:
    """A running fake TrueNAS."""

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
        """Every JSON-RPC call received, in order."""
        return self._server.calls

    @property
    def upgrades(self) -> list[dict[str, str]]:
        """The headers of every HTTP request (the WebSocket upgrades)."""
        return self._server.upgrades

    def methods_called(self) -> list[str]:
        """The names of the methods called, in order."""
        return [call.method for call in self._server.calls]


@contextmanager
def fake_truenas(scenario: Scenario | None = None) -> Iterator[FakeTruenas]:
    """Serve ``scenario`` (the synthetic system when None) on a free local port."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeTruenas(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
