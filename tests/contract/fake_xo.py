"""A fake Xen Orchestra REST interface on localhost for the contract tests (P8-T2).

It serves the shape the collector expects (docs/vendor-notes/xo.md; every name is unverified
against the vendor reference): ``GET /rest/v0`` as the REST root, ``GET /rest/v0/<collection>`` as
newline delimited JSON (``fields`` and ``ndjson`` in the query) and the credential list at
``/rest/v0/users/me/authentication_tokens``. A :class:`Scenario` says which objects each collection
holds and which failures to simulate. Every request is recorded, so a test can check which
collections were requested and that the credential only ever travels in the cookie.
"""

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import urlsplit

CANARY_TOKEN = "CANARY-xo-session-0001"
PREFIX = "/rest/v0"
TOKENS = "users/me/authentication_tokens"
BATCH = 1000


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    path: str
    query: str
    cookie: str | None
    authorization: str | None


@dataclass
class Scenario:
    """What the fake Xen Orchestra serves and which faults it simulates.

    Faults are keyed by the route name: ``root``, ``tokens`` or the name of a collection.
    """

    expected_token: str | None = CANARY_TOKEN
    objects: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # A collection of this many small generated objects, served from a generator.
    generated: dict[str, int] = field(default_factory=dict)
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    truncate: set[str] = field(default_factory=set)
    delay: dict[str, float] = field(default_factory=dict)
    # Serve the objects of these collections in reverse order of their ids.
    reverse: set[str] = field(default_factory=set)
    # The list the credential endpoint answers with (None answers 404).
    tokens: list[dict[str, Any]] | None = None
    # Put the received cookie into the body of error answers (a leaking server).
    echo_cookie: bool = False
    # Answer the REST root with a web page instead of JSON.
    html_root: bool = False


def _route_key(rest: str) -> str | None:
    if rest == "":
        return "root"
    if rest == TOKENS:
        return "tokens"
    if "/" in rest:
        return None
    return rest


def generated_object(index: int) -> dict[str, Any]:
    """The ``index``th object of a generated collection (small on purpose)."""
    return {"id": f"vm-{index:06d}", "name_label": "vm"}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"))

    def do_GET(self) -> None:
        server = cast("_Server", self.server)
        scenario = server.scenario
        parts = urlsplit(self.path)
        cookie = self.headers.get("Cookie")
        server.requests.append(
            Request(parts.path, parts.query, cookie, self.headers.get("Authorization"))
        )
        if not parts.path.startswith(PREFIX):
            self._send_json(404, {"error": "not found"})
            return
        key = _route_key(parts.path[len(PREFIX) :].strip("/"))
        if key is None:
            self._send_json(404, {"error": "not found"})
            return
        expected = scenario.expected_token
        if expected is not None and cookie != f"authenticationToken={expected}":
            self._error(401, scenario, cookie)
            return
        time.sleep(scenario.delay.get(key, 0.0))
        forced = scenario.status.get(key)
        if forced is not None:
            self._error(forced, scenario, cookie)
            return
        if key == "root":
            if scenario.html_root:
                self._send(200, b"<html>not the api</html>", "text/html")
            else:
                self._send_json(200, ["/rest/v0/vms", "/rest/v0/hosts"])
            return
        if key == "tokens":
            if scenario.tokens is None:
                self._error(404, scenario, cookie)
            else:
                self._send_json(200, scenario.tokens)
            return
        if key in scenario.raw:
            self._send(200, scenario.raw[key], "application/x-ndjson")
            return
        if key in scenario.truncate:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Length", "100000")
            self.end_headers()
            self.wfile.write(b'{"id": "a"}\n{"id": "b"')
            self.wfile.flush()
            return
        self._send_collection(scenario, key)

    def _error(self, status: int, scenario: Scenario, cookie: str | None) -> None:
        seen = cookie if scenario.echo_cookie else ""
        self._send_json(status, {"error": "refused", "seen": seen})

    def _send_collection(self, scenario: Scenario, key: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()  # no length: the body ends when the connection closes
        self.close_connection = True
        if key in scenario.generated:
            lines = (
                json.dumps(generated_object(index), separators=(",", ":"))
                for index in range(scenario.generated[key])
            )
        else:
            items = list(scenario.objects.get(key, []))
            if key in scenario.reverse:
                items.sort(key=lambda item: str(item.get("id")), reverse=True)
            lines = (json.dumps(item, separators=(",", ":")) for item in items)
        batch: list[str] = []
        for line in lines:
            batch.append(line)
            if len(batch) >= BATCH:
                self.wfile.write(("\n".join(batch) + "\n").encode("utf-8"))
                batch = []
        if batch:
            self.wfile.write(("\n".join(batch) + "\n").encode("utf-8"))


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A client that gave up (timeout test) closes the socket under the handler.
        return None


class FakeXo:
    """A running fake Xen Orchestra."""

    def __init__(self, server: _Server) -> None:
        self._server = server

    @property
    def url(self) -> str:
        """The base address, plain http on a free local port."""
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    @property
    def scenario(self) -> Scenario:
        """The scenario being served; a test may change it between calls."""
        return self._server.scenario

    @property
    def requests(self) -> list[Request]:
        """Every request received, in order."""
        return self._server.requests

    def requests_for(self, name: str) -> list[Request]:
        """The requests for the collection ``name``."""
        return [request for request in self._server.requests if request.path == f"{PREFIX}/{name}"]


@contextmanager
def fake_xo(scenario: Scenario | None = None) -> Iterator[FakeXo]:
    """Serve ``scenario`` (a default one when None) on a free local port until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeXo(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
