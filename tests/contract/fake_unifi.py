"""A fake UniFi Network application on localhost for the contract tests (P7-T2).

It serves the integration API shape the collector expects (docs/vendor-notes/unifi.md; every name
is unverified against the vendor reference): ``GET <base path>/v1/info``, ``/v1/sites`` and
``/v1/sites/<site>/<resource>``, with ``offset`` and ``limit`` paging. A :class:`Scenario` says
which base path answers, which version it reports, which objects each resource holds and which
failures to simulate. Every request is recorded, so a test can count requests and check that the
credential only ever travels in the key header.

The ordering documents of firewall policies (per pair of zones) and ACL rules (per site) are served
from ``Scenario.firewall_order`` and ``Scenario.acl_order`` (P7-T4; the names are unverified too).
"""

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

CANARY_HEADER = "CANARY-unifi-header-0001"
HEADER = "X-API-KEY"


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    path: str
    query: str
    header: str | None


@dataclass
class Scenario:
    """What the fake controller serves and which faults it simulates.

    Faults are keyed by the route name: ``info``, ``sites`` or the part of the path after the
    site id (``networks``, ``wifi/broadcasts``).
    """

    version: str = "10.3.58"
    base_path: str = "/integration"
    expected_header: str | None = CANARY_HEADER
    sites: list[str] = field(default_factory=lambda: ["site-a"])
    # Objects of a resource, the same for every site, unless ``site_objects`` has the pair.
    objects: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    site_objects: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    truncate: set[str] = field(default_factory=set)
    delay: dict[str, float] = field(default_factory=dict)
    ignore_offset: set[str] = field(default_factory=set)
    total_override: dict[str, int] = field(default_factory=dict)
    omit_total: bool = False
    page_cap: int | None = None
    # Answer 200 with a web page on the direct path when the API lives on another base path.
    html_elsewhere: bool = False
    # Put the received credential into the body of error answers (a leaking controller).
    echo_header: bool = False
    # Ordering documents: (site, source zone, destination zone) -> (before, after the system
    # defined policies) for firewall policies, and site -> rule ids for ACL rules.
    firewall_order: dict[tuple[str, str, str], tuple[list[str], list[str]]] = field(
        default_factory=dict
    )
    acl_order: dict[str, list[str]] = field(default_factory=dict)


def _route_key(rest: str) -> str | None:
    if rest in ("info", "sites"):
        return rest
    parts = rest.split("/", 2)
    if len(parts) == 3 and parts[0] == "sites" and parts[2]:
        return parts[2]
    return None


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

    def _send_error_answer(self, status: int, scenario: Scenario, received: str | None) -> None:
        seen = received if scenario.echo_header else ""
        self._send_json(status, {"error": "refused", "seen": seen})

    def do_GET(self) -> None:
        server = cast("_Server", self.server)
        scenario = server.scenario
        parts = urlsplit(self.path)
        received = self.headers.get(HEADER)
        server.requests.append(Request(parts.path, parts.query, received))
        prefix = f"{scenario.base_path}/v1/"
        if not parts.path.startswith(prefix):
            if scenario.html_elsewhere and parts.path.startswith("/integration/"):
                self._send(200, b"<html>not the api</html>", "text/html")
            else:
                self._send_json(404, {"error": "not found"})
            return
        rest = parts.path[len(prefix) :]
        key = _route_key(rest)
        if key is None:
            self._send_json(404, {"error": "not found"})
            return
        if scenario.expected_header is not None and received != scenario.expected_header:
            self._send_error_answer(401, scenario, received)
            return
        time.sleep(scenario.delay.get(key, 0.0))
        forced = scenario.status.get(key)
        if forced is not None:
            self._send_error_answer(forced, scenario, received)
            return
        if key in scenario.raw:
            self._send(200, scenario.raw[key])
            return
        if key in scenario.truncate:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b'{"data": [{"id": "a"')
            self.wfile.flush()
            return
        if key == "info":
            self._send_json(200, {"applicationVersion": scenario.version})
            return
        ordering = self._ordering(scenario, key, rest, parts.query)
        if ordering is not None:
            self._send_json(200, ordering)
            return
        self._send_json(200, self._page(scenario, key, rest, parts.query))

    @staticmethod
    def _ordering(scenario: Scenario, key: str, rest: str, query: str) -> dict[str, Any] | None:
        """The answer of an ordering call, or None when ``key`` is not one."""
        if key not in ("firewall/policies/ordering", "acl-rules/ordering"):
            return None
        site = rest.split("/", 2)[1]
        if key == "acl-rules/ordering":
            return {"orderedAclRuleIds": scenario.acl_order.get(site, [])}
        values = parse_qs(query)
        source = values.get("sourceFirewallZoneId", [""])[0]
        destination = values.get("destinationFirewallZoneId", [""])[0]
        before, after = scenario.firewall_order.get((site, source, destination), ([], []))
        return {
            "orderedFirewallPolicyIds": {
                "beforeSystemDefined": before,
                "afterSystemDefined": after,
            },
        }

    @staticmethod
    def _page(scenario: Scenario, key: str, rest: str, query: str) -> dict[str, Any]:
        if key == "sites":
            items = [{"id": site, "name": f"Site {site}"} for site in scenario.sites]
        else:
            site = rest.split("/", 2)[1]
            items = scenario.site_objects.get((site, key), scenario.objects.get(key, []))
        values = parse_qs(query)
        offset = int(values.get("offset", ["0"])[0])
        limit = int(values.get("limit", ["50"])[0])
        if scenario.page_cap is not None:
            limit = min(limit, scenario.page_cap)
        if key in scenario.ignore_offset:
            offset = 0
        data = items[offset : offset + limit]
        body: dict[str, Any] = {"offset": offset, "limit": limit, "count": len(data), "data": data}
        if not scenario.omit_total:
            body["totalCount"] = scenario.total_override.get(key, len(items))
        return body


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A client that gave up (timeout test) closes the socket under the handler.
        return None


class FakeUnifi:
    """A running fake controller."""

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

    def requests_for(self, suffix: str) -> list[Request]:
        """The requests whose path ends with ``suffix``."""
        return [request for request in self._server.requests if request.path.endswith(suffix)]


@contextmanager
def fake_unifi(scenario: Scenario | None = None) -> Iterator[FakeUnifi]:
    """Serve ``scenario`` (a default one when None) on a free local port until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeUnifi(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
