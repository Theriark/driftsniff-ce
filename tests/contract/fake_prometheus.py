"""A fake Prometheus API on localhost for the contract tests, and a model for a later simulation.

It serves the read endpoints the collector uses, with the shapes of the Prometheus HTTP API page
and the configuration reference read on 2026-11-12 (docs/vendor-notes/prometheus.md). The data is
synthetic: a Prometheus with three scrape jobs, one Alertmanager, two remote write targets, the
runtime flags and one rule group with two alerting rules and a recording rule.

Prometheus has no token check of its own; the fake plays the reverse proxy in front of it and
wants ``Authorization: Bearer <TOKEN>`` (``Scenario.require_token=False`` serves without one, as a
Prometheus without a proxy does). Like Prometheus, the configuration dump prints ``<secret>`` for
its secret-typed fields, and serves in clear what Prometheus does not hide: remote write headers,
the Azure AD OAuth client secret and a password written into a remote write URL, so a test can
prove that driftsniff keeps only fingerprints of them.

Surface (GET only, every other method answers 405), every answer the envelope
``{"status": "success", "data": ...}`` and errors ``{"status": "error", "errorType", "error"}``:

* ``/api/v1/status/buildinfo`` ``{"version", "revision", "branch", "buildUser", "buildDate",
  "goVersion"}``;
* ``/api/v1/status/config`` ``{"yaml": "<the running configuration as YAML text>"}``;
* ``/api/v1/status/flags`` ``{"<flag name>": "<text>"}``;
* ``/api/v1/rules`` ``{"groups": [{"name", "file", "interval", "limit", "rules": [...],
  "evaluationTime", "lastEvaluation"}]}``; ``type=alert|record`` filters and
  ``exclude_alerts=true`` drops the ``alerts`` of each alerting rule.

A missing or wrong token answers 401 with a plain text body, as a proxy does. :class:`Scenario`
has helpers that change the configuration so that two reads show a drift (:meth:`Scenario.drift`
applies a standard set: one low, one medium, one high and one critical change).
"""

import base64
import copy
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import yaml

TOKEN = "CANARY-pm-0"  # noqa: S105 - a test canary, not a credential
# Values Prometheus serves in clear; tests check that none of them is ever stored in clear.
TENANT_HEADER = "CANARY-prometheus-tenant-01"
URL_PASSWORD = "CANARY-pmu-0"  # noqa: S105
AZURE_SECRET = "CANARY-prometheus-azure-03"  # noqa: S105
VERSION = "3.5.0"
SECRET = "<secret>"  # noqa: S105 - what Prometheus prints for a secret-typed field

ROUTES = {
    "/api/v1/status/buildinfo": "buildinfo",
    "/api/v1/status/config": "config",
    "/api/v1/status/flags": "flags",
    "/api/v1/rules": "rules",
}


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    method: str
    path: str
    query: str
    authorization: str | None
    cookie: str | None


def _relabel(source: list[str], target: str, action: str = "replace") -> dict[str, Any]:
    return {
        "source_labels": source,
        "separator": ";",
        "regex": "(.*)",
        "target_label": target,
        "replacement": "$1",
        "action": action,
    }


def _http() -> dict[str, Any]:
    return {"follow_redirects": True, "enable_http2": True}


def default_state() -> dict[str, Any]:
    """The running configuration, flags and rules of a small synthetic Prometheus."""
    config = {
        "global": {
            "scrape_interval": "1m",
            "scrape_timeout": "10s",
            "scrape_protocols": [
                "OpenMetricsText1.0.0",
                "OpenMetricsText0.0.1",
                "PrometheusText0.0.4",
            ],
            "evaluation_interval": "1m",
            "external_labels": {"site": "lab-01", "env": "lab"},
        },
        "runtime": {"gogc": 75},
        "rule_files": ["/etc/prometheus/rules/*.yml"],
        "alerting": {
            "alertmanagers": [
                {
                    **_http(),
                    "scheme": "http",
                    "timeout": "10s",
                    "api_version": "v2",
                    "static_configs": [{"targets": ["192.0.2.20:9093"]}],
                }
            ]
        },
        "scrape_configs": [
            {
                **_http(),
                "job_name": "prometheus",
                "honor_timestamps": True,
                "scrape_interval": "1m",
                "scrape_timeout": "10s",
                "metrics_path": "/metrics",
                "scheme": "http",
                "enable_compression": True,
                "static_configs": [{"targets": ["localhost:9090"]}],
            },
            {
                **_http(),
                "job_name": "node",
                "honor_timestamps": True,
                "scrape_interval": "1m",
                "scrape_timeout": "10s",
                "metrics_path": "/metrics",
                "scheme": "https",
                "enable_compression": True,
                "tls_config": {"insecure_skip_verify": False},
                "static_configs": [
                    {"targets": ["192.0.2.11:9100", "192.0.2.12:9100"], "labels": {"rack": "a1"}}
                ],
                "relabel_configs": [_relabel(["__address__"], "instance")],
            },
            {
                **_http(),
                "job_name": "blackbox",
                "honor_timestamps": True,
                "scrape_interval": "1m",
                "scrape_timeout": "10s",
                "metrics_path": "/probe",
                "scheme": "http",
                "params": {"module": ["http_2xx"]},
                "basic_auth": {"username": "probe", "password": SECRET},
                "static_configs": [{"targets": ["https://www.example.invalid"]}],
                "relabel_configs": [
                    _relabel(["__address__"], "__param_target"),
                    _relabel(["__param_target"], "instance"),
                    {**_relabel([], "__address__"), "replacement": "198.51.100.5:9115"},
                ],
            },
        ],
        "remote_write": [
            {
                **_http(),
                "url": f"https://metrics-user:{URL_PASSWORD}@mimir.example.invalid/api/v1/push",
                "remote_timeout": "30s",
                "headers": {"X-Scope-OrgID": TENANT_HEADER},
                "queue_config": {"capacity": 10000, "max_shards": 50, "min_shards": 1},
                "metadata_config": {"send": True, "send_interval": "1m"},
            },
            {
                **_http(),
                "name": "longterm",
                "url": "https://thanos.example.invalid/api/v1/receive",
                "remote_timeout": "30s",
                "azuread": {
                    "cloud": "AzurePublic",
                    "oauth": {
                        "client_id": "00000000-0000-4000-8000-000000000001",
                        "client_secret": AZURE_SECRET,
                        "tenant_id": "00000000-0000-4000-8000-000000000002",
                    },
                },
                "write_relabel_configs": [_relabel(["__name__"], "", "keep")],
            },
        ],
    }
    flags = {
        "config.file": "/etc/prometheus/prometheus.yml",
        "web.listen-address": "0.0.0.0:9090",
        "web.enable-admin-api": "false",
        "web.enable-lifecycle": "false",
        "web.enable-remote-write-receiver": "false",
        "web.config.file": "",
        "web.external-url": "https://prometheus.example.invalid",
        "storage.tsdb.path": "/prometheus",
        "storage.tsdb.retention.time": "15d",
        "storage.tsdb.retention.size": "0B",
        "query.timeout": "2m",
        "query.max-concurrency": "20",
        "log.level": "info",
    }
    rules = [
        {
            "name": "NodeDown",
            "query": 'up{job="node"} == 0',
            "duration": 300,
            "keepFiringFor": 0,
            "labels": {"severity": "critical"},
            "annotations": {"summary": "A node exporter is down"},
            "alerts": [],
            "health": "ok",
            "state": "inactive",
            "lastError": "",
            "evaluationTime": 0.0004,
            "lastEvaluation": "2026-11-12T09:00:00Z",
            "type": "alerting",
        },
        {
            "name": "DiskAlmostFull",
            "query": "node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.1",
            "duration": 900,
            "keepFiringFor": 0,
            "labels": {"severity": "warning"},
            "annotations": {"summary": "A disk is over 90 percent full"},
            "alerts": [],
            "health": "ok",
            "state": "inactive",
            "lastError": "",
            "evaluationTime": 0.0011,
            "lastEvaluation": "2026-11-12T09:00:00Z",
            "type": "alerting",
        },
        {
            "name": "instance:node_cpu:rate5m",
            "query": 'rate(node_cpu_seconds_total{mode!="idle"}[5m])',
            "labels": {"team": "ops"},
            "health": "ok",
            "lastError": "",
            "evaluationTime": 0.0007,
            "lastEvaluation": "2026-11-12T09:00:00Z",
            "type": "recording",
        },
    ]
    groups = [
        {
            "name": "node",
            "file": "/etc/prometheus/rules/node.yml",
            "interval": 60,
            "limit": 0,
            "rules": rules,
            "evaluationTime": 0.0022,
            "lastEvaluation": "2026-11-12T09:00:00Z",
        }
    ]
    buildinfo = {
        "version": VERSION,
        "revision": "0000000000000000000000000000000000000000",
        "branch": "HEAD",
        "buildUser": "root@example.invalid",
        "buildDate": "20261101-00:00:00",
        "goVersion": "go1.24.4",
    }
    return {"config": config, "flags": flags, "groups": groups, "buildinfo": buildinfo}


@dataclass
class Scenario:
    """What the fake Prometheus serves and which faults it simulates.

    Faults are keyed by route name (``buildinfo``, ``config``, ``flags``, ``rules``): ``status``
    answers that HTTP status with an error envelope, ``raw`` serves those bytes instead.
    """

    state: dict[str, Any] = field(default_factory=default_state)
    require_token: bool = True
    # basic auth (user, password) asked for instead of the bearer token (basic_auth_users)
    basic: tuple[str, str] | None = None
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)

    # -- drift helpers ----------------------------------------------------------------------

    def _job(self, name: str) -> dict[str, Any]:
        for job in self.state["config"]["scrape_configs"]:
            if job["job_name"] == name:
                return cast("dict[str, Any]", job)
        raise KeyError(name)

    def _rule(self, name: str) -> dict[str, Any]:
        for group in self.state["groups"]:
            for rule in group["rules"]:
                if rule["name"] == name:
                    return cast("dict[str, Any]", rule)
        raise KeyError(name)

    def set_scrape_interval(self, job: str, interval: str) -> None:
        """Low: the time between scrapes of a job."""
        self._job(job)["scrape_interval"] = interval

    def set_alert_query(self, name: str, query: str) -> None:
        """Medium: the expression of an alerting rule."""
        self._rule(name)["query"] = query

    def set_retention(self, value: str) -> None:
        """Medium: the storage.tsdb.retention.time flag."""
        self.state["flags"]["storage.tsdb.retention.time"] = value

    def remove_scrape_job(self, job: str) -> None:
        """High (object floor): a scrape job is gone."""
        jobs = self.state["config"]["scrape_configs"]
        jobs.remove(self._job(job))

    def delete_alert_rule(self, name: str) -> None:
        """High (object floor): an alerting rule is gone."""
        for group in self.state["groups"]:
            group["rules"] = [rule for rule in group["rules"] if rule["name"] != name]

    def set_remote_write_url(self, index: int, url: str) -> None:
        """High: a remote write target sends elsewhere (an unnamed one is removed and added)."""
        self.state["config"]["remote_write"][index]["url"] = url

    def enable_admin_api(self) -> None:
        """Critical: the admin API flag."""
        self.state["flags"]["web.enable-admin-api"] = "true"

    def tick(self) -> None:
        """Volatile changes only (rule health, evaluation times, alerts): no drift."""
        for group in self.state["groups"]:
            group["evaluationTime"] += 0.0001
            group["lastEvaluation"] = "2026-11-12T09:01:00Z"
            for rule in group["rules"]:
                rule["evaluationTime"] += 0.0001
                rule["lastEvaluation"] = "2026-11-12T09:01:00Z"
                rule["health"] = "ok"
                if rule["type"] == "alerting":
                    rule["state"] = "firing"
                    rule["alerts"] = [
                        {
                            "labels": {"alertname": rule["name"]},
                            "annotations": {},
                            "state": "firing",
                            "activeAt": "2026-11-12T09:00:30Z",
                            "value": "1e+00",
                        }
                    ]

    def drift(self) -> None:
        """The standard drift of the simulation: one change of each severity the pack grades."""
        self.tick()
        self.set_scrape_interval("node", "30s")  # low
        self.set_alert_query("DiskAlmostFull", "node_filesystem_avail_bytes < 1e9")  # medium
        self.remove_scrape_job("blackbox")  # high
        self.enable_admin_api()  # critical


# -- serving -----------------------------------------------------------------------------------


def _rules(state: dict[str, Any], query: dict[str, list[str]]) -> dict[str, Any]:
    groups = copy.deepcopy(state["groups"])
    wanted = {"alert": "alerting", "record": "recording"}.get(query.get("type", [""])[0])
    for group in groups:
        if wanted is not None:
            group["rules"] = [rule for rule in group["rules"] if rule["type"] == wanted]
        if query.get("exclude_alerts") == ["true"]:
            for rule in group["rules"]:
                rule.pop("alerts", None)
    return {"groups": groups}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"))

    def _error(self, status: int, error_type: str, message: str) -> None:
        self._json(status, {"status": "error", "errorType": error_type, "error": message})

    def _record(self, method: str) -> tuple[str, dict[str, list[str]]]:
        server = cast("_Server", self.server)
        parts = urlsplit(self.path)
        server.requests.append(
            Request(
                method,
                parts.path,
                parts.query,
                self.headers.get("Authorization"),
                self.headers.get("Cookie"),
            )
        )
        return parts.path, parse_qs(parts.query)

    def _refuse(self) -> None:
        self._record(self.command)
        self._error(405, "bad_data", "method not allowed")

    do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

    def do_GET(self) -> None:
        scenario = cast("_Server", self.server).scenario
        path, query = self._record("GET")
        expected = f"Bearer {TOKEN}"
        if scenario.basic is not None:
            pair = base64.b64encode(":".join(scenario.basic).encode()).decode("ascii")
            expected = f"Basic {pair}"
        if scenario.require_token and self.headers.get("Authorization") != expected:
            self._send(401, b"Unauthorized\n", "text/plain")
            return
        route = ROUTES.get(path)
        if route is None:
            self._send(404, b"404 page not found\n", "text/plain")
            return
        forced = scenario.status.get(route)
        if forced is not None:
            self._error(forced, "internal", "simulated failure")
            return
        if route in scenario.raw:
            self._send(200, scenario.raw[route])
            return
        state = scenario.state
        data: Any
        if route == "buildinfo":
            data = state["buildinfo"]
        elif route == "config":
            data = {"yaml": yaml.safe_dump(state["config"], sort_keys=False)}
        elif route == "flags":
            data = state["flags"]
        else:
            data = _rules(state, query)
        self._json(200, {"status": "success", "data": data})


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakePrometheus:
    """A running fake Prometheus."""

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


@contextmanager
def fake_prometheus(scenario: Scenario | None = None) -> Iterator[FakePrometheus]:
    """Serve ``scenario`` (the default Prometheus when None) until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakePrometheus(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
