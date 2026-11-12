"""A fake Grafana HTTP API on localhost for the contract tests, and a model for a later simulation.

It serves the read endpoints the collector uses, with the shapes read from the Grafana HTTP API
documentation on 2026-11-12 (docs/vendor-notes/grafana.md). The data is synthetic: one
organisation with a Prometheus and a PostgreSQL data source, three folders (one nested), three
dashboards, two alert rules, two contact points, a notification policy tree, four users, two
teams and two service accounts.

Like Grafana itself the fake keeps the secure values of data sources and contact points and hides
them when it answers: a data source answers ``password`` and ``basicAuthPassword`` empty and lists
its secure fields in ``secureJsonFields`` as ``true``; a contact point answers its secure settings
as ``[REDACTED]`` (that a plain GET redacts is UNVERIFIED, see the vendor notes). What Grafana does
NOT hide, a webhook URL that carries its own token, is served, so a test can prove that driftsniff
keeps only a fingerprint of it.

Surface (GET only, every other method answers 405):

* ``/api/health`` public, ``{"commit", "database", "version"}``;
* ``/api/org`` ``{"id", "name"}`` for every valid token;
* ``/api/search?type=dash-folder|dash-db&limit=&page=`` a bare list, page by page, for every token;
* ``/api/dashboards/uid/{uid}`` ``{"dashboard": model, "meta": {...}}`` for every token;
* ``/api/datasources``, ``/api/folders/{uid}/permissions``, ``/api/v1/provisioning/alert-rules``,
  ``/api/v1/provisioning/contact-points``, ``/api/v1/provisioning/policies`` (one object),
  ``/api/org/users``, ``/api/teams/search?perpage=&page=`` (``{"totalCount", "teams", "page",
  "perPage"}``) and ``/api/serviceaccounts/search?perpage=&page=`` (``serviceAccounts``) for an
  Admin token only (403 for a Viewer).

The token travels in ``Authorization: Bearer <token>``; a missing or unknown one answers 401.
Errors use Grafana's shape ``{"message"}``. :class:`Scenario` has helpers that change the
configuration so that two reads show a drift (:meth:`Scenario.drift` applies a standard set).
"""

import copy
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlsplit

ADMIN_TOKEN = "CANARY-grafana-admin-00"  # noqa: S105 - a test canary, not a credential
VIEWER_TOKEN = "CANARY-grafana-viewer-00"  # noqa: S105 - a test canary, not a credential
# Secret values Grafana stores; tests check that none of them is ever stored in clear.
DATASOURCE_PASSWORD = "CANARY-gfdb-0"  # noqa: S105
HOOK_URL = "https://hooks.example.invalid/CANARY-grafana-hook-00"
HOOK_PASSWORD = "CANARY-grafana-hook-pass-00"  # noqa: S105
NEW_HOOK_URL = "https://hooks.example.invalid/CANARY-grafana-hook-01"
VERSION = "12.2.1"
REDACTED = "[REDACTED]"

ADMIN_ONLY = frozenset(
    {
        "datasources",
        "folder_permissions",
        "alert_rules",
        "contact_points",
        "policies",
        "org_users",
        "teams",
        "service_accounts",
    }
)
_PROVISIONING = {
    "alert-rules": "alert_rules",
    "contact-points": "contact_points",
    "policies": "policies",
}
# The secure settings of each contact point type the fake serves.
_SECURE_SETTINGS = {"webhook": ("password",), "email": ()}


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    method: str
    path: str
    query: str
    authorization: str | None
    cookie: str | None


def _panel(panel_id: int, title: str, expr: str) -> dict[str, Any]:
    return {
        "id": panel_id,
        "type": "timeseries",
        "title": title,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "datasource": {"type": "prometheus", "uid": "prom-main"},
        "targets": [{"refId": "A", "expr": expr}],
    }


def _query(ref_id: str, datasource: str, model: dict[str, Any]) -> dict[str, Any]:
    return {
        "refId": ref_id,
        "queryType": "",
        "relativeTimeRange": {"from": 600, "to": 0},
        "datasourceUid": datasource,
        "model": {"refId": ref_id, **model},
    }


def default_state() -> dict[str, Any]:
    """The stored configuration of a small synthetic Grafana organisation."""
    return {
        "datasources": [
            {
                "id": 1,
                "orgId": 1,
                "uid": "prom-main",
                "name": "Prometheus",
                "type": "prometheus",
                "typeLogoUrl": "public/app/plugins/datasource/prometheus/img/prometheus_logo.svg",
                "access": "proxy",
                "url": "http://192.0.2.10:9090",
                "user": "",
                "database": "",
                "basicAuth": False,
                "basicAuthUser": "",
                "withCredentials": False,
                "isDefault": True,
                "jsonData": {"httpMethod": "POST", "timeInterval": "30s"},
                "_secure": {},
                "version": 3,
                "readOnly": False,
            },
            {
                "id": 2,
                "orgId": 1,
                "uid": "pg-inventory",
                "name": "Inventory DB",
                "type": "grafana-postgresql-datasource",
                "typeLogoUrl": "public/plugins/grafana-postgresql-datasource/img/logo.svg",
                "access": "proxy",
                "url": "db-01.lab.example.invalid:5432",
                "user": "grafana_reader",
                "database": "",
                "basicAuth": False,
                "basicAuthUser": "",
                "withCredentials": False,
                "isDefault": False,
                "jsonData": {
                    "database": "inventory",
                    "sslmode": "require",
                    "tlsSkipVerify": False,
                    "maxOpenConns": 10,
                },
                "_secure": {"password": DATASOURCE_PASSWORD},
                "version": 7,
                "readOnly": False,
            },
        ],
        "folders": [
            {
                "id": 11,
                "uid": "fold-ops",
                "title": "Operations",
                "parent": None,
                "permissions": [
                    {"userId": 0, "teamId": 0, "role": "Viewer", "permission": 1},
                    {"userId": 0, "teamId": 0, "role": "Editor", "permission": 2},
                    {"userId": 0, "teamId": 1, "team": "sre", "role": "", "permission": 4},
                ],
            },
            {
                "id": 12,
                "uid": "fold-net",
                "title": "Network",
                "parent": "fold-ops",
                "permissions": [
                    {"userId": 0, "teamId": 0, "role": "Viewer", "permission": 1},
                    {"userId": 0, "teamId": 0, "role": "Editor", "permission": 2},
                ],
            },
            {
                "id": 13,
                "uid": "fold-biz",
                "title": "Business",
                "parent": None,
                "permissions": [
                    {"userId": 3, "userLogin": "dana", "teamId": 0, "role": "", "permission": 2},
                ],
            },
        ],
        "dashboards": [
            {
                "folder": "fold-ops",
                "model": {
                    "id": 21,
                    "uid": "dash-hosts",
                    "title": "Host overview",
                    "tags": ["hosts", "ops"],
                    "timezone": "browser",
                    "schemaVersion": 39,
                    "version": 12,
                    "panels": [
                        _panel(1, "CPU", "avg by (instance) (rate(node_cpu_seconds_total[5m]))"),
                        _panel(2, "Memory", "node_memory_MemAvailable_bytes"),
                    ],
                    "templating": {"list": []},
                    "time": {"from": "now-6h", "to": "now"},
                    "refresh": "1m",
                },
            },
            {
                "folder": "fold-net",
                "model": {
                    "id": 22,
                    "uid": "dash-links",
                    "title": "Uplinks",
                    "tags": ["network"],
                    "timezone": "utc",
                    "schemaVersion": 39,
                    "version": 4,
                    "panels": [_panel(1, "Throughput", "rate(ifHCInOctets[5m]) * 8")],
                },
            },
            {
                "folder": "fold-biz",
                "model": {
                    "id": 23,
                    "uid": "dash-stock",
                    "title": "Stock levels",
                    "tags": [],
                    "timezone": "browser",
                    "schemaVersion": 39,
                    "version": 2,
                    "panels": [],
                },
            },
        ],
        "alert_rules": [
            {
                "id": 31,
                "uid": "rule-cpu",
                "orgID": 1,
                "folderUID": "fold-ops",
                "ruleGroup": "hosts",
                "title": "CPU high",
                "condition": "B",
                "data": [
                    _query("A", "prom-main", {"expr": "avg(rate(node_cpu_seconds_total[5m]))"}),
                    _query("B", "__expr__", {"type": "threshold", "expression": "A"}),
                ],
                "updated": "2026-11-12T08:00:00Z",
                "noDataState": "NoData",
                "execErrState": "Error",
                "for": "5m",
                "keepFiringFor": "0s",
                "annotations": {"summary": "CPU above 90 percent"},
                "labels": {"team": "sre"},
                "provenance": "",
                "isPaused": False,
            },
            {
                "id": 32,
                "uid": "rule-link",
                "orgID": 1,
                "folderUID": "fold-net",
                "ruleGroup": "network",
                "title": "Uplink down",
                "condition": "B",
                "data": [
                    _query("A", "prom-main", {"expr": 'up{job="snmp"}'}),
                    _query("B", "__expr__", {"type": "threshold", "expression": "A"}),
                ],
                "updated": "2026-11-12T08:00:00Z",
                "noDataState": "Alerting",
                "execErrState": "Error",
                "for": "2m",
                "keepFiringFor": "0s",
                "annotations": {},
                "labels": {"team": "network"},
                "provenance": "file",
                "isPaused": False,
            },
        ],
        "contact_points": [
            {
                "uid": "cp-hook",
                "name": "on-call webhook",
                "type": "webhook",
                "settings": {
                    "url": HOOK_URL,
                    "httpMethod": "POST",
                    "username": "grafana",
                    "password": HOOK_PASSWORD,
                },
                "disableResolveMessage": False,
                "provenance": "",
            },
            {
                "uid": "cp-mail",
                "name": "ops mail",
                "type": "email",
                "settings": {"addresses": "ops@example.invalid", "singleEmail": True},
                "disableResolveMessage": False,
                "provenance": "",
            },
        ],
        "policies": {
            "receiver": "ops mail",
            "group_by": ["grafana_folder", "alertname"],
            "group_wait": "30s",
            "group_interval": "5m",
            "repeat_interval": "4h",
            "routes": [
                {
                    "receiver": "on-call webhook",
                    "object_matchers": [["team", "=", "sre"]],
                    "continue": False,
                },
                {"receiver": "ops mail", "object_matchers": [["team", "=", "network"]]},
            ],
            "provenance": "",
        },
        "org_users": [
            _user(1, "admin", "Admin"),
            _user(2, "erin", "Editor"),
            _user(3, "dana", "Viewer"),
            _user(4, "kiosk", "Viewer"),
        ],
        "teams": [
            {"id": 1, "orgId": 1, "name": "sre", "email": "sre@example.invalid", "memberCount": 2},
            {"id": 2, "orgId": 1, "name": "network", "email": "", "memberCount": 1},
        ],
        "service_accounts": [
            {
                "id": 5,
                "name": "driftsniff",
                "login": "sa-1-driftsniff",
                "orgId": 1,
                "isDisabled": False,
                "role": "Admin",
                "tokens": 1,
            },
            {
                "id": 6,
                "name": "terraform",
                "login": "sa-1-terraform",
                "orgId": 1,
                "isDisabled": False,
                "role": "Editor",
                "tokens": 2,
            },
        ],
    }


def _user(user_id: int, login: str, role: str) -> dict[str, Any]:
    return {
        "orgId": 1,
        "userId": user_id,
        "email": f"{login}@example.invalid",
        "name": login.title(),
        "avatarUrl": f"/avatar/{user_id:032x}",
        "login": login,
        "role": role,
        "lastSeenAt": "2026-11-12T08:00:00Z",
        "lastSeenAtAge": "10m",
    }


@dataclass
class Scenario:
    """What the fake Grafana stores and which faults it simulates.

    ``tokens`` maps an accepted token to its organisation role (``Admin`` or ``Viewer``). Faults
    are keyed by the route name: ``health``, ``org``, ``search``, ``dashboard``, or a resource
    key such as ``datasources``, ``folder_permissions`` or ``teams``.
    """

    state: dict[str, Any] = field(default_factory=default_state)
    tokens: dict[str, str] = field(
        default_factory=lambda: {ADMIN_TOKEN: "Admin", VIEWER_TOKEN: "Viewer"}
    )
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    # Serve every list in reverse order (the order must never matter).
    reverse: bool = False
    # Put the received Authorization header into the body of error answers (a leaking server).
    echo_key: bool = False

    # -- drift helpers ----------------------------------------------------------------------

    def _find(self, name: str, key: Any, key_field: str = "uid") -> dict[str, Any]:
        for item in self.state[name]:
            if item[key_field] == key:
                return cast("dict[str, Any]", item)
        raise KeyError(f"{name} {key}")

    def _dashboard(self, uid: str) -> dict[str, Any]:
        for item in self.state["dashboards"]:
            if item["model"]["uid"] == uid:
                return cast("dict[str, Any]", item["model"])
        raise KeyError(uid)

    def set_user_role(self, user_id: int, role: str) -> None:
        """Give an organisation user the role None, Viewer, Editor or Admin."""
        self._find("org_users", user_id, "userId")["role"] = role

    def set_datasource_url(self, uid: str, url: str) -> None:
        source = self._find("datasources", uid)
        source["url"] = url
        source["version"] += 1

    def set_datasource_tls_skip_verify(self, uid: str, value: bool) -> None:
        source = self._find("datasources", uid)
        source["jsonData"]["tlsSkipVerify"] = value
        source["version"] += 1

    def pause_alert_rule(self, uid: str, paused: bool = True) -> None:
        rule = self._find("alert_rules", uid)
        rule["isPaused"] = paused
        rule["updated"] = "2026-11-12T09:30:00Z"

    def delete_alert_rule(self, uid: str) -> None:
        self.state["alert_rules"].remove(self._find("alert_rules", uid))

    def set_contact_point_setting(self, uid: str, name: str, value: Any) -> None:
        self._find("contact_points", uid)["settings"][name] = value

    def set_policy_receiver(self, receiver: str) -> None:
        self.state["policies"]["receiver"] = receiver

    def retitle_panel(self, dashboard_uid: str, index: int, title: str) -> None:
        """Change a panel title and save the dashboard (its version goes up)."""
        model = self._dashboard(dashboard_uid)
        model["panels"][index]["title"] = title
        model["version"] += 1

    def grant_folder(self, folder_uid: str, team_id: int, team: str, permission: int) -> None:
        self._find("folders", folder_uid)["permissions"].append(
            {"userId": 0, "teamId": team_id, "team": team, "role": "", "permission": permission}
        )

    def add_team(self, team_id: int, name: str) -> None:
        self.state["teams"].append(
            {"id": team_id, "orgId": 1, "name": name, "email": "", "memberCount": 0}
        )

    def tick(self) -> None:
        """Volatile changes only (last seen, saves without a change, rule evaluation stamps)."""
        for user in self.state["org_users"]:
            user["lastSeenAt"] = "2026-11-12T09:00:00Z"
            user["lastSeenAtAge"] = "1m"
        for item in self.state["dashboards"]:
            item["model"]["version"] += 1
        for rule in self.state["alert_rules"]:
            rule["updated"] = "2026-11-12T09:00:00Z"
        for source in self.state["datasources"]:
            source["version"] += 1

    def drift(self) -> None:
        """The standard drift of the simulation: one change of each kind the pack grades."""
        self.tick()
        self.set_user_role(3, "Admin")  # critical
        self.set_datasource_url("prom-main", "http://192.0.2.20:9090")  # high
        self.pause_alert_rule("rule-cpu")  # high
        self.set_contact_point_setting("cp-hook", "url", NEW_HOOK_URL)  # high (floor)
        self.add_team(3, "contractors")  # medium
        self.retitle_panel("dash-hosts", 0, "CPU busy")  # low


# -- serving -----------------------------------------------------------------------------------


def _search_hit(kind: str, item: dict[str, Any], folders: list[dict[str, Any]]) -> dict[str, Any]:
    """One search result, with the fields the documentation lists."""
    if kind == "dash-folder":
        uid, title, parent, item_id, tags = (
            item["uid"],
            item["title"],
            item["parent"],
            item["id"],
            [],
        )
    else:
        model = item["model"]
        uid, title, parent, item_id = model["uid"], model["title"], item["folder"], model["id"]
        tags = model.get("tags", [])
    slug = title.lower().replace(" ", "-")
    prefix = "/dashboards/f" if kind == "dash-folder" else "/d"
    hit: dict[str, Any] = {
        "id": item_id,
        "uid": uid,
        "orgId": 1,
        "title": title,
        "uri": f"db/{slug}",
        "url": f"{prefix}/{uid}/{slug}",
        "slug": "",
        "type": kind,
        "tags": tags,
        "isStarred": False,
        "sortMeta": 0,
    }
    if parent is not None:
        folder = next(f for f in folders if f["uid"] == parent)
        hit.update(
            folderId=folder["id"],
            folderUid=parent,
            folderTitle=folder["title"],
            folderUrl=f"/dashboards/f/{parent}/",
        )
    return hit


def _hidden_datasource(source: dict[str, Any]) -> dict[str, Any]:
    answer = {key: value for key, value in source.items() if key != "_secure"}
    answer["password"] = ""
    answer["basicAuthPassword"] = ""
    answer["secureJsonFields"] = dict.fromkeys(source["_secure"], True)
    return answer


def _hidden_contact_point(point: dict[str, Any]) -> dict[str, Any]:
    answer = copy.deepcopy(point)
    for name in _SECURE_SETTINGS.get(point["type"], ()):
        if name in answer["settings"]:
            answer["settings"][name] = REDACTED
    return answer


def _permission_entry(folder: dict[str, Any], index: int, entry: dict[str, Any]) -> dict[str, Any]:
    names = {1: "View", 2: "Edit", 4: "Admin"}
    return {
        "id": folder["id"] * 100 + index,
        "folderId": folder["id"],
        "created": "2026-11-01T10:00:00Z",
        "updated": "2026-11-01T10:00:00Z",
        "userId": entry.get("userId", 0),
        "userLogin": entry.get("userLogin", ""),
        "userEmail": "",
        "teamId": entry.get("teamId", 0),
        "team": entry.get("team", ""),
        "role": entry.get("role", ""),
        "permission": entry["permission"],
        "permissionName": names[entry["permission"]],
        "uid": folder["uid"],
        "title": folder["title"],
        "slug": "",
        "isFolder": True,
        "url": "",
    }


def _page(items: list[Any], query: dict[str, list[str]], size_key: str) -> list[Any]:
    size = int(query.get(size_key, ["1000"])[0])
    page = int(query.get("page", ["1"])[0])
    return items[(page - 1) * size : page * size]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"))

    def _error(self, status: int, message: str) -> None:
        scenario = cast("_Server", self.server).scenario
        text = self.headers.get("Authorization", "") if scenario.echo_key else message
        self._json(status, {"message": text})

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
        self._error(405, "Method Not Allowed")

    do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

    def _route(self, path: str) -> tuple[str, str] | None:
        """The route key and its argument (a uid), or None for an unknown path."""
        parts = [unquote(part) for part in path.strip("/").split("/")]
        fixed = {
            "api/org": "org",
            "api/search": "search",
            "api/datasources": "datasources",
            "api/org/users": "org_users",
            "api/teams/search": "teams",
            "api/serviceaccounts/search": "service_accounts",
        }
        joined = "/".join(parts)
        if joined in fixed:
            return fixed[joined], ""
        if parts[:3] == ["api", "v1", "provisioning"] and len(parts) == 4:
            key = _PROVISIONING.get(parts[3])
            return (key, "") if key else None
        if parts[:3] == ["api", "dashboards", "uid"] and len(parts) == 4:
            return "dashboard", parts[3]
        if parts[:2] == ["api", "folders"] and len(parts) == 4 and parts[3] == "permissions":
            return "folder_permissions", parts[2]
        return None

    def do_GET(self) -> None:
        scenario = cast("_Server", self.server).scenario
        path, query = self._record("GET")
        if path == "/api/health":
            if "health" in scenario.status:
                self._error(scenario.status["health"], "Simulated failure")
            elif "health" in scenario.raw:
                self._send(200, scenario.raw["health"])
            else:
                self._json(200, {"commit": "0123abc", "database": "ok", "version": VERSION})
            return
        header = self.headers.get("Authorization") or ""
        role = (
            scenario.tokens.get(header.removeprefix("Bearer "))
            if header.startswith("Bearer ")
            else None
        )
        if role is None:
            self._error(401, "Unauthorized")
            return
        route = self._route(path)
        if route is None:
            self._error(404, "Not found")
            return
        key, argument = route
        forced = scenario.status.get(key)
        if forced is not None:
            self._error(forced, "Simulated failure")
            return
        if key in scenario.raw:
            self._send(200, scenario.raw[key])
            return
        if key in ADMIN_ONLY and role != "Admin":
            self._error(403, "You'll need additional permissions to perform this action.")
            return
        answer = self._answer(scenario, key, argument, query)
        if answer is None:
            self._error(404, "Not found")
            return
        if scenario.reverse and isinstance(answer, list):
            answer.reverse()
        self._json(200, answer)

    @staticmethod
    def _answer(scenario: Scenario, key: str, argument: str, query: dict[str, list[str]]) -> Any:
        state = scenario.state
        if key == "org":
            return {"id": 1, "name": "Main Org."}
        if key == "search":
            kind = query.get("type", [""])[0]
            source = state["folders"] if kind == "dash-folder" else state["dashboards"]
            hits = [_search_hit(kind, item, state["folders"]) for item in source]
            hits.sort(key=lambda hit: hit["title"])
            return _page(hits, query, "limit")
        if key == "dashboard":
            for item in state["dashboards"]:
                model = item["model"]
                if model["uid"] == argument:
                    folder = next(f for f in state["folders"] if f["uid"] == item["folder"])
                    meta = {
                        "isStarred": False,
                        "url": f"/d/{argument}/",
                        "folderId": folder["id"],
                        "folderUid": folder["uid"],
                        "folderTitle": folder["title"],
                        "slug": "",
                        "version": model["version"],
                        "canSave": True,
                        "canEdit": True,
                    }
                    return {"dashboard": copy.deepcopy(model), "meta": meta}
            return None
        if key == "datasources":
            return [_hidden_datasource(source) for source in state["datasources"]]
        if key == "folder_permissions":
            for folder in state["folders"]:
                if folder["uid"] == argument:
                    return [
                        _permission_entry(folder, index, entry)
                        for index, entry in enumerate(folder["permissions"])
                    ]
            return None
        if key == "contact_points":
            return [_hidden_contact_point(point) for point in state["contact_points"]]
        if key in ("teams", "service_accounts"):
            items = copy.deepcopy(state[key])
            page = _page(items, query, "perpage")
            name = "teams" if key == "teams" else "serviceAccounts"
            return {
                "totalCount": len(items),
                name: page,
                "page": int(query.get("page", ["1"])[0]),
                "perPage": int(query.get("perpage", ["1000"])[0]),
            }
        return copy.deepcopy(state[key])


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeGrafana:
    """A running fake Grafana."""

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
def fake_grafana(scenario: Scenario | None = None) -> Iterator[FakeGrafana]:
    """Serve ``scenario`` (the default organisation when None) until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeGrafana(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
