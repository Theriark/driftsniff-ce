"""A fake Checkmk REST API on localhost for the contract tests, and a model for a later simulation.

It serves the read endpoints the collector uses, with the paths and answer shapes read from the
Checkmk source (tag 2.4.0) on 2026-11-12 (docs/vendor-notes/checkmk.md). The data is synthetic: a
site ``mysite`` with four hosts in three folders, host, service and contact groups, users, time
periods, the password store and two notification rules.

Like Checkmk itself the fake keeps what the site stores and leaves out what the REST API never
returns: user passwords and automation secrets, and the password of a password store entry. What
Checkmk does return (host and folder SNMP communities, IPMI credentials of a management board,
the parameters of a notification method) is served, so a test can prove that driftsniff keeps
only fingerprints of them.

Surface (GET only, every other method answers 405), below ``/<site>/check_mk/api/1.0``:

* ``/version`` ``{"site", "group", "rest_api", "versions": {"checkmk", ...}, "edition", "demo"}``;
* ``/domain-types/<type>/collections/all`` for ``host_config`` (query ``effective_attributes``),
  ``folder_config`` (query ``recursive``; without it only the subfolders of the root),
  ``host_group_config``, ``service_group_config``, ``contact_group_config``, ``user_config``,
  ``time_period``, ``password`` and ``notification_rule``. Each answers a collection
  ``{"links", "id", "domainType", "value": [domain object], "extensions"}``; a domain object is
  ``{"links", "domainType", "id", "title", "members", "extensions"}``.

Credentials travel in ``Authorization: Bearer <user> <secret>``; a missing or wrong one answers
401. A user without the permission for a collection also gets 401, as Checkmk raises the same
authentication error for a missing permission. Errors use Checkmk's problem shape
``{"title", "status", "detail"}``. An unknown site answers 404 with an HTML body.
:class:`Scenario` has helpers that change the configuration so that two reads show a drift
(:meth:`Scenario.drift` applies a standard set; :meth:`Scenario.tick` changes volatile fields
only).
"""

import copy
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

SITE = "mysite"
API = f"/{SITE}/check_mk/api/1.0"
AUTOMATION_USER = "automation"
AUTOMATION_SECRET = "CANARY-checkmk-00"  # noqa: S105 - a test canary, not a credential
READER_USER = "driftsniff-reader"
READER_SECRET = "CANARY-checkmk-01"  # noqa: S105
# Secret values the site stores; tests check that none of them is ever stored in clear.
SNMP_COMMUNITY = "CANARY-checkmk-02"
SNMP_AUTH_PASSWORD = "CANARY-checkmk-03"  # noqa: S105
SNMP_PRIVACY_PASSWORD = "CANARY-checkmk-04"  # noqa: S105
IPMI_PASSWORD = "CANARY-checkmk-05"  # noqa: S105
WEBHOOK_URL = "https://hooks.example.invalid/CANARY-checkmk-06"
STORED_PASSWORD = "CANARY-checkmk-07"  # noqa: S105 - never served, as in Checkmk
VERSION = "2.4.0p2.cre"

DOMAIN_TYPES = {
    "host_config": "hosts",
    "folder_config": "folders",
    "host_group_config": "host_groups",
    "service_group_config": "service_groups",
    "contact_group_config": "contact_groups",
    "user_config": "users",
    "time_period": "time_periods",
    "password": "passwords",
    "notification_rule": "notification_rules",
}
# What the reader may not list: Checkmk needs wato.users for users and contact groups and
# wato.passwords for the password store.
READER_DENIED = frozenset({"users", "contact_groups", "passwords"})


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    method: str
    path: str
    query: str
    authorization: str | None
    cookie: str | None


def _meta(second: int) -> dict[str, Any]:
    return {
        "created_at": 1762800000.0,
        "updated_at": 1762800000.0 + second,
        "created_by": "cmkadmin",
    }


def _contactgroups(*groups: str) -> dict[str, Any]:
    return {
        "groups": list(groups),
        "use": True,
        "use_for_services": False,
        "recurse_use": False,
        "recurse_perms": False,
    }


def _state(on: bool, value: Any = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"state": "enabled" if on else "disabled"}
    if value is not None:
        entry["value"] = value
    return entry


def _notification_rule(rule_id: str, description: str, plugin: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": rule_id,
        "rule_config": {
            "rule_properties": {
                "description": description,
                "comment": "",
                "documentation_url": "",
                "do_not_apply_this_rule": _state(False),
                "allow_users_to_deactivate": _state(True),
            },
            "notification_method": {
                "notify_plugin": {
                    "option": "create_notification_with_the_following_parameters",
                    "plugin_params": plugin,
                },
                "notification_bulking": _state(False),
            },
            "contact_selection": {
                "all_contacts_of_the_notified_object": _state(True),
                "all_users": _state(False),
                "members_of_contact_groups": _state(True, ["ops"]),
            },
            "conditions": {
                "match_host_groups": _state(True, ["linux-servers"]),
                "match_only_during_time_period": _state(True, "workhours"),
            },
        },
    }


def default_state() -> dict[str, Any]:
    """The stored Setup configuration of a small synthetic Checkmk site."""
    return {
        "hosts": [
            {
                "id": "web-01",
                "folder": "/servers/linux",
                "attributes": {
                    "alias": "Web server 1",
                    "ipaddress": "192.0.2.10",
                    "labels": {"env": "prod", "os": "linux"},
                    "tag_agent": "cmk-agent",
                    "tag_criticality": "prod",
                    "meta_data": _meta(0),
                },
            },
            {
                "id": "db-01",
                "folder": "/servers/linux",
                "attributes": {
                    "ipaddress": "192.0.2.11",
                    "parents": ["switch-core"],
                    "management_protocol": "ipmi",
                    "management_address": "192.0.2.111",
                    "management_ipmi_credentials": {"username": "ipmi", "password": IPMI_PASSWORD},
                    "contactgroups": _contactgroups("dba"),
                    "meta_data": _meta(0),
                    "inventory_failed": False,
                },
            },
            {
                "id": "switch-core",
                "folder": "/network",
                "attributes": {
                    "ipaddress": "198.51.100.2",
                    "tag_agent": "no-agent",
                    "tag_snmp_ds": "snmp-v2",
                    "snmp_community": SNMP_COMMUNITY,
                    "meta_data": _meta(0),
                },
            },
            {
                "id": "printer-01",
                "folder": "/network",
                "attributes": {
                    "alias": "Floor printer",
                    "ipaddress": "198.51.100.40",
                    "tag_criticality": "offline",
                    "meta_data": _meta(0),
                    "waiting_for_discovery": False,
                },
            },
        ],
        "folders": [
            {"id": "~", "title": "Main", "path": "/", "attributes": {"meta_data": _meta(0)}},
            {
                "id": "~servers",
                "title": "Servers",
                "path": "/servers",
                "attributes": {
                    "tag_agent": "cmk-agent",
                    "contactgroups": _contactgroups("ops"),
                    "meta_data": _meta(0),
                },
            },
            {
                "id": "~servers~linux",
                "title": "Linux",
                "path": "/servers/linux",
                "attributes": {"labels": {"os": "linux"}, "meta_data": _meta(0)},
            },
            {
                "id": "~network",
                "title": "Network",
                "path": "/network",
                "attributes": {
                    "tag_snmp_ds": "snmp-v2",
                    "snmp_community": [
                        "authPriv",
                        "SHA-256",
                        "driftsniff",
                        SNMP_AUTH_PASSWORD,
                        "AES-128",
                        SNMP_PRIVACY_PASSWORD,
                    ],
                    "network_scan_result": {"state": True, "start": 1762800000, "end": None},
                    "meta_data": _meta(0),
                },
            },
        ],
        "host_groups": [
            {"id": "linux-servers", "alias": "Linux servers"},
            {"id": "network", "alias": "Network devices"},
        ],
        "service_groups": [{"id": "web", "alias": "Web services"}],
        "contact_groups": [
            {"id": "all", "alias": "Everything", "inventory_paths": {"type": "allow_all"}},
            {"id": "ops", "alias": "Operations", "inventory_paths": {"type": "allow_all"}},
            {
                "id": "dba",
                "alias": "Database admins",
                "inventory_paths": {
                    "type": "specific_paths",
                    "paths": [
                        {
                            "path": "software.applications",
                            "attributes": {"type": "no_restriction"},
                            "columns": {"type": "restrict_values", "values": ["name"]},
                            "nodes": {"type": "no_restriction"},
                        }
                    ],
                },
            },
        ],
        "users": [
            {
                "id": AUTOMATION_USER,
                "fullname": "Check_MK Automation",
                "roles": ["admin"],
                "contactgroups": [],
                "disable_login": False,
                "auth_option": {"auth_type": "automation", "store_automation_secret": False},
                "idle_timeout": {"option": "global"},
                "disable_notifications": {},
                "_secret": AUTOMATION_SECRET,
            },
            {
                "id": "cmkadmin",
                "fullname": "cmkadmin",
                "roles": ["admin"],
                "contactgroups": ["all"],
                "disable_login": False,
                "auth_option": {"auth_type": "password", "enforce_password_change": False},
                "idle_timeout": {"option": "global"},
                "disable_notifications": {},
                "interface_options": {"interface_theme": "modern-dark"},
                "_password": "CANARY-checkmk-08",
            },
            {
                "id": "ops-anna",
                "fullname": "Anna Ops",
                "roles": ["user"],
                "contactgroups": ["ops"],
                "disable_login": False,
                "contact_options": {"email": "anna@example.invalid", "fallback_contact": False},
                "auth_option": {"auth_type": "password", "enforce_password_change": False},
                "idle_timeout": {"option": "individual", "duration": 3600},
                "disable_notifications": {},
                "language": "en",
                "_password": "CANARY-checkmk-09",
            },
            {
                "id": "former-ops",
                "fullname": "Former Ops",
                "roles": ["user"],
                "contactgroups": ["ops"],
                "disable_login": True,
                "auth_option": {"auth_type": "password", "enforce_password_change": True},
                "idle_timeout": {"option": "global"},
                "disable_notifications": {"disable": True},
            },
            {
                "id": READER_USER,
                "fullname": "driftsniff reader",
                "roles": ["guest"],
                "contactgroups": [],
                "disable_login": False,
                "auth_option": {"auth_type": "automation", "store_automation_secret": False},
                "idle_timeout": {"option": "global"},
                "disable_notifications": {},
                "_secret": READER_SECRET,
            },
        ],
        "time_periods": [
            {
                "id": "24X7",
                "alias": "Always",
                "active_time_ranges": [
                    {"day": day, "time_ranges": [{"start": "00:00", "end": "23:59"}]}
                    for day in (
                        "monday",
                        "tuesday",
                        "wednesday",
                        "thursday",
                        "friday",
                        "saturday",
                        "sunday",
                    )
                ],
                "exceptions": [],
            },
            {
                "id": "workhours",
                "alias": "Work hours",
                "exclude": [],
                "active_time_ranges": [
                    {"day": day, "time_ranges": [{"start": "08:00", "end": "17:00"}]}
                    for day in ("monday", "tuesday", "wednesday", "thursday", "friday")
                ],
                "exceptions": [
                    {"date": "2026-12-25", "time_ranges": []},
                ],
            },
        ],
        "passwords": [
            {
                "id": "snmp-switches",
                "title": "SNMP switches",
                "comment": "Read community of the core switches",
                "docu_url": "",
                "owned_by": "admin",
                "shared_with": ["ops"],
                "_password": STORED_PASSWORD,
            },
        ],
        "notification_rules": [
            _notification_rule(
                "3f1c0d4e-0000-4000-8000-000000000001",
                "Mail the contacts",
                {"plugin_name": "mail", "from": {"address": "checkmk@example.invalid"}},
            ),
            _notification_rule(
                "3f1c0d4e-0000-4000-8000-000000000002",
                "Chat webhook",
                {"plugin_name": "slack", "webhook_url": ["webhook_url", WEBHOOK_URL]},
            ),
        ],
    }


@dataclass
class Scenario:
    """What the fake Checkmk stores and which faults it simulates.

    ``accounts`` maps an automation user to its secret. Faults are keyed by the route name:
    ``version`` or a collection name such as ``hosts``.
    """

    state: dict[str, Any] = field(default_factory=default_state)
    accounts: dict[str, str] = field(
        default_factory=lambda: {AUTOMATION_USER: AUTOMATION_SECRET, READER_USER: READER_SECRET}
    )
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    # Serve every collection in reverse order (the order must never matter).
    reverse: bool = False
    # Put the received Authorization header into the detail of error answers (a leaking server).
    echo_credentials: bool = False

    # -- drift helpers ----------------------------------------------------------------------

    def _find(self, name: str, key: str) -> dict[str, Any]:
        for item in self.state[name]:
            if item["id"] == key:
                return cast("dict[str, Any]", item)
        raise KeyError(f"{name} {key}")

    def grant_role(self, user_id: str, role: str) -> None:
        """Give a user one more role (``admin``, ``user``, ``guest``)."""
        self._find("users", user_id)["roles"].append(role)

    def set_disable_login(self, user_id: str, value: bool) -> None:
        self._find("users", user_id)["disable_login"] = value

    def remove_host(self, host: str) -> None:
        self.state["hosts"] = [item for item in self.state["hosts"] if item["id"] != host]

    def set_host_label(self, host: str, key: str, value: str | None) -> None:
        """Add, change or (with None) remove a label of a host."""
        labels = self._find("hosts", host)["attributes"].setdefault("labels", {})
        if value is None:
            labels.pop(key, None)
        else:
            labels[key] = value

    def set_folder_attribute(self, folder: str, name: str, value: Any) -> None:
        self._find("folders", folder)["attributes"][name] = value

    def set_snmp_community(self, host: str, value: str) -> None:
        self._find("hosts", host)["attributes"]["snmp_community"] = value

    def set_contact_group_alias(self, group: str, alias: str) -> None:
        self._find("contact_groups", group)["alias"] = alias

    def tick(self) -> None:
        """Volatile changes only (bookkeeping, scan results, discovery flags): no drift."""
        for name in ("hosts", "folders"):
            for item in self.state[name]:
                item["attributes"]["meta_data"]["updated_at"] += 60
        for host in self.state["hosts"]:
            attributes = host["attributes"]
            attributes["inventory_failed"] = not attributes.get("inventory_failed", False)
            attributes["waiting_for_discovery"] = True
        scan = self._find("folders", "~network")["attributes"]["network_scan_result"]
        scan["start"] += 3600
        scan["end"] = scan["start"] + 12

    def drift(self) -> None:
        """The standard drift of the simulation: one change of each kind the pack grades."""
        self.tick()
        self.grant_role("ops-anna", "admin")  # critical
        self.set_disable_login("former-ops", False)  # high
        self.remove_host("printer-01")  # high
        self.set_folder_attribute("~servers", "tag_agent", "all-agents")  # medium
        self.set_contact_group_alias("ops", "Operations team")  # medium
        self.set_host_label("web-01", "env", "staging")  # low


# -- serving -----------------------------------------------------------------------------------


def _domain_object(domain_type: str, ident: str, title: str, extensions: Any) -> dict[str, Any]:
    return {
        "links": [
            {
                "domainType": "link",
                "rel": "self",
                "href": f"http://127.0.0.1{API}/objects/{domain_type}/{ident}",
                "method": "GET",
                "type": "application/json",
            }
        ],
        "domainType": domain_type,
        "id": ident,
        "title": title,
        "members": {},
        "extensions": extensions,
    }


def _hidden(item: dict[str, Any]) -> dict[str, Any]:
    """The stored item without what Checkmk never serves (keys starting with an underscore)."""
    return {key: value for key, value in copy.deepcopy(item).items() if not key.startswith("_")}


def _serve(name: str, item: dict[str, Any], query: dict[str, list[str]]) -> dict[str, Any]:
    """One stored item as the domain object Checkmk builds for it (docs/vendor-notes/checkmk.md)."""
    data = _hidden(item)
    ident = data.pop("id")
    if name == "hosts":
        effective = query.get("effective_attributes") == ["true"]
        extensions = {
            "folder": data["folder"],
            "attributes": data["attributes"],
            "effective_attributes": copy.deepcopy(data["attributes"]) if effective else None,
            "is_cluster": False,
            "is_offline": data["attributes"].get("tag_criticality") == "offline",
            "cluster_nodes": None,
        }
        title = data["attributes"].get("alias") or ident
        return _domain_object("host_config", ident, title, extensions)
    if name == "folders":
        title = data.pop("title")
        return _domain_object("folder_config", ident, title, data)
    if name in ("host_groups", "service_groups", "contact_groups"):
        alias = data.pop("alias")
        return _domain_object(f"{name[:-1]}_config", ident, alias, data)
    if name == "users":
        return _domain_object("user_config", ident, data["fullname"], data)
    if name == "time_periods":
        return _domain_object("time_period", ident, data["alias"], data)
    if name == "passwords":
        title = data.pop("title")
        return _domain_object("password", ident, title, data)
    description = data["rule_config"]["rule_properties"]["description"]
    return _domain_object("notification_rule", ident, description, data)


def _collection(scenario: Scenario, domain_type: str, query: dict[str, list[str]]) -> Any:
    name = DOMAIN_TYPES[domain_type]
    items = scenario.state[name]
    if name == "folders" and query.get("recursive") != ["true"]:
        items = [item for item in items if item["path"].count("/") == 1 and item["path"] != "/"]
    value = [_serve(name, item, query) for item in items]
    if scenario.reverse:
        value.reverse()
    return {
        "links": [
            {
                "domainType": "link",
                "rel": "self",
                "href": f"http://127.0.0.1{API}/domain-types/{domain_type}/collections/all",
                "method": "GET",
                "type": "application/json",
            }
        ],
        "id": "host" if domain_type == "host_config" else domain_type,
        "domainType": domain_type,
        "value": value,
        "extensions": {},
    }


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

    def _problem(self, status: int, title: str, detail: str) -> None:
        scenario = cast("_Server", self.server).scenario
        if scenario.echo_credentials:
            detail = self.headers.get("Authorization", "")
        self._send(
            status,
            json.dumps({"title": title, "status": status, "detail": detail}).encode("utf-8"),
            "application/problem+json",
        )

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
        self._problem(405, "Method Not Allowed", "The method is not allowed for the requested URL.")

    do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

    def _user(self, scenario: Scenario) -> str | None:
        """The automation user the Bearer header names, when its secret is right."""
        header = self.headers.get("Authorization") or ""
        if not header.startswith("Bearer "):
            return None
        user, _, secret = header.removeprefix("Bearer ").strip().partition(" ")
        return user if user and scenario.accounts.get(user) == secret else None

    def do_GET(self) -> None:
        scenario = cast("_Server", self.server).scenario
        path, query = self._record("GET")
        if not path.startswith(f"{API}/"):
            self._send(404, b"<html><body>Not Found</body></html>", "text/html")
            return
        user = self._user(scenario)
        if user is None:
            self._problem(401, "Unauthorized", "You need to be logged in to access this resource.")
            return
        route = path.removeprefix(API)
        parts = route.strip("/").split("/")
        if route == "/version":
            key = "version"
        elif (
            len(parts) == 4
            and parts[0] == "domain-types"
            and parts[2:] == ["collections", "all"]
            and parts[1] in DOMAIN_TYPES
        ):
            key = DOMAIN_TYPES[parts[1]]
        else:
            self._problem(404, "Not Found", "The requested URL was not found on the server.")
            return
        forced = scenario.status.get(key)
        if forced is not None:
            self._problem(forced, "Simulated failure", "Simulated failure")
            return
        if key in scenario.raw:
            self._send(200, scenario.raw[key])
            return
        if user == READER_USER and key in READER_DENIED:
            self._problem(401, "Unauthorized", "You are not permitted to perform this action.")
            return
        if key == "version":
            self._json(
                200,
                {
                    "site": SITE,
                    "group": "mysite",
                    "rest_api": {"revision": "0"},
                    "versions": {
                        "apache": [2, 4, 62],
                        "checkmk": VERSION,
                        "python": "3.12.3 (main) [GCC 13.2.0]",
                        "mod_wsgi": [5, 0, 0],
                        "wsgi": [1, 0],
                    },
                    "edition": "cre",
                    "demo": False,
                },
            )
            return
        self._json(200, _collection(scenario, parts[1], query))


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeCheckmk:
    """A running fake Checkmk site."""

    def __init__(self, server: _Server) -> None:
        self._server = server

    @property
    def url(self) -> str:
        """The site address, plain http on a free local port: ``http://127.0.0.1:<port>/mysite``."""
        return f"http://127.0.0.1:{self._server.server_address[1]}/{SITE}"

    @property
    def scenario(self) -> Scenario:
        """The scenario being served; a test may change it between calls."""
        return self._server.scenario

    @property
    def requests(self) -> list[Request]:
        """Every request received, in order."""
        return self._server.requests


@contextmanager
def fake_checkmk(scenario: Scenario | None = None) -> Iterator[FakeCheckmk]:
    """Serve ``scenario`` (the default site when None) until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeCheckmk(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
