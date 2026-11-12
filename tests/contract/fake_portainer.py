"""A fake Portainer API on localhost for the contract tests, and a model for a later simulation.

It serves the read endpoints the collector uses, with the shapes read from the Portainer source on
2026-11-12 (docs/vendor-notes/portainer.md). The data is synthetic: an installation with a local
Docker environment, an agent environment and an Edge environment, two groups, tags, an Edge
group, three stacks (one from git), users, teams, memberships, two registries and the settings.

Like Portainer itself the fake keeps the whole stored state, secrets included, and hides what
Portainer hides when it answers: the settings lose the LDAP password, the OAuth client secret and
the kube secret key; registries lose their password; users are cut to Id, Username and Role;
environments lose their Azure credentials and, with ``excludeSnapshots=true``, their snapshots.
What Portainer does NOT hide (an Edge key, the agent secret, a registry access token, stack
environment values, a git password, the stack file) is served, so a test can prove that driftsniff
keeps only fingerprints of them.

Surface (GET only, every other method answers 405):

* ``/api/status`` public, ``{"Version", "InstanceID"}``;
* ``/api/system/version`` ``{"ServerVersion", "DatabaseVersion", "ServerEdition", ...}``;
* ``/api/endpoints``, ``/api/endpoint_groups``, ``/api/tags``, ``/api/stacks``, ``/api/users``,
  ``/api/teams``, ``/api/registries`` lists for every valid token;
* ``/api/edge_groups``, ``/api/team_memberships``, ``/api/settings`` for an administrator token
  only (403 otherwise);
* ``/api/stacks/{id}/file`` ``{"StackFileContent"}``.

The token travels in ``X-API-Key``; a missing or unknown one answers 401. Errors use Portainer's
shape ``{"message", "details"}``. :class:`Scenario` has helpers that change the configuration so
that two reads show a drift (:meth:`Scenario.drift` applies a standard set).
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

ADMIN_TOKEN = "ptr_CANARYadminToken0001"  # noqa: S105 - a test canary, not a credential
STANDARD_TOKEN = "ptr_CANARYstandardToken01"  # noqa: S105 - a test canary, not a credential
# Secret values Portainer stores; tests check that none of them is ever stored in clear.
EDGE_KEY = "CANARY-edge-00"
AGENT_SECRET = "CANARY-agent-secret-0001"  # noqa: S105
REGISTRY_TOKEN = "CANARY-registry-access-token-0001"  # noqa: S105
REGISTRY_PASSWORD = "CANARY-registry-password-0001"  # noqa: S105
LDAP_PASSWORD = "CANARY-ldap-reader-password-0001"  # noqa: S105
OAUTH_SECRET = "CANARY-oauth-client-secret-0001"  # noqa: S105
GIT_PASSWORD = "CANARY-git-password-0001"  # noqa: S105
DB_PASSWORD = "CANARY-db-password-0001"  # noqa: S105
VERSION = "2.21.4"

ADMIN_ONLY = frozenset({"edge_groups", "team_memberships", "settings"})
LISTS = (
    "endpoints",
    "endpoint_groups",
    "tags",
    "edge_groups",
    "stacks",
    "users",
    "teams",
    "team_memberships",
    "registries",
)


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    method: str
    path: str
    query: str
    api_key: str | None
    authorization: str | None
    cookie: str | None


def _policy(role: int = 0) -> dict[str, Any]:
    return {"RoleId": role}


def default_state() -> dict[str, Any]:
    """The stored configuration of a small synthetic Portainer installation."""
    compose = (
        "services:\n  db:\n    image: postgres:16\n    environment:\n"
        "      POSTGRES_PASSWORD: ${DB_PASSWORD}\n"
    )
    return {
        "endpoints": [
            {
                "Id": 1,
                "Name": "local",
                "Type": 1,
                "ContainerEngine": "docker",
                "URL": "unix:///var/run/docker.sock",
                "PublicURL": "",
                "GroupId": 1,
                "TagIds": [1],
                "TLSConfig": {"TLS": False, "TLSSkipVerify": False},
                "AzureCredentials": {"ApplicationID": "", "TenantID": "", "AuthenticationKey": ""},
                "Status": 1,
                "Snapshots": [
                    {"Time": 1762900000, "DockerVersion": "27.3.1", "RunningContainerCount": 7}
                ],
                "UserAccessPolicies": {},
                "TeamAccessPolicies": {"1": _policy()},
                "EdgeKey": "",
                "EdgeCheckinInterval": 0,
                "SecuritySettings": {
                    "allowBindMountsForRegularUsers": False,
                    "allowPrivilegedModeForRegularUsers": False,
                    "allowVolumeBrowserForRegularUsers": False,
                    "allowHostNamespaceForRegularUsers": False,
                    "allowDeviceMappingForRegularUsers": False,
                    "allowStackManagementForRegularUsers": True,
                    "allowContainerCapabilitiesForRegularUsers": False,
                    "allowSysctlSettingForRegularUsers": False,
                    "enableHostManagementFeatures": False,
                },
                "Heartbeat": True,
                "LastCheckInDate": 0,
            },
            {
                "Id": 2,
                "Name": "lab-agent",
                "Type": 2,
                "ContainerEngine": "docker",
                "URL": "tcp://agent-01.lab.invalid:9001",
                "PublicURL": "agent-01.lab.invalid",
                "GroupId": 2,
                "TagIds": [1, 2],
                "TLSConfig": {"TLS": True, "TLSSkipVerify": False},
                "Status": 1,
                "UserAccessPolicies": {"3": _policy()},
                "TeamAccessPolicies": {},
                "EdgeKey": "",
                "Heartbeat": True,
            },
            {
                "Id": 3,
                "Name": "branch-edge",
                "Type": 4,
                "ContainerEngine": "docker",
                "URL": "",
                "GroupId": 2,
                "TagIds": [3],
                "TLSConfig": {"TLS": False, "TLSSkipVerify": False},
                "Status": 2,
                "UserAccessPolicies": {},
                "TeamAccessPolicies": {},
                "EdgeID": "6e4c8c0a-0000-4000-8000-000000000003",
                "EdgeKey": EDGE_KEY,
                "EdgeCheckinInterval": 5,
                "Edge": {
                    "AsyncMode": False,
                    "PingInterval": 60,
                    "SnapshotInterval": 60,
                    "CommandInterval": 60,
                },
                "UserTrusted": True,
                "LastCheckInDate": 1762900000,
            },
        ],
        "endpoint_groups": [
            {
                "Id": 1,
                "Name": "Unassigned",
                "Description": "Unassigned environments",
                "TagIds": [],
                "UserAccessPolicies": {},
                "TeamAccessPolicies": {},
            },
            {
                "Id": 2,
                "Name": "Lab",
                "Description": "Lab hosts",
                "TagIds": [2],
                "UserAccessPolicies": {},
                "TeamAccessPolicies": {"1": _policy()},
            },
        ],
        "tags": [
            {"ID": 1, "Name": "prod", "Endpoints": {"1": True, "2": True}, "EndpointGroups": {}},
            {"ID": 2, "Name": "lab", "Endpoints": {"2": True}, "EndpointGroups": {"2": True}},
            {"ID": 3, "Name": "edge", "Endpoints": {"3": True}, "EndpointGroups": {}},
        ],
        "edge_groups": [
            {
                "Id": 1,
                "Name": "branches",
                "Dynamic": True,
                "TagIds": [3],
                "PartialMatch": False,
                "Endpoints": [],
                "HasEdgeStack": False,
                "HasEdgeJob": False,
                "TrustedEndpoints": [3],
            },
        ],
        "stacks": [
            {
                "Id": 1,
                "Name": "monitoring",
                "Type": 2,
                "EndpointId": 1,
                "SwarmId": "",
                "EntryPoint": "docker-compose.yml",
                "Env": [{"name": "GRAFANA_PORT", "value": "3000"}],
                "Status": 1,
                "ProjectPath": "/data/compose/1",
                "CreationDate": 1762800000,
                "CreatedBy": "admin",
                "UpdateDate": 1762850000,
                "UpdatedBy": "admin",
                "AdditionalFiles": [],
                "AutoUpdate": None,
                "GitConfig": None,
                "FromAppTemplate": False,
                "_file": "services:\n  grafana:\n    image: grafana/grafana:11.3.0\n",
            },
            {
                "Id": 2,
                "Name": "app-db",
                "Type": 2,
                "EndpointId": 2,
                "SwarmId": "",
                "EntryPoint": "docker-compose.yml",
                "Env": [
                    {"name": "DB_PASSWORD", "value": DB_PASSWORD},
                    {"name": "TZ", "value": "UTC"},
                ],
                "Status": 1,
                "ProjectPath": "/data/compose/2",
                "CreationDate": 1762800100,
                "CreatedBy": "ops",
                "UpdateDate": 0,
                "UpdatedBy": "",
                "AdditionalFiles": [],
                "AutoUpdate": None,
                "GitConfig": None,
                "FromAppTemplate": False,
                "_file": compose,
            },
            {
                "Id": 3,
                "Name": "web",
                "Type": 2,
                "EndpointId": 2,
                "SwarmId": "",
                "EntryPoint": "deploy/compose.yml",
                "Env": [],
                "Status": 1,
                "ProjectPath": "/data/compose/3",
                "CreationDate": 1762800200,
                "CreatedBy": "ops",
                "UpdateDate": 0,
                "UpdatedBy": "",
                "AdditionalFiles": [],
                "AutoUpdate": {
                    "Interval": "5m",
                    "Webhook": "",
                    "ForceUpdate": False,
                    "ForcePullImage": True,
                    "JobID": "17",
                },
                "GitConfig": {
                    "URL": "https://git.example.invalid/ops/web.git",
                    "ReferenceName": "refs/heads/main",
                    "ConfigFilePath": "deploy/compose.yml",
                    "Authentication": {"Username": "deploy", "Password": GIT_PASSWORD},
                    "ConfigHash": "3f2a9c",
                    "TLSSkipVerify": False,
                },
                "FromAppTemplate": False,
                "_file": "services:\n  web:\n    image: nginx:1.27\n",
            },
        ],
        "users": [
            {
                "Id": 1,
                "Username": "admin",
                "Role": 1,
                "Password": "$2a$10$CANARYhash1",
                "TokenIssueAt": 1762900000,
            },
            {
                "Id": 2,
                "Username": "ops",
                "Role": 2,
                "Password": "$2a$10$CANARYhash2",
                "TokenIssueAt": 1762900001,
            },
            {
                "Id": 3,
                "Username": "auditor",
                "Role": 2,
                "Password": "$2a$10$CANARYhash3",
                "TokenIssueAt": 1762900002,
            },
        ],
        "teams": [{"Id": 1, "Name": "operations"}, {"Id": 2, "Name": "developers"}],
        "team_memberships": [
            {"Id": 1, "UserID": 2, "TeamID": 1, "Role": 2},
            {"Id": 2, "UserID": 3, "TeamID": 2, "Role": 2},
        ],
        "registries": [
            {
                "Id": 1,
                "Type": 6,
                "Name": "dockerhub",
                "URL": "docker.io",
                "BaseURL": "",
                "Authentication": True,
                "Username": "theriark-ci",
                "Password": REGISTRY_PASSWORD,
                "ManagementConfiguration": None,
                "RegistryAccesses": {
                    "1": {
                        "UserAccessPolicies": {},
                        "TeamAccessPolicies": {"1": _policy()},
                        "Namespaces": [],
                    }
                },
            },
            {
                "Id": 2,
                "Type": 3,
                "Name": "internal",
                "URL": "registry.lab.invalid:5000",
                "BaseURL": "",
                "Authentication": True,
                "Username": "puller",
                "Password": REGISTRY_PASSWORD,
                "AccessToken": REGISTRY_TOKEN,
                "AccessTokenExpiry": 1762990000,
                "ManagementConfiguration": {
                    "Type": 3,
                    "Authentication": True,
                    "Username": "puller",
                    "Password": REGISTRY_PASSWORD,
                    "TLSConfig": {"TLS": True, "TLSSkipVerify": False},
                },
                "RegistryAccesses": {
                    "2": {
                        "UserAccessPolicies": {"3": _policy()},
                        "TeamAccessPolicies": {},
                        "Namespaces": [],
                    }
                },
            },
        ],
        "settings": {
            "LogoURL": "",
            "BlackListedLabels": [],
            "AuthenticationMethod": 1,
            "InternalAuthSettings": {"RequiredPasswordLength": 12},
            "LDAPSettings": {
                "AnonymousMode": False,
                "ReaderDN": "cn=reader,dc=lab,dc=invalid",
                "Password": LDAP_PASSWORD,
                "URL": "ldap.lab.invalid:389",
                "TLSConfig": {"TLS": False, "TLSSkipVerify": False},
                "StartTLS": True,
                "SearchSettings": [
                    {
                        "BaseDN": "ou=people,dc=lab,dc=invalid",
                        "Filter": "(objectClass=person)",
                        "UserNameAttribute": "uid",
                    }
                ],
                "GroupSearchSettings": [
                    {"GroupBaseDN": "", "GroupFilter": "", "GroupAttribute": ""}
                ],
                "AutoCreateUsers": False,
            },
            "OAuthSettings": {
                "ClientID": "portainer",
                "ClientSecret": OAUTH_SECRET,
                "AccessTokenURI": "https://sso.example.invalid/token",
                "AuthorizationURI": "https://sso.example.invalid/authorize",
                "ResourceURI": "https://sso.example.invalid/userinfo",
                "RedirectURI": "https://portainer.example.invalid",
                "UserIdentifier": "email",
                "Scopes": "openid email",
                "OAuthAutoCreateUsers": False,
                "DefaultTeamID": 0,
                "SSO": True,
                "LogoutURI": "",
                "KubeSecretKey": "Q0FOQVJZa3ViZQ==",
                "AuthStyle": 0,
            },
            "SnapshotInterval": "5m",
            "TemplatesURL": "",
            "EdgeAgentCheckinInterval": 5,
            "EnableEdgeComputeFeatures": True,
            "UserSessionTimeout": "8h",
            "KubeconfigExpiry": "0",
            "HelmRepositoryURL": "https://charts.bitnami.com/bitnami",
            "KubectlShellImage": "portainer/kubectl-shell:2.21.4",
            "TrustOnFirstConnect": False,
            "EnforceEdgeID": True,
            "AgentSecret": AGENT_SECRET,
            "EdgePortainerUrl": "https://portainer.example.invalid",
            "DisplayDonationHeader": False,
            "DisplayExternalContributors": False,
            "EnableHostManagementFeatures": False,
            "ForceSecureCookies": True,
        },
    }


@dataclass
class Scenario:
    """What the fake Portainer stores and which faults it simulates.

    ``tokens`` maps an accepted token to its user role (1 administrator, 2 standard user). Faults
    are keyed by the route name: ``version``, a list name such as ``endpoints``, or ``stack_file``.
    """

    state: dict[str, Any] = field(default_factory=default_state)
    tokens: dict[str, int] = field(default_factory=lambda: {ADMIN_TOKEN: 1, STANDARD_TOKEN: 2})
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    # Serve every list in reverse order of its ids (the order must never matter).
    reverse: bool = False
    # Put the received key into the body of error answers (a leaking server).
    echo_key: bool = False

    # -- drift helpers ----------------------------------------------------------------------

    def _find(self, name: str, key: int, key_field: str = "Id") -> dict[str, Any]:
        for item in self.state[name]:
            if item[key_field] == key:
                return cast("dict[str, Any]", item)
        raise KeyError(f"{name} {key}")

    def set_user_role(self, user_id: int, role: int) -> None:
        """Make a user an administrator (1) or a standard user (2)."""
        self._find("users", user_id)["Role"] = role

    def set_authentication_method(self, method: int) -> None:
        """1 internal, 2 LDAP, 3 OAuth."""
        self.state["settings"]["AuthenticationMethod"] = method

    def set_stack_env(self, stack_id: int, name: str, value: str | None) -> None:
        """Add, change or (with None) remove an environment variable of a stack."""
        stack = self._find("stacks", stack_id)
        env = [item for item in stack["Env"] if item["name"] != name]
        if value is not None:
            env.append({"name": name, "value": value})
        stack["Env"] = env

    def set_stack_file(self, stack_id: int, content: str) -> None:
        self._find("stacks", stack_id)["_file"] = content

    def rename_tag(self, tag_id: int, name: str) -> None:
        self._find("tags", tag_id, "ID")["Name"] = name

    def set_registry_url(self, registry_id: int, url: str) -> None:
        self._find("registries", registry_id)["URL"] = url

    def grant_environment_user(self, endpoint_id: int, user_id: int, role: int = 0) -> None:
        self._find("endpoints", endpoint_id)["UserAccessPolicies"][str(user_id)] = _policy(role)

    def set_tls_skip_verify(self, endpoint_id: int, value: bool) -> None:
        self._find("endpoints", endpoint_id)["TLSConfig"]["TLSSkipVerify"] = value

    def add_team(self, team_id: int, name: str) -> None:
        self.state["teams"].append({"Id": team_id, "Name": name})

    def tick(self) -> None:
        """Volatile changes only (snapshots, check-ins, token issue times): no drift."""
        for endpoint in self.state["endpoints"]:
            endpoint["LastCheckInDate"] = endpoint.get("LastCheckInDate", 0) + 60
            endpoint["Status"] = 1
            for snapshot in endpoint.get("Snapshots", []):
                snapshot["Time"] += 60
        for user in self.state["users"]:
            user["TokenIssueAt"] += 60
        for stack in self.state["stacks"]:
            stack["UpdateDate"] += 1

    def drift(self) -> None:
        """The standard drift of the simulation: one change of each kind the pack grades."""
        self.tick()
        self.set_user_role(3, 1)  # critical
        self.set_authentication_method(2)  # critical
        self.set_registry_url(2, "registry.other.invalid:5000")  # high
        self.set_stack_env(2, "DB_PASSWORD", "CANARY-db-password-0002")  # high
        self.rename_tag(2, "laboratory")  # low


# -- serving -----------------------------------------------------------------------------------


def _hidden(name: str, items: Any, query: dict[str, list[str]]) -> Any:
    """What Portainer hides before it answers (docs/vendor-notes/portainer.md)."""
    items = copy.deepcopy(items)
    if name == "settings":
        items["LDAPSettings"]["Password"] = ""
        items["OAuthSettings"]["ClientSecret"] = ""
        items["OAuthSettings"]["KubeSecretKey"] = None
        return items
    for item in items:
        if name == "registries":
            item["Password"] = ""
            config = item.get("ManagementConfiguration")
            if config is not None:
                item["ManagementConfiguration"] = {"TLSConfig": config.get("TLSConfig")}
        if name == "endpoints":
            item.pop("AzureCredentials", None)
            if query.get("excludeSnapshots") == ["true"]:
                item.pop("Snapshots", None)
        if name == "stacks":
            item.pop("_file", None)
    return items


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
        details = self.headers.get("X-API-Key", "") if scenario.echo_key else message
        self._json(status, {"message": message, "details": details})

    def _record(self, method: str) -> tuple[str, dict[str, list[str]]]:
        server = cast("_Server", self.server)
        parts = urlsplit(self.path)
        server.requests.append(
            Request(
                method,
                parts.path,
                parts.query,
                self.headers.get("X-API-Key"),
                self.headers.get("Authorization"),
                self.headers.get("Cookie"),
            )
        )
        return parts.path, parse_qs(parts.query)

    def _refuse(self) -> None:
        self._record(self.command)
        self._error(405, "Method Not Allowed")

    do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

    def do_GET(self) -> None:
        scenario = cast("_Server", self.server).scenario
        path, query = self._record("GET")
        if path == "/api/status":
            self._json(200, {"Version": VERSION, "InstanceID": "4f1c-synthetic"})
            return
        role = scenario.tokens.get(self.headers.get("X-API-Key") or "")
        if role is None:
            self._error(401, "Unauthorized")
            return
        parts = path.strip("/").split("/")
        if parts[:1] != ["api"]:
            self._error(404, "Not found")
            return
        route = "/".join(parts[1:])
        if route == "system/version":
            key = "version"
        elif len(parts) == 4 and parts[1] == "stacks" and parts[3] == "file":
            key = "stack_file"
        elif route in (*LISTS, "settings"):
            key = route
        else:
            self._error(404, "Not found")
            return
        forced = scenario.status.get(key)
        if forced is not None:
            self._error(forced, "Simulated failure")
            return
        if key in scenario.raw:
            self._send(200, scenario.raw[key])
            return
        if key in ADMIN_ONLY and role != 1:
            self._error(403, "Access denied to resource")
            return
        if key == "version":
            self._json(
                200,
                {
                    "UpdateAvailable": False,
                    "LatestVersion": VERSION,
                    "ServerVersion": VERSION,
                    "VersionSupport": "STS",
                    "ServerEdition": "CE",
                    "DatabaseVersion": VERSION,
                    "Build": {"BuildNumber": "synthetic", "GoVersion": "go1.23.4"},
                },
            )
            return
        if key == "stack_file":
            self._stack_file(scenario, parts[2])
            return
        self._json(200, self._answer(scenario, key, query))

    def _stack_file(self, scenario: Scenario, raw_id: str) -> None:
        for stack in scenario.state["stacks"]:
            if str(stack["Id"]) == raw_id:
                self._json(200, {"StackFileContent": stack["_file"]})
                return
        self._error(404, "Unable to find a stack with the specified identifier inside the database")

    @staticmethod
    def _answer(scenario: Scenario, key: str, query: dict[str, list[str]]) -> Any:
        items = _hidden(key, scenario.state[key], query)
        if key == "users":
            items = [
                {"Id": user["Id"], "Username": user["Username"], "Role": user["Role"]}
                for user in scenario.state["users"]
            ]
        if scenario.reverse and isinstance(items, list):
            items.reverse()
        return items


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakePortainer:
    """A running fake Portainer."""

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
def fake_portainer(scenario: Scenario | None = None) -> Iterator[FakePortainer]:
    """Serve ``scenario`` (the default installation when None) until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakePortainer(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
