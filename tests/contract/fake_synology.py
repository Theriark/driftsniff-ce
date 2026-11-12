"""A fake Synology DSM Web API on localhost for the contract tests.

It serves what the Synology collector expects (docs/vendor-notes/synology.md; every ``SYNO.Core.*``
name and field is unverified against a real DSM) and is written so that it can be ported to the
company Mock Platform as the Development and Stage simulation of a NAS:

* ``/webapi/query.cgi`` answers ``SYNO.API.Info`` ``query`` with the path and versions of every
  API; ``/webapi/entry.cgi`` serves ``SYNO.API.Auth`` (``login``, ``logout``) and the
  ``SYNO.Core.*`` calls. Parameters are read from the form body of a POST and from the query
  string of a GET, as DSM does.
* ``login`` checks ``account`` and ``passwd`` against :attr:`Scenario.accounts` and answers
  ``{"data": {"sid": ...}, "success": true}``; every other call needs a live ``_sid``. A wrong
  password is error 400, a 2-step account 403, a disabled one 401. :meth:`FakeSynology.expire`
  ends every session (the next call answers 119), and ``Scenario.session_calls`` ends a session
  after that many calls (106).
* Answers are ``{"data": ..., "success": true}`` or ``{"error": {"code": n}, "success": false}``.
  Lists honour ``offset`` and ``limit`` and report ``total``.
* :attr:`Scenario.config` is the whole configuration of the NAS as plain data, all synthetic.
  :meth:`FakeSynology.mutate` changes it between two reads so that drift appears; the helpers
  below it make the usual risky changes.

Every request is recorded with its query string and form fields, so a test can check that the
password and the sid only travel in the form body.
"""

import copy
import json
import secrets
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

CANARY_USER = "driftsniff-reader"
CANARY_PASSWORD = "CANARY-syno-00"  # noqa: S105 - a test canary, not a credential
CANARY_CREDENTIAL = f"{CANARY_USER}:{CANARY_PASSWORD}"

# API name to (path, minVersion, maxVersion), as SYNO.API.Info lists them.
APIS: dict[str, tuple[str, int, int]] = {
    "SYNO.API.Info": ("query.cgi", 1, 1),
    "SYNO.API.Auth": ("entry.cgi", 1, 7),
    "SYNO.Core.Share": ("entry.cgi", 1, 1),
    "SYNO.Core.Share.Permission": ("entry.cgi", 1, 1),
    "SYNO.Core.User": ("entry.cgi", 1, 1),
    "SYNO.Core.Group": ("entry.cgi", 1, 1),
    "SYNO.Core.Group.Member": ("entry.cgi", 1, 1),
    "SYNO.Core.Terminal": ("entry.cgi", 1, 3),
    "SYNO.Core.Security.Firewall": ("entry.cgi", 1, 1),
    "SYNO.Core.Security.Firewall.Profile": ("entry.cgi", 1, 1),
    "SYNO.Core.Security.AutoBlock": ("entry.cgi", 1, 1),
    "SYNO.Core.OTP.EnforcePolicy": ("entry.cgi", 1, 1),
    "SYNO.Core.FileServ.SMB": ("entry.cgi", 1, 3),
    "SYNO.Core.FileServ.NFS": ("entry.cgi", 1, 2),
    "SYNO.Core.FileServ.AFP": ("entry.cgi", 1, 1),
    "SYNO.Core.Package": ("entry.cgi", 1, 2),
    "SYNO.Core.Network.Interface": ("entry.cgi", 1, 1),
    "SYNO.Core.Network": ("entry.cgi", 1, 2),
    "SYNO.Core.QuickConnect": ("entry.cgi", 1, 3),
}

# A settings API (method get) to the key of its object in Scenario.config.
SETTINGS: dict[str, str] = {
    "SYNO.Core.Terminal": "terminal",
    "SYNO.Core.Security.Firewall": "firewall",
    "SYNO.Core.Security.AutoBlock": "auto_block",
    "SYNO.Core.OTP.EnforcePolicy": "otp_policy",
    "SYNO.Core.FileServ.SMB": "smb",
    "SYNO.Core.FileServ.NFS": "nfs",
    "SYNO.Core.FileServ.AFP": "afp",
    "SYNO.Core.Network": "network",
    "SYNO.Core.QuickConnect": "quickconnect",
}

# DSM error codes the fake answers with.
NO_SUCH_API = 102
NO_PRIVILEGE = 105
SESSION_TIMEOUT = 106
SID_NOT_FOUND = 119
WRONG_PASSWORD = 400
DISABLED_ACCOUNT = 401
TWO_FACTOR_REQUIRED = 403


def _permission(name: str, *, read: bool = False, write: bool = False) -> dict[str, Any]:
    return {
        "name": name,
        "is_readonly": read and not write,
        "is_writable": write,
        "is_deny": False,
        "is_custom": False,
        "is_admin": name in ("admin", CANARY_USER, "administrators"),
        "inherit": "-",
    }


def default_config() -> dict[str, Any]:
    """A small NAS as an administrator sees it. Every name and value is synthetic."""
    users = ["admin", "alice", "bob", CANARY_USER, "guest"]
    shares = [
        {
            "name": "backup",
            "desc": "nightly backups",
            "vol_path": "/volume1",
            "uuid": "5f0c1c3a-0001",
            "hidden": True,
            "encryption": 1,
            "enable_recycle_bin": False,
            "recycle_bin_admin_only": True,
            "unite_permission": False,
            "is_aclmode": True,
            "is_usb_share": False,
        },
        {
            "name": "media",
            "desc": "films and music",
            "vol_path": "/volume1",
            "uuid": "5f0c1c3a-0002",
            "hidden": False,
            "encryption": 0,
            "enable_recycle_bin": True,
            "recycle_bin_admin_only": False,
            "unite_permission": False,
            "is_aclmode": True,
            "is_usb_share": False,
        },
        {
            "name": "public",
            "desc": "shared with every account",
            "vol_path": "/volume1",
            "uuid": "5f0c1c3a-0003",
            "hidden": False,
            "encryption": 0,
            "enable_recycle_bin": True,
            "recycle_bin_admin_only": False,
            "unite_permission": False,
            "is_aclmode": True,
            "is_usb_share": False,
        },
    ]
    user_rows = {
        "backup": [_permission(name, write=name in ("admin", CANARY_USER)) for name in users],
        "media": [_permission(name, read=name == "bob", write=name == "alice") for name in users],
        "public": [
            _permission(name, read=name != "guest", write=name == "alice") for name in users
        ],
    }
    group_rows = {
        share: [
            _permission("administrators", write=True),
            _permission("users", read=share != "backup"),
        ]
        for share in ("backup", "media", "public")
    }
    return {
        "shares": shares,
        "permissions": {"local_user": user_rows, "local_group": group_rows},
        "users": [
            {
                "name": "admin",
                "uid": 1024,
                "description": "System default user",
                "email": "",
                "expired": "now",
                "cannot_chg_passwd": False,
                "passwd_never_expire": True,
                "password_last_change": 19000,
                "2fa_status": False,
            },
            {
                "name": "alice",
                "uid": 1026,
                "description": "household",
                "email": "alice@example.invalid",
                "expired": "normal",
                "cannot_chg_passwd": False,
                "passwd_never_expire": False,
                "password_last_change": 20100,
                "2fa_status": True,
            },
            {
                "name": "bob",
                "uid": 1027,
                "description": "household",
                "email": "bob@example.invalid",
                "expired": "normal",
                "cannot_chg_passwd": False,
                "passwd_never_expire": False,
                "password_last_change": 20110,
                "2fa_status": False,
            },
            {
                "name": CANARY_USER,
                "uid": 1030,
                "description": "driftsniff reads the configuration",
                "email": "",
                "expired": "normal",
                "cannot_chg_passwd": True,
                "passwd_never_expire": True,
                "password_last_change": 20200,
                "2fa_status": False,
            },
            {
                "name": "guest",
                "uid": 1025,
                "description": "Guest",
                "email": "",
                "expired": "now",
                "cannot_chg_passwd": False,
                "passwd_never_expire": True,
                "password_last_change": 19000,
                "2fa_status": False,
            },
        ],
        "groups": [
            {"name": "administrators", "gid": 101, "description": "System default admin group"},
            {"name": "http", "gid": 1023, "description": "Web services"},
            {"name": "users", "gid": 100, "description": "System default group"},
        ],
        "members": {
            "administrators": ["admin", CANARY_USER],
            "http": [],
            "users": ["admin", "alice", "bob", CANARY_USER],
        },
        "terminal": {"enable_ssh": False, "enable_telnet": False, "ssh_port": 22},
        "firewall": {"enable_firewall": True, "profile_name": "home"},
        "profiles": [{"name": "default"}, {"name": "home"}],
        "auto_block": {"enable": True, "attempts": 10, "within_mins": 5, "expire_day": 0},
        "otp_policy": {"otp_enforce_option": "admin"},
        "smb": {"enable_samba": True, "workgroup": "WORKGROUP"},
        "nfs": {"enable_nfs": False},
        "afp": {"enable_afp": False},
        "packages": [
            {
                "id": "HyperBackup",
                "name": "Hyper Backup",
                "version": "4.1.0-3718",
                "timestamp": 1730000000000,
                "additional": {"status": "running", "startable": True},
            },
            {
                "id": "SynologyPhotos",
                "name": "Synology Photos",
                "version": "1.7.0-0794",
                "timestamp": 1730000100000,
                "additional": {"status": "running", "startable": True},
            },
        ],
        "interfaces": [
            {
                "ifname": "eth0",
                "ip": "192.0.2.10",
                "mask": "255.255.255.0",
                "type": "lan",
                "use_dhcp": False,
                "status": "connected",
            },
            {
                "ifname": "eth1",
                "ip": "",
                "mask": "",
                "type": "lan",
                "use_dhcp": True,
                "status": "disconnected",
            },
        ],
        "network": {
            "arp_ignore": True,
            "dns_manual": True,
            "dns_primary": "192.0.2.1",
            "dns_secondary": "",
            "enable_ip_conflict_detect": True,
            "enable_windomain": False,
            "gateway": "192.0.2.1",
            "gateway_info": {
                "ifname": "eth0",
                "ip": "192.0.2.10",
                "mask": "255.255.255.0",
                "status": "connected",
                "type": "lan",
                "use_dhcp": False,
            },
            "ipv4_first": False,
            "multi_gateway": False,
            "server_name": "nas-lab",
            "use_dhcp_domain": True,
            "v6gateway": "",
        },
        "quickconnect": {"enabled": False, "server_alias": ""},
    }


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received; ``form`` holds the fields of a POST body."""

    method: str
    path: str
    query: str
    form: dict[str, str]

    @property
    def params(self) -> dict[str, str]:
        """The fields DSM reads: the query string, then the form body."""
        merged = {key: values[-1] for key, values in parse_qs(self.query).items()}
        merged.update(self.form)
        return merged


@dataclass
class Scenario:
    """What the fake NAS serves and which faults it simulates."""

    accounts: dict[str, str] = field(default_factory=lambda: {CANARY_USER: CANARY_PASSWORD})
    two_factor: set[str] = field(default_factory=set)
    disabled: set[str] = field(default_factory=set)
    config: dict[str, Any] = field(default_factory=default_config)
    # APIs that the info query does not list, and APIs that answer 105 (no privilege).
    missing: set[str] = field(default_factory=set)
    forbidden: set[str] = field(default_factory=set)
    # End a session after this many calls with it (error 106); None never does.
    session_calls: int | None = None
    # Answer every request with this HTTP status instead.
    http_status: int | None = None


def _ok(data: Any) -> dict[str, Any]:
    return {"data": data, "success": True}


def _error(code: int) -> dict[str, Any]:
    return {"error": {"code": code}, "success": False}


def _page(items: list[Any], params: dict[str, str], key: str) -> dict[str, Any]:
    offset = int(params.get("offset", "0") or 0)
    limit = int(params.get("limit", "-1") or -1)
    chosen = items[offset:] if limit < 0 else items[offset : offset + limit]
    return {key: chosen, "offset": offset, "total": len(items)}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def do_GET(self) -> None:
        self._handle("GET", {})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8")
        form = {key: values[-1] for key, values in parse_qs(body).items()}
        self._handle("POST", form)

    def _handle(self, method: str, form: dict[str, str]) -> None:
        server = cast("_Server", self.server)
        parts = urlsplit(self.path)
        request = Request(method, parts.path, parts.query, form)
        with server.lock:
            server.requests.append(request)
            status, payload = server.answer(request)
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []
        self.sessions: dict[str, int] = {}
        self.lock = threading.Lock()

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None

    # -- routing ------------------------------------------------------------------------------

    def answer(self, request: Request) -> tuple[int, Any]:
        scenario = self.scenario
        if scenario.http_status is not None:
            return scenario.http_status, {"error": "forced"}
        params = request.params
        api, method = params.get("api", ""), params.get("method", "")
        if not request.path.startswith("/webapi/"):
            return 404, {"error": "not found"}
        listed = APIS.get(api)
        if listed is None or api in scenario.missing:
            return 200, _error(NO_SUCH_API)
        if request.path != f"/webapi/{listed[0]}":
            return 200, _error(NO_SUCH_API)
        if api == "SYNO.API.Info":
            return 200, _ok(self._info())
        if api == "SYNO.API.Auth":
            return 200, self._auth(method, params)
        code = self._session(params.get("_sid"))
        if code is not None:
            return 200, _error(code)
        if api in scenario.forbidden:
            return 200, _error(NO_PRIVILEGE)
        return 200, self._core(api, method, params)

    def _info(self) -> dict[str, Any]:
        return {
            name: {"path": path, "minVersion": low, "maxVersion": high, "requestFormat": "JSON"}
            for name, (path, low, high) in APIS.items()
            if name not in self.scenario.missing
        }

    def _auth(self, method: str, params: dict[str, str]) -> dict[str, Any]:
        scenario = self.scenario
        if method == "logout":
            self.sessions.pop(params.get("_sid", ""), None)
            return _ok({})
        if method != "login":
            return _error(103)
        account = params.get("account", "")
        if scenario.accounts.get(account) != params.get("passwd"):
            return _error(WRONG_PASSWORD)
        if account in scenario.disabled:
            return _error(DISABLED_ACCOUNT)
        if account in scenario.two_factor and not params.get("otp_code"):
            return _error(TWO_FACTOR_REQUIRED)
        sid = secrets.token_urlsafe(24)
        self.sessions[sid] = 0
        return _ok({"sid": sid, "is_portal_port": False})

    def _session(self, sid: str | None) -> int | None:
        if sid is None or sid not in self.sessions:
            return SID_NOT_FOUND
        limit = self.scenario.session_calls
        if limit is not None and self.sessions[sid] >= limit:
            del self.sessions[sid]
            return SESSION_TIMEOUT
        self.sessions[sid] += 1
        return None

    def _core(self, api: str, method: str, params: dict[str, str]) -> dict[str, Any]:
        config = self.scenario.config
        if api in SETTINGS and method == "get":
            return _ok(copy.deepcopy(config[SETTINGS[api]]))
        if method != "list":
            return _error(103)
        if api == "SYNO.Core.Share":
            return _ok(_page(copy.deepcopy(config["shares"]), params, "shares"))
        if api == "SYNO.Core.Share.Permission":
            rows = config["permissions"].get(params.get("user_group_type", ""), {})
            share = params.get("name", "")
            if share not in rows:
                return _error(101)
            return _ok(_page(copy.deepcopy(rows[share]), params, "items"))
        if api == "SYNO.Core.User":
            return _ok(_page(copy.deepcopy(config["users"]), params, "users"))
        if api == "SYNO.Core.Group":
            return _ok(_page(copy.deepcopy(config["groups"]), params, "groups"))
        if api == "SYNO.Core.Group.Member":
            names = config["members"].get(params.get("group", ""))
            if names is None:
                return _error(101)
            users = {user["name"]: user for user in config["users"]}
            found = [
                {
                    "name": name,
                    "uid": users[name]["uid"],
                    "description": users[name]["description"],
                }
                for name in names
            ]
            return _ok(_page(found, params, "users"))
        if api == "SYNO.Core.Security.Firewall.Profile":
            return _ok({"profiles": copy.deepcopy(config["profiles"])})
        if api == "SYNO.Core.Package":
            return _ok(_page(copy.deepcopy(config["packages"]), params, "packages"))
        if api == "SYNO.Core.Network.Interface":
            return _ok(copy.deepcopy(config["interfaces"]))
        return _error(103)


class FakeSynology:
    """A running fake NAS."""

    def __init__(self, server: _Server) -> None:
        self._server = server

    @property
    def url(self) -> str:
        """The base address, plain http on a free local port."""
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    @property
    def scenario(self) -> Scenario:
        return self._server.scenario

    @property
    def requests(self) -> list[Request]:
        """Every request received, in order."""
        return self._server.requests

    @property
    def live_sessions(self) -> int:
        """How many sessions are signed in and not ended."""
        return len(self._server.sessions)

    def calls(self, api: str) -> list[Request]:
        """The requests for one API."""
        return [request for request in self.requests if request.params.get("api") == api]

    def expire(self) -> None:
        """End every session, as a DSM restart or an idle timeout does (the next call gets 119)."""
        with self._server.lock:
            self._server.sessions.clear()

    def mutate(self, change: Callable[[dict[str, Any]], None]) -> None:
        """Change the configuration between two reads."""
        with self._server.lock:
            change(self._server.scenario.config)

    # -- the usual risky changes ---------------------------------------------------------------

    def set_setting(self, key: str, name: str, value: Any) -> None:
        """Set one field of a settings object (``terminal``, ``firewall``, ``quickconnect``...)."""
        self.mutate(lambda config: config[key].__setitem__(name, value))

    def add_member(self, group: str, user: str) -> None:
        """Add ``user`` to ``group`` (``administrators`` makes an administrator)."""
        self.mutate(lambda config: config["members"][group].append(user))

    def grant_guest(self, share: str, *, write: bool) -> None:
        """Give the guest account read or write access to ``share``."""

        def change(config: dict[str, Any]) -> None:
            for row in config["permissions"]["local_user"][share]:
                if row["name"] == "guest":
                    row.update(is_readonly=not write, is_writable=write, is_deny=False)

        self.mutate(change)

    def install_package(self, package_id: str, name: str, version: str) -> None:
        """Install one package."""
        item = {
            "id": package_id,
            "name": name,
            "version": version,
            "timestamp": 1731000000000,
            "additional": {"status": "running", "startable": True},
        }
        self.mutate(lambda config: config["packages"].append(item))


@contextmanager
def fake_synology(scenario: Scenario | None = None) -> Iterator[FakeSynology]:
    """Serve ``scenario`` (a default one when None) on a free local port until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeSynology(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
