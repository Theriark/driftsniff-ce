"""A fake QNAP QTS NAS on localhost for the contract tests, and later the Mock Platform port.

It serves the CGI shapes of docs/vendor-notes/qnap.md (every name UNVERIFIED) with synthetic
values: no answer here was captured from a real NAS, the shapes follow captured answers of
python-qnapstats (QTS 4.2 and 4.5).

API surface (all answers ``text/xml``, a ``QDocRoot`` document with values in CDATA):

* ``POST /cgi-bin/authLogin.cgi`` form ``user``, ``pwd`` (base64 of the password). Right: a new
  session, ``authPassed`` 1, ``authSid``, ``isAdmin``, ``username``. Wrong: ``authPassed`` 0.
  ``Scenario.two_step``: ``authPassed`` 0 with ``need_2sv`` 1.
* ``GET /cgi-bin/authLogin.cgi`` without parameters: the login page answer, no session needed:
  model, firmware and the web interface flags (``Scenario.web``). With ``user``/``pwd`` in the
  query it is refused (a client must never send the password in a URL).
* ``GET /cgi-bin/authLogout.cgi?logout=1&sid=``: ends that session.
* ``GET /cgi-bin/management/manaRequest.cgi?subfunc=sysinfo&...&sid=``: system information with
  numbered adapter elements and volatile values (uptime, temperatures, counters).
* ``GET /cgi-bin/management/chartReq.cgi?chart_func=disk_usage&...&sid=``: volumes and the shared
  folders per volume.
* ``GET /cgi-bin/application/appRequest.cgi?subfunc=qpkg&...&sid=``: installed apps (``qItem``).

A read without a live session answers HTTP 200 with ``authPassed`` 0, as QNAP does. Faults:
``status`` (an HTTP status per route), ``raw`` (a body per route), ``expire_after`` (end every
session after that many reads), ``refused`` (routes that answer ``authPassed`` 0 to every session:
a non-administrator). :func:`apply_drift` changes the configuration so a second read shows drift.
Every request is recorded with its method, path, query and form body.
"""

import base64
import itertools
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

USER = "driftsniff-reader"
CANARY_PASSWORD = "CANARY-qnap-00"  # noqa: S105 - a test canary, not a credential

LOGIN = "/cgi-bin/authLogin.cgi"
LOGOUT = "/cgi-bin/authLogout.cgi"
SYSINFO = "/cgi-bin/management/manaRequest.cgi"
DISK_USAGE = "/cgi-bin/management/chartReq.cgi"
APPS = "/cgi-bin/application/appRequest.cgi"
ROUTES = {SYSINFO: "sysinfo", DISK_USAGE: "disk_usage", APPS: "apps"}


def default_interfaces() -> list[dict[str, Any]]:
    return [
        {
            "ifname": "eth0",
            "dname": "Adapter 1",
            "ip": "192.0.2.10",
            "mask": "255.255.255.0",
            "mac": "00:08:9b:00:00:01",
            "usage": "STATIC",
            "speed": "2500",
            "dns": ["192.0.2.53", "198.51.100.53"],
        },
        {
            "ifname": "eth1",
            "dname": "Adapter 2",
            "ip": "198.51.100.20",
            "mask": "255.255.255.0",
            "mac": "00:08:9b:00:00:02",
            "usage": "DHCP",
            "speed": "2500",
            "dns": ["198.51.100.53"],
        },
    ]


def default_volumes() -> list[dict[str, Any]]:
    return [
        {"value": "1", "label": "DataVol1", "raid": "raid5", "disks": "1,2,3,4", "encrypted": "1"},
        {"value": "2", "label": "Scratch", "raid": "single", "disks": "5", "encrypted": "0"},
    ]


def default_shares() -> list[dict[str, Any]]:
    return [
        {"name": "Public", "volume": "1"},
        {"name": "Backups", "volume": "1"},
        {"name": "homes", "volume": "1"},
        {"name": "Container", "volume": "2", "type": "system"},
    ]


def default_web() -> dict[str, str]:
    return {
        "forceSSL": "1",
        "stunnelPort": "443",
        "webFSEnabled": "1",
        "QMultimediaEnabled": "0",
        "MSV2WebEnabled": "0",
        "QDownloadEnabled": "0",
        "NVREnabled": "0",
        "WFM2": "1",
        "QMusicsEnabled": "0",
        "QVideosEnabled": "0",
        "QPhotosEnabled": "0",
        "QWebEnabled": "0",
        "QWebPort": "80",
        "QWebSSLEnabled": "0",
        "QWebSSLPort": "8081",
    }


def default_apps() -> list[dict[str, Any]]:
    return [
        {
            "name": "container-station",
            "displayName": "Container Station",
            "version": "3.0.7.891",
            "enable": "TRUE",
            "provider": "QNAP Systems, Inc.",
            "unofficial": "0",
            "code_signing_status": "1",
            "status": "complete",
        },
        {
            "name": "HybridBackup",
            "displayName": "Hybrid Backup Sync",
            "version": "25.1.3",
            "enable": "TRUE",
            "provider": "QNAP Systems, Inc.",
            "unofficial": "0",
            "code_signing_status": "1",
            "status": "complete",
        },
    ]


@dataclass
class Scenario:
    """What the fake NAS serves and which faults it simulates. Synthetic values only."""

    user: str = USER
    password: str = CANARY_PASSWORD
    admin: bool = True
    two_step: bool = False
    hostname: str = "nas-lab-01"
    model: str = "TS-464"
    firmware: str = "5.1.4"
    build: str = "20231128"
    timezone: str = "(GMT+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna"
    dns: list[str] = field(default_factory=lambda: ["192.0.2.53", "198.51.100.53"])
    interfaces: list[dict[str, Any]] = field(default_factory=default_interfaces)
    volumes: list[dict[str, Any]] = field(default_factory=default_volumes)
    shares: list[dict[str, Any]] = field(default_factory=default_shares)
    web: dict[str, str] = field(default_factory=default_web)
    apps: list[dict[str, Any]] = field(default_factory=default_apps)
    # Faults, keyed by route: "login", "logout", "login_page", "sysinfo", "disk_usage", "apps".
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    refused: set[str] = field(default_factory=set)
    # End every live session after this many session reads (None: sessions never expire).
    expire_after: int | None = None
    # Volatile values change on every answer, so a stable result proves they are not kept.
    tick: int = 0


def apply_drift(scenario: Scenario) -> None:
    """A set of configuration changes the second read must report (see the contract tests)."""
    scenario.web["forceSSL"] = "0"
    scenario.dns = ["203.0.113.53"]
    scenario.shares.append({"name": "Exchange", "volume": "2"})
    scenario.apps.append(
        {
            "name": "SomeTool",
            "displayName": "Some Tool",
            "version": "1.0",
            "enable": "TRUE",
            "provider": "Example",
            "unofficial": "1",
            "code_signing_status": "0",
            "status": "complete",
        }
    )
    scenario.hostname = "nas-lab-02"


def _cdata(tag: str, value: object) -> str:
    text = str(value).replace("]]>", "]]]]><![CDATA[>")
    return f"<{tag}><![CDATA[{text}]]></{tag}>"


def _document(*parts: str) -> bytes:
    body = "".join(parts)
    head = '<?xml version="1.0" encoding="UTF-8" ?>\n<QDocRoot version="1.0">\n'
    return f"{head}{body}</QDocRoot>".encode()


def _model_and_firmware(scenario: Scenario) -> str:
    return (
        "<model>"
        + _cdata("modelName", "TS-X64")
        + _cdata("internalModelName", "TS-X64")
        + _cdata("displayModelName", scenario.model)
        + "</model><firmware>"
        + _cdata("version", scenario.firmware)
        + _cdata("number", "2596")
        + _cdata("build", scenario.build)
        + _cdata("patch", "0")
        + _cdata("buildTime", "2023/11/28")
        + "</firmware>"
        + _cdata("hostname", scenario.hostname)
    )


def sysinfo_xml(scenario: Scenario) -> bytes:
    nics = [_cdata("nic_cnt", len(scenario.interfaces))]
    for number, nic in enumerate(scenario.interfaces, start=1):
        dns = "".join(f"<dns{i}>{server}</dns{i}>" for i, server in enumerate(nic["dns"], 1))
        nics.append(
            f"<ifindex{number}>{number + 1}</ifindex{number}>"
            f"<ifname{number}>{nic['ifname']}</ifname{number}>"
            f"<dname{number}>{nic['dname']}</dname{number}>"
            f"<rx_packet{number}>{1000 * scenario.tick + 7}</rx_packet{number}>"
            f"<tx_packet{number}>{500 * scenario.tick + 3}</tx_packet{number}>"
            f"<eth_status{number}>1</eth_status{number}>"
            f"<eth_max_speed{number}>{nic['speed']}</eth_max_speed{number}>"
            f"<eth_ip{number}>{nic['ip']}</eth_ip{number}>"
            f"<eth_mask{number}>{nic['mask']}</eth_mask{number}>"
            f"<eth_mac{number}>{nic['mac']}</eth_mac{number}>"
            f"<eth_usage{number}>{nic['usage']}</eth_usage{number}>"
            f"<eth_ipv6_info{number}><eth_ipv6_enable>0</eth_ipv6_enable></eth_ipv6_info{number}>"
            f"<dnsinfo{number}>{dns}</dnsinfo{number}>"
        )
    # QNAP repeats the DNS list; the collector keeps each server once.
    dns_list = "".join(_cdata("DNS_LIST", f" {server}\n") for server in scenario.dns * 2)
    root = (
        "<func><name><![CDATA[S_MENU_40]]></name><ownContent><root>"
        + _cdata("timezone", scenario.timezone)
        + _cdata("cpu_usage", f"{scenario.tick % 50}.5 %")
        + _cdata("total_memory", "16000.0")
        + _cdata("free_memory", f"{9000 + scenario.tick}.0")
        + "".join(nics)
        + f"<dnsInfo>{dns_list}</dnsInfo>"
        + _cdata("uptime_day", scenario.tick)
        + _cdata("uptime_min", (scenario.tick * 7) % 60)
        + f"<cpu_tempc>{40 + scenario.tick % 10}</cpu_tempc><sys_tempc>33</sys_tempc>"
        + f"<sysfan_count>1</sysfan_count><sysfan1>{1400 + scenario.tick}</sysfan1>"
        + "</root></ownContent></func>"
    )
    return _document(_cdata("authPassed", 1), _model_and_firmware(scenario), root)


def disk_usage_xml(scenario: Scenario) -> bytes:
    volumes = "".join(
        "<volume>"
        + _cdata("volumeStat", volume["raid"])
        + _cdata("volumeDisks", f" {volume['disks']}")
        + _cdata("volumeStatus", "0")
        + _cdata("Progress", "100")
        + _cdata("volumeType", "4")
        + _cdata("volumeValue", volume["value"])
        + _cdata("freeSize", 10**9 + scenario.tick)
        + _cdata("volumeLabel", volume["label"])
        + _cdata("is_default_volume", "1" if volume["value"] == "1" else "0")
        + _cdata("encryptfs_bool", volume["encrypted"])
        + "</volume>"
        for volume in scenario.volumes
    )
    uses = []
    for volume in scenario.volumes:
        folders = "".join(
            "<folder_element>"
            + _cdata("sharename", share["name"])
            + _cdata("used_size", 4096 * (scenario.tick + 1))
            + (_cdata("type", share["type"]) if "type" in share else "")
            + "</folder_element>"
            for share in scenario.shares
            if share["volume"] == volume["value"]
        )
        uses.append(
            "<volumeUse>"
            + _cdata("volumeValue", volume["value"])
            + _cdata("total_size", 4 * 10**12)
            + _cdata("free_size", 10**12 - scenario.tick)
            + folders
            + "</volumeUse>"
        )
    return _document(
        _cdata("authPassed", 1),
        _model_and_firmware(scenario),
        f"<volumeList>{volumes}</volumeList><volumeUseList>{''.join(uses)}</volumeUseList>",
    )


def apps_xml(scenario: Scenario) -> bytes:
    items = "".join(
        "<qItem>"
        + _cdata("name", app["name"])
        + "<attr>"
        + "".join(_cdata(key, value) for key, value in app.items() if key != "name")
        + _cdata("task_info", f"t{scenario.tick}")
        + "</attr></qItem>"
        for app in scenario.apps
    )
    return _document(
        _cdata("authPassed", 1),
        f"<func><name><![CDATA[qpkg]]></name><ownContent>{items}</ownContent></func>",
        _cdata("result", "0"),
    )


def login_page_xml(scenario: Scenario) -> bytes:
    flags = "".join(_cdata(key, value) for key, value in scenario.web.items())
    return _document(
        _cdata("authPassed", 0), _model_and_firmware(scenario), _cdata("hero_model", 0), flags
    )


def login_xml(scenario: Scenario, sid: str | None) -> bytes:
    if sid is None:
        need = _cdata("need_2sv", 1) if scenario.two_step else ""
        return _document(_cdata("authPassed", 0), _cdata("errorValue", -1), need)
    return _document(
        _cdata("authPassed", 1),
        _cdata("authSid", sid),
        _cdata("pw_status", 0),
        _cdata("isAdmin", 1 if scenario.admin else 0),
        _cdata("username", scenario.user),
        _cdata("groupname", "administrators" if scenario.admin else "everyone"),
    )


def refused_xml() -> bytes:
    return _document(_cdata("authPassed", 0))


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    method: str
    path: str
    query: str
    body: str


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self, body: str) -> tuple[str, dict[str, list[str]]]:
        server = cast("_Server", self.server)
        parts = urlsplit(self.path)
        server.requests.append(Request(self.command, parts.path, parts.query, body))
        return parts.path, parse_qs(parts.query)

    def _fault(self, route: str) -> bool:
        scenario = cast("_Server", self.server).scenario
        if route in scenario.status:
            self._send(scenario.status[route], b"<html>refused</html>")
            return True
        if route in scenario.raw:
            self._send(200, scenario.raw[route])
            return True
        return False

    def do_POST(self) -> None:
        server = cast("_Server", self.server)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        path, _ = self._record(body)
        if path != LOGIN:
            self._send(404, b"")
            return
        if self._fault("login"):
            return
        form = parse_qs(body)
        scenario = server.scenario
        try:
            password = base64.b64decode(form.get("pwd", [""])[0], validate=True).decode("utf-8")
        except ValueError:
            password = None
        good = form.get("user") == [scenario.user] and password == scenario.password
        sid = server.new_session() if good and not scenario.two_step else None
        self._send(200, login_xml(scenario, sid))

    def do_GET(self) -> None:
        server = cast("_Server", self.server)
        scenario = server.scenario
        path, query = self._record("")
        if path == LOGIN:
            if "pwd" in query or "user" in query:
                self._send(400, b"")
                return
            if not self._fault("login_page"):
                self._send(200, login_page_xml(scenario))
            return
        if path == LOGOUT:
            if not self._fault("logout"):
                server.sessions.discard(query.get("sid", [""])[0])
                self._send(200, _document(_cdata("authPassed", 1)))
            return
        route = ROUTES.get(path)
        if route is None:
            self._send(404, b"")
            return
        if self._fault(route):
            return
        sid = query.get("sid", [""])[0]
        if sid not in server.sessions or route in scenario.refused:
            self._send(200, refused_xml())
            return
        server.reads += 1
        if scenario.expire_after is not None and server.reads >= scenario.expire_after:
            server.sessions.clear()
            server.reads = 0
            scenario.expire_after = None
        builders = {"sysinfo": sysinfo_xml, "disk_usage": disk_usage_xml, "apps": apps_xml}
        self._send(200, builders[route](scenario))


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []
        self.sessions: set[str] = set()
        self.reads = 0
        self._counter = itertools.count(1)

    def new_session(self) -> str:
        sid = f"s{next(self._counter):07d}"
        self.sessions.add(sid)
        return sid

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeQnap:
    """A running fake QNAP NAS."""

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
    def requests(self) -> list[Request]:
        """Every request received, in order."""
        return self._server.requests

    @property
    def open_sessions(self) -> set[str]:
        """The sessions not signed out."""
        return self._server.sessions

    def mutate(self) -> None:
        """Apply :func:`apply_drift` and move the volatile values on."""
        apply_drift(self._server.scenario)
        self._server.scenario.tick += 1


@contextmanager
def fake_qnap(scenario: Scenario | None = None) -> Iterator[FakeQnap]:
    """Serve ``scenario`` (a default one when None) on a free local port until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeQnap(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
