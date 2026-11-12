"""A fake Redfish BMC on localhost for the contract tests, and a model for a later simulation.

It serves the resources the collector follows, with the property names of the DMTF Redfish
schemas (docs/vendor-notes/redfish.md). The data is synthetic: one server (``Systems/1``) and its
BMC (``Managers/1``), ids as iLO and Supermicro use them, with fixed account slots as some BMCs
list them (slot 3 is empty: ``UserName`` ``""``). Names are ``example.invalid``, addresses RFC 5737.

The fake keeps every resource as one JSON document under its path, so a test or a simulation
changes the configuration by changing a document. Like a BMC it hides what the schemas say is
null in responses (account passwords, the LDAP password, the HTTP headers of a subscription), and
it serves what a BMC may serve (an SNMP community string, the context of a subscription, a BIOS
password attribute), so a test can prove that driftsniff keeps only fingerprints of them.

Surface:

* ``GET /redfish/v1/`` without a credential: the service root (``RedfishVersion``, ``Vendor``,
  ``Product``, links to ``Systems``, ``Managers``, ``AccountService``, ``EventService``,
  ``CertificateService``, ``UpdateService``, ``SessionService`` and ``Links.Sessions``);
* ``POST /redfish/v1/SessionService/Sessions`` with ``{"UserName", "Password"}``: 201, headers
  ``X-Auth-Token`` and ``Location``; a wrong pair is 401;
* ``DELETE`` of the ``Location``: 204, the token stops working;
* ``GET`` of every other path in :data:`Scenario.docs` with a valid ``X-Auth-Token``; no or an
  unknown token is 401, an unknown path 404, any other method 405.

Errors use the Redfish error shape ``{"error": {"code", "message"}}``. :class:`Scenario` has the
helpers that change the configuration; :meth:`Scenario.drift` applies one low, medium, high and
critical change each, and :meth:`Scenario.tick` changes only volatile properties.
"""

import copy
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import urlsplit

USERNAME = "driftsniff"
PASSWORD = "CANARY-redfish-00"  # noqa: S105 - a test canary, not a credential
# Values a BMC may serve; tests check that none of them is ever stored in clear.
SNMP_COMMUNITY = "CANARY-redfish-snmp-00"
SUBSCRIPTION_CONTEXT = "CANARY-redfish-context-00"
BIOS_PASSWORD = "CANARY-redfish-bios-00"  # noqa: S105
# Values the fake stores but never serves, as the schemas require.
ACCOUNT_PASSWORD = "CANARY-redfish-account-00"  # noqa: S105
LDAP_PASSWORD = "CANARY-redfish-ldap-00"  # noqa: S105
TOKEN_PREFIX = "CANARY-redfish-token-"  # noqa: S105

ROOT = "/redfish/v1"
SESSIONS = f"{ROOT}/SessionService/Sessions"
FIRMWARE_VERSION = "2.14.0"
REDFISH_VERSION = "1.17.0"
# Keys a BMC answers as null (write-only), and internal keys the fake never serves.
HIDDEN = {"Password", "_password"}


def _link(path: str) -> dict[str, str]:
    return {"@odata.id": path}


def _collection(path: str, members: list[str]) -> dict[str, Any]:
    return {
        "@odata.id": path,
        "@odata.type": "#Collection",
        "Name": path.rsplit("/", 1)[-1],
        "Members": [_link(member) for member in members],
        "Members@odata.count": len(members),
    }


def _account(slot: int, name: str, role: str, enabled: bool) -> dict[str, Any]:
    return {
        "@odata.id": f"{ROOT}/AccountService/Accounts/{slot}",
        "@odata.etag": f'W/"{slot}"',
        "Id": str(slot),
        "Name": "User Account",
        "Description": "User Account",
        "UserName": name,
        "RoleId": role,
        "Enabled": enabled,
        "Locked": False,
        "AccountTypes": ["Redfish", "WebUI"] if name else [],
        "Password": None,
        "_password": ACCOUNT_PASSWORD if name else "",
        "Links": {"Role": _link(f"{ROOT}/AccountService/Roles/{role}")} if name else {},
    }


def default_docs() -> dict[str, dict[str, Any]]:
    """Every resource of a small synthetic server and its BMC, by path."""
    system = f"{ROOT}/Systems/1"
    manager = f"{ROOT}/Managers/1"
    interface = f"{manager}/EthernetInterfaces/1"
    https_cert = f"{manager}/NetworkProtocol/HTTPS/Certificates/1"
    docs: dict[str, dict[str, Any]] = {
        f"{ROOT}/": {
            "@odata.id": f"{ROOT}/",
            "@odata.type": "#ServiceRoot.v1_17_0.ServiceRoot",
            "Id": "RootService",
            "Name": "Root Service",
            "RedfishVersion": REDFISH_VERSION,
            "Vendor": "Contoso",
            "Product": "Contoso BMC",
            "UUID": "c0a80001-0000-4000-8000-000000000001",
            "Systems": _link(f"{ROOT}/Systems"),
            "Managers": _link(f"{ROOT}/Managers"),
            "AccountService": _link(f"{ROOT}/AccountService"),
            "EventService": _link(f"{ROOT}/EventService"),
            "CertificateService": _link(f"{ROOT}/CertificateService"),
            "UpdateService": _link(f"{ROOT}/UpdateService"),
            "SessionService": _link(f"{ROOT}/SessionService"),
            "Links": {"Sessions": _link(SESSIONS)},
        },
        f"{ROOT}/Systems": _collection(f"{ROOT}/Systems", [system]),
        system: {
            "@odata.id": system,
            "@odata.etag": 'W/"s1"',
            "Id": "1",
            "Name": "System",
            "Description": "Rack server in row A",
            "HostName": "srv-01.example.invalid",
            "Manufacturer": "Contoso",
            "Model": "R100",
            "SerialNumber": "SN0001",
            "UUID": "c0a80001-0000-4000-8000-000000000002",
            "AssetTag": "",
            "SystemType": "Physical",
            "BiosVersion": "1.4.2",
            "PowerState": "On",
            "PowerRestorePolicy": "LastState",
            "Status": {"State": "Enabled", "Health": "OK"},
            "IndicatorLED": "Off",
            "Boot": {
                "BootSourceOverrideEnabled": "Disabled",
                "BootSourceOverrideMode": "UEFI",
                "BootSourceOverrideTarget": "None",
                "BootSourceOverrideTarget@Redfish.AllowableValues": ["None", "Pxe", "Hdd"],
                "BootOrder": ["Boot0001", "Boot0002"],
            },
            "ProcessorSummary": {"Count": 2, "Model": "Contoso CPU", "Status": {"Health": "OK"}},
            "MemorySummary": {"TotalSystemMemoryGiB": 256, "Status": {"Health": "OK"}},
            "TrustedModules": [{"InterfaceType": "TPM2_0", "Status": {"State": "Enabled"}}],
            "Bios": _link(f"{system}/Bios"),
            "SecureBoot": _link(f"{system}/SecureBoot"),
            "Processors": _link(f"{system}/Processors"),
            "Links": {"ManagedBy": [_link(manager)]},
            "Actions": {"#ComputerSystem.Reset": {"target": f"{system}/Actions/Reset"}},
            "Oem": {"Contoso": {"LastPostCode": 7}},
        },
        f"{system}/Bios": {
            "@odata.id": f"{system}/Bios",
            "Id": "Bios",
            "Name": "BIOS Configuration",
            "AttributeRegistry": "BiosAttributeRegistry.1.4",
            "Attributes": {
                "BootMode": "Uefi",
                "ProcVirtualization": "Enabled",
                "SriovGlobalEnable": "Disabled",
                "UsbPorts": "AllOn",
                "AdminPassword": BIOS_PASSWORD,
            },
        },
        f"{system}/SecureBoot": {
            "@odata.id": f"{system}/SecureBoot",
            "Id": "SecureBoot",
            "Name": "UEFI Secure Boot",
            "SecureBootEnable": True,
            "SecureBootMode": "DeployedMode",
            "SecureBootCurrentBoot": "Enabled",
        },
        f"{ROOT}/Managers": _collection(f"{ROOT}/Managers", [manager]),
        manager: {
            "@odata.id": manager,
            "Id": "1",
            "Name": "Manager",
            "Description": "Baseboard management controller",
            "ManagerType": "BMC",
            "Model": "Contoso BMC",
            "FirmwareVersion": FIRMWARE_VERSION,
            "UUID": "c0a80001-0000-4000-8000-000000000003",
            "DateTime": "2026-11-12T09:00:00+00:00",
            "DateTimeLocalOffset": "+00:00",
            "PowerState": "On",
            "Status": {"State": "Enabled", "Health": "OK"},
            "GraphicalConsole": {"ServiceEnabled": True, "ConnectTypesSupported": ["KVMIP"]},
            "NetworkProtocol": _link(f"{manager}/NetworkProtocol"),
            "EthernetInterfaces": _link(f"{manager}/EthernetInterfaces"),
        },
        f"{manager}/NetworkProtocol": {
            "@odata.id": f"{manager}/NetworkProtocol",
            "Id": "NetworkProtocol",
            "Name": "Manager Network Protocol",
            "HostName": "bmc-01",
            "FQDN": "bmc-01.example.invalid",
            "HTTP": {"ProtocolEnabled": False, "Port": 80},
            "HTTPS": {"ProtocolEnabled": True, "Port": 443, "Certificates": _link(f"{https_cert}")},
            "SSH": {"ProtocolEnabled": False, "Port": 22},
            "IPMI": {"ProtocolEnabled": False, "Port": 623},
            "SNMP": {
                "ProtocolEnabled": True,
                "Port": 161,
                "EnableSNMPv1": False,
                "EnableSNMPv2c": True,
                "EnableSNMPv3": True,
                "CommunityStrings": [
                    {
                        "Name": "monitoring",
                        "AccessMode": "Limited",
                        "CommunityString": SNMP_COMMUNITY,
                    }
                ],
            },
            "NTP": {
                "ProtocolEnabled": True,
                "Port": 123,
                "NTPServers": ["192.0.2.10", "192.0.2.11"],
            },
            "Status": {"State": "Enabled", "Health": "OK"},
        },
        f"{manager}/EthernetInterfaces": _collection(f"{manager}/EthernetInterfaces", [interface]),
        interface: {
            "@odata.id": interface,
            "Id": "1",
            "Name": "Manager Ethernet Interface",
            "InterfaceEnabled": True,
            "MACAddress": "02:00:00:00:00:01",
            "HostName": "bmc-01",
            "FQDN": "bmc-01.example.invalid",
            "LinkStatus": "LinkUp",
            "SpeedMbps": 1000,
            "IPv4Addresses": [
                {
                    "Address": "192.0.2.21",
                    "SubnetMask": "255.255.255.0",
                    "AddressOrigin": "Static",
                    "Gateway": "192.0.2.1",
                }
            ],
            "DHCPv4": {"DHCPEnabled": False, "UseDNSServers": False},
            "StaticNameServers": ["192.0.2.53"],
            "NameServers": ["192.0.2.53"],
            "VLAN": {"VLANEnable": False, "VLANId": 0},
            "Status": {"State": "Enabled", "Health": "OK"},
        },
        f"{ROOT}/AccountService": {
            "@odata.id": f"{ROOT}/AccountService",
            "Id": "AccountService",
            "Name": "Account Service",
            "ServiceEnabled": True,
            "MinPasswordLength": 12,
            "MaxPasswordLength": 40,
            "AccountLockoutThreshold": 5,
            "AccountLockoutDuration": 300,
            "AccountLockoutCounterResetAfter": 300,
            "AuthFailureLoggingThreshold": 3,
            "LocalAccountAuth": "Enabled",
            "LDAP": {
                "ServiceEnabled": False,
                "ServiceAddresses": ["ldaps://ldap.example.invalid"],
                "Authentication": {
                    "AuthenticationType": "UsernameAndPassword",
                    "Username": "cn=bmc,dc=example,dc=invalid",
                    "Password": None,
                    "_password": LDAP_PASSWORD,
                },
                "RemoteRoleMapping": [{"RemoteGroup": "bmc-admins", "LocalRole": "Administrator"}],
            },
            "Status": {"State": "Enabled", "Health": "OK"},
            "Accounts": _link(f"{ROOT}/AccountService/Accounts"),
            "Roles": _link(f"{ROOT}/AccountService/Roles"),
        },
        f"{ROOT}/EventService": {
            "@odata.id": f"{ROOT}/EventService",
            "Id": "EventService",
            "Name": "Event Service",
            "ServiceEnabled": True,
            "Subscriptions": _link(f"{ROOT}/EventService/Subscriptions"),
        },
        f"{ROOT}/EventService/Subscriptions": _collection(
            f"{ROOT}/EventService/Subscriptions", [f"{ROOT}/EventService/Subscriptions/1"]
        ),
        f"{ROOT}/EventService/Subscriptions/1": {
            "@odata.id": f"{ROOT}/EventService/Subscriptions/1",
            "Id": "1",
            "Name": "Event Subscription",
            "Destination": "https://events.example.invalid/redfish",
            "Protocol": "Redfish",
            "SubscriptionType": "RedfishEvent",
            "EventFormatType": "Event",
            "RegistryPrefixes": ["Base", "ResourceEvent"],
            "Context": SUBSCRIPTION_CONTEXT,
            "HttpHeaders": [],
            "DeliveryRetryPolicy": "RetryForever",
            "Status": {"State": "Enabled", "Health": "OK"},
        },
        f"{ROOT}/CertificateService": {
            "@odata.id": f"{ROOT}/CertificateService",
            "Id": "CertificateService",
            "Name": "Certificate Service",
            "CertificateLocations": _link(f"{ROOT}/CertificateService/CertificateLocations"),
        },
        f"{ROOT}/CertificateService/CertificateLocations": {
            "@odata.id": f"{ROOT}/CertificateService/CertificateLocations",
            "Id": "CertificateLocations",
            "Name": "Certificate Locations",
            "Links": {"Certificates": [_link(https_cert)], "Certificates@odata.count": 1},
        },
        https_cert: {
            "@odata.id": https_cert,
            "Id": "1",
            "Name": "HTTPS certificate",
            "CertificateType": "PEM",
            "CertificateString": "synthetic certificate text",
            "Subject": {"CommonName": "bmc-01.example.invalid", "Organization": "Example"},
            "Issuer": {"CommonName": "Example Lab CA", "Organization": "Example"},
            "ValidNotBefore": "2026-01-01T00:00:00Z",
            "ValidNotAfter": "2027-01-01T00:00:00Z",
            "SerialNumber": "01",
            "Fingerprint": "AA:BB:CC:01",
            "FingerprintHashAlgorithm": "TPM_ALG_SHA256",
            "KeyUsage": ["KeyEncipherment", "ServerAuthentication"],
        },
        f"{ROOT}/UpdateService": {
            "@odata.id": f"{ROOT}/UpdateService",
            "Id": "UpdateService",
            "Name": "Update Service",
            "FirmwareInventory": _link(f"{ROOT}/UpdateService/FirmwareInventory"),
        },
    }
    accounts = [
        _account(1, "admin", "Administrator", True),
        _account(2, USERNAME, "ReadOnly", True),
        _account(3, "", "ReadOnly", False),
        _account(4, "operator", "Operator", True),
    ]
    docs[f"{ROOT}/AccountService/Accounts"] = _collection(
        f"{ROOT}/AccountService/Accounts", [account["@odata.id"] for account in accounts]
    )
    for account in accounts:
        docs[account["@odata.id"]] = account
    inventory = {
        "BMC": ("BMC firmware", FIRMWARE_VERSION),
        "BIOS": ("System BIOS", "1.4.2"),
    }
    base = f"{ROOT}/UpdateService/FirmwareInventory"
    docs[base] = _collection(base, [f"{base}/{key}" for key in inventory])
    for key, (name, version) in inventory.items():
        docs[f"{base}/{key}"] = {
            "@odata.id": f"{base}/{key}",
            "Id": key,
            "Name": name,
            "Version": version,
            "Updateable": True,
            "Status": {"State": "Enabled", "Health": "OK"},
        }
    return docs


@dataclass
class Scenario:
    """What the fake BMC stores and which faults it simulates.

    ``status`` forces an HTTP status for a path (the session collection included), ``raw`` serves
    bytes for a path instead of its document. ``location`` False leaves the ``Location`` header out
    of the sign in answer.
    """

    docs: dict[str, dict[str, Any]] = field(default_factory=default_docs)
    users: dict[str, str] = field(default_factory=lambda: {USERNAME: PASSWORD})
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    location: bool = True
    # Serve every collection in reverse order (the order must never matter).
    reverse: bool = False
    # Put the received password and token into the body of error answers (a leaking server).
    echo: bool = False
    sessions: dict[str, str] = field(default_factory=dict)
    issued: int = 0

    def doc(self, path: str) -> dict[str, Any]:
        return self.docs[ROOT + path]

    # -- drift helpers ----------------------------------------------------------------------

    def set_description(self, text: str) -> None:
        """Low: the description of the server."""
        self.doc("/Systems/1")["Description"] = text

    def set_ntp_servers(self, servers: list[str]) -> None:
        """Medium: the NTP servers of the BMC."""
        self.doc("/Managers/1/NetworkProtocol")["NTP"]["NTPServers"] = servers

    def set_firmware(self, version: str) -> None:
        """Medium: a BMC firmware update (the manager and the inventory entry)."""
        self.doc("/Managers/1")["FirmwareVersion"] = version
        self.doc("/UpdateService/FirmwareInventory/BMC")["Version"] = version

    def set_protocol(self, name: str, enabled: bool) -> None:
        """SSH on is high, IPMI or Telnet on is critical."""
        protocols = self.doc("/Managers/1/NetworkProtocol")
        protocols.setdefault(name, {"Port": {"SSH": 22, "IPMI": 623, "Telnet": 23}.get(name)})
        protocols[name]["ProtocolEnabled"] = enabled

    def set_secure_boot(self, enabled: bool) -> None:
        """Critical when switched off."""
        self.doc("/Systems/1/SecureBoot")["SecureBootEnable"] = enabled

    def set_boot_order(self, order: list[str]) -> None:
        """High."""
        self.doc("/Systems/1")["Boot"]["BootOrder"] = order

    def set_bios(self, attribute: str, value: Any) -> None:
        """Medium."""
        self.doc("/Systems/1/Bios")["Attributes"][attribute] = value

    def set_role(self, slot: int, role: str) -> None:
        """Critical when the role becomes Administrator."""
        self.doc(f"/AccountService/Accounts/{slot}")["RoleId"] = role

    def add_account(self, slot: int, name: str, role: str) -> None:
        """Critical: a new account in an empty slot (or a new slot)."""
        path = f"{ROOT}/AccountService/Accounts/{slot}"
        self.docs[path] = _account(slot, name, role, True)
        members = self.doc("/AccountService/Accounts")["Members"]
        if _link(path) not in members:
            members.append(_link(path))

    def set_subscription_destination(self, url: str) -> None:
        """High."""
        self.doc("/EventService/Subscriptions/1")["Destination"] = url

    def tick(self) -> None:
        """Volatile changes only (power, health, clock, link, lock, etags): no drift."""
        system = self.doc("/Systems/1")
        system["PowerState"] = "Off" if system["PowerState"] == "On" else "On"
        system["Status"]["Health"] = "Warning"
        system["@odata.etag"] = 'W/"s2"'
        system["ProcessorSummary"]["Status"]["Health"] = "Critical"
        self.doc("/Systems/1/SecureBoot")["SecureBootCurrentBoot"] = "Disabled"
        self.doc("/Managers/1")["DateTime"] = "2026-11-12T10:00:00+00:00"
        interface = self.doc("/Managers/1/EthernetInterfaces/1")
        interface["LinkStatus"] = "LinkDown"
        interface["SpeedMbps"] = 100
        self.doc("/AccountService/Accounts/4")["Locked"] = True
        self.doc("/UpdateService/FirmwareInventory/BIOS")["Status"]["Health"] = "Warning"

    def drift(self) -> None:
        """The standard drift of the simulation: one change of each severity."""
        self.tick()
        self.set_description("Rack server in row B")  # low
        self.set_ntp_servers(["192.0.2.12", "192.0.2.11"])  # medium
        self.set_protocol("SSH", True)  # high
        self.set_protocol("IPMI", True)  # critical
        self.add_account(3, "intruder", "Administrator")  # critical (new account)


# -- serving -----------------------------------------------------------------------------------


def _served(doc: dict[str, Any], reverse: bool) -> dict[str, Any]:
    """What a BMC answers: write-only values are null, internal values are gone."""

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: (None if k in HIDDEN else strip(v)) for k, v in value.items() if k[0] != "_"}
        if isinstance(value, list):
            return [strip(member) for member in value]
        return value

    served = cast("dict[str, Any]", strip(copy.deepcopy(doc)))
    if reverse and isinstance(served.get("Members"), list):
        served["Members"].reverse()
    return served


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    method: str
    path: str
    query: str
    token: str | None
    authorization: str | None
    body: bytes


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    @property
    def _scenario(self) -> Scenario:
        return cast("_Server", self.server).scenario

    def _send(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str, echo: str = "") -> None:
        text = f"{message} {echo}" if self._scenario.echo else message
        payload = {"error": {"code": "Base.1.15.GeneralError", "message": text}}
        self._send(status, json.dumps(payload).encode("utf-8"))

    def _record(self) -> tuple[str, bytes]:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        parts = urlsplit(self.path)
        cast("_Server", self.server).requests.append(
            Request(
                self.command,
                parts.path,
                parts.query,
                self.headers.get("X-Auth-Token"),
                self.headers.get("Authorization"),
                body,
            )
        )
        return parts.path, body

    def _authorized(self) -> bool:
        token = self.headers.get("X-Auth-Token") or ""
        if token in self._scenario.sessions.values():
            return True
        self._error(401, "NoValidSession", token)
        return False

    def do_POST(self) -> None:
        scenario = self._scenario
        path, body = self._record()
        if path.rstrip("/") != SESSIONS:
            self._error(405, "Method Not Allowed")
            return
        forced = scenario.status.get(SESSIONS)
        if forced is not None:
            self._error(forced, "Simulated failure")
            return
        try:
            login = json.loads(body)
        except ValueError:
            self._error(400, "MalformedJSON")
            return
        name, password = login.get("UserName"), login.get("Password")
        if not isinstance(name, str) or scenario.users.get(name) != password:
            self._error(401, "Base.1.15.NoValidSession", str(password))
            return
        scenario.issued += 1
        session = f"{SESSIONS}/{scenario.issued}"
        token = f"{TOKEN_PREFIX}{scenario.issued:02d}"
        scenario.sessions[session] = token
        headers = {"X-Auth-Token": token}
        if scenario.location:
            headers["Location"] = session
        payload = {"@odata.id": session, "Id": str(scenario.issued), "UserName": name}
        self._send(201, json.dumps(payload).encode("utf-8"), headers)

    def do_DELETE(self) -> None:
        path, _ = self._record()
        if not self._authorized():
            return
        if self._scenario.sessions.pop(path, None) is None:
            self._error(404, "ResourceMissingAtURI")
            return
        self._send(204, b"")

    def do_GET(self) -> None:
        scenario = self._scenario
        path, _ = self._record()
        if path in (ROOT, f"{ROOT}/"):
            path = f"{ROOT}/"
        elif not self._authorized():
            return
        forced = scenario.status.get(path)
        if forced is not None:
            self._error(forced, "Simulated failure")
            return
        if path in scenario.raw:
            self._send(200, scenario.raw[path])
            return
        doc = scenario.docs.get(path)
        if doc is None:
            self._error(404, "ResourceMissingAtURI")
            return
        self._send(200, json.dumps(_served(doc, scenario.reverse)).encode("utf-8"))

    def _refuse(self) -> None:
        self._record()
        self._error(405, "Method Not Allowed")

    do_PUT = do_PATCH = _refuse


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeRedfish:
    """A running fake BMC."""

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
def fake_redfish(scenario: Scenario | None = None) -> Iterator[FakeRedfish]:
    """Serve ``scenario`` (the default BMC when None) until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeRedfish(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
