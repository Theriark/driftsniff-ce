"""A fake Proxmox VE API on localhost for the contract tests, and a model for a later simulation.

It serves the read endpoints the collector uses, with the shapes read from the Proxmox VE API
schema and sources on 2026-11-12 (docs/vendor-notes/proxmox.md). The data is synthetic: a two node
cluster (``pve1``, ``pve2``) with two virtual machines, one container, storage, a cluster firewall
with a security group, aliases and an IP set, users with an API token, groups, a custom role, ACL
entries, an LDAP and an OpenID realm, a backup and a replication job, HA, SDN and a pool. Names
end in ``example.invalid``; addresses are from RFC 5737.

Like Proxmox the fake answers every path with ``{"data": ...}`` and booleans as 0 and 1. It keeps
what Proxmox keeps and serves what Proxmox serves: the cloud-init password, the container
environment, the yubico keys of a user and the OpenID client key are served (the realm read
returns the stored hash), so a test can prove driftsniff keeps only fingerprints of them.

Surface (GET only under ``/api2/json``; every other method answers 405):

* ``/version`` ``{"version", "release", "repoid"}``;
* ``/cluster/options``, ``/cluster/firewall/options``: one object;
* ``/nodes`` and ``/nodes/{node}/config``;
* ``/cluster/resources?type=vm`` (guests with live usage) and
  ``/nodes/{node}/qemu/{vmid}/config``, ``/nodes/{node}/lxc/{vmid}/config``;
* ``/storage``, ``/cluster/firewall/rules``, ``/cluster/firewall/groups``,
  ``/cluster/firewall/groups/{group}``, ``/cluster/firewall/aliases``, ``/cluster/firewall/ipset``,
  ``/cluster/firewall/ipset/{name}``;
* ``/access/users?full=1`` (with tokens), ``/access/groups``, ``/access/roles``, ``/access/acl``,
  ``/access/domains`` (realm, type, comment, tfa) and ``/access/domains/{realm}`` (stored hash);
* ``/cluster/backup``, ``/cluster/replication``, ``/cluster/ha/resources``,
  ``/cluster/ha/groups``, ``/cluster/sdn/zones``, ``/cluster/sdn/vnets``, ``/pools``.

The token travels in ``Authorization: PVEAPIToken=user@realm!tokenid=secret``; a missing or
unknown one answers 401. A path the fake does not know answers 501, as Proxmox does. Errors carry
``{"data": null}``. :class:`Scenario` has helpers that change the configuration so that two reads
show a drift (:meth:`Scenario.drift` applies one low, one medium, three high and two critical).
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

API_TOKEN = "driftsniff@pve!audit=CANARY-proxmox-token-00"  # noqa: S105 - a test canary
# Secret values Proxmox serves; tests check that none of them is ever stored in clear.
CI_PASSWORD = "CANARY-pxci-0"  # noqa: S105
CI_PASSWORD_NEW = "CANARY-pxcj-0"  # noqa: S105
CONTAINER_ENV = "DB_PASS=CANARY-proxmox-env-00"
YUBICO_KEYS = "CANARY-pxyk-0"
OIDC_CLIENT_KEY = "CANARY-pxoc-0"
SECRETS = (API_TOKEN, CI_PASSWORD, CI_PASSWORD_NEW, CONTAINER_ENV, YUBICO_KEYS, OIDC_CLIENT_KEY)
VERSION = "8.3.2"
PREFIX = "/api2/json"


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    method: str
    path: str
    query: str
    authorization: str | None
    cookie: str | None


def default_state() -> dict[str, Any]:
    """The stored configuration of a small synthetic Proxmox VE cluster."""
    return {
        "cluster_options": {
            "keyboard": "en-us",
            "console": "html5",
            "mac_prefix": "BC:24:11",
            "email_from": "pve@example.invalid",
            "description": "Lab datacenter",
            "http_proxy": "http://proxy.example.invalid:3128",
            "allowed-tags": [],
        },
        "nodes": [
            {
                "node": "pve1",
                "status": "online",
                "ssl_fingerprint": "AA:BB:CC:01",
                "cpu": 0.05,
                "mem": 4_000_000_000,
                "uptime": 86_400,
                "_config": {"description": "first node", "digest": "d-node1"},
            },
            {
                "node": "pve2",
                "status": "online",
                "ssl_fingerprint": "AA:BB:CC:02",
                "cpu": 0.07,
                "mem": 5_000_000_000,
                "uptime": 86_000,
                "_config": {
                    "acmedomain0": "domain=pve2.example.invalid",
                    "digest": "d-node2",
                },
            },
        ],
        "guests": [
            {
                "vmid": 100,
                "type": "qemu",
                "node": "pve1",
                "status": "running",
                "uptime": 3_600,
                "cpu": 0.02,
                "mem": 1_000_000_000,
                "_config": {
                    "name": "web-01",
                    "memory": "4096",
                    "cores": 2,
                    "sockets": 1,
                    "cpu": "x86-64-v2-AES",
                    "ostype": "l26",
                    "onboot": 1,
                    "protection": 1,
                    "agent": "1",
                    "boot": "order=scsi0;net0",
                    "scsihw": "virtio-scsi-single",
                    "scsi0": "local-lvm:vm-100-disk-0,iothread=1,size=32G",
                    "net0": "virtio=BC:24:11:00:01:00,bridge=vmbr0,firewall=1",
                    "ipconfig0": "ip=192.0.2.10/24,gw=192.0.2.1",
                    "ciuser": "ops",
                    "cipassword": CI_PASSWORD,
                    "description": "Web server",
                    "digest": "d-100-a",
                    "meta": "creation-qemu=9.0.2,ctime=1762800000",
                    "vmgenid": "00000000-0000-4000-8000-000000000100",
                    "smbios1": "uuid=00000000-0000-4000-8000-000000000101",
                },
            },
            {
                "vmid": 101,
                "type": "qemu",
                "node": "pve2",
                "status": "stopped",
                "uptime": 0,
                "cpu": 0,
                "mem": 0,
                "_config": {
                    "name": "db-01",
                    "memory": "8192",
                    "cores": 4,
                    "ostype": "l26",
                    "virtio0": "ceph:vm-101-disk-0,size=64G",
                    "net0": "virtio=BC:24:11:00:01:01,bridge=vmbr0,tag=20",
                    "net1": "virtio=BC:24:11:00:01:02,bridge=vmbr1",
                    "digest": "d-101-a",
                },
            },
            {
                "vmid": 200,
                "type": "lxc",
                "node": "pve1",
                "status": "running",
                "uptime": 7_200,
                "cpu": 0.01,
                "mem": 200_000_000,
                "_config": {
                    "hostname": "dns-01",
                    "memory": 512,
                    "swap": 512,
                    "cores": 1,
                    "ostype": "debian",
                    "arch": "amd64",
                    "unprivileged": 1,
                    "features": "nesting=1",
                    "rootfs": "local-lvm:vm-200-disk-0,size=8G",
                    "net0": "name=eth0,bridge=vmbr0,ip=192.0.2.53/24,gw=192.0.2.1",
                    "mp0": "local-lvm:vm-200-disk-1,mp=/srv,size=4G",
                    "env": CONTAINER_ENV,
                    "digest": "d-200-a",
                },
            },
        ],
        "storage": [
            {
                "storage": "local",
                "type": "dir",
                "path": "/var/lib/vz",
                "content": "iso,vztmpl,backup",
            },
            {
                "storage": "local-lvm",
                "type": "lvmthin",
                "vgname": "pve",
                "thinpool": "data",
                "content": "images,rootdir",
            },
            {
                "storage": "pbs",
                "type": "pbs",
                "server": "198.51.100.20",
                "datastore": "lab",
                "username": "backup@pbs",
                "fingerprint": "AA:BB:CC:DD",
                "content": "backup",
                "prune-backups": "keep-daily=7,keep-weekly=4",
            },
        ],
        "firewall_options": {
            "enable": 1,
            "policy_in": "DROP",
            "policy_out": "ACCEPT",
            "ebtables": 1,
            "digest": "d-fw-1",
        },
        "firewall_rules": [
            {
                "pos": 0,
                "type": "in",
                "action": "ACCEPT",
                "macro": "SSH",
                "source": "+management",
                "enable": 1,
                "comment": "admins",
                "digest": "d-fw-1",
            },
            {
                "pos": 1,
                "type": "in",
                "action": "ACCEPT",
                "proto": "tcp",
                "dport": "8006",
                "source": "admin_net",
                "enable": 1,
                "digest": "d-fw-1",
            },
            {"pos": 2, "type": "group", "action": "webservers", "enable": 1, "digest": "d-fw-1"},
        ],
        "firewall_groups": [
            {
                "group": "webservers",
                "comment": "public web",
                "digest": "d-fw-1",
                "_rules": [
                    {
                        "pos": 0,
                        "type": "in",
                        "action": "ACCEPT",
                        "macro": "HTTPS",
                        "enable": 1,
                        "digest": "d-fw-1",
                    },
                    {
                        "pos": 1,
                        "type": "in",
                        "action": "DROP",
                        "proto": "tcp",
                        "dport": "80",
                        "enable": 1,
                        "log": "info",
                        "digest": "d-fw-1",
                    },
                ],
            }
        ],
        "aliases": [
            {
                "name": "admin_net",
                "cidr": "203.0.113.0/28",
                "comment": "admin VPN",
                "ipversion": 4,
                "digest": "d-fw-1",
            },
        ],
        "ipsets": [
            {
                "name": "management",
                "comment": "jump hosts",
                "digest": "d-fw-1",
                "_entries": [
                    {"cidr": "192.0.2.5", "comment": "jump-01", "digest": "d-fw-1"},
                    {"cidr": "192.0.2.6", "nomatch": 0, "digest": "d-fw-1"},
                ],
            }
        ],
        "users": [
            {
                "userid": "root@pam",
                "enable": 1,
                "expire": 0,
                "email": "root@example.invalid",
                "realm-type": "pam",
                "tfa-locked-until": 0,
                "totp-locked": 0,
                "tokens": [],
            },
            {
                "userid": "ops@pve",
                "enable": 1,
                "expire": 0,
                "firstname": "Ops",
                "groups": "operators",
                "keys": YUBICO_KEYS,
                "realm-type": "pve",
                "tokens": [],
            },
            {
                "userid": "driftsniff@pve",
                "enable": 1,
                "expire": 0,
                "comment": "drift reader",
                "realm-type": "pve",
                "tokens": [{"tokenid": "audit", "privsep": 1, "expire": 0, "comment": "read only"}],
            },
        ],
        "groups": [{"groupid": "operators", "comment": "ops team", "users": "ops@pve"}],
        "roles": [
            {"roleid": "Administrator", "special": 1, "privs": "Sys.Audit,Sys.Modify,VM.Audit"},
            {"roleid": "PVEAuditor", "special": 1, "privs": "Datastore.Audit,Sys.Audit,VM.Audit"},
            {"roleid": "Operator", "special": 0, "privs": "VM.Audit,VM.PowerMgmt"},
        ],
        "acl": [
            {
                "path": "/",
                "type": "user",
                "ugid": "root@pam",
                "roleid": "Administrator",
                "propagate": 1,
            },
            {
                "path": "/",
                "type": "token",
                "ugid": "driftsniff@pve!audit",
                "roleid": "PVEAuditor",
                "propagate": 1,
            },
            {
                "path": "/vms",
                "type": "group",
                "ugid": "operators",
                "roleid": "Operator",
                "propagate": 1,
            },
        ],
        "domains": [
            {"realm": "pam", "type": "pam", "comment": "Linux PAM standard authentication"},
            {
                "realm": "pve",
                "type": "pve",
                "comment": "Proxmox VE authentication server",
                "default": 1,
            },
            {
                "realm": "corp",
                "type": "ldap",
                "comment": "Corporate directory",
                "server1": "ldap.example.invalid",
                "port": 636,
                "mode": "ldaps",
                "verify": 1,
                "base_dn": "dc=example,dc=invalid",
                "bind_dn": "cn=pve,dc=example,dc=invalid",
                "user_attr": "uid",
            },
            {
                "realm": "sso",
                "type": "openid",
                "comment": "Single sign on",
                "issuer-url": "https://sso.example.invalid/realms/lab",
                "client-id": "proxmox",
                "client-key": OIDC_CLIENT_KEY,
                "autocreate": 0,
                "username-claim": "subject",
            },
        ],
        "backup": [
            {
                "id": "backup-daily",
                "type": "vzdump",
                "enabled": 1,
                "schedule": "02:00",
                "storage": "pbs",
                "all": 1,
                "mode": "snapshot",
                "compress": "zstd",
                "notification-mode": "notification-system",
                "comment": "nightly",
                "next-run": 1762912800,
            },
        ],
        "replication": [
            {
                "id": "101-0",
                "type": "local",
                "guest": 101,
                "jobnum": 0,
                "target": "pve1",
                "schedule": "*/15",
                "source": "pve2",
            },
        ],
        "ha_resources": [
            {
                "sid": "vm:101",
                "type": "vm",
                "state": "started",
                "group": "prefer-pve2",
                "max_restart": 1,
                "max_relocate": 1,
                "digest": "d-ha-1",
            },
        ],
        "ha_groups": [
            {
                "group": "prefer-pve2",
                "type": "group",
                "nodes": "pve2:2,pve1:1",
                "restricted": 0,
                "nofailback": 0,
                "digest": "d-ha-1",
            },
        ],
        "sdn_zones": [
            {"zone": "lab", "type": "vlan", "bridge": "vmbr0", "digest": "d-sdn-1"},
        ],
        "sdn_vnets": [
            {"vnet": "vlan20", "zone": "lab", "type": "vnet", "tag": 20, "digest": "d-sdn-1"},
        ],
        "pools": [
            {
                "poolid": "web",
                "comment": "web tier",
                "members": [
                    {
                        "id": "qemu/100",
                        "type": "qemu",
                        "vmid": 100,
                        "node": "pve1",
                        "status": "running",
                        "cpu": 0.02,
                        "mem": 1_000_000_000,
                    },
                    {
                        "id": "storage/pve1/local",
                        "type": "storage",
                        "node": "pve1",
                        "storage": "local",
                        "disk": 10_000_000_000,
                    },
                ],
            }
        ],
    }


@dataclass
class Scenario:
    """What the fake Proxmox VE stores and which faults it simulates.

    ``status`` forces an HTTP status on a route key (the API path without ``/api2/json`` and
    without the leading slash, with ``{...}`` for a name: ``access/acl``, ``nodes/{node}/config``,
    ``nodes/{node}/qemu/{vmid}/config``, ``cluster/firewall/groups/{group}``). ``raw`` serves a
    body as it is on a route key.
    """

    state: dict[str, Any] = field(default_factory=default_state)
    tokens: frozenset[str] = frozenset({API_TOKEN})
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    # Serve every list in reverse order (the order must never matter).
    reverse: bool = False
    # Put the received Authorization header into the body of error answers (a leaking server).
    echo_key: bool = False

    # -- drift helpers ----------------------------------------------------------------------

    def _find(self, name: str, key_field: str, key: Any) -> dict[str, Any]:
        for item in self.state[name]:
            if item[key_field] == key:
                return cast("dict[str, Any]", item)
        raise KeyError(f"{name} {key}")

    def guest_config(self, vmid: int) -> dict[str, Any]:
        return cast("dict[str, Any]", self._find("guests", "vmid", vmid)["_config"])

    def rename_vm(self, vmid: int, name: str) -> None:
        """Low: a new name."""
        self.guest_config(vmid)["name"] = name

    def set_guest_key(self, vmid: int, key: str, value: Any) -> None:
        """Set (or with None remove) one config key of a guest, such as net0 or cipassword."""
        config = self.guest_config(vmid)
        if value is None:
            config.pop(key, None)
        else:
            config[key] = value

    def set_backup_enabled(self, job_id: str, enabled: int) -> None:
        """High when it becomes 0."""
        self._find("backup", "id", job_id)["enabled"] = enabled

    def add_user(self, userid: str) -> None:
        """High: a new user (object floor)."""
        self.state["users"].append(
            {"userid": userid, "enable": 1, "expire": 0, "realm-type": "pve", "tokens": []}
        )

    def add_token(self, userid: str, tokenid: str, privsep: int = 1) -> None:
        """High: a new API token (object floor)."""
        user = self._find("users", "userid", userid)
        user["tokens"].append({"tokenid": tokenid, "privsep": privsep, "expire": 0})

    def set_firewall_enable(self, value: int) -> None:
        """Critical when the cluster firewall becomes 0."""
        self.state["firewall_options"]["enable"] = value

    def grant_acl(self, path: str, kind: str, ugid: str, roleid: str) -> None:
        """Critical for the Administrator role (proxmox-admin-acl floor), high for another."""
        self.state["acl"].append(
            {"path": path, "type": kind, "ugid": ugid, "roleid": roleid, "propagate": 1}
        )

    def tick(self) -> None:
        """Volatile changes only (usage, uptime, next run): no drift."""
        for node in self.state["nodes"]:
            node["uptime"] += 60
            node["cpu"] = round(node["cpu"] + 0.01, 2)
        for guest in self.state["guests"]:
            guest["uptime"] += 60
            guest["mem"] += 1024
        for job in self.state["backup"]:
            job["next-run"] += 86_400
        for pool in self.state["pools"]:
            for member in pool["members"]:
                if "mem" in member:
                    member["mem"] += 1024
        for user in self.state["users"]:
            user["tfa-locked-until"] = 0

    def drift(self) -> None:
        """The standard drift of the simulation: one change of each kind the pack grades."""
        self.tick()
        self.rename_vm(100, "web-01b")  # low
        self.set_guest_key(
            100, "net0", "virtio=BC:24:11:00:01:00,bridge=vmbr1,firewall=1"
        )  # medium
        self.set_guest_key(100, "cipassword", CI_PASSWORD_NEW)  # high, secret
        self.set_backup_enabled("backup-daily", 0)  # high
        self.add_user("intruder@pve")  # high
        self.set_firewall_enable(0)  # critical
        self.grant_acl("/", "user", "intruder@pve", "Administrator")  # critical


# -- serving -----------------------------------------------------------------------------------

_LISTS = {
    "storage": "storage",
    "cluster/firewall/rules": "firewall_rules",
    "cluster/firewall/aliases": "aliases",
    "access/groups": "groups",
    "access/roles": "roles",
    "access/acl": "acl",
    "cluster/backup": "backup",
    "cluster/replication": "replication",
    "cluster/ha/resources": "ha_resources",
    "cluster/ha/groups": "ha_groups",
    "cluster/sdn/zones": "sdn_zones",
    "cluster/sdn/vnets": "sdn_vnets",
    "pools": "pools",
}


def _public(item: dict[str, Any]) -> dict[str, Any]:
    """An object without the fake's own ``_`` members."""
    return {key: value for key, value in item.items() if not key.startswith("_")}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json;charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _data(self, payload: object) -> None:
        self._send(200, json.dumps({"data": payload}).encode("utf-8"))

    def _error(self, status: int) -> None:
        scenario = cast("_Server", self.server).scenario
        body: dict[str, Any] = {"data": None}
        if scenario.echo_key:
            body["message"] = self.headers.get("Authorization", "")
        self._send(status, json.dumps(body).encode("utf-8"))

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
        self._error(405)

    do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

    def do_GET(self) -> None:
        scenario = cast("_Server", self.server).scenario
        path, query = self._record("GET")
        header = self.headers.get("Authorization") or ""
        if not header.startswith("PVEAPIToken=") or header[12:] not in scenario.tokens:
            self._error(401)
            return
        if not path.startswith(PREFIX + "/"):
            self._error(501)
            return
        parts = path[len(PREFIX) + 1 :].strip("/").split("/")
        found = self._route(scenario, parts, query)
        if found is None:
            self._error(501)
            return
        key, answer = found
        forced = scenario.status.get(key)
        if forced is not None:
            self._error(forced)
            return
        if key in scenario.raw:
            self._send(200, scenario.raw[key])
            return
        if answer is _MISSING:
            self._error(500)  # Proxmox answers 500 "does not exist" for an unknown name
            return
        answer = copy.deepcopy(answer)
        if scenario.reverse and isinstance(answer, list):
            answer.reverse()
        self._data(answer)

    @staticmethod
    def _route(
        scenario: Scenario, parts: list[str], query: dict[str, list[str]]
    ) -> tuple[str, Any] | None:
        state = scenario.state
        route = "/".join(parts)
        if route == "version":
            return route, {"version": VERSION, "release": "8.3", "repoid": "c1689ccb1065a83b"}
        if route == "cluster/options":
            return route, state["cluster_options"]
        if route == "cluster/firewall/options":
            return route, state["firewall_options"]
        if route in _LISTS:
            return route, state[_LISTS[route]]
        if route == "nodes":
            return route, [_public(node) for node in state["nodes"]]
        if route == "cluster/resources":
            guests = [
                {
                    **_public(guest),
                    "id": f"{guest['type']}/{guest['vmid']}",
                    "name": guest["_config"].get("name", guest["_config"].get("hostname")),
                }
                for guest in state["guests"]
            ]
            if query.get("type") == ["vm"]:
                return route, guests
            return route, guests + [
                {"id": f"node/{n['node']}", "type": "node", "node": n["node"]}
                for n in state["nodes"]
            ]
        if route == "cluster/firewall/groups":
            return route, [_public(group) for group in state["firewall_groups"]]
        if route == "cluster/firewall/ipset":
            return route, [_public(ipset) for ipset in state["ipsets"]]
        if route == "access/users":
            users = copy.deepcopy(state["users"])
            if query.get("full") != ["1"]:
                for user in users:
                    user.pop("tokens", None)
                    user.pop("groups", None)
            return route, users
        if route == "access/domains":
            fields = ("realm", "type", "comment", "tfa")
            return route, [
                {key: realm[key] for key in fields if key in realm} for realm in state["domains"]
            ]
        if len(parts) == 3 and parts[0] == "nodes" and parts[2] == "config":
            node = _named(state["nodes"], "node", parts[1])
            return "nodes/{node}/config", _MISSING if node is None else node["_config"]
        if len(parts) == 5 and parts[0] == "nodes" and parts[2] in ("qemu", "lxc"):
            if parts[4] != "config":
                return None
            guest = next(
                (
                    g
                    for g in state["guests"]
                    if str(g["vmid"]) == parts[3]
                    and g["node"] == parts[1]
                    and g["type"] == parts[2]
                ),
                None,
            )
            key = f"nodes/{{node}}/{parts[2]}/{{vmid}}/config"
            return key, _MISSING if guest is None else guest["_config"]
        if len(parts) == 4 and parts[:3] == ["cluster", "firewall", "groups"]:
            group = _named(state["firewall_groups"], "group", parts[3])
            return "cluster/firewall/groups/{group}", _MISSING if group is None else group["_rules"]
        if len(parts) == 4 and parts[:3] == ["cluster", "firewall", "ipset"]:
            ipset = _named(state["ipsets"], "name", parts[3])
            return "cluster/firewall/ipset/{name}", _MISSING if ipset is None else ipset["_entries"]
        if len(parts) == 3 and parts[:2] == ["access", "domains"]:
            realm = _named(state["domains"], "realm", parts[2])
            return "access/domains/{realm}", (
                _MISSING if realm is None else {**realm, "digest": "d-domains-1"}
            )
        return None


_MISSING: Any = object()


def _named(items: list[dict[str, Any]], key_field: str, name: str) -> dict[str, Any] | None:
    return next((item for item in items if str(item[key_field]) == name), None)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeProxmox:
    """A running fake Proxmox VE."""

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
def fake_proxmox(scenario: Scenario | None = None) -> Iterator[FakeProxmox]:
    """Serve ``scenario`` (the default cluster when None) until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeProxmox(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
