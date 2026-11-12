"""The Proxmox VE client: probe and read only GETs under ``/api2/json``.

``ProxmoxClient`` is a :class:`~driftsniff.collectors.base.Collector` for the REST API of Proxmox
VE. Paths and fields were read from the official API schema and the Proxmox sources on 2026-11-12
(docs/vendor-notes/proxmox.md); no lab Proxmox VE was used.

* The credential is a whole API token, ``USER@REALM!TOKENID=SECRET``. It travels in one header,
  ``Authorization: PVEAPIToken=<token>``, and nowhere else: never in a query string, a log line or
  an error text. This module logs nothing, and every error text is fixed.
* ``probe()`` reads ``/version``, which needs a valid token, so a refused token stops the run
  before anything else is read.
* Coverage: 404 and 501 (Proxmox answers 501 for a path it does not know, for example SDN without
  its package) are ``not_available``, 403 is ``forbidden``; both keep the previous state of the
  resource. Proxmox filters many lists by permission instead of refusing them, so a token without
  the rights sees an empty list; the setup guide asks for PVEAuditor on ``/`` for that reason.
* Guests: ``/cluster/resources?type=vm`` lists every guest with its node (one request for the
  whole cluster); then each config is one GET. More than ``MAX_GUESTS`` of a kind fails that
  resource, so the run stays inside its time limit and nothing is reported as removed.

``probe()`` resolves the host name once, refuses a blocked answer and pins the first answer
(``collectors/resolve.py``); TLS modes come from ``collectors/tls.py``. Redirects are refused.
"""

import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final

import httpx

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
    REQUEST_TIMEOUT_SECONDS,
    STATUS_ERROR,
    Collector,
    CollectorError,
    FetchResult,
    ResourceSpec,
    fetch_json,
    make_client,
)
from driftsniff.collectors.proxmox import normalize as shape
from driftsniff.collectors.proxmox import resources as res
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.addresses import validate_base_url

ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_NO_API: Final = "no_api"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"
ERROR_TOO_MANY_GUESTS: Final = "too_many_guests"

STATUS_UNAUTHORIZED: Final = "401"
STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
_NOT_AVAILABLE: Final = (STATUS_NOT_FOUND, "501")

_TOKEN: Final = re.compile(r"[^\s:/]+@[A-Za-z][A-Za-z0-9._-]*![A-Za-z][A-Za-z0-9._-]*=\S+")
_VERSION: Final = re.compile(r"\d{1,4}\.\d{1,4}(?:[.-][0-9A-Za-z.~+-]{1,32})?")

type Objects = list[dict[str, JsonValue]]


class ProxmoxClient(Collector):
    """Reads Proxmox VE read only. One instance serves one run."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        allow_plain_http: bool = False,
        transport: httpx.BaseTransport | None = None,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
        resolver: Resolver | None = None,
        tls: TlsSettings | None = None,
        data_dir: Path | str = DEFAULT_DATA_DIR,
    ) -> None:
        if not _TOKEN.fullmatch(api_token) or not api_token.isascii():
            raise ValueError("the API token must look like user@realm!tokenid=secret")
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._headers = {res.AUTH_HEADER: f"{res.AUTH_SCHEME}{api_token}"}
        self._resolver = resolver or system_resolver
        self._address = AddressPin()
        self._client = make_client(
            transport=transport,
            tls=tls,
            data_dir=data_dir,
            address=self._address if transport is None else None,
        )
        self._client.timeout = httpx.Timeout(request_timeout)
        self._ready = False
        self._bytes = 0
        self._readers: dict[str, Callable[[], Objects]] = {
            res.RESOURCE_CLUSTER_OPTIONS: lambda: shape.single(self._get("/cluster/options")),
            res.RESOURCE_NODES: self._nodes,
            res.RESOURCE_VMS: lambda: self._guests("qemu", res.VM_SLOTS),
            res.RESOURCE_CONTAINERS: lambda: self._guests("lxc", res.CONTAINER_SLOTS),
            res.RESOURCE_FIREWALL_OPTIONS: lambda: shape.single(
                self._get("/cluster/firewall/options")
            ),
            res.RESOURCE_FIREWALL_RULES: self._firewall_rules,
            res.RESOURCE_FIREWALL_IPSETS: self._ipsets,
            res.RESOURCE_USERS: lambda: shape.users(self._get("/access/users?full=1")),
            res.RESOURCE_TOKENS: lambda: shape.tokens(self._get("/access/users?full=1")),
            res.RESOURCE_GROUPS: lambda: self._listed(res.RESOURCE_GROUPS, "users"),
            res.RESOURCE_ROLES: lambda: self._listed(res.RESOURCE_ROLES, "privs"),
            res.RESOURCE_ACL: lambda: shape.acl_entries(self._get("/access/acl"))[0],
            res.RESOURCE_ADMIN_ACL: lambda: shape.acl_entries(self._get("/access/acl"))[1],
            res.RESOURCE_REALMS: self._realms,
            res.RESOURCE_POOLS: lambda: [
                shape.pool_members(pool) for pool in self._listed(res.RESOURCE_POOLS)
            ],
        }

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Check the address and the token; return the pve-manager version it reports."""
        self._ready = False
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        try:
            parsed = shape.unwrap(self._fetch(res.VERSION_PATH)[0])
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                error_class = (
                    ERROR_UNAUTHORIZED if error.status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
                )
                raise CollectorError(
                    error_class, "Proxmox VE refused the API token", status=error.status
                ) from None
            if error.status in _NOT_AVAILABLE or error.error_class in (
                ERROR_BAD_JSON,
                shape.ERROR_BAD_PAYLOAD,
            ):
                raise CollectorError(ERROR_NO_API, "the Proxmox VE API did not answer") from None
            raise
        if not isinstance(parsed, dict):
            raise CollectorError(ERROR_NO_API, "the Proxmox VE API did not answer")
        self._ready = True
        version = parsed.get(res.VERSION_FIELD)
        if isinstance(version, str) and _VERSION.fullmatch(version.strip()):
            return version.strip()
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in reading order."""
        return [ResourceSpec(resource.name, resource.path) for resource in res.RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource (and, where needed, one detail per listed object)."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the API token was not accepted")
        if spec.name not in res.RESOURCE_PATHS:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        self._bytes = 0
        try:
            reader = self._readers.get(spec.name)
            objects = reader() if reader is not None else self._listed(spec.name)
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=self._bytes)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    # -- readers ------------------------------------------------------------------------------

    def _listed(self, name: str, names_field: str | None = None) -> Objects:
        """A plain list resource; ``names_field`` is a comma separated list made a sorted one."""
        resource = res.RESOURCE_PATHS[name]
        objects = shape.object_list(self._get(resource.path))
        if names_field is not None:
            for item in objects:
                if names_field in item:
                    item[names_field] = shape.split_names(item[names_field])
        return shape.keyed(objects, resource.key_field)

    def _nodes(self) -> Objects:
        result: Objects = []
        for listed in shape.keyed(shape.object_list(self._get("/nodes")), "node"):
            node = shape.path_segment(listed["node"])
            config = self._get(f"/nodes/{node}/config")
            if not isinstance(config, dict):
                raise shape.bad("a node config is not an object")
            item = shape.fold_slots(dict(config), res.NODE_SLOTS)
            item.update(node=node, ssl_fingerprint=listed.get("ssl_fingerprint"))
            result.append(item)
        return result

    def _guests(self, kind: str, slots: Sequence[str]) -> Objects:
        listed = shape.object_list(self._get("/cluster/resources?type=vm"))
        mine = shape.keyed((guest for guest in listed if guest.get("type") == kind), "vmid")
        if len(mine) > res.MAX_GUESTS:
            raise CollectorError(
                ERROR_TOO_MANY_GUESTS,
                f"more than {res.MAX_GUESTS} guests of this kind; one run does not read them all",
            )
        result: Objects = []
        for guest in mine:
            vmid = guest["vmid"]
            if not isinstance(vmid, int):
                raise shape.bad("a guest id is not a number")
            node = shape.path_segment(guest.get("node"))
            config = self._get(f"/nodes/{node}/{kind}/{vmid}/config")
            if not isinstance(config, dict):
                raise shape.bad("a guest config is not an object")
            item = shape.fold_slots(dict(config), slots)
            item.update(vmid=vmid, node=node)
            result.append(item)
        return result

    def _firewall_rules(self) -> Objects:
        """Cluster rules keyed ``cluster/<pos>``, security group rules ``group/<name>/<pos>``."""
        found: Objects = []
        for rule in shape.object_list(self._get("/cluster/firewall/rules")):
            found.append({**rule, "id": f"cluster/{rule.get('pos')}", "group": None})
        for listed in shape.object_list(self._get("/cluster/firewall/groups")):
            group = shape.path_segment(listed.get("group"))
            for rule in shape.object_list(self._get(f"/cluster/firewall/groups/{group}")):
                found.append({**rule, "id": f"group/{group}/{rule.get('pos')}", "group": group})
        for rule in found:
            if not isinstance(rule.get("pos"), int) or isinstance(rule.get("pos"), bool):
                raise shape.bad("a firewall rule has no position")
        return shape.keyed(found, "id")

    def _ipsets(self) -> Objects:
        result: Objects = []
        for ipset in shape.keyed(shape.object_list(self._get("/cluster/firewall/ipset")), "name"):
            name = shape.path_segment(ipset["name"])
            entries = shape.object_list(self._get(f"/cluster/firewall/ipset/{name}"))
            ipset["entries"] = shape.keyed(entries, "cidr")
            result.append(ipset)
        return result

    def _realms(self) -> Objects:
        result: Objects = []
        for listed in shape.keyed(shape.object_list(self._get("/access/domains")), "realm"):
            realm = shape.path_segment(listed["realm"])
            detail = self._get(f"/access/domains/{realm}")
            if not isinstance(detail, dict):
                raise shape.bad("a realm config is not an object")
            result.append({**listed, **detail, "realm": realm})
        return result

    # -- helpers ------------------------------------------------------------------------------

    def _fetch(self, path: str) -> tuple[JsonValue, int]:
        return fetch_json(
            self._client, f"{self._base_url}{res.API_PREFIX}{path}", headers=self._headers
        )

    def _get(self, path: str) -> JsonValue:
        parsed, size = self._fetch(path)
        self._bytes += size
        return shape.unwrap(parsed)

    def _failure(self, error: CollectorError) -> FetchResult:
        """The coverage of a failed read: 404, 501 and 403 are statuses, not run failures."""
        if error.status in _NOT_AVAILABLE:
            # 501 is stored as 404: both mean "no such path here", and a 5xx would be retried.
            return FetchResult.failure(
                ERROR_NOT_AVAILABLE,
                "this resource is not available on this Proxmox VE",
                status=STATUS_NOT_FOUND,
                bytes_fetched=self._bytes,
            )
        if error.status == STATUS_FORBIDDEN:
            return FetchResult.failure(
                ERROR_FORBIDDEN,
                "the API token may not read this resource",
                status=STATUS_FORBIDDEN,
                bytes_fetched=self._bytes,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(
            error.error_class, str(error), status=status, bytes_fetched=self._bytes
        )
