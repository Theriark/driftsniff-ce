"""The Redfish client: one collector for any DMTF Redfish BMC, a session per run.

``RedfishClient`` is a :class:`~driftsniff.collectors.base.Collector`. Names and shapes follow the
DMTF Redfish schemas (docs/vendor-notes/redfish.md); no lab BMC was used.

* Sign in: ``POST`` of ``{"UserName", "Password"}`` to the session collection (the root's
  ``Links.Sessions``, else ``/redfish/v1/SessionService/Sessions``). The password travels once per
  run, in that JSON body, never in a header, query string, log line or error text. The answer's
  ``X-Auth-Token`` header is sent with every later request and nowhere else; ``close()`` deletes the
  session at the ``Location`` the BMC gave, so a run never leaves a session open (BMCs allow only a
  few). HTTP Basic is not used: every vendor read documents sessions.
* ``probe()`` reads the service root without a credential (``RedfishVersion``, ``Vendor``,
  ``Product``), signs in and reads the firmware version of the first manager. A refused sign in is
  ``unauthorized`` (401) and is never repeated in the same run: BMCs lock accounts.
* Every resource is found by following links from the service root, so vendor ids such as
  ``System.Embedded.1`` are never written in code. A service the root does not link (an older BMC
  without ``CertificateService``) or a 404 is ``not_available``; a 403 is ``forbidden``. Both keep
  the previous state of the resource.
* Bounded: at most :data:`~resources.MAX_MEMBERS` members per collection and
  :data:`~resources.MAX_REQUESTS` requests per run; each request has the 30 second limit and the
  body limit of ``collectors/base.py``. Every document is read once per run (a cache), so the probe
  and the resources share the reads of the managers and systems.
* Redirects are refused, TLS modes come from ``collectors/tls.py``, and ``probe()`` pins the
  resolved address (``collectors/resolve.py``) as the other collectors do. This module logs
  nothing, and every error text is fixed.
"""

import json
import logging
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
    ERROR_BAD_PAYLOAD,
    ERROR_TIMEOUT,
    REQUEST_TIMEOUT_SECONDS,
    STATUS_ERROR,
    Collector,
    CollectorError,
    FetchResult,
    ResourceSpec,
    _check_status,
    _transport_error,
    make_client,
    read_limited,
)
from driftsniff.collectors.redfish.normalize import (
    bios_objects,
    clean,
    keyed,
    link_of,
    member_paths,
    safe_path,
    text_id,
    version_text,
)
from driftsniff.collectors.redfish.resources import (
    FIELD_MANAGER,
    FIELD_OBJECT_KEY,
    FIELD_URI,
    MAX_MEMBERS,
    MAX_REQUESTS,
    RESOURCE_ACCOUNT_SERVICE,
    RESOURCE_ACCOUNTS,
    RESOURCE_BIOS,
    RESOURCE_CERTIFICATES,
    RESOURCE_FIRMWARE,
    RESOURCE_INTERFACES,
    RESOURCE_MANAGERS,
    RESOURCE_NETWORK,
    RESOURCE_SUBSCRIPTIONS,
    RESOURCE_SYSTEMS,
    RESOURCES,
    ROOT_PATH,
    SESSIONS_PATH,
    TOKEN_HEADER,
)
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.addresses import validate_base_url

ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_NO_API: Final = "no_api"
ERROR_NO_SESSION: Final = "no_session"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"
ERROR_TOO_MANY: Final = "too_many_requests"

STATUS_UNAUTHORIZED: Final = "401"
STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_NOT_ALLOWED: Final = "405"
MAX_USERNAME_CHARS: Final = 128
MAX_TOKEN_CHARS: Final = 1024

Document = dict[str, JsonValue]


class _HideSessionHeader(logging.Filter):
    """Drops the httpcore trace lines that hold the headers of a sign in answer.

    httpcore logs the response headers at DEBUG, and the sign in answer carries the session token
    in ``X-Auth-Token``; with this filter that line never reaches a log handler.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return "x-auth-token" not in record.getMessage().lower()


_TRACE_LOGGER: Final = logging.getLogger("httpcore.http11")
if not any(isinstance(item, _HideSessionHeader) for item in _TRACE_LOGGER.filters):
    _TRACE_LOGGER.addFilter(_HideSessionHeader())


def _not_available() -> CollectorError:
    return CollectorError(
        ERROR_NOT_AVAILABLE, "the BMC does not offer this resource", status=STATUS_NOT_FOUND
    )


class RedfishClient(Collector):
    """Reads a Redfish BMC read only. One instance serves one run."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        allow_plain_http: bool = False,
        transport: httpx.BaseTransport | None = None,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
        resolver: Resolver | None = None,
        tls: TlsSettings | None = None,
        data_dir: Path | str = DEFAULT_DATA_DIR,
    ) -> None:
        name = username.strip()
        if not name or len(name) > MAX_USERNAME_CHARS or not name.isprintable():
            raise ValueError("the user name is blank, too long or has control characters")
        if not password:
            raise ValueError("the password is blank")
        self._username = name
        self._password = password
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._resolver = resolver or system_resolver
        self._address = AddressPin()
        self._client = make_client(
            transport=transport,
            tls=tls,
            data_dir=data_dir,
            address=self._address if transport is None else None,
        )
        self._client.timeout = httpx.Timeout(request_timeout)
        self._token: str | None = None
        self._session_path: str | None = None
        self._root: Document = {}
        self._cache: dict[str, Document] = {}
        self._requests = 0
        self._bytes = 0
        self._readers: dict[str, Callable[[], list[Document]]] = {
            RESOURCE_SYSTEMS: self._systems,
            RESOURCE_BIOS: self._bios,
            RESOURCE_MANAGERS: self._managers,
            RESOURCE_NETWORK: self._network,
            RESOURCE_INTERFACES: self._interfaces,
            RESOURCE_ACCOUNTS: self._accounts,
            RESOURCE_ACCOUNT_SERVICE: self._account_service,
            RESOURCE_SUBSCRIPTIONS: self._subscriptions,
            RESOURCE_CERTIFICATES: self._certificates,
            RESOURCE_FIRMWARE: self._firmware,
        }

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Read the service root, sign in and return ``Vendor Product firmware (Redfish x)``."""
        self._sign_out()
        self._cache.clear()
        self._requests = 0
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        try:
            root = self._get(ROOT_PATH, auth=False)
        except CollectorError as error:
            if error.status in (STATUS_NOT_FOUND, STATUS_NOT_ALLOWED) or error.error_class in (
                ERROR_BAD_JSON,
                ERROR_BAD_PAYLOAD,
            ):
                raise CollectorError(
                    ERROR_NO_API, "the address does not answer as Redfish"
                ) from None
            raise
        if not isinstance(root.get("RedfishVersion"), str):
            raise CollectorError(ERROR_NO_API, "the address does not answer as Redfish")
        self._root = root
        self._sign_in(link_of(root, "Links", "Sessions") or SESSIONS_PATH)
        return version_text(root, self._firmware_version())

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in the order of ``resources.RESOURCES``."""
        return [ResourceSpec(name) for name in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource; its objects are cleaned and sorted by their key."""
        if self._token is None:
            raise CollectorError(ERROR_NOT_PROBED, "the BMC did not accept the sign in")
        reader = self._readers.get(spec.name)
        if reader is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        self._bytes = 0
        try:
            objects = reader()
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=self._bytes)

    def close(self) -> None:
        """Delete the session and close the HTTP client."""
        try:
            self._sign_out()
        finally:
            self._client.close()

    # -- resources ----------------------------------------------------------------------------

    def _systems(self) -> list[Document]:
        found: list[Document] = []
        for system in self._service_members("Systems"):
            secure = link_of(system, "SecureBoot")
            if secure is not None:
                system = {**system, "SecureBoot": self._get(secure)}
            found.append(_cleaned(system))
        return keyed(found, "Id")

    def _bios(self) -> list[Document]:
        found: list[Document] = []
        linked = False
        for system in self._service_members("Systems"):
            path = link_of(system, "Bios")
            if path is not None:
                linked = True
                found.extend(bios_objects(text_id(system), self._get(path)))
        if not linked:
            raise _not_available()
        return keyed(found, FIELD_OBJECT_KEY)

    def _managers(self) -> list[Document]:
        return keyed([_cleaned(item) for item in self._service_members("Managers")], "Id")

    def _network(self) -> list[Document]:
        found: list[Document] = []
        for manager in self._service_members("Managers"):
            path = link_of(manager, "NetworkProtocol")
            if path is not None:
                found.append({**_cleaned(self._get(path)), FIELD_MANAGER: text_id(manager)})
        if not found:
            raise _not_available()
        return keyed(found, FIELD_MANAGER)

    def _interfaces(self) -> list[Document]:
        found: list[Document] = []
        linked = False
        for manager in self._service_members("Managers"):
            path = link_of(manager, "EthernetInterfaces")
            if path is None:
                continue
            linked = True
            manager_id = text_id(manager)
            for interface in self._members(path):
                key = f"{manager_id}/{text_id(interface)}"
                found.append(
                    {**_cleaned(interface), FIELD_MANAGER: manager_id, FIELD_OBJECT_KEY: key}
                )
        if not linked:
            raise _not_available()
        return keyed(found, FIELD_OBJECT_KEY)

    def _accounts(self) -> list[Document]:
        accounts = self._members(self._linked(self._service("AccountService"), "Accounts"))
        # Some BMCs list fixed account slots; a slot without a user name is not an account.
        named = [item for item in accounts if item.get("UserName") not in (None, "")]
        return keyed([_cleaned(item) for item in named], "UserName")

    def _account_service(self) -> list[Document]:
        service = self._service("AccountService")
        text_id(service)
        return [_cleaned(service)]

    def _subscriptions(self) -> list[Document]:
        path = self._linked(self._service("EventService"), "Subscriptions")
        return keyed([_cleaned(item) for item in self._members(path)], "Id")

    def _certificates(self) -> list[Document]:
        service = self._service("CertificateService")
        locations = self._get(self._linked(service, "CertificateLocations"))
        paths = member_paths(_links(locations), "Certificates")
        if len(paths) > MAX_MEMBERS:
            raise CollectorError(
                ERROR_BAD_PAYLOAD, f"a collection has more than {MAX_MEMBERS} members"
            )
        return keyed([{**_cleaned(self._get(path)), FIELD_URI: path} for path in paths], FIELD_URI)

    def _firmware(self) -> list[Document]:
        path = self._linked(self._service("UpdateService"), "FirmwareInventory")
        return keyed([_cleaned(item) for item in self._members(path)], "Id")

    # -- following links ----------------------------------------------------------------------

    def _service(self, name: str) -> Document:
        """The document a root link points to (``Systems``, ``AccountService``...)."""
        return self._get(self._linked(self._root, name))

    @staticmethod
    def _linked(document: Mapping[str, JsonValue], name: str) -> str:
        path = link_of(document, name)
        if path is None:
            raise _not_available()
        return path

    def _service_members(self, name: str) -> list[Document]:
        return self._members(self._linked(self._root, name))

    def _members(self, path: str) -> list[Document]:
        """Every member of the collection at ``path``, following ``Members@odata.nextLink``."""
        paths: list[str] = []
        next_path: str | None = path
        while next_path is not None:
            page = self._get(next_path)
            paths.extend(member_paths(page))
            if len(paths) > MAX_MEMBERS:
                raise CollectorError(
                    ERROR_BAD_PAYLOAD, f"a collection has more than {MAX_MEMBERS} members"
                )
            following = page.get("Members@odata.nextLink")
            next_path = None if following is None else safe_path(following)
            if following is not None and next_path is None:
                raise CollectorError(
                    ERROR_BAD_PAYLOAD, "a link of the answer is not a Redfish path"
                )
        return [self._get(member) for member in paths]

    def _firmware_version(self) -> JsonValue:
        """The ``FirmwareVersion`` of the first manager, or None when it cannot be read."""
        try:
            managers = self._service_members("Managers")
        except CollectorError:
            return None
        return managers[0].get("FirmwareVersion") if managers else None

    # -- session ------------------------------------------------------------------------------

    def _sign_in(self, path: str) -> None:
        body = {"UserName": self._username, "Password": self._password}
        try:
            headers, _ = self._send("POST", path, body=body, auth=False)
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                raise CollectorError(
                    ERROR_UNAUTHORIZED,
                    "the BMC refused the user name or the password",
                    status=STATUS_UNAUTHORIZED,
                ) from None
            if error.status in (STATUS_NOT_FOUND, STATUS_NOT_ALLOWED):
                raise CollectorError(
                    ERROR_NO_SESSION, "the BMC does not offer Redfish sessions"
                ) from None
            raise
        token = headers.get(TOKEN_HEADER, "")
        if (
            not token
            or len(token) > MAX_TOKEN_CHARS
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in token)
        ):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the sign in answer holds no usable session")
        self._token = token
        location = headers.get("Location")
        self._session_path = safe_path(urlsplit(location).path) if location else None

    def _sign_out(self) -> None:
        """Delete the session, if there is one; a failure to delete is ignored."""
        token, path = self._token, self._session_path
        self._session_path = None
        if token is None:
            return
        try:
            if path is not None:
                self._send("DELETE", path)
        except CollectorError:
            pass
        finally:
            self._token = None

    # -- transport ----------------------------------------------------------------------------

    def _get(self, path: str, *, auth: bool = True) -> Document:
        """The JSON object at ``path``, read once per run."""
        cached = self._cache.get(path)
        if cached is not None:
            return cached
        _, body = self._send("GET", path, auth=auth)
        try:
            parsed: JsonValue = json.loads(body)
        except ValueError:
            raise CollectorError(ERROR_BAD_JSON, "the response is not valid JSON") from None
        if not isinstance(parsed, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a Redfish resource")
        self._cache[path] = parsed
        return parsed

    def _send(
        self, method: str, path: str, *, body: Mapping[str, Any] | None = None, auth: bool = True
    ) -> tuple[httpx.Headers, bytes]:
        """One request; raises :class:`CollectorError` with fixed texts for every failure."""
        self._requests += 1
        if self._requests > MAX_REQUESTS:
            raise CollectorError(
                ERROR_TOO_MANY, f"the run needed more than {MAX_REQUESTS} requests to the BMC"
            )
        headers = {"Accept": "application/json", "OData-Version": "4.0"}
        if auth and self._token is not None:
            headers[TOKEN_HEADER] = self._token
        url = f"{self._base_url}{path}"
        try:
            with self._client.stream(
                method, url, headers=headers, json=None if body is None else dict(body)
            ) as response:
                _check_status(response)
                data = read_limited(response)
                answer_headers = response.headers
        except httpx.TimeoutException:
            raise CollectorError(ERROR_TIMEOUT, "the BMC did not answer in time") from None
        except httpx.HTTPError as error:
            raise _transport_error(error) from None
        self._bytes += len(data)
        return answer_headers, data

    def _failure(self, error: CollectorError) -> FetchResult:
        """404 and 403 are coverage statuses, not failures of the run."""
        if error.status == STATUS_NOT_FOUND:
            error = _not_available()
        elif error.status == STATUS_FORBIDDEN:
            error = CollectorError(
                ERROR_FORBIDDEN, "the BMC account may not read this", status=STATUS_FORBIDDEN
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(
            error.error_class, str(error), status=status, bytes_fetched=self._bytes
        )


def _cleaned(document: Document) -> Document:
    cleaned = clean(document)
    return cleaned if isinstance(cleaned, dict) else {}


def _links(document: Document) -> Document:
    links = document.get("Links")
    if not isinstance(links, dict):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer has no links")
    return links
