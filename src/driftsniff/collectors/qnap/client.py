"""The QNAP QTS / QuTS hero collector: session login, XML reads and logout.

``QnapClient`` is a :class:`~driftsniff.collectors.base.Collector` for the CGI interface of QTS and
QuTS hero. QNAP publishes no reference for the configuration CGIs; every path and element name is
**unverified** (docs/vendor-notes/qnap.md lists the open source clients they come from).

* Sign in: ``POST /cgi-bin/authLogin.cgi`` with the form fields ``user`` and ``pwd`` (the password
  base64 encoded, as QNAP expects). The password travels only in that POST body: never in a query
  string, a log line or an error text. The answer carries the session id ``authSid``. An account
  with 2-step verification is not supported and fails the probe with a fixed text.
* Reads: ``GET`` of each CGI with ``sid=<session>`` in the query, the way QNAP's own web interface
  and the clients in the notes send it. The session id never appears in an error text (all texts
  here are fixed) and this module logs nothing.
* A read whose answer says ``authPassed`` 0 means the session is gone (expired, or signed out on
  the NAS). The client signs in once more and repeats that read once. Refused again with a fresh
  session, the read is coverage ``403`` (class ``forbidden``): most of these CGIs need an
  administrator, and the run keeps the stored state of the resource.
* ``close()`` signs out (``GET /cgi-bin/authLogout.cgi?logout=1&sid=``) so no session stays open
  after a run; a failed sign out is ignored.

Answers are XML, read up to :data:`MAX_XML_BYTES` and parsed by ``normalize.parse_document``, which
refuses a document type declaration (no entity expansion, no external entities). TLS, the
redirect refusal, the 30 second timeout and the address pin are those of the shared client
(``collectors/base.py``, ``collectors/tls.py``, ``collectors/resolve.py``), as for Xen Orchestra.
"""

import base64
import re
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import Final
from xml.etree.ElementTree import Element

import httpx

from driftsniff.collectors.base import (
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
from driftsniff.collectors.qnap.normalize import (
    EXTRACTORS,
    firmware_version,
    parse_document,
    text_of,
)
from driftsniff.collectors.qnap.resources import (
    LOGIN_PATH,
    LOGOUT_PATH,
    NO_SESSION_PATHS,
    RESOURCE_PATHS,
    RESOURCES,
    SYSINFO_PATH,
)
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.rules.loader import load_rules
from driftsniff.rules.schema import ResourceTable
from driftsniff.sources.addresses import validate_base_url

MAX_XML_BYTES: Final = 16 * 1024 * 1024
MAX_USERNAME_CHARS: Final = 128

ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_TWO_STEP: Final = "two_step_unsupported"
ERROR_NO_API: Final = "no_api"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"

_SID: Final = re.compile(r"[A-Za-z0-9]{1,128}")
_REFUSED_TEXT: Final = "QNAP refused the user name or password"
_TWO_STEP_TEXT: Final = (
    "the account uses 2-step verification, which driftsniff does not support; use an account "
    "without it"
)
_NO_API_TEXT: Final = "the QNAP sign in interface did not answer"
_FORBIDDEN_TEXT: Final = "the account may not read this resource"


@cache
def _shipped_tables() -> dict[str, ResourceTable]:
    return dict(load_rules().type_tables)


class _SessionRefused(Exception):
    """A read answered ``authPassed`` 0: the session is not (or no longer) accepted."""


class QnapClient(Collector):
    """Reads a QNAP NAS read only. One instance serves one run."""

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
        tables: dict[str, ResourceTable] | None = None,
    ) -> None:
        name = username.strip()
        if not name or len(name) > MAX_USERNAME_CHARS or not name.isprintable():
            raise ValueError("the user name is blank, too long or has control characters")
        if not password:
            raise ValueError("the password is blank")
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._form = {
            "user": name,
            "pwd": base64.b64encode(password.encode("utf-8")).decode("ascii"),
        }
        self._resolver = resolver or system_resolver
        self._tables = tables if tables is not None else _shipped_tables()
        self._address = AddressPin()
        self._client = make_client(
            transport=transport,
            tls=tls,
            data_dir=data_dir,
            address=self._address if transport is None else None,
        )
        self._client.timeout = httpx.Timeout(request_timeout)
        self._sid: str | None = None
        self._documents: dict[str, Element] = {}

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Pin the address, sign in and return the firmware version of the NAS."""
        self._sid = None
        self._documents.clear()
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        self._login()
        root, _ = self._read(SYSINFO_PATH)
        return firmware_version(root)

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads: those that have a type table."""
        return [
            ResourceSpec(name, RESOURCE_PATHS[name]) for name in RESOURCES if name in self._tables
        ]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource; a document two resources share is read once per run."""
        if self._sid is None:
            raise CollectorError(ERROR_NOT_PROBED, "the credential was not accepted")
        if spec.name not in RESOURCE_PATHS or spec.name not in self._tables:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        path = RESOURCE_PATHS[spec.name]
        try:
            root, size = self._read(path)
            objects = EXTRACTORS[spec.name](root)
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=size)

    def close(self) -> None:
        """Sign out when a session is open, then close the HTTP client."""
        sid, self._sid = self._sid, None
        try:
            if sid is not None:
                self._call("GET", LOGOUT_PATH, params={"logout": "1", "sid": sid})
        except CollectorError:
            pass  # the session ends on the NAS by itself; nothing to report
        finally:
            self._client.close()

    # -- helpers ------------------------------------------------------------------------------

    def _login(self) -> None:
        """Sign in with the POST form; keeps the session id or raises with a fixed text."""
        try:
            root, _ = self._call("POST", LOGIN_PATH, data=self._form)
        except CollectorError as error:
            if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_PAYLOAD:
                raise CollectorError(ERROR_NO_API, _NO_API_TEXT) from None
            raise
        if text_of(root, "need_2sv") == "1":
            raise CollectorError(ERROR_TWO_STEP, _TWO_STEP_TEXT)
        sid = text_of(root, "authSid")
        if text_of(root, "authPassed") != "1" or not sid:
            raise CollectorError(ERROR_UNAUTHORIZED, _REFUSED_TEXT)
        if _SID.fullmatch(sid) is None:
            raise CollectorError(ERROR_BAD_PAYLOAD, "the session id of the answer is not usable")
        self._sid = sid

    def _read(self, path: str) -> tuple[Element, int]:
        """The document of ``path`` (cached per run); signs in again once for a lost session."""
        cached = self._documents.get(path)
        if cached is not None:
            return cached, 0
        try:
            root, size = self._session_read(path)
        except _SessionRefused:
            self._login()
            try:
                root, size = self._session_read(path)
            except _SessionRefused:
                raise CollectorError(
                    ERROR_FORBIDDEN, _FORBIDDEN_TEXT, status=STATUS_FORBIDDEN
                ) from None
        self._documents[path] = root
        return root, size

    def _session_read(self, path: str) -> tuple[Element, int]:
        if path in NO_SESSION_PATHS:
            return self._call("GET", path)
        root, size = self._call("GET", path, params={"sid": self._sid or ""})
        if text_of(root, "authPassed") == "0":
            raise _SessionRefused
        return root, size

    def _call(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
    ) -> tuple[Element, int]:
        """One request: status checked, body capped, XML parsed. Error texts are fixed."""
        try:
            with self._client.stream(
                method, f"{self._base_url}{path}", params=params, data=data
            ) as response:
                _check_status(response)
                body = read_limited(response, max_bytes=MAX_XML_BYTES)
        except httpx.TimeoutException:
            raise CollectorError(ERROR_TIMEOUT, "the controller did not answer in time") from None
        except httpx.HTTPError as error:
            raise _transport_error(error) from None
        return parse_document(body), len(body)

    @staticmethod
    def _failure(error: CollectorError) -> FetchResult:
        """The coverage of a failed read: 404 and 403 are statuses, not failures of the run."""
        if error.status == STATUS_NOT_FOUND:
            return FetchResult.failure(
                ERROR_NOT_AVAILABLE, "this resource is not available", status=STATUS_NOT_FOUND
            )
        if error.status == STATUS_FORBIDDEN:
            return FetchResult.failure(ERROR_FORBIDDEN, _FORBIDDEN_TEXT, status=STATUS_FORBIDDEN)
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(error.error_class, str(error), status=status)
