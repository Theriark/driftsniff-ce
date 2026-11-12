"""The TrueNAS client: JSON-RPC 2.0 over one WebSocket, read only.

``TruenasClient`` is a :class:`~driftsniff.collectors.base.Collector` for TrueNAS Community Edition
and Enterprise 25.04 and later (docs/vendor-notes/truenas.md says why the deprecated REST API is not
used). Method names and fields are checked against the published API reference only; no lab
TrueNAS was used.

* The credential is ``username:API key``. The API key travels once per run, inside the
  ``auth.login_ex`` call (mechanism ``API_KEY_PLAIN``) on the open WebSocket, and nowhere else:
  never in a URL, a header, a log line or an error text. TrueNAS revokes an API key that is used
  over plain http, so the client refuses http unless ``allow_plain_http`` is set (tests and the
  mock platform only).
* ``probe()`` resolves and pins the address (``collectors/resolve.py``), opens the WebSocket at
  :data:`~driftsniff.collectors.truenas.resources.API_PATH`, signs in and reads ``system.version``.
  The connection stays open for the run and :meth:`close` ends it.
* ``fetch()`` makes one method call per resource. A method TrueNAS does not know is coverage
  ``404`` (``not_available``); a call the user may not make is coverage ``403`` (``forbidden``).
  Both keep the previous state of the resource, so nothing is reported as removed.
* An answer whose id is not the one asked for (a late answer to a call that timed out, or an event)
  is skipped, at most :data:`MAX_SKIPPED` times per call.
"""

import json
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import Final

import httpx

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
    ERROR_BAD_PAYLOAD,
    ERROR_CONNECTION,
    ERROR_TIMEOUT,
    MAX_BODY_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    STATUS_ERROR,
    Collector,
    CollectorError,
    FetchResult,
    ResourceSpec,
    make_client,
)
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.collectors.truenas.normalize import prepare_objects
from driftsniff.collectors.truenas.resources import (
    API_PATH,
    LOGIN_MECHANISM,
    LOGIN_METHOD,
    RESOURCE_BY_NAME,
    RESOURCES,
    VERSION_METHOD,
)
from driftsniff.collectors.truenas.websocket import WebSocket
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.rules.loader import load_rules
from driftsniff.rules.schema import ResourceTable
from driftsniff.sources.addresses import validate_base_url

ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_NO_API: Final = "no_api"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"
ERROR_RPC: Final = "rpc_error"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"

RPC_METHOD_NOT_FOUND: Final = -32601
DENIED_ERRNAMES: Final = frozenset({"EACCES", "EPERM", "ENOTAUTHENTICATED"})
MAX_SKIPPED: Final = 1000
MAX_VERSION_CHARS: Final = 64

_NO_API_TEXT: Final = "the TrueNAS JSON-RPC API did not answer (TrueNAS 25.04 or later is needed)"


@cache
def _shipped_tables() -> dict[str, ResourceTable]:
    return dict(load_rules().type_tables)


def split_credential(credential: str) -> tuple[str, str]:
    """``username:API key`` as its two parts; raises ``ValueError`` (fixed text) otherwise."""
    username, colon, key = credential.partition(":")
    if not colon or not username or not key:
        raise ValueError("enter the credential as username:API key")
    for part in (username, key):
        if any(ord(char) < 0x21 or ord(char) > 0x7E for char in part):
            raise ValueError("the credential has spaces or characters TrueNAS does not use")
    return username, key


class TruenasClient(Collector):
    """Reads TrueNAS read only. One instance serves one run."""

    def __init__(
        self,
        base_url: str,
        credential: str,
        *,
        allow_plain_http: bool = False,
        transport: httpx.BaseTransport | None = None,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
        resolver: Resolver | None = None,
        tls: TlsSettings | None = None,
        data_dir: Path | str = DEFAULT_DATA_DIR,
        tables: dict[str, ResourceTable] | None = None,
    ) -> None:
        self._username, self._key = split_credential(credential)
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._resolver = resolver or system_resolver
        self._tables = tables if tables is not None else _shipped_tables()
        self._timeout = request_timeout
        self._address = AddressPin()
        self._client = make_client(
            transport=transport,
            tls=tls,
            data_dir=data_dir,
            address=self._address if transport is None else None,
        )
        self._client.timeout = httpx.Timeout(request_timeout)
        self._socket: WebSocket | None = None
        self._next_id = 0
        self._ready = False

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Open the WebSocket, sign in with the API key and read the version."""
        self._ready = False
        self._drop_socket()
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        self._open()
        self._ready = True
        try:
            version, _ = self._call(VERSION_METHOD, [])
        except CollectorError:
            return None
        if isinstance(version, str) and version.strip():
            return version.strip()[:MAX_VERSION_CHARS]
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources of :data:`RESOURCES` that have a type table, in that order."""
        return [
            ResourceSpec(resource.name, resource.method)
            for resource in RESOURCES
            if resource.name in self._tables
        ]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource with one method call."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the credential was not accepted")
        resource = RESOURCE_BY_NAME.get(spec.name)
        if resource is None or spec.name not in self._tables:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        try:
            result, size = self._call(resource.method, resource.params)
            objects = prepare_objects(spec.name, result, single=resource.single)
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=size)

    def close(self) -> None:
        """Close the WebSocket and the HTTP client."""
        self._drop_socket()
        self._client.close()

    # -- helpers ------------------------------------------------------------------------------

    def _drop_socket(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def _open(self) -> None:
        """Open the WebSocket and sign in; a refusal raises with a fixed text."""
        try:
            self._socket = WebSocket.connect(
                self._client, f"{self._base_url}{API_PATH}", self._timeout
            )
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                raise self._refused(error.status) from None
            if error.status == STATUS_NOT_FOUND:
                raise CollectorError(ERROR_NO_API, _NO_API_TEXT) from None
            raise
        self._sign_in()

    def _sign_in(self) -> None:
        params: list[JsonValue] = [
            {
                "mechanism": LOGIN_MECHANISM,
                "username": self._username,
                "api_key": self._key,
                "login_options": {"user_info": False},
            }
        ]
        try:
            answer, _ = self._call(LOGIN_METHOD, params)
        except CollectorError as error:
            if error.status == STATUS_NOT_FOUND:
                raise CollectorError(ERROR_NO_API, _NO_API_TEXT) from None
            if error.status == STATUS_FORBIDDEN:
                raise self._refused(STATUS_UNAUTHORIZED) from None
            raise
        if not isinstance(answer, dict) or answer.get("response_type") != "SUCCESS":
            raise self._refused(STATUS_UNAUTHORIZED)

    def _call(self, method: str, params: list[JsonValue]) -> tuple[JsonValue, int]:
        """Call ``method`` and return its result and the bytes of the answer.

        A JSON-RPC error raises :class:`CollectorError`: an unknown method has status 404, a refused
        one 403, anything else is ``rpc_error``. The texts are fixed; the error the controller sent
        is never shown.
        """
        if self._socket is None:
            # A call after a timeout or a lost connection (a retry of the pipeline) reconnects.
            self._open()
        assert self._socket is not None  # noqa: S101 - _open sets it or raises
        self._next_id += 1
        call_id = self._next_id
        request: dict[str, JsonValue] = {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": method,
            "params": params,
        }
        try:
            return self._exchange(self._socket, call_id, request)
        except CollectorError as error:
            if error.error_class in (ERROR_TIMEOUT, ERROR_CONNECTION):
                # The stream may stop inside a frame, so it is never read again.
                self._drop_socket()
            raise

    @classmethod
    def _exchange(
        cls, socket: WebSocket, call_id: int, request: dict[str, JsonValue]
    ) -> tuple[JsonValue, int]:
        socket.send_text(json.dumps(request, separators=(",", ":")))
        for _ in range(MAX_SKIPPED + 1):
            text = socket.receive_text(MAX_BODY_BYTES)
            try:
                answer = json.loads(text)
            except ValueError:
                raise CollectorError(ERROR_BAD_JSON, "the response is not valid JSON") from None
            if not isinstance(answer, dict) or answer.get("id") != call_id:
                continue
            if "error" in answer:
                raise cls._rpc_error(answer["error"])
            if "result" not in answer:
                raise CollectorError(ERROR_BAD_PAYLOAD, "the answer has neither result nor error")
            return answer["result"], len(text.encode("utf-8"))
        raise CollectorError(ERROR_BAD_PAYLOAD, "the controller sent too many unrelated messages")

    @staticmethod
    def _rpc_error(error: object) -> CollectorError:
        code = error.get("code") if isinstance(error, dict) else None
        data = error.get("data") if isinstance(error, dict) else None
        errname = data.get("errname") if isinstance(data, dict) else None
        if code == RPC_METHOD_NOT_FOUND:
            return CollectorError(
                ERROR_NOT_AVAILABLE, "TrueNAS does not know this method", status=STATUS_NOT_FOUND
            )
        if errname in DENIED_ERRNAMES:
            return CollectorError(
                ERROR_FORBIDDEN, "the credential may not make this call", status=STATUS_FORBIDDEN
            )
        return CollectorError(ERROR_RPC, "TrueNAS answered the call with an error")

    @staticmethod
    def _refused(status: str) -> CollectorError:
        error_class = ERROR_UNAUTHORIZED if status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
        return CollectorError(error_class, "TrueNAS refused the credential", status=status)

    @staticmethod
    def _failure(error: CollectorError) -> FetchResult:
        """The coverage of a failed read: 404 and 403 are statuses, not failures of the run."""
        if error.status == STATUS_NOT_FOUND:
            return FetchResult.failure(
                ERROR_NOT_AVAILABLE, "this resource is not available", status=STATUS_NOT_FOUND
            )
        if error.status == STATUS_FORBIDDEN:
            return FetchResult.failure(
                ERROR_FORBIDDEN,
                "the credential may not read this resource",
                status=STATUS_FORBIDDEN,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(error.error_class, str(error), status=status)
