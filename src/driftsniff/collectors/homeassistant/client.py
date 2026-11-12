"""The Home Assistant client: the WebSocket API over one connection, read only.

``HomeAssistantClient`` is a :class:`~driftsniff.collectors.base.Collector` for Home Assistant
Core (any installation type). Commands and fields come from the Home Assistant core source and
developer documentation only (docs/vendor-notes/homeassistant.md); no lab Home Assistant was used.

* The credential is a long-lived access token. It travels once per connection, inside the ``auth``
  message on the open WebSocket, and nowhere else: never in a URL, a header, a log line or an
  error text. The REST API would need it in an ``Authorization: Bearer`` header on every request;
  every resource read here is a WebSocket command, so REST is not used at all.
* ``probe()`` resolves and pins the address (``collectors/resolve.py``), opens the WebSocket at
  :data:`~driftsniff.collectors.homeassistant.resources.API_PATH` with the WebSocket client of the
  TrueNAS collector (``collectors/truenas/websocket.py``), signs in and returns the ``ha_version``
  of the ``auth_ok`` answer. The connection stays open for the run and :meth:`close` ends it.
* ``fetch()`` sends one command per resource; automations and scripts send ``get_states`` once per
  run for their entity ids and then one config command per entity. ``unknown_command`` is coverage
  ``404`` (``not_available``); ``unauthorized`` (a command that needs an administrator token) is
  coverage ``403`` (``forbidden``). Both keep the previous state of the resource.
* An answer whose id is not the one asked for is skipped, at most :data:`MAX_SKIPPED` times.
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
from driftsniff.collectors.homeassistant.normalize import prepare_objects
from driftsniff.collectors.homeassistant.resources import (
    API_PATH,
    RESOURCE_BY_NAME,
    RESOURCES,
    STATES_COMMAND,
    HomeAssistantResource,
)
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.tls import AddressPin, TlsSettings
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
ERROR_COMMAND: Final = "command_error"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"

DENIED_CODES: Final = frozenset({"unauthorized", "not_allowed"})
MAX_SKIPPED: Final = 1000
MAX_VERSION_CHARS: Final = 64

_NO_API_TEXT: Final = "the Home Assistant WebSocket API did not answer"


@cache
def _shipped_tables() -> dict[str, ResourceTable]:
    return dict(load_rules().type_tables)


def _loads(text: str) -> JsonValue:
    try:
        parsed: JsonValue = json.loads(text)
    except ValueError:
        raise CollectorError(ERROR_BAD_JSON, "the response is not valid JSON") from None
    return parsed


class HomeAssistantClient(Collector):
    """Reads Home Assistant read only. One instance serves one run."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        allow_plain_http: bool = False,
        transport: httpx.BaseTransport | None = None,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
        resolver: Resolver | None = None,
        tls: TlsSettings | None = None,
        data_dir: Path | str = DEFAULT_DATA_DIR,
        tables: dict[str, ResourceTable] | None = None,
    ) -> None:
        if not token or any(ord(char) < 0x21 or ord(char) > 0x7E for char in token):
            raise ValueError("the access token is blank or has spaces or unusual characters")
        self._token = token
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
        self._version: str | None = None
        self._states: list[tuple[str, JsonValue]] | None = None
        self._ready = False

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Open the WebSocket, sign in with the token and return the version it reported."""
        self._ready = False
        self._states = None
        self._drop_socket()
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        self._open()
        self._ready = True
        return self._version

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources of :data:`RESOURCES` that have a type table, in that order."""
        return [
            ResourceSpec(resource.name, resource.command)
            for resource in RESOURCES
            if resource.name in self._tables
        ]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the access token was not accepted")
        resource = RESOURCE_BY_NAME.get(spec.name)
        if resource is None or spec.name not in self._tables:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        try:
            if resource.domain is None:
                result, size = self._call(resource.command, {})
            else:
                result, size = self._entities(resource)
            objects = prepare_objects(spec.name, resource.key_field, result, single=resource.single)
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=size)

    def close(self) -> None:
        """Close the WebSocket and the HTTP client."""
        self._drop_socket()
        self._client.close()

    # -- helpers ------------------------------------------------------------------------------

    def _entities(self, resource: HomeAssistantResource) -> tuple[JsonValue, int]:
        """The automations or scripts: entity ids from the states, then one config per entity."""
        size = 0
        if self._states is None:
            states, size = self._call(STATES_COMMAND, {})
            if not isinstance(states, list):
                raise CollectorError(ERROR_BAD_PAYLOAD, "the states are not a list")
            # Only the entity id and the state of automations and scripts are kept; no other
            # state value (a sensor reading) is held past this line.
            self._states = [
                (state["entity_id"], state.get("state"))
                for state in states
                if isinstance(state, dict)
                and isinstance(state.get("entity_id"), str)
                and state["entity_id"].split(".", 1)[0] in ("automation", "script")
            ]
        objects: list[JsonValue] = []
        for entity_id, state in self._states:
            if entity_id.split(".", 1)[0] != resource.domain:
                continue
            answer, used = self._call(resource.command, {"entity_id": entity_id})
            size += used
            config = answer.get("config") if isinstance(answer, dict) else None
            if not isinstance(config, dict):
                raise CollectorError(ERROR_BAD_PAYLOAD, "the answer has no configuration")
            item: dict[str, JsonValue] = {"entity_id": entity_id, "config": config}
            if resource.domain == "automation":
                item["enabled"] = {"on": True, "off": False}.get(str(state))
            objects.append(item)
        return objects, size

    def _drop_socket(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def _open(self) -> None:
        """Open the WebSocket and sign in; a refusal raises with a fixed text."""
        try:
            socket = WebSocket.connect(self._client, f"{self._base_url}{API_PATH}", self._timeout)
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                raise self._refused(error.status) from None
            if error.status == STATUS_NOT_FOUND:
                raise CollectorError(ERROR_NO_API, _NO_API_TEXT) from None
            raise
        try:
            self._sign_in(socket)
        except CollectorError:
            socket.close()
            raise
        self._socket = socket
        self._next_id = 0

    def _sign_in(self, socket: WebSocket) -> None:
        first = _loads(socket.receive_text(MAX_BODY_BYTES))
        if not isinstance(first, dict) or first.get("type") != "auth_required":
            raise CollectorError(ERROR_NO_API, _NO_API_TEXT)
        socket.send_text(json.dumps({"type": "auth", "access_token": self._token}))
        try:
            answer = _loads(socket.receive_text(MAX_BODY_BYTES))
        except CollectorError as error:
            if error.error_class == ERROR_CONNECTION:
                # Home Assistant closes the connection right after auth_invalid.
                raise self._refused(STATUS_UNAUTHORIZED) from None
            raise
        kind = answer.get("type") if isinstance(answer, dict) else None
        if kind == "auth_invalid":
            raise self._refused(STATUS_UNAUTHORIZED)
        if kind != "auth_ok" or not isinstance(answer, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the sign in answer was not understood")
        version = answer.get("ha_version")
        if isinstance(version, str) and version.strip():
            self._version = version.strip()[:MAX_VERSION_CHARS]

    def _call(self, command: str, fields: dict[str, JsonValue]) -> tuple[JsonValue, int]:
        """Send ``command`` and return its result and the bytes of the answer.

        An error answer raises :class:`CollectorError`: an unknown command has status 404, a
        refused one 403, anything else is ``command_error``. The texts are fixed; the message Home
        Assistant sent is never shown.
        """
        if self._socket is None:
            # A call after a timeout or a lost connection (a retry of the pipeline) reconnects.
            self._open()
        assert self._socket is not None  # noqa: S101 - _open sets it or raises
        self._next_id += 1
        call_id = self._next_id
        request: dict[str, JsonValue] = {**fields, "id": call_id, "type": command}
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
            answer = _loads(text)
            if not isinstance(answer, dict) or answer.get("id") != call_id:
                continue
            if answer.get("type") != "result":
                continue
            if answer.get("success") is not True:
                raise cls._command_error(answer.get("error"))
            return answer.get("result"), len(text.encode("utf-8"))
        raise CollectorError(ERROR_BAD_PAYLOAD, "Home Assistant sent too many unrelated messages")

    @staticmethod
    def _command_error(error: object) -> CollectorError:
        code = error.get("code") if isinstance(error, dict) else None
        if code == "unknown_command":
            return CollectorError(
                ERROR_NOT_AVAILABLE,
                "Home Assistant does not know this command",
                status=STATUS_NOT_FOUND,
            )
        if code in DENIED_CODES:
            return CollectorError(
                ERROR_FORBIDDEN, "the token may not send this command", status=STATUS_FORBIDDEN
            )
        return CollectorError(ERROR_COMMAND, "Home Assistant answered the command with an error")

    @staticmethod
    def _refused(status: str) -> CollectorError:
        error_class = ERROR_UNAUTHORIZED if status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
        return CollectorError(error_class, "Home Assistant refused the access token", status=status)

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
                "the access token may not read this resource (an administrator token is needed)",
                status=STATUS_FORBIDDEN,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(error.error_class, str(error), status=status)
