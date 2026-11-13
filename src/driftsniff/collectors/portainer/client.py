"""The Portainer client: probe, list reads and stack files.

``PortainerClient`` is a :class:`~driftsniff.collectors.base.Collector` for the HTTP API of
Portainer (CE and BE share the paths it uses). Paths, header and field names were read from the
Portainer source on 2026-11-12 (docs/vendor-notes/portainer.md); no lab Portainer was used.

* The access token travels in one request header, ``X-API-Key``, and nowhere else: never in a
  query string, a log line or an error text. This module logs nothing, and every error text is
  fixed.
* ``probe()`` reads ``/api/system/version``, which needs a valid token, so a refused token stops
  the run before anything else is read. It returns ``ServerVersion`` when it looks like a version.
* Every resource is one GET of a JSON list (the settings: one object). Coverage: 404 is
  ``not_available`` and 403 ``forbidden`` (a non-admin token gets 403 on the admin-only
  resources); both keep the previous state of the resource, so nothing is reported as removed.
* Edge groups answer 503 while the Edge compute features are turned off (Portainer BE 2.45.3,
  2026-11-13). When the settings confirm that, the resource is read as empty: no Edge group is in
  effect, and the run is not partial on every check. Any other 503 stays a failure.
* Stacks: the content of each stack file is read from ``/api/stacks/{id}/file`` and stored in the
  stack as ``StackFileContent`` (a secret field: only its fingerprint is kept). A file that cannot
  be read fails the stacks resource, so its previous state stays rather than a false change.

``probe()`` resolves the host name once, refuses a blocked answer and pins the first answer
(``collectors/resolve.py``); TLS modes come from ``collectors/tls.py``. Redirects are refused.
"""

import re
from collections.abc import Sequence
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
from driftsniff.collectors.portainer.normalize import prepare_objects
from driftsniff.collectors.portainer.resources import (
    API_KEY_HEADER,
    RESOURCE_EDGE_GROUPS,
    RESOURCE_PATHS,
    RESOURCE_SETTINGS,
    RESOURCE_STACKS,
    RESOURCES,
    STACK_FILE_FIELD,
    STACK_FILE_PATH,
    VERSION_FIELD,
    VERSION_PATH,
)
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.addresses import validate_base_url

ERROR_BAD_PAYLOAD: Final = "bad_payload"
ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_NO_API: Final = "no_api"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"
STATUS_UNAVAILABLE: Final = "503"
EDGE_COMPUTE_SETTING: Final = "EnableEdgeComputeFeatures"

_VERSION = re.compile(r"\d{1,4}\.\d{1,4}(?:\.\d{1,6})?(?:[.+-][0-9A-Za-z.+-]{0,32})?")


class PortainerClient(Collector):
    """Reads Portainer read only. One instance serves one run."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        allow_plain_http: bool = False,
        transport: httpx.BaseTransport | None = None,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
        resolver: Resolver | None = None,
        tls: TlsSettings | None = None,
        data_dir: Path | str = DEFAULT_DATA_DIR,
    ) -> None:
        if not api_key or any(ord(char) < 0x21 or ord(char) > 0x7E for char in api_key):
            raise ValueError("the access token is blank or has characters a header cannot carry")
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._headers = {API_KEY_HEADER: api_key}
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

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Check the address and the token; return the Portainer version when it reports one."""
        self._ready = False
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        try:
            parsed, _ = fetch_json(
                self._client, f"{self._base_url}{VERSION_PATH}", headers=self._headers
            )
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                error_class = (
                    ERROR_UNAUTHORIZED if error.status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
                )
                raise CollectorError(
                    error_class, "Portainer refused the access token", status=error.status
                ) from None
            if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_JSON:
                raise CollectorError(ERROR_NO_API, "the Portainer API did not answer") from None
            raise
        if not isinstance(parsed, dict):
            raise CollectorError(ERROR_NO_API, "the Portainer API did not answer")
        self._ready = True
        version = parsed.get(VERSION_FIELD)
        if isinstance(version, str) and _VERSION.fullmatch(version.strip()):
            return version.strip()
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in reading order."""
        return [ResourceSpec(resource.name, resource.path) for resource in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource (and, for stacks, the file of every stack)."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the access token was not accepted")
        resource = RESOURCE_PATHS.get(spec.name)
        if resource is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        self._bytes = 0
        try:
            raw = self._get(resource.path)
            objects = prepare_objects(resource.name, resource.key_field, raw)
            if resource.name == RESOURCE_STACKS:
                for stack in objects:
                    stack[STACK_FILE_FIELD] = self._stack_file(stack[resource.key_field])
        except CollectorError as error:
            if (
                resource.name == RESOURCE_EDGE_GROUPS
                and error.status == STATUS_UNAVAILABLE
                and self._edge_compute_off()
            ):
                return FetchResult.success([], bytes_fetched=self._bytes)
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=self._bytes)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    # -- helpers ------------------------------------------------------------------------------

    def _get(self, path: str) -> JsonValue:
        parsed, size = fetch_json(self._client, f"{self._base_url}{path}", headers=self._headers)
        self._bytes += size
        return parsed

    def _edge_compute_off(self) -> bool:
        """True only when the settings say the Edge compute features are turned off."""
        try:
            settings = self._get(RESOURCE_PATHS[RESOURCE_SETTINGS].path)
        except CollectorError:
            return False
        return isinstance(settings, dict) and settings.get(EDGE_COMPUTE_SETTING) is False

    def _stack_file(self, stack_id: JsonValue) -> JsonValue:
        if not isinstance(stack_id, int) or isinstance(stack_id, bool):
            raise CollectorError(ERROR_BAD_PAYLOAD, "a stack id is not a number")
        parsed = self._get(STACK_FILE_PATH.format(id=stack_id))
        if not isinstance(parsed, dict) or not isinstance(parsed.get(STACK_FILE_FIELD), str):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a stack file")
        return parsed[STACK_FILE_FIELD]

    def _failure(self, error: CollectorError) -> FetchResult:
        """The coverage of a failed read: 404 and 403 are statuses, not failures of the run."""
        if error.status == STATUS_NOT_FOUND:
            return FetchResult.failure(
                ERROR_NOT_AVAILABLE,
                "this resource is not available on this version",
                status=STATUS_NOT_FOUND,
                bytes_fetched=self._bytes,
            )
        if error.status == STATUS_FORBIDDEN:
            return FetchResult.failure(
                ERROR_FORBIDDEN,
                "the access token may not read this resource",
                status=STATUS_FORBIDDEN,
                bytes_fetched=self._bytes,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(
            error.error_class, str(error), status=status, bytes_fetched=self._bytes
        )
