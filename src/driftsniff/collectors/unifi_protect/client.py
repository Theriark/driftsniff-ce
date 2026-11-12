"""The UniFi Protect client: probe and list reads of the Protect integration API.

``ProtectClient`` is a :class:`~driftsniff.collectors.base.Collector` for the integration API of
UniFi Protect on a UniFi OS console. Paths and shapes come from Ubiquiti's OpenAPI document
(docs/vendor-notes/unifi_protect.md); no lab console was used.

* The API key travels in one request header, the ``X-API-KEY`` of the UniFi Network integration API
  (imported from ``collectors/unifi/client.py``), and nowhere else: never in a query string, a log
  line or an error text. This module logs nothing, and every error text is fixed.
* ``probe()`` reads ``meta/info``. A refused key (401, 403) stops the run before anything else is
  read; 404 or an answer that is not the information object is ``no_api`` (Protect is not
  installed, or the address is not a UniFi OS console). It returns ``applicationVersion`` when it
  reads as a version. There is no version floor: the published document is the only reference.
* Every resource is one GET of a JSON array (``/nvrs``: one object). Coverage: 404 is
  ``not_available`` (an older Protect without that endpoint), 403 ``forbidden``; both keep the
  previous state of the resource, so nothing is reported as removed.
* Objects must carry a non-empty string ``id`` and are sorted by it; otherwise they are raw.

``probe()`` resolves the host name once, refuses a blocked answer and pins the first answer
(``collectors/resolve.py``); TLS modes come from ``collectors/tls.py``. Redirects are refused.
"""

from collections.abc import Sequence
from pathlib import Path

import httpx

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
    ERROR_BAD_PAYLOAD,
    REQUEST_TIMEOUT_SECONDS,
    STATUS_ERROR,
    Collector,
    CollectorError,
    FetchResult,
    ResourceSpec,
    fetch_json,
    make_client,
)
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.collectors.unifi.client import (
    API_KEY_HEADER,
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    STATUS_FORBIDDEN,
    STATUS_NOT_FOUND,
    STATUS_UNAUTHORIZED,
    parse_version,
)
from driftsniff.collectors.unifi_protect.resources import (
    BASE_PATH,
    INFO_PATH,
    KEY_FIELD,
    RESOURCE_NVR,
    RESOURCE_PATHS,
    RESOURCES,
    VERSION_FIELD,
)
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.addresses import validate_base_url


def prepare_objects(name: str, raw: JsonValue) -> list[dict[str, JsonValue]]:
    """The answer of one resource as a list of objects sorted by ``id``.

    ``protect-nvr`` answers one object, every other resource a list. Raises
    :class:`CollectorError` (``bad_payload``) for another shape or an object without a usable id.
    """
    if name == RESOURCE_NVR and isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
    objects: list[dict[str, JsonValue]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        key = item.get(KEY_FIELD)
        if not isinstance(key, str) or not key:
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        objects.append(dict(item))
    objects.sort(key=lambda item: str(item[KEY_FIELD]))
    return objects


class ProtectClient(Collector):
    """Reads UniFi Protect read only. One instance serves one run."""

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
            raise ValueError("the API key is blank or has characters a header cannot carry")
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
        """Check the address and the key; return the Protect version when it reports one."""
        self._ready = False
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        try:
            parsed, _ = fetch_json(self._client, self._url(INFO_PATH), headers=self._headers)
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                error_class = (
                    ERROR_UNAUTHORIZED if error.status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
                )
                raise CollectorError(
                    error_class, "UniFi Protect refused the API key", status=error.status
                ) from None
            if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_JSON:
                raise CollectorError(ERROR_NO_API, "the UniFi Protect API did not answer") from None
            raise
        if not isinstance(parsed, dict) or VERSION_FIELD not in parsed:
            raise CollectorError(ERROR_NO_API, "the UniFi Protect API did not answer")
        self._ready = True
        version = parsed[VERSION_FIELD]
        if isinstance(version, str) and parse_version(version) is not None:
            return version.strip()
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in reading order."""
        return [ResourceSpec(resource.name, resource.path) for resource in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the API key was not accepted")
        resource = RESOURCE_PATHS.get(spec.name)
        if resource is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        self._bytes = 0
        try:
            parsed, self._bytes = fetch_json(
                self._client, self._url(resource.path), headers=self._headers
            )
            objects = prepare_objects(resource.name, parsed)
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=self._bytes)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    # -- helpers ------------------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base_url}{BASE_PATH}{path}"

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
                "the API key may not read this resource",
                status=STATUS_FORBIDDEN,
                bytes_fetched=self._bytes,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(
            error.error_class, str(error), status=status, bytes_fetched=self._bytes
        )
