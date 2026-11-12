"""The Prometheus client: probe, configuration, flags and rules.

``PrometheusClient`` is a :class:`~driftsniff.collectors.base.Collector` for the HTTP API of
Prometheus (``/api/v1``). Paths and answer shapes were read from the Prometheus documentation on
2026-11-12 (docs/vendor-notes/prometheus.md); no lab Prometheus was used.

* Prometheus itself has no token check: it is usually behind a reverse proxy that wants one, or
  its web configuration asks for basic auth. The credential travels as ``Authorization: Bearer``
  and nowhere else: never in a query string, a log line or an error text. A server without any
  check ignores the header. This module logs nothing, and every error text is fixed.
* ``probe()`` reads ``/api/v1/status/buildinfo``; a refused token (401 or 403 from the proxy)
  stops the run before anything else is read. It returns ``version`` when it looks like one.
* Three GETs feed eight resources (``resources.py``). Each answer is read once per run and kept
  for the other resources of the same answer. Coverage: 404 is ``not_available`` and 403
  ``forbidden``; both keep the previous state of the resource, so nothing is reported as removed.

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
from driftsniff.collectors.prometheus.normalize import (
    Objects,
    config_objects,
    flags_object,
    parse_yaml,
    rules_objects,
)
from driftsniff.collectors.prometheus.resources import (
    CONFIG_PATH,
    FLAGS_PATH,
    RESOURCE_FLAGS,
    RESOURCE_PATHS,
    RESOURCES,
    VERSION_PATH,
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
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"

_VERSION = re.compile(r"\d{1,4}\.\d{1,4}(?:\.\d{1,6})?(?:[.+-][0-9A-Za-z.+-]{0,32})?")


def _data(parsed: JsonValue) -> JsonValue:
    """The ``data`` of a successful API envelope."""
    if not isinstance(parsed, dict) or parsed.get("status") != "success" or "data" not in parsed:
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a Prometheus API answer")
    return parsed["data"]


class PrometheusClient(Collector):
    """Reads Prometheus read only. One instance serves one run."""

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
    ) -> None:
        if not token or any(ord(char) < 0x21 or ord(char) > 0x7E for char in token):
            raise ValueError("the bearer token is blank or has characters a header cannot carry")
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._headers = {"Authorization": f"Bearer {token}"}
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
        self._answers: dict[str, dict[str, Objects]] = {}

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Check the address and the token; return the Prometheus version when it reports one."""
        self._ready = False
        self._answers.clear()
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        try:
            data = _data(self._get(VERSION_PATH)[0])
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                error_class = (
                    ERROR_UNAUTHORIZED if error.status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
                )
                raise CollectorError(
                    error_class, "Prometheus refused the bearer token", status=error.status
                ) from None
            if error.status == STATUS_NOT_FOUND or error.error_class in (
                ERROR_BAD_JSON,
                ERROR_BAD_PAYLOAD,
            ):
                raise CollectorError(ERROR_NO_API, "the Prometheus API did not answer") from None
            raise
        if not isinstance(data, dict):
            raise CollectorError(ERROR_NO_API, "the Prometheus API did not answer")
        self._ready = True
        version = data.get("version")
        if isinstance(version, str) and _VERSION.fullmatch(version.strip()):
            return version.strip()
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in reading order."""
        return [ResourceSpec(resource.name, resource.path) for resource in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource; the answer it comes from is requested once per run."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the bearer token was not accepted")
        resource = RESOURCE_PATHS.get(spec.name)
        if resource is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        size = 0
        try:
            answer = self._answers.get(resource.path)
            if answer is None:
                parsed, size = self._get(resource.path)
                answer = self._split(resource.path, _data(parsed))
                self._answers[resource.path] = answer
        except CollectorError as error:
            return self._failure(error, size)
        return FetchResult.success(answer[resource.name], bytes_fetched=size)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    # -- helpers ------------------------------------------------------------------------------

    def _get(self, path: str) -> tuple[JsonValue, int]:
        return fetch_json(self._client, f"{self._base_url}{path}", headers=self._headers)

    @staticmethod
    def _split(path: str, data: JsonValue) -> dict[str, Objects]:
        """The resources of one answer, by name."""
        if path == CONFIG_PATH:
            text = data.get("yaml") if isinstance(data, dict) else None
            if not isinstance(text, str):
                raise CollectorError(ERROR_BAD_PAYLOAD, "the configuration answer has no YAML")
            return config_objects(parse_yaml(text))
        if path == FLAGS_PATH:
            return {RESOURCE_FLAGS: flags_object(data)}
        return rules_objects(data)

    @staticmethod
    def _failure(error: CollectorError, size: int) -> FetchResult:
        """The coverage of a failed read: 404 and 403 are statuses, not failures of the run."""
        if error.status == STATUS_NOT_FOUND:
            return FetchResult.failure(
                ERROR_NOT_AVAILABLE,
                "this resource is not available on this version",
                status=STATUS_NOT_FOUND,
                bytes_fetched=size,
            )
        if error.status == STATUS_FORBIDDEN:
            return FetchResult.failure(
                ERROR_FORBIDDEN,
                "the bearer token may not read this resource",
                status=STATUS_FORBIDDEN,
                bytes_fetched=size,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(error.error_class, str(error), status=status, bytes_fetched=size)
