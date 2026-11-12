"""The Checkmk client: probe and collection reads of the Setup (WATO) configuration.

``CheckmkClient`` is a :class:`~driftsniff.collectors.base.Collector` for the Checkmk REST API of
one site. Paths, the header and the answer shapes were read from the Checkmk source (tag
``2.4.0``) and documentation on 2026-11-12 (docs/vendor-notes/checkmk.md); no lab site was used.

* The automation user and its secret travel in one request header,
  ``Authorization: Bearer <user> <secret>``, and nowhere else: never in a query string, a log line
  or an error text. This module logs nothing, and every error text is fixed.
* ``probe()`` reads ``/version``, which needs a signed in user, so a refused secret stops the run
  before anything else is read. It returns ``versions.checkmk`` (for example ``2.4.0p2.cre``, the
  edition is its last part) when it looks like a Checkmk version.
* Every resource is one GET of a collection. Coverage: 404 is ``not_available`` (an older Checkmk
  without that endpoint). Checkmk answers a missing permission with 401 or 403 (statement 3 of the
  notes), and the probe has already proven the secret, so both are ``forbidden`` on a resource;
  either keeps the previous state of the resource, so nothing is reported as removed.
* Only GET without ETag headers is sent. Activation, discovery and every other call that changes
  the site are never made.

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
from driftsniff.collectors.checkmk.normalize import prepare_objects
from driftsniff.collectors.checkmk.resources import (
    API_PREFIX,
    AUTH_HEADER,
    RESOURCE_PATHS,
    RESOURCES,
    VERSION_PATH,
)
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.config import DEFAULT_DATA_DIR
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

# 2.4.0, 2.4.0p2, 2.4.0p2.cre, 2.3.0b4.cee, 2024.11.12 (a daily build).
_VERSION = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}(?:[a-z]{1,2}\d{1,4})?(?:\.[a-z]{2,8})?")


def _header_safe(value: str) -> bool:
    """Printable ASCII without a space: the Bearer token splits user and secret at a space."""
    return bool(value) and all(0x21 <= ord(char) <= 0x7E for char in value)


class CheckmkClient(Collector):
    """Reads the configuration of one Checkmk site read only. One instance serves one run."""

    def __init__(
        self,
        base_url: str,
        username: str,
        secret: str,
        *,
        allow_plain_http: bool = False,
        transport: httpx.BaseTransport | None = None,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
        resolver: Resolver | None = None,
        tls: TlsSettings | None = None,
        data_dir: Path | str = DEFAULT_DATA_DIR,
    ) -> None:
        if not _header_safe(username):
            raise ValueError("the user name is blank or has spaces or characters a header refuses")
        if not _header_safe(secret):
            raise ValueError("the secret is blank or has spaces or characters a header refuses")
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._api = self._base_url + API_PREFIX
        self._headers = {AUTH_HEADER: f"Bearer {username} {secret}"}
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

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Check the address and the secret; return the Checkmk version when it reports one."""
        self._ready = False
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        try:
            parsed, _ = fetch_json(
                self._client, f"{self._api}{VERSION_PATH}", headers=self._headers
            )
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                error_class = (
                    ERROR_UNAUTHORIZED if error.status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
                )
                raise CollectorError(
                    error_class, "Checkmk refused the user name or secret", status=error.status
                ) from None
            if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_JSON:
                raise CollectorError(ERROR_NO_API, "the Checkmk REST API did not answer") from None
            raise
        versions = parsed.get("versions") if isinstance(parsed, dict) else None
        if not isinstance(versions, dict):
            raise CollectorError(ERROR_NO_API, "the Checkmk REST API did not answer")
        self._ready = True
        version = versions.get("checkmk")
        if isinstance(version, str) and _VERSION.fullmatch(version.strip()):
            return version.strip()
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in reading order."""
        return [ResourceSpec(resource.name, resource.path) for resource in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the user name or secret was not accepted")
        resource = RESOURCE_PATHS.get(spec.name)
        if resource is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        size = 0
        try:
            raw, size = fetch_json(
                self._client, f"{self._api}{resource.path}", headers=self._headers
            )
            objects = prepare_objects(resource.name, raw)
        except CollectorError as error:
            return _failure(error, size)
        return FetchResult.success(objects, bytes_fetched=size)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


def _failure(error: CollectorError, size: int) -> FetchResult:
    """The coverage of a failed read: 404, 403 and 401 are statuses, not failures of the run."""
    if error.status == STATUS_NOT_FOUND:
        return FetchResult.failure(
            ERROR_NOT_AVAILABLE,
            "this resource is not available on this version",
            status=STATUS_NOT_FOUND,
            bytes_fetched=size,
        )
    if error.status in (STATUS_FORBIDDEN, STATUS_UNAUTHORIZED):
        return FetchResult.failure(
            ERROR_FORBIDDEN,
            "the automation user may not read this resource",
            status=error.status,
            bytes_fetched=size,
        )
    status = error.status if error.status else STATUS_ERROR
    return FetchResult.failure(error.error_class, str(error), status=status, bytes_fetched=size)
