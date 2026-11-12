"""The Grafana client: probe, list reads, paged reads, dashboards and folder permissions.

``GrafanaClient`` is a :class:`~driftsniff.collectors.base.Collector` for the Grafana HTTP API.
Paths, parameters and fields were read from the Grafana documentation on 2026-11-12
(docs/vendor-notes/grafana.md); no lab Grafana was used.

* The service account token travels in one request header, ``Authorization: Bearer <token>``, and
  nowhere else: never in a query string, a log line or an error text. This module logs nothing,
  and every error text is fixed.
* ``probe()`` reads ``/api/health`` (public, without the token) for the version, then
  ``/api/org`` with the token, so a refused token stops the run before anything else is read.
* Coverage: 404 is ``not_available`` and 403 ``forbidden`` (a Viewer or Editor service account
  gets 403 on data sources, alerting provisioning, users, teams, service accounts and folder
  permissions); both keep the previous state of the resource, so nothing is reported as removed.
* Folders and dashboards come from ``/api/search`` page by page. Each dashboard is then read from
  ``/api/dashboards/uid/{uid}``, at most ``MAX_DASHBOARDS`` of them (the lowest uids); when there
  are more the read is good but carries the warning ``too_many_dashboards``. The permissions of
  each folder come from ``/api/folders/{uid}/permissions``. One sub-read that fails fails the
  whole resource, so its previous state stays rather than a false change.

``probe()`` resolves the host name once, refuses a blocked answer and pins the first answer
(``collectors/resolve.py``); TLS modes come from ``collectors/tls.py``. Redirects are refused.
"""

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Final
from urllib.parse import quote

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
from driftsniff.collectors.grafana.normalize import (
    dashboard_object,
    folder_permissions,
    prepare_objects,
)
from driftsniff.collectors.grafana.resources import (
    AUTHORIZATION_HEADER,
    DASHBOARD_PATH,
    FOLDER_PERMISSIONS_PATH,
    HEALTH_PATH,
    HEALTH_VERSION_FIELD,
    MAX_DASHBOARDS,
    MAX_PAGES,
    ORG_PATH,
    RESOURCE_DASHBOARDS,
    RESOURCE_FOLDER_PERMISSIONS,
    RESOURCE_PATHS,
    RESOURCES,
    SEARCH_PAGE_SIZE,
    GrafanaResource,
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
ERROR_TOO_MANY_PAGES: Final = "too_many_pages"
WARNING_TOO_MANY_DASHBOARDS: Final = "too_many_dashboards"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"

_VERSION = re.compile(r"\d{1,4}\.\d{1,4}(?:\.\d{1,6})?(?:[.+-][0-9A-Za-z.+-]{0,32})?")


class GrafanaClient(Collector):
    """Reads Grafana read only. One instance serves one run."""

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
            raise ValueError(
                "the service account token is blank or has characters a header cannot carry"
            )
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._headers = {AUTHORIZATION_HEADER: f"Bearer {token}"}
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
        """Check the address and the token; return the Grafana version when it reports one."""
        self._ready = False
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        try:
            health, _ = fetch_json(self._client, f"{self._base_url}{HEALTH_PATH}")
        except CollectorError as error:
            if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_JSON:
                raise CollectorError(ERROR_NO_API, "the Grafana API did not answer") from None
            raise
        if not isinstance(health, dict):
            raise CollectorError(ERROR_NO_API, "the Grafana API did not answer")
        try:
            org, _ = fetch_json(self._client, f"{self._base_url}{ORG_PATH}", headers=self._headers)
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                error_class = (
                    ERROR_UNAUTHORIZED if error.status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
                )
                raise CollectorError(
                    error_class, "Grafana refused the service account token", status=error.status
                ) from None
            if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_JSON:
                raise CollectorError(ERROR_NO_API, "the Grafana API did not answer") from None
            raise
        if not isinstance(org, dict):
            raise CollectorError(ERROR_NO_API, "the Grafana API did not answer")
        self._ready = True
        version = health.get(HEALTH_VERSION_FIELD)
        if isinstance(version, str) and _VERSION.fullmatch(version.strip()):
            return version.strip()
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in reading order."""
        return [ResourceSpec(resource.name, resource.path) for resource in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource (with its pages, dashboards or folder permissions)."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the service account token was not accepted")
        resource = RESOURCE_PATHS.get(spec.name)
        if resource is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        self._bytes = 0
        warning: tuple[str, str] | None = None
        try:
            objects = prepare_objects(resource.name, resource.key_field, self._list(resource))
            if resource.name == RESOURCE_DASHBOARDS:
                if len(objects) > MAX_DASHBOARDS:
                    warning = (
                        WARNING_TOO_MANY_DASHBOARDS,
                        f"only the first {MAX_DASHBOARDS} dashboards (by uid) were read",
                    )
                objects = [self._dashboard(item["uid"]) for item in objects[:MAX_DASHBOARDS]]
            elif resource.name == RESOURCE_FOLDER_PERMISSIONS:
                objects = [
                    folder_permissions(item, self._permissions(item["uid"])) for item in objects
                ]
        except CollectorError as error:
            return self._failure(error)
        if warning is None:
            return FetchResult.success(objects, bytes_fetched=self._bytes)
        return FetchResult.success(
            objects, bytes_fetched=self._bytes, warning_class=warning[0], warning_text=warning[1]
        )

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    # -- helpers ------------------------------------------------------------------------------

    def _get(self, path: str) -> JsonValue:
        parsed, size = fetch_json(self._client, f"{self._base_url}{path}", headers=self._headers)
        self._bytes += size
        return parsed

    def _list(self, resource: GrafanaResource) -> JsonValue:
        """The whole answer of a resource: one GET, or every page of a paged one."""
        if not resource.paged:
            return self._get(resource.path)
        collected: list[JsonValue] = []
        for page in range(1, MAX_PAGES + 1):
            if resource.paged == "search":
                members = self._get(f"{resource.path}&limit={SEARCH_PAGE_SIZE}&page={page}")
            else:
                answer = self._get(f"{resource.path}?perpage={SEARCH_PAGE_SIZE}&page={page}")
                members = answer.get(resource.paged) if isinstance(answer, dict) else None
            if not isinstance(members, list):
                raise CollectorError(ERROR_BAD_PAYLOAD, "a page of the answer is not a list")
            collected.extend(members)
            if len(members) < SEARCH_PAGE_SIZE:
                return collected
        raise CollectorError(ERROR_TOO_MANY_PAGES, "the list has more pages than are read")

    def _dashboard(self, uid: JsonValue) -> dict[str, JsonValue]:
        return dashboard_object(self._get(DASHBOARD_PATH.format(uid=_segment(uid))))

    def _permissions(self, uid: JsonValue) -> JsonValue:
        return self._get(FOLDER_PERMISSIONS_PATH.format(uid=_segment(uid)))

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
                "the service account may not read this resource",
                status=STATUS_FORBIDDEN,
                bytes_fetched=self._bytes,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(
            error.error_class, str(error), status=status, bytes_fetched=self._bytes
        )


def _segment(uid: JsonValue) -> str:
    """A uid as one path segment; Grafana uids are short words, anything else is refused."""
    if not isinstance(uid, str) or not uid:
        raise CollectorError(ERROR_BAD_PAYLOAD, "a uid is not text")
    return quote(uid, safe="")
