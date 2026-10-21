"""The UniFi client: probe, version floor and paging (P7-T2).

``UnifiClient`` is a :class:`~driftsniff.collectors.base.Collector` for the integration API of the
UniFi Network application (docs/unifi-client.md has the user view). Paths, header name and
envelope names are **unverified**: dependency D5 (the vendor reference) is open and no lab
controller was used (docs/vendor-notes/unifi.md). The behaviour below is the plan's and does not
depend on them.

* The API key travels in one request header, ``X-API-KEY``, and nowhere else: never in a query
  string, a log line or an error text. This module logs nothing, and every error text is fixed.
* ``probe()`` calls the information endpoint on the direct integration path and then on the console
  proxy path; the first that answers wins and is kept in :attr:`UnifiClient.base_path`, which the
  caller stores in the source options. A version below :data:`FLOOR_VERSION` (compared as integer
  tuples) raises :class:`UnsupportedVersionError` before anything else is requested.
* Lists are read ``limit=200`` at a time with ``offset``. A page that repeats the previous page
  stops the loop with ``paging_loop``. When the controller reports a total the loop runs until
  that total is reached; it never stops at a short page then, because a controller may cap its page
  size below 200 and a silently cut list would show up as removed objects. Without a total, a
  short page ends the list. A list that ends before its reported total is ``bad_payload``.
* Coverage: 404 on a resource is ``not_available`` (status ``404``), 403 is ``forbidden`` (status
  ``403``). Both keep the previous state of the resource, so nothing is reported as removed.
* Raw objects go to the pipeline untouched. Only the paging envelope and the object key are read
  through pydantic (``models.py``).

TLS modes come from ``collectors/tls.py`` (P7-T3): the caller passes the settings of the source.

Not done here (other tasks): the ordering lists of firewall policies and ACL rules (P7-T4) and the
factory that builds a client from a stored source and saves the detected base path and the state
``unsupported``.

A host name is resolved once, before the first request, and every address is checked with
``blocked_reason``. The connection then resolves the name again, so a name that changes its answer
between the two is not caught (DNS rebinding); the redirect refusal of the shared client remains.
"""

import ipaddress
import re
import socket
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote, urlsplit

import httpx
from pydantic import ValidationError

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
    ERROR_CONNECTION,
    REQUEST_TIMEOUT_SECONDS,
    STATUS_ERROR,
    Collector,
    CollectorError,
    FetchResult,
    ResourceSpec,
    fetch_json,
    make_client,
)
from driftsniff.collectors.tls import TlsSettings
from driftsniff.collectors.unifi.models import InfoAnswer, ObjectRef, PageEnvelope
from driftsniff.collectors.unifi.resources import (
    API_VERSION_PREFIX,
    BASE_PATHS,
    INFO_PATH,
    RESOURCE_PATHS,
    RESOURCES,
    SITES_PATH,
)
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.addresses import blocked_reason, validate_base_url

API_KEY_HEADER: Final = "X-API-KEY"
FLOOR_VERSION: Final = (10, 1, 84)
PAGE_LIMIT: Final = 200
MAX_PAGES: Final = 1000

ERROR_UNSUPPORTED_VERSION: Final = "unsupported_version"
ERROR_PAGING_LOOP: Final = "paging_loop"
ERROR_BAD_PAYLOAD: Final = "bad_payload"
ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_NO_API: Final = "no_api"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_BLOCKED_ADDRESS: Final = "blocked_address"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"

_VERSION = re.compile(r"(\d{1,4})\.(\d{1,4})\.(\d{1,6})(?:[.+-][0-9A-Za-z.+-]{0,32})?")
_SITE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")

Resolver = Callable[[str], Sequence[str]]


def parse_version(text: str) -> tuple[int, int, int] | None:
    """The first three numbers of a version such as ``10.1.84`` (a suffix is ignored), or None."""
    match = _VERSION.fullmatch(text.strip())
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _format(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


class UnsupportedVersionError(CollectorError):
    """The controller is older than the floor, or its version cannot be read.

    The message holds only numbers this module parsed itself, never the text the controller sent.
    """

    def __init__(self, message: str) -> None:
        super().__init__(ERROR_UNSUPPORTED_VERSION, message)


def _system_resolver(host: str) -> Sequence[str]:
    try:
        found = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise CollectorError(
            ERROR_CONNECTION,
            "the controller address cannot be resolved",
        ) from None
    return [str(entry[4][0]) for entry in found]


class UnifiClient(Collector):
    """Reads the UniFi Network application read only. One instance serves one run."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        base_path: str | None = None,
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
        self._hint = base_path if base_path in BASE_PATHS else None
        self._resolver = resolver or _system_resolver
        self._client = make_client(transport=transport, tls=tls, data_dir=data_dir)
        self._client.timeout = httpx.Timeout(request_timeout)
        self._base_path: str | None = None
        self._version: str | None = None
        self._ready = False
        self._site_ids: list[str] | None = None
        self._bytes = 0

    @property
    def base_path(self) -> str | None:
        """The base path that answered the information call, for the caller to store."""
        return self._base_path

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Find the base path, read the version and enforce the floor."""
        self._ready = False
        self._check_address()
        for path in self._candidate_paths():
            try:
                parsed, _ = fetch_json(
                    self._client,
                    self._url(path, INFO_PATH),
                    headers=self._headers,
                )
            except CollectorError as error:
                if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                    raise self._refused(error.status) from None
                if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_JSON:
                    continue
                raise
            raw = self._application_version(parsed)
            if raw is None:
                continue
            self._base_path = path
            return self._check_floor(raw)
        raise CollectorError(ERROR_NO_API, "neither base path answered the information call")

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, sites first."""
        return [ResourceSpec(item.name, item.site_path or SITES_PATH) for item in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read every page of one resource; objects of a site resource come from every site."""
        if not self._ready or self._base_path is None:
            raise CollectorError(
                ERROR_NOT_PROBED,
                "the version of the controller was not accepted",
            )
        resource = RESOURCE_PATHS.get(spec.name)
        if resource is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        self._bytes = 0
        objects: list[dict[str, Any]] = []
        try:
            if resource.site_path is None:
                sites = self._read_list(self._url(self._base_path, SITES_PATH))
                self._site_ids = self._ids_of(sites)
                objects = sites
            else:
                for site_id in self._sites(self._base_path):
                    path = f"{SITES_PATH}/{quote(site_id, safe='')}{resource.site_path}"
                    objects.extend(self._read_list(self._url(self._base_path, path)))
        except CollectorError as error:
            return self._failure(error)
        result_objects: Sequence[dict[str, JsonValue]] = objects
        return FetchResult.success(result_objects, bytes_fetched=self._bytes)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    # -- probe helpers ------------------------------------------------------------------------

    def _check_address(self) -> None:
        host = urlsplit(self._base_url).hostname or ""
        for text in self._resolver(host):
            try:
                address = ipaddress.ip_address(text.split("%", 1)[0])
            except ValueError:
                raise CollectorError(
                    ERROR_BLOCKED_ADDRESS,
                    "the controller address resolves to an unusable value",
                ) from None
            if blocked_reason(address) is not None:
                raise CollectorError(
                    ERROR_BLOCKED_ADDRESS,
                    "the controller address resolves to a blocked address",
                )

    def _candidate_paths(self) -> list[str]:
        if self._hint is None:
            return list(BASE_PATHS)
        return [self._hint, *(path for path in BASE_PATHS if path != self._hint)]

    @staticmethod
    def _refused(status: str) -> CollectorError:
        error_class = ERROR_UNAUTHORIZED if status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
        return CollectorError(error_class, "the controller refused the credential", status=status)

    @staticmethod
    def _application_version(parsed: JsonValue) -> str | None:
        """The version text of an information answer, or None when it is not one."""
        if not isinstance(parsed, dict):
            return None
        try:
            return InfoAnswer.model_validate(parsed).application_version
        except ValidationError:
            return None

    def _check_floor(self, raw: str) -> str:
        version = parse_version(raw)
        if version is None:
            raise UnsupportedVersionError(
                "the UniFi Network version cannot be read, so nothing is collected"
            )
        if version < FLOOR_VERSION:
            raise UnsupportedVersionError(
                f"UniFi Network {_format(version)} is older than the supported "
                f"{_format(FLOOR_VERSION)}, so nothing is collected"
            )
        self._version = raw.strip()
        self._ready = True
        return self._version

    # -- reading lists ------------------------------------------------------------------------

    def _url(self, base_path: str, path: str) -> str:
        return f"{self._base_url}{base_path}{API_VERSION_PREFIX}{path}"

    def _sites(self, base_path: str) -> list[str]:
        if self._site_ids is None:
            sites = self._read_list(self._url(base_path, SITES_PATH))
            self._site_ids = self._ids_of(sites)
        return self._site_ids

    @staticmethod
    def _ids_of(objects: Sequence[dict[str, Any]]) -> list[str]:
        ids: list[str] = []
        for item in objects:
            try:
                key = ObjectRef.model_validate(item).id
            except ValidationError:
                raise CollectorError(ERROR_BAD_PAYLOAD, "a site has no usable id") from None
            if _SITE_ID.fullmatch(key) is None:
                raise CollectorError(ERROR_BAD_PAYLOAD, "a site id has unexpected characters")
            if key not in ids:
                ids.append(key)
        return ids

    def _read_list(self, url: str) -> list[dict[str, Any]]:
        """Every object of one list, ``PAGE_LIMIT`` at a time."""
        objects: list[dict[str, Any]] = []
        previous: list[dict[str, Any]] | None = None
        for _ in range(MAX_PAGES):
            parsed, size = fetch_json(
                self._client,
                f"{url}?offset={len(objects)}&limit={PAGE_LIMIT}",
                headers=self._headers,
            )
            self._bytes += size
            page = self._envelope(parsed)
            data = page.data
            if data and data == previous:
                raise CollectorError(ERROR_PAGING_LOOP, "the controller repeats a page")
            objects.extend(data)
            total = page.total_count
            if total is None:
                if len(data) < PAGE_LIMIT:
                    return objects
            elif len(objects) >= total:
                return objects
            elif not data:
                raise CollectorError(
                    ERROR_BAD_PAYLOAD,
                    "the controller listed fewer objects than it reported",
                )
            previous = data
        raise CollectorError(ERROR_PAGING_LOOP, "the list did not end within the page limit")

    @staticmethod
    def _envelope(parsed: JsonValue) -> PageEnvelope:
        if not isinstance(parsed, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a page of objects")
        try:
            return PageEnvelope.model_validate(parsed)
        except ValidationError:
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a page of objects") from None

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
                "the key may not read this resource",
                status=STATUS_FORBIDDEN,
                bytes_fetched=self._bytes,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(
            error.error_class,
            str(error),
            status=status,
            bytes_fetched=self._bytes,
        )
