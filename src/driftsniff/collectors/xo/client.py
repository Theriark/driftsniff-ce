"""The Xen Orchestra REST client: probe, ndjson streaming and credential expiry (P8-T2).

``XoClient`` is a :class:`~driftsniff.collectors.base.Collector` for the REST interface of Xen
Orchestra (XO). The paths, the cookie name, the field names and the credential endpoint are
**unverified** (docs/vendor-notes/xo.md; the vendor reference was not read and no lab XO exists).
The behaviour below is the plan's and does not depend on them.

* The session credential travels in one cookie, ``authenticationToken``, and nowhere else: never as
  basic credentials, never in a query string, a log line or an error text. This module logs
  nothing, and every error text is fixed.
* Each collection is requested once with an explicit field list built from its type table
  (``resources.field_list``) and newline delimited JSON output, read line by line from a streaming
  response (``base.fetch_ndjson``), so memory stays flat while the body streams; the 200 MB limit
  counts bytes as they arrive. No paging parameters are assumed: a collection is treated as
  unpaginated, sorted by id after the fetch (``normalize.prepare_objects``), and the order the
  server returned is never trusted.
* A line that is not valid JSON fails that resource (``bad_payload``) and no other. A 404 on a
  resource is coverage ``404`` and a 403 coverage ``403`` (class ``not_available`` and
  ``forbidden``), never a failure of the run, as for UniFi (plan P7-T2). Both keep the previous
  state of the resource, so nothing is reported as removed.
* ``probe()`` asks the REST root once. XO reports no version through it, so it returns None. After
  a good probe the client tries once to read the expiry of the credential in use; 403, 404 or any
  other failure of that one read is tolerated and the expiry the administrator entered is used. A
  credential that expires within :data:`EXPIRY_WARNING_DAYS` days, or has expired, makes
  :meth:`XoClient.token_expiring` true; the caller sets the source state ``token_expiring`` from it.

TLS modes come from ``collectors/tls.py``: the caller passes the settings of the source.

Not done here (other tasks): the factory that builds a client from a stored source and saves the
state ``token_expiring`` (``serve`` has no scheduler until it exists).
"""

import re
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime, time, timedelta
from functools import cache
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
    fetch_ndjson,
    make_client,
)
from driftsniff.collectors.resolve import Resolver, check_address, system_resolver
from driftsniff.collectors.tls import TlsSettings
from driftsniff.collectors.xo.normalize import prepare_objects
from driftsniff.collectors.xo.resources import (
    COLLECTIONS,
    COOKIE_NAME,
    REST_PREFIX,
    TOKEN_PATH,
    collection_path,
    collection_query,
    field_list,
)
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.rules.loader import load_rules
from driftsniff.rules.schema import ResourceTable
from driftsniff.sources.addresses import validate_base_url

EXPIRY_WARNING_DAYS: Final = 14

ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_NO_API: Final = "no_api"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"

# Printable ASCII without space, quote, comma, semicolon and backslash: a cookie value as is.
_TOKEN = re.compile(r"[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]{1,1024}")

Clock = Callable[[], datetime]


@cache
def _shipped_tables() -> dict[str, ResourceTable]:
    return dict(load_rules().type_tables)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def entered_expiry(value: date | datetime | None) -> datetime | None:
    """The expiry an administrator entered as a moment: a date means the end of that day (UTC)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return datetime.combine(value, time(23, 59, 59), tzinfo=UTC)


def expiry_is_near(expires_at: datetime | None, now: datetime) -> bool:
    """Whether a credential that expires at ``expires_at`` is past, or ends within 14 days."""
    return expires_at is not None and expires_at - now <= timedelta(days=EXPIRY_WARNING_DAYS)


def _moment(value: JsonValue) -> datetime | None:
    """A moment from an epoch in milliseconds or an ISO 8601 text; None when it is neither."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        try:
            return datetime.fromtimestamp(value / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return None


class XoClient(Collector):
    """Reads Xen Orchestra read only. One instance serves one run."""

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
        expires_on: date | datetime | None = None,
        clock: Clock | None = None,
    ) -> None:
        if _TOKEN.fullmatch(token) is None:
            raise ValueError("the credential is blank or has characters a cookie cannot carry")
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._token = token
        self._headers = {"Cookie": f"{COOKIE_NAME}={token}"}
        self._resolver = resolver or system_resolver
        self._tables = tables if tables is not None else _shipped_tables()
        self._entered = entered_expiry(expires_on)
        self._observed: datetime | None = None
        self._clock = clock or _utc_now
        self._client = make_client(transport=transport, tls=tls, data_dir=data_dir)
        self._client.timeout = httpx.Timeout(request_timeout)
        self._ready = False

    # -- expiry -------------------------------------------------------------------------------

    @property
    def credential_expires_at(self) -> datetime | None:
        """The expiry the REST interface reported for the credential in use, if it did."""
        return self._observed

    @property
    def expiry(self) -> datetime | None:
        """The expiry that counts: the one the interface reported, else the one entered."""
        return self._observed or self._entered

    def token_expiring(self) -> bool:
        """Whether the credential has expired or ends within 14 days (source state)."""
        return expiry_is_near(self.expiry, self._clock())

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Check the address and the credential, then read the credential expiry once."""
        self._ready = False
        check_address(self._base_url, self._resolver)
        try:
            fetch_json(self._client, f"{self._base_url}{REST_PREFIX}", headers=self._headers)
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                raise self._refused(error.status) from None
            if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_JSON:
                raise CollectorError(
                    ERROR_NO_API, "the Xen Orchestra REST interface did not answer"
                ) from None
            raise
        self._ready = True
        self._read_expiry()
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The collections the client reads: those of the plan that have a type table."""
        return [
            ResourceSpec(name, f"{REST_PREFIX}{collection_path(name)}")
            for name in COLLECTIONS
            if name in self._tables
        ]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one collection as ndjson; never asks for a collection without a type table."""
        if not self._ready:
            raise CollectorError(ERROR_NOT_PROBED, "the credential was not accepted")
        table = self._tables.get(spec.name)
        if table is None or spec.name not in COLLECTIONS:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        url = (
            f"{self._base_url}{REST_PREFIX}{collection_path(spec.name)}"
            f"?{collection_query(field_list(spec.name, table))}"
        )
        try:
            raw, size = fetch_ndjson(self._client, url, headers=self._headers)
            objects = prepare_objects(spec.name, raw)
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=size)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    # -- helpers ------------------------------------------------------------------------------

    @staticmethod
    def _refused(status: str) -> CollectorError:
        error_class = ERROR_UNAUTHORIZED if status == STATUS_UNAUTHORIZED else ERROR_FORBIDDEN
        return CollectorError(error_class, "Xen Orchestra refused the credential", status=status)

    def _read_expiry(self) -> None:
        """Try once to read the expiry of the credential in use; any failure is tolerated."""
        self._observed = None
        url = f"{self._base_url}{REST_PREFIX}{TOKEN_PATH}"
        try:
            parsed, _ = fetch_json(self._client, url, headers=self._headers)
        except CollectorError:
            return
        self._observed = self._expiry_of(parsed)

    def _expiry_of(self, parsed: JsonValue) -> datetime | None:
        """The expiry of the entry that is the credential in use, or None."""
        if not isinstance(parsed, list):
            return None
        for entry in parsed:
            if isinstance(entry, dict) and entry.get("id") == self._token:
                return _moment(entry.get("expiration"))
        return None

    @staticmethod
    def _failure(error: CollectorError) -> FetchResult:
        """The coverage of a failed read: 404 and 403 are statuses, not failures of the run."""
        if error.status == STATUS_NOT_FOUND:
            return FetchResult.failure(
                ERROR_NOT_AVAILABLE,
                "this collection is not available",
                status=STATUS_NOT_FOUND,
            )
        if error.status == STATUS_FORBIDDEN:
            return FetchResult.failure(
                ERROR_FORBIDDEN,
                "the credential may not read this collection",
                status=STATUS_FORBIDDEN,
            )
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(error.error_class, str(error), status=status)
