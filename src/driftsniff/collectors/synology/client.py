"""The Synology DSM Web API client: discovery, a session per run and the resource reads.

``SynologyClient`` is a :class:`~driftsniff.collectors.base.Collector` for DSM 7.x. The
discovery and sign in calls follow Synology's DSM Login Web API Guide; every ``SYNO.Core.*`` call
is **unverified** (docs/vendor-notes/synology.md, ``resources.py``).

* DSM has no API keys. The factory joins the source's ``username`` option and the stored password
  as ``user name:password`` for this client (``normalize.split_credential``). The password
  travels once per run, in the form body of the sign in POST, never in a query string, a log
  line or an error text. This module logs nothing,
  and every error text is fixed or holds only numbers it parsed itself.
* ``probe()`` asks ``SYNO.API.Info`` for the path and versions of every API, then signs in with
  ``SYNO.API.Auth`` (version 6, ``format=sid``). The session id (sid) is sent as the form field
  ``_sid`` of every POST and nowhere else. ``close()`` signs out. A refused sign in is never tried
  again in the same run: DSM blocks an address after repeated failures (auto block).
* A call answered with a session error (106 timeout, 107 duplicate sign in, 119 sid not found)
  signs in once more and repeats the call once; a second session error fails the resource.
* Coverage: an API the NAS does not list, or a version it does not serve, or the error codes
  102 to 104 are ``not_available`` (status 404); 105 (no privilege) is ``forbidden`` (status
  403). Both keep the previous state of the resource, so nothing is reported as removed.
* Every call is a POST to ``/webapi/<path>``; redirects are refused, bodies are limited to 200 MB
  and requests to 30 seconds (``collectors/base.py``). TLS modes come from ``collectors/tls.py``.

``probe()`` resolves the host name once, refuses a blocked answer and pins the first answer for
the whole run (``collectors/resolve.py``), as the other collectors do.
"""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

import httpx

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
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
from driftsniff.collectors.resolve import Resolver, pin_address, system_resolver
from driftsniff.collectors.synology.normalize import (
    guest_access,
    keyed,
    objects_of,
    share_object,
    split_credential,
)
from driftsniff.collectors.synology.resources import (
    ADMIN_GROUP,
    API_AUTH,
    API_INFO,
    AUTH_VERSION,
    FILE_SERVICE_CALLS,
    GROUP_LIST,
    INFO_PATH,
    MEMBER_LIST,
    PAGE_LIMIT,
    PERMISSION_LIST,
    PRINCIPAL_TYPES,
    RESOURCE_ADMINISTRATORS,
    RESOURCE_BY_NAME,
    RESOURCE_FILE_SERVICES,
    RESOURCE_GROUPS,
    RESOURCE_GUEST_ACCESS,
    RESOURCE_SHARES,
    RESOURCES,
    SESSION_NAME,
    SHARE_LIST,
    SINGLETON_FIELD,
    Call,
    SynologyResource,
)
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.addresses import validate_base_url

WEBAPI_PREFIX: Final = "/webapi/"
MAX_PAGES: Final = 1000

ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_TWO_FACTOR: Final = "two_factor_required"
ERROR_ACCOUNT_DISABLED: Final = "account_disabled"
ERROR_PASSWORD_EXPIRED: Final = "password_expired"  # noqa: S105 - an error class
ERROR_ADDRESS_BLOCKED: Final = "address_blocked"
ERROR_SESSION: Final = "session_lost"
ERROR_API_ERROR: Final = "api_error"
ERROR_NO_API: Final = "no_api"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"

# DSM error codes (DSM Login Web API Guide, common codes 100 to 119 and sign in codes 400 to 410).
CODES_NOT_AVAILABLE: Final = frozenset({102, 103, 104})
CODE_NO_PRIVILEGE: Final = 105
CODES_SESSION: Final = frozenset({106, 107, 119})
_SIGN_IN_REFUSALS: Final = {
    400: (ERROR_UNAUTHORIZED, "DSM refused the user name or the password"),
    401: (ERROR_ACCOUNT_DISABLED, "the DSM account is disabled"),
    402: (ERROR_FORBIDDEN, "the DSM account may not sign in to this service"),
    403: (ERROR_TWO_FACTOR, "the DSM account asks for a 2-step verification code"),
    404: (ERROR_TWO_FACTOR, "the DSM account asks for a 2-step verification code"),
    406: (ERROR_TWO_FACTOR, "DSM enforces 2-step verification for this account"),
    407: (ERROR_ADDRESS_BLOCKED, "DSM blocked the address of driftsniff (auto block)"),
    408: (ERROR_PASSWORD_EXPIRED, "the password of the DSM account has expired"),
    409: (ERROR_PASSWORD_EXPIRED, "the password of the DSM account has expired"),
    410: (ERROR_PASSWORD_EXPIRED, "the password of the DSM account must be changed"),
}

ApiInfo = dict[str, tuple[str, int, int]]


class _DsmError(Exception):
    """A DSM answer with ``success`` false and its numeric code (never shown with any text)."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class SynologyClient(Collector):
    """Reads Synology DSM read only. One instance serves one run."""

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
    ) -> None:
        self._account, self._password = split_credential(credential)
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._resolver = resolver or system_resolver
        self._address = AddressPin()
        self._client = make_client(
            transport=transport,
            tls=tls,
            data_dir=data_dir,
            address=self._address if transport is None else None,
        )
        self._client.timeout = httpx.Timeout(request_timeout)
        self._apis: ApiInfo = {}
        self._sid: str | None = None
        self._bytes = 0

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Discover the APIs and sign in. DSM reports no version through these calls: None."""
        self._sign_out()
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        self._apis = self._discover()
        auth = self._apis.get(API_AUTH)
        if auth is None or not auth[1] <= AUTH_VERSION <= auth[2]:
            raise CollectorError(ERROR_NO_API, "the NAS does not offer the DSM sign in this needs")
        self._sign_in()
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in the order of ``resources.RESOURCES``."""
        return [ResourceSpec(resource.name, resource.calls[0].api) for resource in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource; its objects are sorted by their key."""
        if self._sid is None:
            raise CollectorError(ERROR_NOT_PROBED, "the NAS did not accept the sign in")
        resource = RESOURCE_BY_NAME.get(spec.name)
        if resource is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        self._bytes = 0
        try:
            objects = keyed(self._read(resource), resource.key_field)
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=self._bytes)

    def close(self) -> None:
        """Sign out and close the HTTP client."""
        try:
            self._sign_out()
        finally:
            self._client.close()

    # -- reading resources --------------------------------------------------------------------

    def _read(self, resource: SynologyResource) -> list[dict[str, JsonValue]]:
        name = resource.name
        if name in (RESOURCE_SHARES, RESOURCE_GUEST_ACCESS):
            return self._shares(guest_only=name == RESOURCE_GUEST_ACCESS)
        if name == RESOURCE_GROUPS:
            groups = self._list(GROUP_LIST)
            for group in groups:
                members = self._list(MEMBER_LIST, {"group": str(group.get("name", ""))})
                group["members"] = [str(member.get("name")) for member in members]
            return groups
        if name == RESOURCE_ADMINISTRATORS:
            return self._list(MEMBER_LIST, {"group": ADMIN_GROUP})
        if name == RESOURCE_FILE_SERVICES:
            found: list[dict[str, JsonValue]] = []
            for key, call in FILE_SERVICE_CALLS.items():
                for item in self._list(call):
                    found.append({**item, SINGLETON_FIELD: key})
            return found
        return self._list(resource.calls[0])

    def _shares(self, *, guest_only: bool) -> list[dict[str, JsonValue]]:
        """The shares with their permission rows, or the guest view of them."""
        result: list[dict[str, JsonValue]] = []
        for share in self._list(SHARE_LIST):
            name = share.get("name")
            if not isinstance(name, str) or not name:
                raise CollectorError(ERROR_BAD_PAYLOAD, "a shared folder has no usable name")
            types = PRINCIPAL_TYPES[:1] if guest_only else PRINCIPAL_TYPES
            rows = {
                principal: self._list(PERMISSION_LIST, {"name": name, "user_group_type": principal})
                for principal in types
            }
            if guest_only:
                view = guest_access(name, rows[PRINCIPAL_TYPES[0]])
                if view is not None:
                    result.append(view)
            else:
                result.append(share_object(share, rows))
        return result

    def _list(
        self, call: Call, extra: Mapping[str, str] | None = None
    ) -> list[dict[str, JsonValue]]:
        """Every object one call lists, ``PAGE_LIMIT`` at a time for a paged call."""
        params = dict(extra or {})
        if not call.paged:
            return objects_of(self._call(call, params), call.list_key)
        objects: list[dict[str, JsonValue]] = []
        for _ in range(MAX_PAGES):
            page_params = {**params, "offset": str(len(objects)), "limit": str(PAGE_LIMIT)}
            data = self._call(call, page_params)
            page = objects_of(data, call.list_key)
            objects.extend(page)
            total = data.get("total") if isinstance(data, dict) else None
            if not isinstance(total, int) or isinstance(total, bool):
                return objects
            if len(objects) >= total:
                return objects
            if not page:
                raise CollectorError(ERROR_BAD_PAYLOAD, "the NAS listed fewer objects than it said")
        raise CollectorError(ERROR_BAD_PAYLOAD, "the list did not end within the page limit")

    def _call(self, call: Call, params: Mapping[str, str]) -> JsonValue:
        """One call of a resource API with the session; a lost session is renewed once."""
        found = self._apis.get(call.api)
        if found is None or not found[1] <= call.version <= found[2]:
            raise CollectorError(
                ERROR_NOT_AVAILABLE, "the NAS does not offer this API", status=STATUS_NOT_FOUND
            )
        form = {
            "api": call.api,
            "method": call.method,
            "version": str(call.version),
            **call.params,
            **params,
        }
        for attempt in range(2):
            try:
                return self._post(found[0], {**form, "_sid": self._sid or ""})
            except _DsmError as error:
                if error.code in CODES_SESSION and attempt == 0:
                    self._sid = None
                    self._sign_in()
                    continue
                raise self._api_error(error.code) from None
        raise CollectorError(ERROR_SESSION, "the DSM session was lost twice in a row")

    @staticmethod
    def _api_error(code: int) -> CollectorError:
        if code in CODES_NOT_AVAILABLE:
            return CollectorError(
                ERROR_NOT_AVAILABLE, "the NAS does not offer this API", status=STATUS_NOT_FOUND
            )
        if code == CODE_NO_PRIVILEGE:
            return CollectorError(
                ERROR_FORBIDDEN, "the DSM account may not read this", status=STATUS_FORBIDDEN
            )
        if code in CODES_SESSION:
            return CollectorError(ERROR_SESSION, "the DSM session was lost twice in a row")
        return CollectorError(ERROR_API_ERROR, f"DSM refused the request with error code {code}")

    # -- discovery and session ----------------------------------------------------------------

    def _discover(self) -> ApiInfo:
        """The path, lowest and highest version of every API the NAS lists."""
        form = {"api": API_INFO, "version": "1", "method": "query", "query": "ALL"}
        try:
            data = self._post(INFO_PATH, form)
        except _DsmError:
            raise CollectorError(ERROR_NO_API, "the NAS did not list its APIs") from None
        except CollectorError as error:
            if error.status == STATUS_NOT_FOUND or error.error_class == ERROR_BAD_JSON:
                raise CollectorError(ERROR_NO_API, "the address does not answer as DSM") from None
            raise
        if not isinstance(data, dict):
            raise CollectorError(ERROR_NO_API, "the NAS did not list its APIs")
        apis: ApiInfo = {}
        for name, entry in data.items():
            if not isinstance(entry, dict):
                continue
            path, low, high = entry.get("path"), entry.get("minVersion"), entry.get("maxVersion")
            if (
                isinstance(path, str)
                and _safe_path(path)
                and isinstance(low, int)
                and isinstance(high, int)
            ):
                apis[name] = (path, low, high)
        return apis

    def _sign_in(self) -> None:
        auth = self._apis[API_AUTH]
        form = {
            "api": API_AUTH,
            "version": str(AUTH_VERSION),
            "method": "login",
            "account": self._account,
            "passwd": self._password,
            "session": SESSION_NAME,
            "format": "sid",
        }
        try:
            data = self._post(auth[0], form)
        except _DsmError as error:
            error_class, text = _SIGN_IN_REFUSALS.get(
                error.code, (ERROR_UNAUTHORIZED, "DSM refused the sign in")
            )
            raise CollectorError(error_class, text, status=STATUS_UNAUTHORIZED) from None
        sid = data.get("sid") if isinstance(data, dict) else None
        if not isinstance(sid, str) or not sid:
            raise CollectorError(ERROR_BAD_PAYLOAD, "the sign in answer holds no session")
        self._sid = sid

    def _sign_out(self) -> None:
        """End the session, if there is one; a failure to sign out is ignored."""
        sid, self._sid = self._sid, None
        auth = self._apis.get(API_AUTH)
        if sid is None or auth is None:
            return
        form = {
            "api": API_AUTH,
            "version": str(AUTH_VERSION),
            "method": "logout",
            "session": SESSION_NAME,
            "_sid": sid,
        }
        try:
            self._post(auth[0], form)
        except (CollectorError, _DsmError):
            return

    # -- transport ----------------------------------------------------------------------------

    def _post(self, path: str, form: Mapping[str, str]) -> JsonValue:
        """POST ``form`` to ``/webapi/<path>`` and return ``data`` of a successful answer.

        Raises :class:`_DsmError` for ``success`` false and :class:`CollectorError` (fixed texts)
        for every transport, status and JSON failure.
        """
        url = f"{self._base_url}{WEBAPI_PREFIX}{path}"
        try:
            with self._client.stream("POST", url, data=dict(form)) as response:
                _check_status(response)
                body = read_limited(response)
        except httpx.TimeoutException:
            raise CollectorError(ERROR_TIMEOUT, "the NAS did not answer in time") from None
        except httpx.HTTPError as error:
            raise _transport_error(error) from None
        self._bytes += len(body)
        try:
            parsed: JsonValue = json.loads(body)
        except ValueError:
            raise CollectorError(ERROR_BAD_JSON, "the response is not valid JSON") from None
        if not isinstance(parsed, dict) or not isinstance(parsed.get("success"), bool):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a DSM answer")
        if parsed["success"] is not True:
            detail = parsed.get("error")
            code = detail.get("code") if isinstance(detail, dict) else None
            raise _DsmError(code if isinstance(code, int) and not isinstance(code, bool) else 0)
        return parsed.get("data")

    def _failure(self, error: CollectorError) -> FetchResult:
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(
            error.error_class, str(error), status=status, bytes_fetched=self._bytes
        )


def _safe_path(path: str) -> bool:
    """A path of the API list: a plain file name below ``/webapi`` such as ``entry.cgi``."""
    return (
        0 < len(path) <= 64
        and all(char.isalnum() or char in "._-/" for char in path)
        and (".." not in path and not path.startswith("/"))
    )
