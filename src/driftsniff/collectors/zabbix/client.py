"""The Zabbix API client: probe, token check and the ``*.get`` reads.

``ZabbixClient`` is a :class:`~driftsniff.collectors.base.Collector` for the JSON-RPC 2.0 API of
Zabbix 6.0 and later (docs/vendor-notes/zabbix.md, read on 2026-11-12; no lab Zabbix was used).

* The address is the frontend address, with the path the frontend is served under when there is
  one (``https://zabbix.example.invalid/zabbix``). The client posts to
  ``<address>/api_jsonrpc.php``; an address that already ends with ``/api_jsonrpc.php`` is used as
  it is.
* The credential is an API token (Zabbix 5.4 and later). It travels in exactly one place and never
  in a query string, a log line or an error text: from Zabbix 6.4 in the header
  ``Authorization: Bearer``, before 6.4 in the ``auth`` member of the request body, which is the
  only way 6.0 accepts it (the ``auth`` member was deprecated in 6.4 and removed in 7.2). This
  module logs nothing, and every error text is fixed or holds only numbers it parsed itself.
* ``probe()`` calls ``apiinfo.version`` without any credential (Zabbix refuses one there), refuses
  a version below 6.0 (``unsupported_version``), then checks the token with a one-row
  ``hostgroup.get``: any refusal there is ``unauthorized`` and stops the run.
* Every resource is one ``*.get`` (``resources.py``). Hosts and triggers are listed by id first
  (at most ``MAX_OBJECTS``, more fails the resource rather than storing part of it) and then read
  ``CHUNK_SIZE`` ids per request, so no single answer grows with the size of the installation.
* Coverage: a JSON-RPC error that names a permission is ``forbidden`` (status 403), an unknown
  method is ``not_available`` (404); both keep the previous state of the resource. Any other
  JSON-RPC error is ``api_error`` with its numeric code only; the server's text is never shown.

``probe()`` resolves the host name once, refuses a blocked answer and pins the first answer
(``collectors/resolve.py``); TLS modes come from ``collectors/tls.py``. Redirects are refused,
bodies are limited to 200 MB and requests to 30 seconds (``collectors/base.py``).
"""

import json
import re
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
from driftsniff.collectors.tls import AddressPin, TlsSettings
from driftsniff.collectors.zabbix.normalize import id_order, prepare_objects, usable_id
from driftsniff.collectors.zabbix.resources import (
    BEARER_FROM,
    ENDPOINT,
    MIN_VERSION,
    RESOURCE_BY_NAME,
    RESOURCES,
    Version,
    ZabbixResource,
)
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.addresses import validate_base_url

CONTENT_TYPE: Final = "application/json-rpc"
CHUNK_SIZE: Final = 500
MAX_OBJECTS: Final = 100_000

ERROR_NOT_AVAILABLE: Final = "not_available"
ERROR_FORBIDDEN: Final = "forbidden"
ERROR_UNAUTHORIZED: Final = "unauthorized"
ERROR_UNSUPPORTED_VERSION: Final = "unsupported_version"
ERROR_API_ERROR: Final = "api_error"
ERROR_TOO_MANY: Final = "too_many_objects"
ERROR_NO_API: Final = "no_api"
ERROR_NOT_PROBED: Final = "not_probed"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"

STATUS_FORBIDDEN: Final = "403"
STATUS_NOT_FOUND: Final = "404"
STATUS_UNAUTHORIZED: Final = "401"

CODE_METHOD_NOT_FOUND: Final = -32601
_VERSION: Final = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,4})(?:[a-z0-9.+-]{0,32})?")
_PERMISSION: Final = re.compile(r"permission", re.IGNORECASE)


class _RpcError(Exception):
    """A JSON-RPC error answer. Its code is shown; its texts are only matched, never shown."""

    def __init__(self, code: int, texts: str) -> None:
        super().__init__(code)
        self.code = code
        self.texts = texts


def api_url(base_url: str) -> str:
    """The JSON-RPC endpoint below a frontend address."""
    return base_url if base_url.endswith(ENDPOINT) else f"{base_url}{ENDPOINT}"


class ZabbixClient(Collector):
    """Reads Zabbix read only. One instance serves one run."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        allow_plain_http: bool = False,
        transport: httpx.BaseTransport | None = None,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
        resolver: Resolver | None = None,
        tls: TlsSettings | None = None,
        data_dir: Path | str = DEFAULT_DATA_DIR,
        chunk_size: int = CHUNK_SIZE,
        max_objects: int = MAX_OBJECTS,
    ) -> None:
        if not api_token or any(ord(char) < 0x21 or ord(char) > 0x7E for char in api_token):
            raise ValueError("the API token is blank or has characters a header cannot carry")
        self._base_url = validate_base_url(base_url, allow_plain_http=allow_plain_http)
        self._url = api_url(self._base_url)
        self._token = api_token
        self._resolver = resolver or system_resolver
        self._address = AddressPin()
        self._client = make_client(
            transport=transport,
            tls=tls,
            data_dir=data_dir,
            address=self._address if transport is None else None,
        )
        self._client.timeout = httpx.Timeout(request_timeout)
        self._chunk = chunk_size
        self._max = max_objects
        self._version: Version | None = None
        self._request_id = 0
        self._bytes = 0

    # -- the collector contract ---------------------------------------------------------------

    def probe(self) -> str | None:
        """Read the version without the token, then check the token. Returns the version."""
        self._version = None
        self._address.clear()
        self._address.set(pin_address(self._base_url, self._resolver))
        try:
            raw = self._call("apiinfo.version", [], version=None)
        except _RpcError:
            raise CollectorError(ERROR_NO_API, "the Zabbix API did not answer") from None
        except CollectorError as error:
            if error.status == STATUS_NOT_FOUND or error.error_class in (
                ERROR_BAD_JSON,
                ERROR_BAD_PAYLOAD,
            ):
                raise CollectorError(ERROR_NO_API, "the Zabbix API did not answer") from None
            raise
        match = _VERSION.fullmatch(raw.strip()) if isinstance(raw, str) else None
        if match is None:
            raise CollectorError(ERROR_NO_API, "the Zabbix API did not report its version")
        version = (int(match.group(1)), int(match.group(2)))
        if version < MIN_VERSION:
            raise CollectorError(
                ERROR_UNSUPPORTED_VERSION,
                f"Zabbix {version[0]}.{version[1]} is older than 6.0, the oldest version read",
            )
        try:
            self._call("hostgroup.get", {"output": ["groupid"], "limit": 1}, version=version)
        except _RpcError:
            raise CollectorError(
                ERROR_UNAUTHORIZED, "Zabbix refused the API token", status=STATUS_UNAUTHORIZED
            ) from None
        except CollectorError as error:
            if error.status in (STATUS_UNAUTHORIZED, STATUS_FORBIDDEN):
                raise CollectorError(
                    ERROR_UNAUTHORIZED, "Zabbix refused the API token", status=error.status
                ) from None
            raise
        self._version = version
        return match.group(0)

    def resources(self) -> Sequence[ResourceSpec]:
        """The resources the client reads, in reading order."""
        return [ResourceSpec(resource.name, resource.method) for resource in RESOURCES]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource; its objects are sorted by id."""
        if self._version is None:
            raise CollectorError(ERROR_NOT_PROBED, "the API token was not accepted")
        resource = RESOURCE_BY_NAME.get(spec.name)
        if resource is None:
            return FetchResult.failure(ERROR_UNKNOWN_RESOURCE, "the resource is not read here")
        self._bytes = 0
        try:
            raw = self._read(resource, self._version)
            objects = prepare_objects(resource.name, resource.key_field, raw)
        except _RpcError as error:
            return self._failure(self._api_error(error))
        except CollectorError as error:
            return self._failure(error)
        return FetchResult.success(objects, bytes_fetched=self._bytes)

    def close(self) -> None:
        """Close the HTTP client. An API token has no session to end."""
        self._client.close()

    # -- reading ------------------------------------------------------------------------------

    def _read(self, resource: ZabbixResource, version: Version) -> JsonValue:
        params = resource.params(version)
        if not resource.paged:
            return self._call(resource.method, params, version=version)
        listed = self._call(
            resource.method,
            {
                "output": [resource.key_field],
                "filter": params.get("filter", {}),
                "sortfield": resource.key_field,
                "limit": self._max + 1,
            },
            version=version,
        )
        ids = self._ids(listed, resource.key_field)
        if len(ids) > self._max:
            raise CollectorError(
                ERROR_TOO_MANY, f"Zabbix lists more than {self._max} objects of this resource"
            )
        objects: list[JsonValue] = []
        for start in range(0, len(ids), self._chunk):
            chunk: list[JsonValue] = list(ids[start : start + self._chunk])
            page = self._call(
                resource.method, {**params, resource.ids_param: chunk}, version=version
            )
            if not isinstance(page, list):
                raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
            objects.extend(page)
        return objects

    @staticmethod
    def _ids(listed: JsonValue, key_field: str) -> list[str]:
        if not isinstance(listed, list):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
        ids: list[str] = []
        for item in listed:
            key = item.get(key_field) if isinstance(item, dict) else None
            if not usable_id(key):
                raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
            ids.append(str(key))
        return sorted(set(ids), key=id_order)

    @staticmethod
    def _api_error(error: _RpcError) -> CollectorError:
        if _PERMISSION.search(error.texts):
            return CollectorError(
                ERROR_FORBIDDEN, "the API token may not read this resource", status=STATUS_FORBIDDEN
            )
        if error.code == CODE_METHOD_NOT_FOUND:
            return CollectorError(
                ERROR_NOT_AVAILABLE,
                "this resource is not available on this version",
                status=STATUS_NOT_FOUND,
            )
        return CollectorError(ERROR_API_ERROR, f"Zabbix refused the request with code {error.code}")

    # -- transport ----------------------------------------------------------------------------

    def _call(
        self,
        method: str,
        params: Mapping[str, JsonValue] | list[JsonValue],
        *,
        version: Version | None,
    ) -> JsonValue:
        """POST one JSON-RPC request and return its ``result``.

        ``version`` None sends no credential (``apiinfo.version``). Raises :class:`_RpcError` for
        an error answer and :class:`CollectorError` (fixed texts) for every other failure.
        """
        self._request_id += 1
        request: dict[str, JsonValue] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if isinstance(params, list) else dict(params),
            "id": self._request_id,
        }
        headers = {"Content-Type": CONTENT_TYPE}
        if version is not None and version >= BEARER_FROM:
            headers["Authorization"] = f"Bearer {self._token}"
        elif version is not None:
            request["auth"] = self._token
        body = json.dumps(request).encode("utf-8")
        try:
            with self._client.stream("POST", self._url, content=body, headers=headers) as response:
                _check_status(response)
                answer = read_limited(response)
        except httpx.TimeoutException:
            raise CollectorError(ERROR_TIMEOUT, "Zabbix did not answer in time") from None
        except httpx.HTTPError as error:
            raise _transport_error(error) from None
        self._bytes += len(answer)
        try:
            parsed: JsonValue = json.loads(answer)
        except ValueError:
            raise CollectorError(ERROR_BAD_JSON, "the response is not valid JSON") from None
        if not isinstance(parsed, dict) or parsed.get("jsonrpc") != "2.0":
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a JSON-RPC answer")
        failure = parsed.get("error")
        if isinstance(failure, dict):
            code = failure.get("code")
            texts = f"{failure.get('message', '')} {failure.get('data', '')}"
            raise _RpcError(
                code if isinstance(code, int) and not isinstance(code, bool) else 0, texts
            )
        if parsed.get("id") != self._request_id or "result" not in parsed:
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a JSON-RPC answer")
        return parsed["result"]

    def _failure(self, error: CollectorError) -> FetchResult:
        status = error.status if error.status else STATUS_ERROR
        return FetchResult.failure(
            error.error_class, str(error), status=status, bytes_fetched=self._bytes
        )
