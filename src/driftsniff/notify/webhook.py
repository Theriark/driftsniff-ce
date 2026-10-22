"""The webhook sender (P9-T4, docs/notifications.md).

The body is the JSON object of :class:`~driftsniff.notify.message.NotificationMessage`. It is
signed so a receiver can tell that driftsniff sent it and that it was not changed or replayed
later: the signature is the hex HMAC-SHA-256, with the webhook key, of the timestamp, a full stop
and the body bytes. Two request fields carry it:

* ``X-Driftsniff-Timestamp``: the time of sending, whole seconds since 1970 (covered by the
  signature, so it cannot be moved);
* ``X-Driftsniff-Signature``: the hex digest.

:func:`verify` is the check a receiver makes (docs/notifications.md shows it for other languages).

The request never follows a redirect (a redirect is a failure, class ``redirect``), connects to the
address that :func:`~driftsniff.notify.targets.check_target` approved, reads no response body (only
the status), and puts nothing of the URL into an error or a log.
"""

import hashlib
import hmac
import json
import logging
import ssl
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

import httpcore
import httpx

from driftsniff.collectors.resolve import Resolver
from driftsniff.collectors.tls import MODE_VERIFY, TlsSettings, make_ssl_context
from driftsniff.notify.message import NotificationMessage
from driftsniff.notify.targets import CheckedTarget, TargetRefusedError, check_target

# httpx logs every request line at INFO, the URL included, and a webhook URL may carry a token.
logging.getLogger("httpx").setLevel(logging.WARNING)

SIGNATURE_HEADER: Final = "X-Driftsniff-Signature"
TIMESTAMP_HEADER: Final = "X-Driftsniff-Timestamp"
USER_AGENT: Final = "driftsniff-notifier"
DEFAULT_TIMEOUT_SECONDS: Final = 10.0
DEFAULT_TOLERANCE_SECONDS: Final = 300

ERROR_TIMEOUT: Final = "timeout"
ERROR_CONNECTION: Final = "connection"
ERROR_TLS: Final = "tls_error"
ERROR_REDIRECT: Final = "redirect"
ERROR_REJECTED: Final = "rejected"
ERROR_SERVER: Final = "server_error"
ERROR_UNEXPECTED: Final = "unexpected"


@dataclass(frozen=True, slots=True)
class SendResult:
    """The outcome of one attempt. ``retry`` says whether another attempt may succeed."""

    ok: bool
    error_class: str | None = None
    http_status: int | None = None
    retry: bool = False


def encode_body(message: NotificationMessage) -> bytes:
    """The JSON body: compact, sorted keys, UTF-8."""
    return json.dumps(
        message.as_dict(), separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def sign(key: bytes, timestamp: str, body: bytes) -> str:
    """The signature (hex) of a body sent at ``timestamp``."""
    return hmac.new(key, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


def verify(
    key: bytes,
    timestamp: str,
    body: bytes,
    signature: str,
    *,
    now: float,
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
) -> bool:
    """What a receiver checks: the timestamp is recent and the signature matches (constant time)."""
    if not (timestamp.isascii() and timestamp.isdigit()):
        return False
    if abs(now - int(timestamp)) > tolerance:
        return False
    return hmac.compare_digest(sign(key, timestamp, body), signature)


class _AddressBackend(httpcore.NetworkBackend):
    """The standard backend, but every TCP connection goes to the address that was approved."""

    def __init__(self, address: str) -> None:
        self._address = address
        self._inner = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        return self._inner.connect_tcp(
            self._address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("unix sockets are not used")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class _ApprovedAddressTransport(httpx.HTTPTransport):
    """An httpx transport that connects only to the approved address (no second DNS lookup)."""

    def __init__(self, target: CheckedTarget, context: ssl.SSLContext) -> None:
        super().__init__(verify=context, trust_env=False)
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=context,
            max_connections=1,
            max_keepalive_connections=0,
            network_backend=_AddressBackend(target.address),
        )


def _classify(error: Exception) -> SendResult:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            # A wrong certificate does not get better by asking again a second later.
            return SendResult(False, ERROR_TLS)
        current = current.__cause__ or current.__context__
    if isinstance(error, httpx.TimeoutException):
        return SendResult(False, ERROR_TIMEOUT, retry=True)
    if isinstance(error, httpx.TransportError):
        return SendResult(False, ERROR_CONNECTION, retry=True)
    return SendResult(False, ERROR_UNEXPECTED)


def send_webhook(
    url: str,
    message: NotificationMessage,
    key: bytes,
    *,
    resolver: Resolver,
    now: Callable[[], float],
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> SendResult:
    """Post one message and say what happened. Never raises for a failed delivery.

    The target is resolved and checked now; a blocked one gives class ``blocked_address`` and
    nothing is sent. Connection errors, timeouts and answers 5xx and 429 are retryable; a redirect,
    another 4xx and a TLS error are not.
    """
    host = urlsplit(url).hostname or ""
    try:
        target = check_target(host, resolver)
    except TargetRefusedError as refused:
        return SendResult(False, refused.error_class)
    context = ssl_context or make_ssl_context(TlsSettings(MODE_VERIFY))
    body = encode_body(message)
    timestamp = str(int(now()))
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        TIMESTAMP_HEADER: timestamp,
        SIGNATURE_HEADER: sign(key, timestamp, body),
    }
    try:
        with (
            httpx.Client(
                transport=_ApprovedAddressTransport(target, context),
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream("POST", url, content=body, headers=headers) as response,
        ):
            status = response.status_code
    except Exception as error:
        return _classify(error)
    if 200 <= status < 300:
        return SendResult(True, http_status=status)
    if 300 <= status < 400:
        return SendResult(False, ERROR_REDIRECT, status)
    if status >= 500 or status == 429:
        return SendResult(False, ERROR_SERVER, status, retry=True)
    return SendResult(False, ERROR_REJECTED, status)
