"""TLS modes shared by the collectors (P7-T3).

A source stores one of four modes in its options (docs/tls.md has the user view):

* ``verify`` (the default): the system trust store plus the certifi bundle, host name checked;
* ``ca_file``: only the CA bundle ``<data dir>/ca/<tls_ca_file>``, PEM, at most 64 KB, host name
  checked. The option holds a file **name**, never a path, so it cannot point outside the folder;
* ``pinned``: the SHA-256 of the server certificate in DER form (``tls_pin``, 64 hex characters)
  decides. The comparison runs **inside the TLS handshake, before any request byte is sent**: the
  HTTP pool gets a network backend whose ``start_tls`` step reads the peer certificate and closes
  the connection on a mismatch (:class:`PinMismatch`). There is no check after the response, so the
  API key never reaches a server whose certificate is not the pinned one. Chain and host name are
  not checked in this mode; the pin is the trust decision;
* ``insecure``: nothing is verified. The service needs the confirmation text
  :data:`INSECURE_CONFIRMATION`, writes the audit event and stores the flag ``insecure``.

This module does not import the collector base (the base imports it), logs nothing, and every
message is fixed: no path, fingerprint or certificate text is put into an error.
"""

import hashlib
import hmac
import re
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import certifi
import httpcore
import httpx

from driftsniff.config import DEFAULT_DATA_DIR

MODE_VERIFY: Final = "verify"
MODE_CA_FILE: Final = "ca_file"
MODE_PINNED: Final = "pinned"
MODE_INSECURE: Final = "insecure"
MODES: Final = (MODE_VERIFY, MODE_CA_FILE, MODE_PINNED, MODE_INSECURE)

OPTION_TLS_MODE: Final = "tls_mode"
OPTION_TLS_CA_FILE: Final = "tls_ca_file"
OPTION_TLS_PIN: Final = "tls_pin"
OPTION_INSECURE: Final = "insecure"
TLS_OPTIONS: Final = (OPTION_TLS_MODE, OPTION_TLS_CA_FILE, OPTION_TLS_PIN, OPTION_INSECURE)

INSECURE_CONFIRMATION: Final = "I understand the risk"
CA_FOLDER: Final = "ca"
MAX_CA_BYTES: Final = 64 * 1024

ERROR_TLS: Final = "tls_error"
ERROR_TLS_PIN: Final = "tls_pin_mismatch"

_PIN = re.compile(r"[0-9A-Fa-f]{64}")
_CA_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_PEM_LABEL = re.compile(r"-----BEGIN ([A-Z0-9 ]{1,40})-----")


class TlsConfigError(ValueError):
    """The TLS settings of a source are not usable. The message is fixed text."""


class PinMismatch(httpcore.ConnectError):
    """The server certificate is not the pinned one. The connection was closed before any request
    byte was sent. Subclasses ``httpcore.ConnectError`` so that httpx reports a connection error.
    """

    def __init__(self) -> None:
        super().__init__("the server certificate does not match the pinned fingerprint")


@dataclass(frozen=True, slots=True)
class TlsSettings:
    """The TLS mode of one source and the value that mode needs."""

    mode: str = MODE_VERIFY
    ca_file: str | None = None
    pin: str | None = None


def normalize_pin(text: str) -> str:
    """The pin as 64 lower case hex characters; anything else raises :class:`TlsConfigError`."""
    cleaned = text.strip()
    if _PIN.fullmatch(cleaned) is None:
        raise TlsConfigError("a pin is the SHA-256 of the certificate as 64 hex characters")
    return cleaned.lower()


def check_options(options: Mapping[str, object]) -> TlsSettings:
    """Validate the TLS options of a source and return them as settings.

    The types are checked by the caller (the source service). Here: the mode is one of the four,
    each mode has exactly the value it needs and no other, the CA file is a plain file name, and
    the ``insecure`` flag, which the service sets itself, agrees with the mode. TLS options mean
    nothing on a plain http address, so that combination is refused.
    """
    mode = options.get(OPTION_TLS_MODE, MODE_VERIFY)
    if mode not in MODES:
        raise TlsConfigError("the TLS mode must be verify, ca_file, pinned or insecure")
    ca_file = options.get(OPTION_TLS_CA_FILE)
    pin = options.get(OPTION_TLS_PIN)
    if (ca_file is not None) != (mode == MODE_CA_FILE):
        raise TlsConfigError("a CA file is given exactly when the TLS mode is ca_file")
    if (pin is not None) != (mode == MODE_PINNED):
        raise TlsConfigError("a pin is given exactly when the TLS mode is pinned")
    if bool(options.get(OPTION_INSECURE, False)) != (mode == MODE_INSECURE):
        raise TlsConfigError("the insecure flag is set exactly when the TLS mode is insecure")
    if mode != MODE_VERIFY and options.get("allow_plain_http") is True:
        raise TlsConfigError("a TLS mode other than verify has no meaning on a plain http address")
    if ca_file is not None and (
        not isinstance(ca_file, str) or _CA_NAME.fullmatch(ca_file) is None
    ):
        raise TlsConfigError("the CA file is a plain file name in the CA folder")
    if pin is not None and not isinstance(pin, str):
        raise TlsConfigError("a pin is the SHA-256 of the certificate as 64 hex characters")
    return TlsSettings(
        mode=str(mode),
        ca_file=ca_file if isinstance(ca_file, str) else None,
        pin=normalize_pin(pin) if isinstance(pin, str) else None,
    )


def settings_from_options(options: Mapping[str, object]) -> TlsSettings:
    """The settings a stored source has; a source without TLS options uses ``verify``."""
    return check_options(options)


def load_ca_bundle(name: str, data_dir: Path | str = DEFAULT_DATA_DIR) -> str:
    """The text of the CA bundle ``<data dir>/ca/<name>``, after checking it.

    Refused: a name that is not a plain file name, a missing file, a symbolic link, a file over
    64 KB, a file that is not ASCII PEM, any block that is not a ``CERTIFICATE`` (a private key in
    the bundle is refused), and a bundle OpenSSL cannot load.
    """
    if _CA_NAME.fullmatch(name) is None:
        raise TlsConfigError("the CA file is a plain file name in the CA folder")
    folder = Path(data_dir) / CA_FOLDER
    path = folder / name
    try:
        if path.is_symlink() or not path.is_file():
            raise TlsConfigError("the CA file does not exist in the CA folder")
        with path.open("rb") as handle:
            data = handle.read(MAX_CA_BYTES + 1)
    except OSError:
        raise TlsConfigError("the CA file cannot be read") from None
    if len(data) > MAX_CA_BYTES:
        raise TlsConfigError("the CA file is larger than 64 KB")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise TlsConfigError("the CA file is not PEM text") from None
    labels = _PEM_LABEL.findall(text)
    if not labels or any(label != "CERTIFICATE" for label in labels):
        raise TlsConfigError("the CA file holds anything other than PEM certificates")
    return text


def make_ssl_context(
    settings: TlsSettings, data_dir: Path | str = DEFAULT_DATA_DIR
) -> ssl.SSLContext:
    """The ``ssl`` context for the mode. TLS 1.2 is the lowest version in every mode."""
    if settings.mode == MODE_VERIFY:
        context = ssl.create_default_context()
        context.load_verify_locations(cafile=certifi.where())
    elif settings.mode == MODE_CA_FILE:
        if settings.ca_file is None:
            raise TlsConfigError("a CA file is given exactly when the TLS mode is ca_file")
        bundle = load_ca_bundle(settings.ca_file, data_dir)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        try:
            context.load_verify_locations(cadata=bundle)
        except ssl.SSLError:
            raise TlsConfigError("the CA file holds no usable certificate") from None
    elif settings.mode in (MODE_PINNED, MODE_INSECURE):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        raise TlsConfigError("the TLS mode must be verify, ca_file, pinned or insecure")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


# -- pinning in the handshake ------------------------------------------------------------------


class _PinningStream(httpcore.NetworkStream):
    """A network stream whose ``start_tls`` compares the peer certificate with the pin."""

    def __init__(self, inner: httpcore.NetworkStream, pin: bytes) -> None:
        self._inner = inner
        self._pin = pin

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, timeout)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, timeout)

    def close(self) -> None:
        self._inner.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        secured = self._inner.start_tls(ssl_context, server_hostname, timeout)
        ssl_object = secured.get_extra_info("ssl_object")
        # binary_form is positional: the raw SSL object of the socket takes no keyword.
        der = ssl_object.getpeercert(True) if ssl_object is not None else None
        digest = hashlib.sha256(der).digest() if der else b""
        # Always compare, so the time taken does not depend on how many bytes matched.
        matches = hmac.compare_digest(digest, self._pin)
        if not der or not matches:
            secured.close()
            raise PinMismatch
        return secured

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class PinningBackend(httpcore.NetworkBackend):
    """The standard synchronous backend with every connection wrapped for the pin check."""

    def __init__(self, pin_hex: str, inner: httpcore.NetworkBackend | None = None) -> None:
        self._pin = bytes.fromhex(normalize_pin(pin_hex))
        self._inner = inner if inner is not None else httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        stream = self._inner.connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        return _PinningStream(stream, self._pin)

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        stream = self._inner.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        return _PinningStream(stream, self._pin)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class PinnedTransport(httpx.HTTPTransport):
    """An httpx transport whose connection pool uses :class:`PinningBackend`.

    Only ``https`` requests are served: on plain http there is no handshake to pin, so the request
    is refused before a connection is made.
    """

    def __init__(self, pin_hex: str) -> None:
        context = make_ssl_context(TlsSettings(MODE_PINNED, pin=normalize_pin(pin_hex)))
        super().__init__(verify=context, trust_env=False)
        limits = httpx.Limits()
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            network_backend=PinningBackend(pin_hex),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme != "https":
            raise httpx.UnsupportedProtocol("a pinned source is read over https only")
        return super().handle_request(request)


def build_transport(
    settings: TlsSettings, data_dir: Path | str = DEFAULT_DATA_DIR
) -> httpx.BaseTransport:
    """The httpx transport that enforces ``settings``."""
    if settings.mode == MODE_PINNED:
        if settings.pin is None:
            raise TlsConfigError("a pin is given exactly when the TLS mode is pinned")
        return PinnedTransport(settings.pin)
    return httpx.HTTPTransport(verify=make_ssl_context(settings, data_dir), trust_env=False)


def classify_failure(error: BaseException) -> str | None:
    """The error class of a failed HTTPS request when TLS caused it, else None.

    Walks the cause chain of an httpx error: a :class:`PinMismatch` is ``tls_pin_mismatch``, any
    other ``ssl`` error (certificate not trusted, wrong host name, protocol failure) is
    ``tls_error``.
    """
    seen: set[int] = set()
    current: BaseException | None = error
    found: str | None = None
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, PinMismatch):
            return ERROR_TLS_PIN
        if isinstance(current, ssl.SSLError):
            found = ERROR_TLS
        current = current.__cause__ or current.__context__
    return found
