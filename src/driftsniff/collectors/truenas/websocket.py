"""A minimal WebSocket client (RFC 6455) on top of the shared HTTP client.

The opening handshake is an ordinary ``GET`` with ``Upgrade: websocket`` sent through the client of
``collectors/base.py``, so the TLS mode of the source, the certificate pin checked inside the TLS
handshake, the pinned address and the refusal of redirects all apply unchanged. After the ``101``
answer the connection that httpcore hands over (the ``network_stream`` extension) carries the
frames.

Only what a JSON-RPC client needs is done: text messages, fragmented messages, ping (answered with
pong), pong and close. No extension is offered, so a frame with a reserved bit set, a masked frame
from the server or a binary message breaks the protocol and fails the call. A message larger than
the body limit fails before its payload is read. Every error text is fixed: no frame, URL or
credential is ever put into one.
"""

import base64
import hashlib
import os
import struct
from typing import Final

import httpcore
import httpx

from driftsniff.collectors.base import (
    ERROR_BAD_PAYLOAD,
    ERROR_BODY_TOO_LARGE,
    ERROR_CONNECTION,
    ERROR_HTTP,
    ERROR_REDIRECT,
    ERROR_TIMEOUT,
    MAX_BODY_BYTES,
    CollectorError,
)
from driftsniff.collectors.tls import ERROR_TLS, ERROR_TLS_PIN, classify_failure

ACCEPT_GUID: Final = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
READ_CHUNK: Final = 65536
MAX_CONTROL_PAYLOAD: Final = 125

OP_CONTINUATION: Final = 0x0
OP_TEXT: Final = 0x1
OP_CLOSE: Final = 0x8
OP_PING: Final = 0x9
OP_PONG: Final = 0xA

_TIMEOUT_TEXT: Final = "the controller did not answer in time"
_CLOSED_TEXT: Final = "the controller closed the connection"
_PROTOCOL_TEXT: Final = "the controller broke the WebSocket protocol"
_TLS_TEXT: Final = {
    ERROR_TLS: "the TLS certificate of the controller was not accepted",
    ERROR_TLS_PIN: "the certificate of the controller is not the pinned one; nothing was sent",
}


def accept_value(key: str) -> str:
    """The ``Sec-WebSocket-Accept`` a server must answer for ``key``."""
    digest = hashlib.sha1((key + ACCEPT_GUID).encode("ascii")).digest()  # noqa: S324 - RFC 6455
    return base64.b64encode(digest).decode("ascii")


def mask(data: bytes, key: bytes) -> bytes:
    """``data`` XOR the four byte ``key`` repeated (masking and unmasking are the same)."""
    if not data:
        return b""
    repeated = (key * (len(data) // 4 + 1))[: len(data)]
    value = int.from_bytes(data, "big") ^ int.from_bytes(repeated, "big")
    return value.to_bytes(len(data), "big")


def encode_frame(opcode: int, payload: bytes, *, mask_key: bytes | None = None) -> bytes:
    """One final frame; masked with ``mask_key`` (a client frame) or unmasked (a server frame)."""
    length = len(payload)
    mask_bit = 0x80 if mask_key is not None else 0
    if length < 126:
        header = struct.pack("!BB", 0x80 | opcode, mask_bit | length)
    elif length < 1 << 16:
        header = struct.pack("!BBH", 0x80 | opcode, mask_bit | 126, length)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, mask_bit | 127, length)
    if mask_key is None:
        return header + payload
    return header + mask_key + mask(payload, mask_key)


def _transport_error(error: Exception) -> CollectorError:
    if isinstance(error, httpx.TimeoutException | httpcore.TimeoutException):
        return CollectorError(ERROR_TIMEOUT, _TIMEOUT_TEXT)
    tls_class = classify_failure(error)
    if tls_class is not None:
        return CollectorError(tls_class, _TLS_TEXT[tls_class])
    return CollectorError(ERROR_CONNECTION, "the controller could not be reached")


class WebSocket:
    """One open WebSocket connection. Not thread safe; one run uses it at a time."""

    def __init__(self, response: httpx.Response, stream: httpcore.NetworkStream, timeout: float):
        self._response = response
        self._stream = stream
        self._timeout = timeout
        self._buffer = bytearray()
        self._closed = False

    @classmethod
    def connect(cls, client: httpx.Client, url: str, timeout: float) -> "WebSocket":
        """Open ``url`` (http or https) as a WebSocket through ``client``.

        Raises :class:`CollectorError`: a redirect is ``redirect_refused``, any status other than
        101 is ``http_error`` with that status, a wrong accept value breaks the protocol.
        """
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = client.build_request(
            "GET",
            url,
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": key,
            },
        )
        try:
            response = client.send(request, stream=True)
        except httpx.HTTPError as error:
            raise _transport_error(error) from None
        status = response.status_code
        stream = response.extensions.get("network_stream")
        if status != 101 or stream is None:
            response.close()
            if 300 <= status < 400:
                raise CollectorError(
                    ERROR_REDIRECT,
                    "the controller answered with a redirect, which is never followed",
                    status=str(status),
                )
            raise CollectorError(
                ERROR_HTTP, f"the controller answered with HTTP {status}", status=str(status)
            )
        if response.headers.get("sec-websocket-accept") != accept_value(key):
            response.close()
            raise CollectorError(ERROR_BAD_PAYLOAD, _PROTOCOL_TEXT)
        return cls(response, stream, timeout)

    # -- sending ----------------------------------------------------------------------------

    def send_text(self, text: str) -> None:
        """Send one text message."""
        self._write(encode_frame(OP_TEXT, text.encode("utf-8"), mask_key=os.urandom(4)))

    def _write(self, data: bytes) -> None:
        if self._closed:
            raise CollectorError(ERROR_CONNECTION, _CLOSED_TEXT)
        try:
            self._stream.write(data, timeout=self._timeout)
        except (httpcore.NetworkError, httpcore.TimeoutException, OSError) as error:
            raise _transport_error(error) from None

    # -- receiving --------------------------------------------------------------------------

    def receive_text(self, max_bytes: int = MAX_BODY_BYTES) -> str:
        """The next text message; pings are answered and pongs skipped on the way."""
        parts: list[bytes] = []
        total = 0
        while True:
            first, second = self._read_exact(2)
            fin = bool(first & 0x80)
            opcode = first & 0x0F
            if first & 0x70 or second & 0x80:
                raise CollectorError(ERROR_BAD_PAYLOAD, _PROTOCOL_TEXT)
            length = second & 0x7F
            if length == 126:
                (length,) = struct.unpack("!H", self._read_exact(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", self._read_exact(8))
            if opcode >= OP_CLOSE:
                if not fin or length > MAX_CONTROL_PAYLOAD:
                    raise CollectorError(ERROR_BAD_PAYLOAD, _PROTOCOL_TEXT)
                payload = self._read_exact(length)
                if opcode == OP_CLOSE:
                    self._closed = True
                    raise CollectorError(ERROR_CONNECTION, _CLOSED_TEXT)
                if opcode == OP_PING:
                    self._write(encode_frame(OP_PONG, payload, mask_key=os.urandom(4)))
                elif opcode != OP_PONG:
                    raise CollectorError(ERROR_BAD_PAYLOAD, _PROTOCOL_TEXT)
                continue
            # A message starts with a text frame and goes on with continuation frames only.
            expected = OP_CONTINUATION if parts else OP_TEXT
            if opcode != expected:
                raise CollectorError(ERROR_BAD_PAYLOAD, _PROTOCOL_TEXT)
            total += length
            if total > max_bytes:
                raise CollectorError(
                    ERROR_BODY_TOO_LARGE, f"the response is larger than {max_bytes} bytes"
                )
            parts.append(self._read_exact(length))
            if fin:
                try:
                    return b"".join(parts).decode("utf-8")
                except UnicodeDecodeError:
                    raise CollectorError(ERROR_BAD_PAYLOAD, _PROTOCOL_TEXT) from None

    def _read_exact(self, count: int) -> bytes:
        while len(self._buffer) < count:
            if self._closed:
                raise CollectorError(ERROR_CONNECTION, _CLOSED_TEXT)
            try:
                chunk = self._stream.read(READ_CHUNK, timeout=self._timeout)
            except (httpcore.NetworkError, httpcore.TimeoutException, OSError) as error:
                raise _transport_error(error) from None
            if not chunk:
                self._closed = True
                raise CollectorError(ERROR_CONNECTION, _CLOSED_TEXT)
            self._buffer += chunk
        data = bytes(self._buffer[:count])
        del self._buffer[:count]
        return data

    def close(self) -> None:
        """Send a close frame when the connection is still open, then drop it."""
        if not self._closed:
            self._closed = True
            try:
                self._stream.write(
                    encode_frame(OP_CLOSE, struct.pack("!H", 1000), mask_key=os.urandom(4)),
                    timeout=1.0,
                )
            except (httpcore.NetworkError, httpcore.TimeoutException, OSError):
                pass
        self._response.close()
