"""A local HTTPS server and throwaway certificates for the TLS tests (P7-T3).

Everything is made at test time with the ``cryptography`` library and lives in a temporary folder
that pytest removes: no key and no certificate is committed. The server counts the bytes that
reach it after the handshake, so a test can show that a refused connection carried none.
"""

import datetime
import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_ONE_DAY = datetime.timedelta(days=1)
_MAX_BODY = 1 << 20  # the server never waits for more than this many body bytes


@dataclass(frozen=True, slots=True)
class Pki:
    """A CA and a server certificate for 127.0.0.1, all as files in ``folder``."""

    ca_pem: Path
    cert_pem: Path
    key_pem: Path
    server_der: bytes


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca(folder: Path, name: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate, Path]:
    """A self-signed CA; its certificate is written to ``<folder>/<name>.pem``."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(name))
        .issuer_name(_name(name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _ONE_DAY)
        .not_valid_after(now + _ONE_DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = folder / f"{name}.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, path


def make_pki(folder: Path, name: str = "test-ca") -> Pki:
    """A CA and a server certificate signed by it, valid for 127.0.0.1 and localhost."""
    folder.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert, ca_path = make_ca(folder, name)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _ONE_DAY)
        .not_valid_after(now + _ONE_DAY)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = folder / f"{name}-server.pem"
    key_path = folder / f"{name}-server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return Pki(ca_path, cert_path, key_path, cert.public_bytes(serialization.Encoding.DER))


def _content_length(head: bytes) -> int:
    """The Content-Length of a request head, 0 when it has none or it is not a number."""
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                return max(0, min(int(value.strip()), _MAX_BODY))
            except ValueError:
                return 0
    return 0


class FakeTlsServer:
    """Answers one small JSON document per connection and records what it received."""

    def __init__(self, pki: Pki) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(pki.cert_pem, pki.key_pem)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._received = bytearray()
        self._finished = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self._listener.getsockname()[1]}"

    @property
    def received(self) -> bytes:
        """Every byte read from a client after the handshake."""
        with self._lock:
            return bytes(self._received)

    def wait_finished(self, count: int, timeout: float = 5.0) -> bool:
        """Wait until ``count`` connections have been handled."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._finished >= count:
                    return True
            time.sleep(0.02)
        return False

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            connection: socket.socket | None
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                connection = None
            except OSError:
                return
            if connection is None:
                continue
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(5)
            with self._context.wrap_socket(connection, server_side=True) as secured:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = secured.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if b"\r\n\r\n" in data:
                    # The client writes the head and the body separately. Reply only after the
                    # body is read: closing with unread bytes can reset the connection before
                    # the client has read the response.
                    head_end = data.index(b"\r\n\r\n") + 4
                    wanted = head_end + _content_length(data[:head_end])
                    while len(data) < wanted:
                        chunk = secured.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                with self._lock:
                    self._received.extend(data)
                if b"\r\n\r\n" in data:
                    body = b'{"ok": true}'
                    head = (
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                    )
                    secured.sendall(head.encode("ascii") + body)
        except (OSError, ssl.SSLError):
            return  # a refused handshake or a client that went away is expected
        finally:
            connection.close()
            with self._lock:
                self._finished += 1


@contextmanager
def running_server(pki: Pki) -> Iterator[FakeTlsServer]:
    server = FakeTlsServer(pki)
    try:
        yield server
    finally:
        server.close()
