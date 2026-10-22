"""Local receivers for the notification tests (P9-T4): a webhook receiver and a mail server.

Both run on 127.0.0.1 in a thread. Nothing here is a real service, a real address or a real
credential. The mail server speaks just enough SMTP (EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT,
DATA, QUIT) to take one message; it can offer or hide STARTTLS, refuse the login, answer with a
temporary failure, or start with TLS at once (implicit TLS).
"""

import base64
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import sqlalchemy as sa

from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.db.tables import change_events, change_items, snapshots

from .fake_tls import Pki

SOURCE_ID = 1
SOURCE_NAME = "lab-controller"


@dataclass(frozen=True, slots=True)
class Reply:
    """How the receiver answers one request: a status, an optional redirect and a delay."""

    status: int = 200
    location: str | None = None
    delay: float = 0.0


@dataclass(frozen=True, slots=True)
class Received:
    """One request the receiver took."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class FakeReceiver:
    """A webhook receiver. ``script`` lists the replies in order; after it, 200."""

    def __init__(self, script: list[Reply] | None = None) -> None:
        self.requests: list[Received] = []
        self._script = list(script or [])
        self._lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                headers = {key.lower(): value for key, value in self.headers.items()}
                with receiver._lock:
                    receiver.requests.append(Received("POST", self.path, headers, body))
                    reply = receiver._script.pop(0) if receiver._script else Reply()
                if reply.delay:
                    time.sleep(reply.delay)
                self.send_response(reply.status)
                if reply.location is not None:
                    self.send_header("Location", reply.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


@contextmanager
def running_receiver(script: list[Reply] | None = None) -> Iterator[FakeReceiver]:
    receiver = FakeReceiver(script)
    try:
        yield receiver
    finally:
        receiver.close()


class _Lines:
    """Reads CRLF lines from a socket."""

    def __init__(self, sock: Any) -> None:
        self._sock = sock
        self._buffer = b""

    def line(self) -> str | None:
        while b"\r\n" not in self._buffer:
            chunk = self._sock.recv(4096)
            if not chunk:
                return None
            self._buffer += chunk
        text, _, self._buffer = self._buffer.partition(b"\r\n")
        return text.decode("utf-8", "replace")


@dataclass(slots=True)
class FakeSmtpState:
    """What the mail server saw."""

    messages: list[str] = field(default_factory=list)
    logins: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


class FakeSmtp:
    """A mail server with TLS. ``pki`` gives its certificate."""

    def __init__(
        self,
        pki: Pki,
        *,
        implicit_tls: bool = False,
        offer_starttls: bool = True,
        login: tuple[str, str] | None = None,
        rcpt_reply: str = "250 ok",
    ) -> None:
        self.state = FakeSmtpState()
        self._implicit = implicit_tls
        self._offer = offer_starttls
        self._login = login
        self._rcpt_reply = rcpt_reply
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(pki.cert_pem, pki.key_pem)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._listener.getsockname()[1])

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)

    def wait_for(self, condition: Callable[[FakeSmtpState], bool], timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition(self.state):
                return True
            time.sleep(0.02)
        return False

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection: Any) -> None:
        try:
            connection.settimeout(5)
            sock = connection
            if self._implicit:
                sock = self._context.wrap_socket(connection, server_side=True)
            self._talk(sock, secured=self._implicit)
        except (OSError, ssl.SSLError):
            return
        finally:
            connection.close()

    def _talk(self, sock: Any, *, secured: bool) -> None:
        lines = _Lines(sock)
        sock.sendall(b"220 fake ESMTP\r\n")
        while True:
            text = lines.line()
            if text is None:
                return
            verb = text.split(" ", 1)[0].upper()
            self.state.commands.append(verb)
            if verb == "EHLO":
                extra = ["250-fake"]
                if self._offer and not secured:
                    extra.append("250-STARTTLS")
                if self._login is not None and secured:
                    extra.append("250-AUTH PLAIN")
                sock.sendall(("\r\n".join([*extra, "250 8BITMIME"]) + "\r\n").encode())
            elif verb == "STARTTLS":
                if not self._offer:
                    sock.sendall(b"502 not offered\r\n")
                    continue
                sock.sendall(b"220 go ahead\r\n")
                sock = self._context.wrap_socket(sock, server_side=True)
                lines = _Lines(sock)
                secured = True
            elif verb == "AUTH":
                self._auth(sock, text)
            elif verb == "MAIL":
                sock.sendall(b"250 ok\r\n")
            elif verb == "RCPT":
                sock.sendall((self._rcpt_reply + "\r\n").encode())
            elif verb == "DATA":
                sock.sendall(b"354 end with a dot\r\n")
                body: list[str] = []
                while True:
                    row = lines.line()
                    if row is None:
                        return
                    if row == ".":
                        break
                    body.append(row[1:] if row.startswith("..") else row)
                self.state.messages.append("\n".join(body))
                sock.sendall(b"250 queued\r\n")
            elif verb == "QUIT":
                sock.sendall(b"221 bye\r\n")
                return
            else:
                sock.sendall(b"250 ok\r\n")

    def _auth(self, sock: Any, text: str) -> None:
        parts = text.split(" ")
        try:
            decoded = base64.b64decode(parts[2]).split(b"\x00")
            given = (decoded[1].decode(), decoded[2].decode())
        except (IndexError, ValueError):
            sock.sendall(b"501 bad\r\n")
            return
        if self._login is not None and given == self._login:
            self.state.logins.append(given[0])
            sock.sendall(b"235 welcome\r\n")
        else:
            sock.sendall(b"535 no\r\n")


@contextmanager
def running_smtp(pki: Pki, **options: Any) -> Iterator[FakeSmtp]:
    server = FakeSmtp(pki, **options)
    try:
        yield server
    finally:
        server.close()


def trusting_context(pki: Pki) -> ssl.SSLContext:
    """A client context that trusts only the test CA (host names are checked)."""
    context = ssl.create_default_context(cafile=str(pki.ca_pem))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def make_store(folder: Path) -> Database:
    """A migrated database with one source (id 1) and nothing else."""
    database = Database(database_path(folder))
    upgrade_to_head(database)
    with database.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (?, ?, 'push')", (SOURCE_ID, SOURCE_NAME)
        )
    return database


def add_event(
    database: Database,
    *,
    severity: str = "high",
    source_id: int = SOURCE_ID,
    items: list[dict[str, str | None]] | None = None,
    summary: str | None = None,
) -> int:
    """Store a snapshot, a change event and its items; returns the event id.

    Each item is a dict with the keys of ``change_items`` it should set (``path``, ``before_value``,
    ``after_value``, ``object_name_at_time``, ``resource``...).
    """
    rows = items if items is not None else [{"path": "name"}]
    text = summary or f"{len(rows)} changes in 1 resource type, highest severity {severity}"
    with database.write() as connection:
        snapshot_id = int(
            connection.execute(
                sa.insert(snapshots)
                .values(
                    source_id=source_id,
                    taken_at="2026-10-22T08:00:00Z",
                    manifest_hash="h",
                    manifest_zstd=b"",
                    normaliser_version=1,
                )
                .returning(snapshots.c.id)
            ).scalar_one()
        )
        event_id = int(
            connection.execute(
                sa.insert(change_events)
                .values(
                    source_id=source_id,
                    snapshot_id=snapshot_id,
                    window_start="2026-10-22T07:00:00Z",
                    window_end="2026-10-22T08:00:00Z",
                    max_severity=severity,
                    item_count=len(rows),
                    summary=text,
                    rule_pack_version="pack-t1",
                    created_at="2026-10-22T08:00:00Z",
                )
                .returning(change_events.c.id)
            ).scalar_one()
        )
        for row in rows:
            connection.execute(
                sa.insert(change_items).values(
                    event_id=event_id,
                    resource=row.get("resource", "networks"),
                    change_kind="changed",
                    field_class="config",
                    severity=severity,
                    path=row.get("path", "name"),
                    before_value=row.get("before_value"),
                    after_value=row.get("after_value"),
                    object_name_at_time=row.get("object_name_at_time"),
                )
            )
    return event_id
