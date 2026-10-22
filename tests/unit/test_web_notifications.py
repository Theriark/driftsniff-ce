"""The admin routes of the notification channel (P9-T4): roles, CSRF, input, secrets in answers.

The tests drive the real application with a migrated database and a cheap argon2 setting. The
webhook of the test button is a tiny receiver on 127.0.0.1 in this file.
"""

import json
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from fastapi.testclient import TestClient

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.main import create_app
from driftsniff.notify.deliveries import NotificationService
from driftsniff.secrets.keys import WEBHOOK_LABEL, MasterKey
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher

ORIGIN = "http://testserver"
CORRECT = "CANARY-correct horse battery"  # noqa: S105
MASTER = MasterKey(bytes(range(32)))
URL_SECRET = "CANARY-route-hook-token-0001"  # noqa: S105
MAIL_SECRET = "CANARY-route-mail-password-0002"  # noqa: S105


@dataclass(frozen=True, slots=True)
class Session:
    cookie: str
    csrf: str

    def headers(self, *, csrf: bool = True) -> dict[str, str]:
        headers = {"Cookie": f"{SESSION_COOKIE}={self.cookie}", "Origin": ORIGIN}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        return headers


class Receiver:
    """Answers 204 to every POST and keeps the paths it was called with."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                outer.paths.append(self.path)
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                return

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}/hook/{URL_SECRET}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


@pytest.fixture
def receiver() -> Iterator[Receiver]:
    running = Receiver()
    try:
        yield running
    finally:
        running.close()


@pytest.fixture
def auth(store: Database) -> AuthService:
    service = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    service.create_user("admin", CORRECT, "admin")
    service.create_user("ops", CORRECT, "operator")
    service.create_user("viewer", CORRECT, "viewer")
    return service


@pytest.fixture
def notifications(store: Database) -> Iterator[NotificationService]:
    service = NotificationService(
        store, MASTER, base_url=ORIGIN, resolver=lambda _host: ["127.0.0.1"], sleep=lambda _s: None
    )
    yield service
    service.close()


@pytest.fixture
def client(auth: AuthService, notifications: NotificationService) -> Iterator[TestClient]:
    app = create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}), auth=auth, notifications=notifications
    )
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as test_client:
        yield test_client


def open_session(client: TestClient, auth: AuthService, username: str) -> Session:
    response = client.post("/login", data={"username": username, "password": CORRECT})
    assert response.status_code == 303
    match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
    assert match is not None
    client.cookies.clear()
    principal = auth.authenticate(match.group(1))
    assert principal is not None
    return Session(match.group(1), principal.csrf_token)


@pytest.fixture
def admin(client: TestClient, auth: AuthService) -> Session:
    return open_session(client, auth, "admin")


def put_webhook(client: TestClient, session: Session, url: str, **fields: Any) -> Any:
    return client.put(
        "/notifications/channel",
        headers=session.headers(),
        json={"type": "webhook", "url": url, **fields},
    )


def current(client: TestClient, session: Session) -> Any:
    return client.get("/notifications/channel", headers=session.headers()).json()


def test_no_channel_is_null(client: TestClient, admin: Session) -> None:
    response = client.get("/notifications/channel", headers=admin.headers())
    assert response.status_code == 200
    assert response.json() == {"channel": None}


def test_an_admin_sets_a_webhook_and_the_answer_never_shows_the_path(
    client: TestClient, admin: Session
) -> None:
    response = put_webhook(client, admin, f"https://hooks.example:8443/x/{URL_SECRET}")
    assert response.status_code == 200, response.text
    channel = response.json()["channel"]
    assert channel["type"] == "webhook"
    assert channel["target"] == "https://hooks.example:8443"
    assert channel["min_severity"] == "high"
    assert channel["enabled"] is True
    assert URL_SECRET not in response.text
    again = client.get("/notifications/channel", headers=admin.headers())
    assert again.json() == response.json()
    assert URL_SECRET not in again.text


def test_a_form_post_with_text_flags_works(client: TestClient, admin: Session) -> None:
    response = client.put(
        "/notifications/channel",
        headers=admin.headers(),
        data={
            "type": "webhook",
            "url": "https://hooks.example/x",
            "min_severity": "critical",
            "enabled": "false",
        },
    )
    assert response.status_code == 200, response.text
    channel = response.json()["channel"]
    assert (channel["min_severity"], channel["enabled"]) == ("critical", False)


def test_an_smtp_channel_with_a_list_and_a_number_never_shows_the_password(
    client: TestClient, admin: Session
) -> None:
    response = client.put(
        "/notifications/channel",
        headers=admin.headers(),
        json={
            "type": "smtp",
            "host": "mail.example",
            "port": 465,
            "security": "tls",
            "from_address": "driftsniff@example.com",
            "to_addresses": ["ops@example.com", "lead@example.com"],
            "username": "alerts",
            "password": MAIL_SECRET,
        },
    )
    assert response.status_code == 200, response.text
    channel = response.json()["channel"]
    assert channel["port"] == 465
    assert channel["security"] == "tls"
    assert channel["to_addresses"] == ["ops@example.com", "lead@example.com"]
    assert channel["password_set"] is True
    assert MAIL_SECRET not in response.text


@pytest.mark.parametrize(
    "body",
    [
        {"type": "sms", "url": "https://a.example"},
        {"type": "webhook", "url": "http://169.254.169.254/x"},
        {"type": "webhook", "url": "https://a.example", "min_severity": "urgent"},
        {"type": "webhook", "url": "https://a.example", "enabled": "maybe"},
        {"type": "webhook", "url": "https://a.example", "colour": "red"},
        {"type": "webhook"},
        {"type": "smtp", "host": "mail.example"},
    ],
)
def test_bad_input_is_422_and_nothing_is_stored(
    client: TestClient, admin: Session, body: dict[str, str]
) -> None:
    response = client.put("/notifications/channel", headers=admin.headers(), json=body)
    assert response.status_code == 422, response.text
    assert current(client, admin) == {"channel": None}


def test_a_json_value_of_the_wrong_type_is_not_dropped_quietly(
    client: TestClient, admin: Session
) -> None:
    response = client.put(
        "/notifications/channel",
        headers=admin.headers(),
        json={"type": "webhook", "url": "https://a.example", "enabled": False},
    )
    assert response.status_code == 400


@pytest.mark.parametrize("username", ["ops", "viewer"])
def test_only_an_admin_may_use_the_routes(
    client: TestClient, auth: AuthService, username: str
) -> None:
    session = open_session(client, auth, username)
    assert client.get("/notifications/channel", headers=session.headers()).status_code == 403
    assert put_webhook(client, session, "https://a.example").status_code == 403
    assert client.delete("/notifications/channel", headers=session.headers()).status_code == 403
    assert client.post("/notifications/test", headers=session.headers()).status_code == 403
    assert client.post("/notifications/signing-key", headers=session.headers()).status_code == 403
    assert client.get("/notifications/deliveries", headers=session.headers()).status_code == 403


def test_without_a_session_every_route_is_401(client: TestClient) -> None:
    headers = {"Origin": ORIGIN}
    assert client.get("/notifications/channel").status_code == 401
    assert client.get("/notifications/deliveries").status_code == 401
    assert client.put("/notifications/channel", headers=headers, json={}).status_code == 401
    assert client.delete("/notifications/channel", headers=headers).status_code == 401
    assert client.post("/notifications/test", headers=headers).status_code == 401
    assert client.post("/notifications/signing-key", headers=headers).status_code == 401


def test_a_write_without_the_csrf_value_is_403_and_changes_nothing(
    client: TestClient, admin: Session
) -> None:
    response = client.put(
        "/notifications/channel",
        headers=admin.headers(csrf=False),
        json={"type": "webhook", "url": "https://a.example"},
    )
    assert response.status_code == 403
    bare = admin.headers(csrf=False)
    assert client.delete("/notifications/channel", headers=bare).status_code == 403
    assert client.post("/notifications/test", headers=bare).status_code == 403
    assert current(client, admin) == {"channel": None}


def test_a_bearer_token_cannot_reach_the_routes(client: TestClient) -> None:
    response = client.get("/notifications/channel", headers={"Authorization": "Bearer " + "A" * 43})
    assert response.status_code == 401


def test_delete_removes_the_channel_and_a_second_delete_is_404(
    client: TestClient, admin: Session
) -> None:
    put_webhook(client, admin, "https://a.example/x")
    assert client.delete("/notifications/channel", headers=admin.headers()).status_code == 200
    assert current(client, admin) == {"channel": None}
    assert client.delete("/notifications/channel", headers=admin.headers()).status_code == 404


def test_the_test_button_reports_the_outcome(
    client: TestClient, admin: Session, receiver: Receiver
) -> None:
    missing = client.post("/notifications/test", headers=admin.headers())
    assert missing.status_code == 404
    put_webhook(client, admin, receiver.url)
    response = client.post("/notifications/test", headers=admin.headers())
    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True, "http_status": 204}
    assert receiver.paths == [f"/hook/{URL_SECRET}"]
    assert URL_SECRET not in response.text


def test_the_test_button_names_the_error_class_of_a_failure(
    client: TestClient, admin: Session
) -> None:
    put_webhook(client, admin, f"http://127.0.0.1:1/{URL_SECRET}")
    response = client.post("/notifications/test", headers=admin.headers())
    assert response.status_code == 200
    assert response.json() == {"ok": False, "error_class": "connection"}
    assert URL_SECRET not in response.text


def test_the_signing_key_is_the_derived_webhook_key(client: TestClient, admin: Session) -> None:
    response = client.post("/notifications/signing-key", headers=admin.headers())
    assert response.status_code == 200
    body = response.json()
    assert body["key_hex"] == MASTER.derive(WEBHOOK_LABEL).hex()
    assert body["algorithm"] == "HMAC-SHA-256"
    assert response.headers["cache-control"] == "no-store"


def test_the_delivery_list_is_empty_and_validates_its_query(
    client: TestClient, admin: Session
) -> None:
    ok = client.get("/notifications/deliveries", headers=admin.headers())
    assert ok.status_code == 200
    assert ok.json() == {"deliveries": []}
    for query in ("event_id=0", "limit=500"):
        response = client.get(f"/notifications/deliveries?{query}", headers=admin.headers())
        assert response.status_code == 422


def test_the_audit_events_of_the_routes_hold_no_url_and_no_password(
    client: TestClient, admin: Session, store: Database
) -> None:
    put_webhook(client, admin, f"https://hooks.example/{URL_SECRET}")
    client.put(
        "/notifications/channel",
        headers=admin.headers(),
        json={
            "type": "smtp",
            "host": "mail.example",
            "from_address": "a@b.example",
            "to_addresses": "c@d.example",
            "username": "alerts",
            "password": MAIL_SECRET,
        },
    )
    with store.read() as connection:
        rows = connection.exec_driver_sql("SELECT actor, action, target, detail FROM audit_events")
        text = json.dumps([list(map(str, row)) for row in rows])
    assert "notification.channel_saved" in text
    assert URL_SECRET not in text
    assert MAIL_SECRET not in text


def test_without_a_service_the_routes_answer_503(auth: AuthService) -> None:
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}), auth=auth)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as bare:
        session = open_session(bare, auth, "admin")
        assert bare.get("/notifications/channel", headers=session.headers()).status_code == 503
