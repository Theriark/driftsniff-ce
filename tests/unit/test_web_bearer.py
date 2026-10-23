"""API tokens (P9-T3): creation, scopes, expiry, revocation, audit and the admin routes.

The tests drive the real application with a migrated database, a cheap argon2 setting and an
injected clock. A token value must never be recoverable from the database, the list, the audit
events or the logs; the tests look for the value itself in every one of them.
"""

import json
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import pytest
import sqlalchemy as sa
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import api_tokens, audit_events, sessions, users
from driftsniff.main import create_app
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.bearer import (
    FAILURE_AUDIT_INTERVAL,
    LAST_USED_REFRESH,
    MAX_NAME_CHARS,
    TokenInputError,
    TokenPrincipal,
    TokenRejectedError,
    TokenService,
    _FailureGate,
    bearer_value,
    hash_token,
    normalise_scopes,
)
from driftsniff.web.deps import require_enrich_token, require_read_token, require_token

START = datetime(2026, 10, 22, 8, 0, 0, tzinfo=UTC)
CORRECT = "CANARY-correct horse battery"
ORIGIN = "http://testserver"

probes = APIRouter()


@probes.get("/api/v1/probe/read")
def probe_read(token: Annotated[TokenPrincipal, Depends(require_read_token)]) -> dict[str, Any]:
    return {"name": token.name, "scopes": list(token.scopes)}


@probes.get("/api/v1/probe/enrich")
def probe_enrich(
    token: Annotated[TokenPrincipal, Depends(require_enrich_token)],
) -> dict[str, Any]:
    return {"name": token.name, "scopes": list(token.scopes)}


class Clock:
    """A clock the tests move by hand; both services share it."""

    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


@dataclass(frozen=True, slots=True)
class Session:
    cookie: str
    csrf: str

    def headers(self, *, csrf: bool = True) -> dict[str, str]:
        headers = {"Cookie": f"{SESSION_COOKIE}={self.cookie}", "Origin": ORIGIN}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        return headers


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def auth(store: Database, clock: Clock) -> AuthService:
    service = AuthService(
        store, clock=clock, hasher=make_password_hasher(memory_kib=8, time_cost=1)
    )
    service.create_user("admin", CORRECT, "admin")
    service.create_user("ops", CORRECT, "operator")
    return service


@pytest.fixture
def service(store: Database, clock: Clock) -> TokenService:
    return TokenService(store, clock=clock)


@pytest.fixture
def client(auth: AuthService, service: TokenService) -> Iterator[TestClient]:
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}), auth=auth, tokens=service)
    app.include_router(probes)
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


@pytest.fixture
def operator(client: TestClient, auth: AuthService) -> Session:
    return open_session(client, auth, "ops")


def make_token(
    client: TestClient, session: Session, scopes: str = "read", **fields: Any
) -> dict[str, Any]:
    response = client.post(
        "/tokens", headers=session.headers(), json={"name": "ci", "scopes": scopes, **fields}
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def audit_rows(store: Database) -> list[Any]:
    with store.read() as connection:
        return list(connection.execute(sa.select(audit_events).order_by(audit_events.c.id)).all())


def audit_actions(store: Database) -> list[str]:
    return [row.action for row in audit_rows(store)]


# -- creation and storage ---------------------------------------------------------------------


def test_a_new_token_has_the_agreed_shape_and_is_shown_once(
    client: TestClient, admin: Session
) -> None:
    body = make_token(client, admin, "read,enrich", expires_in_days=30)
    value = body["token"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
    assert body["prefix"] == value[:8]
    assert body["scopes"] == ["read", "enrich"]
    assert body["status"] == "active"
    assert body["expires_at"] == "2026-11-21T08:00:00Z"
    assert "only time" in body["note"]
    listing = client.get("/tokens", headers=admin.headers(csrf=False))
    assert listing.status_code == 200
    assert value not in listing.text
    entry = listing.json()["tokens"][0]
    assert entry["prefix"] == value[:8]
    assert entry["created_by"] == "admin"
    assert "token" not in entry
    assert "token_hash" not in listing.text


def test_only_the_hash_and_the_prefix_are_stored(
    client: TestClient, admin: Session, store: Database
) -> None:
    value = make_token(client, admin)["token"]
    with store.read() as connection:
        row = connection.execute(sa.select(api_tokens)).one()
        everywhere = [
            tuple(found)
            for table in (api_tokens, users, sessions)
            for found in connection.execute(sa.select(table))
        ]
    assert row.token_hash == hash_token(value)
    assert row.token_prefix == value[:8]
    assert value not in repr(everywhere)
    assert value not in repr([tuple(found) for found in audit_rows(store)])
    # Not in the database file or its write-ahead log either.
    for path in (store.path, store.path.with_name(store.path.name + "-wal")):
        if path.exists():
            assert value.encode() not in path.read_bytes()


def test_a_stolen_database_row_is_not_a_token(
    client: TestClient, admin: Session, store: Database
) -> None:
    value = make_token(client, admin)["token"]
    with store.read() as connection:
        row = connection.execute(sa.select(api_tokens)).one()
    for guess in (row.token_hash, row.token_prefix, hash_token(row.token_hash), value[:8]):
        response = client.get("/api/v1/probe/read", headers=bearer(guess))
        assert response.status_code == 401
    assert client.get("/api/v1/probe/read", headers=bearer(value)).status_code == 200


def test_two_tokens_differ_and_the_list_is_newest_first(client: TestClient, admin: Session) -> None:
    first = make_token(client, admin)
    second = make_token(client, admin, "enrich")
    assert first["token"] != second["token"]
    listing = client.get("/tokens", headers=admin.headers(csrf=False)).json()["tokens"]
    assert [entry["id"] for entry in listing] == [second["id"], first["id"]]


def test_a_json_body_with_a_list_and_a_number_works(client: TestClient, admin: Session) -> None:
    response = client.post(
        "/tokens",
        headers=admin.headers(),
        json={"name": "dash", "scopes": ["enrich", "read", "read"], "expires_in_days": 7},
    )
    assert response.status_code == 201
    assert response.json()["scopes"] == ["read", "enrich"]
    assert response.json()["expires_at"] == "2026-10-29T08:00:00Z"


def test_a_form_post_works(client: TestClient, admin: Session) -> None:
    response = client.post(
        "/tokens",
        headers=admin.headers(),
        data={
            "name": "form",
            "scopes": "read enrich",
            "expires_in_days": "",
            "csrf_token": admin.csrf,
        },
    )
    assert response.status_code == 201
    assert response.json()["scopes"] == ["read", "enrich"]
    assert response.json()["expires_at"] is None


@pytest.mark.parametrize(
    "fields",
    [
        {"name": "", "scopes": "read"},
        {"name": "   ", "scopes": "read"},
        {"name": "x" * (MAX_NAME_CHARS + 1), "scopes": "read"},
        {"name": "bad\nname", "scopes": "read"},
        {"name": "ci"},
        {"name": "ci", "scopes": ""},
        {"name": "ci", "scopes": "admin"},
        {"name": "ci", "scopes": "read,write"},
        {"name": "ci", "scopes": "read", "expires_in_days": "0"},
        {"name": "ci", "scopes": "read", "expires_in_days": "3651"},
        {"name": "ci", "scopes": "read", "expires_in_days": "-5"},
        {"name": "ci", "scopes": "read", "expires_in_days": "soon"},
        {"name": "ci", "scopes": "read", "expires_in_day": "30"},
        {"name": "ci", "scopes": "read", "owner": "root"},
    ],
)
def test_bad_input_is_refused_and_nothing_is_stored(
    client: TestClient, admin: Session, store: Database, fields: dict[str, str]
) -> None:
    response = client.post("/tokens", headers=admin.headers(), json=fields)
    assert response.status_code == 422
    with store.read() as connection:
        assert connection.execute(sa.select(sa.func.count()).select_from(api_tokens)).scalar() == 0
    assert "token.created" not in audit_actions(store)


@pytest.mark.parametrize(
    "document",
    [
        {"name": "ci", "scopes": "read", "expires_in_days": True},
        {"name": "ci", "scopes": "read", "expires_in_days": 1.5},
        {"name": "ci", "scopes": "read", "expires_in_days": None},
        {"name": "ci", "scopes": [1, 2]},
        {"name": "ci", "scopes": {"read": True}},
    ],
)
def test_a_json_value_of_the_wrong_type_is_not_dropped_quietly(
    client: TestClient, admin: Session, document: dict[str, Any]
) -> None:
    response = client.post("/tokens", headers=admin.headers(), json=document)
    assert response.status_code == 400


def test_the_name_is_trimmed(client: TestClient, admin: Session) -> None:
    body = make_token(client, admin, name="  nightly job  ")
    assert body["name"] == "nightly job"


# -- who may manage tokens ---------------------------------------------------------------------


def test_only_an_admin_may_manage_tokens(
    client: TestClient, admin: Session, operator: Session
) -> None:
    made = make_token(client, admin)
    for method, url in (
        ("GET", "/tokens"),
        ("POST", "/tokens"),
        ("POST", f"/tokens/{made['id']}/revoke"),
    ):
        refused = client.request(
            method, url, headers=operator.headers(), json={"name": "x", "scopes": "read"}
        )
        assert refused.status_code == 403, (method, url)
        anonymous = client.request(method, url, json={"name": "x", "scopes": "read"})
        assert anonymous.status_code == 401, (method, url)
    assert client.get("/api/v1/probe/read", headers=bearer(made["token"])).status_code == 200


def test_a_write_needs_the_csrf_value(client: TestClient, admin: Session, store: Database) -> None:
    body = {"name": "ci", "scopes": "read"}
    assert client.post("/tokens", headers=admin.headers(csrf=False), json=body).status_code == 403
    made = make_token(client, admin)
    revoke = client.post(f"/tokens/{made['id']}/revoke", headers=admin.headers(csrf=False))
    assert revoke.status_code == 403
    assert client.get("/api/v1/probe/read", headers=bearer(made["token"])).status_code == 200
    assert audit_actions(store) == ["user.created", "user.created", "token.created"]


def test_a_token_cannot_manage_tokens(client: TestClient, admin: Session) -> None:
    value = make_token(client, admin, "read,enrich")["token"]
    assert client.get("/tokens", headers=bearer(value)).status_code == 401
    created = client.post("/tokens", headers=bearer(value), json={"name": "x", "scopes": "read"})
    assert created.status_code == 401


def test_the_api_refuses_a_session_cookie_even_with_a_good_token(
    client: TestClient, admin: Session
) -> None:
    value = make_token(client, admin)["token"]
    headers = bearer(value) | {"Cookie": f"{SESSION_COOKIE}={admin.cookie}"}
    assert client.get("/api/v1/probe/read", headers=headers).status_code == 403


# -- scopes -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scopes", "read_status", "enrich_status"),
    [("read", 200, 403), ("enrich", 403, 200), ("read,enrich", 200, 200)],
)
def test_scope_matrix(
    client: TestClient,
    admin: Session,
    scopes: str,
    read_status: int,
    enrich_status: int,
) -> None:
    value = make_token(client, admin, scopes)["token"]
    assert client.get("/api/v1/probe/read", headers=bearer(value)).status_code == read_status
    assert client.get("/api/v1/probe/enrich", headers=bearer(value)).status_code == enrich_status


def test_a_scope_violation_names_no_token_and_is_audited(
    client: TestClient, admin: Session, store: Database
) -> None:
    made = make_token(client, admin, "read")
    response = client.get("/api/v1/probe/enrich", headers=bearer(made["token"]))
    assert response.status_code == 403
    assert made["token"] not in response.text
    forbidden = [row for row in audit_rows(store) if row.action == "token.forbidden"]
    assert len(forbidden) == 1
    assert forbidden[0].actor == f"token:{made['prefix']}"
    assert forbidden[0].detail == {"reason": "scope", "scope": "enrich", "name": "ci"}


def test_require_token_refuses_an_unknown_scope() -> None:
    with pytest.raises(ValueError, match="unknown token scope"):
        require_token("admin")
    with pytest.raises(TokenInputError, match="scopes"):
        normalise_scopes(["read", "write"])


# -- refused tokens ---------------------------------------------------------------------------


def test_a_missing_header_gets_401_and_writes_no_event(
    client: TestClient, admin: Session, store: Database
) -> None:
    response = client.get("/api/v1/probe/read")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "token.rejected" not in audit_actions(store)


@pytest.mark.parametrize(
    "header",
    [
        "Bearer",
        "Bearer ",
        "Bearer short",
        "Bearer " + "A" * 43 + "!",
        "Bearer " + "A" * 44,
        "Basic " + "A" * 43,
        "A" * 43,
        "Token " + "A" * 43,
        "Bearer " + "A" * 43 + " extra",
    ],
)
def test_a_malformed_header_gets_401(client: TestClient, header: str) -> None:
    response = client.get("/api/v1/probe/read", headers={"Authorization": header})
    assert response.status_code == 401
    assert response.json() == {"detail": "the API token is not valid"}


def test_an_unknown_token_gets_the_same_401(client: TestClient, admin: Session) -> None:
    make_token(client, admin)
    unknown = "CANARY" + "x" * 37
    assert len(unknown) == 43
    response = client.get("/api/v1/probe/read", headers=bearer(unknown))
    assert response.status_code == 401
    assert response.json() == {"detail": "the API token is not valid"}
    assert unknown not in response.text


def test_the_scheme_word_is_not_case_sensitive() -> None:
    value = "A" * 43
    assert bearer_value(f"bearer {value}") == value
    assert bearer_value(f"BEARER   {value}") == value
    assert bearer_value(f"Bearer{value}") is None


def test_an_expired_token_gets_401(client: TestClient, admin: Session, clock: Clock) -> None:
    value = make_token(client, admin, expires_in_days=1)["token"]
    clock.advance(hours=23, minutes=59)
    assert client.get("/api/v1/probe/read", headers=bearer(value)).status_code == 200
    clock.advance(minutes=1)
    response = client.get("/api/v1/probe/read", headers=bearer(value))
    assert response.status_code == 401
    assert response.json() == {"detail": "the API token is not valid"}
    clock.advance(days=30)
    assert client.get("/api/v1/probe/read", headers=bearer(value)).status_code == 401


def test_a_token_without_expiry_stays_valid(
    client: TestClient, admin: Session, clock: Clock
) -> None:
    value = make_token(client, admin)["token"]
    clock.advance(days=3650)
    assert client.get("/api/v1/probe/read", headers=bearer(value)).status_code == 200


def test_a_revoked_token_gets_401_and_revoking_twice_changes_nothing(
    client: TestClient, admin: Session, store: Database, clock: Clock
) -> None:
    made = make_token(client, admin)
    assert client.get("/api/v1/probe/read", headers=bearer(made["token"])).status_code == 200
    first = client.post(f"/tokens/{made['id']}/revoke", headers=admin.headers())
    assert first.status_code == 200
    assert first.json() == {"id": made["id"], "status": "revoked"}
    clock.advance(minutes=5)
    again = client.post(f"/tokens/{made['id']}/revoke", headers=admin.headers())
    assert again.status_code == 200
    assert client.get("/api/v1/probe/read", headers=bearer(made["token"])).status_code == 401
    listing = client.get("/tokens", headers=admin.headers(csrf=False)).json()["tokens"]
    assert listing[0]["status"] == "revoked"
    assert listing[0]["revoked_at"] == "2026-10-22T08:00:00Z"
    assert audit_actions(store).count("token.revoked") == 1


def test_revoking_an_unknown_token_is_404(client: TestClient, admin: Session) -> None:
    assert client.post("/tokens/999/revoke", headers=admin.headers()).status_code == 404
    assert client.post("/tokens/0/revoke", headers=admin.headers()).status_code == 422


def test_the_tokens_of_a_disabled_user_stop_working(
    client: TestClient, admin: Session, auth: AuthService, store: Database
) -> None:
    value = make_token(client, admin)["token"]
    with store.read() as connection:
        user_id = connection.execute(
            sa.select(users.c.id).where(users.c.username == "admin")
        ).scalar_one()
    assert auth.set_user_disabled(user_id, disabled=True, actor="system")
    assert client.get("/api/v1/probe/read", headers=bearer(value)).status_code == 401
    assert auth.set_user_disabled(user_id, disabled=False, actor="system")
    assert client.get("/api/v1/probe/read", headers=bearer(value)).status_code == 200


def test_the_list_shows_the_status_of_every_token(
    client: TestClient, admin: Session, service: TokenService, clock: Clock
) -> None:
    keeps = make_token(client, admin, name="keeps")
    expires = make_token(client, admin, name="expires", expires_in_days=1)
    revoked = make_token(client, admin, name="revoked")
    client.post(f"/tokens/{revoked['id']}/revoke", headers=admin.headers())
    assert {t.name: t.status(clock()) for t in service.list_tokens()} == {
        "keeps": "active",
        "expires": "active",
        "revoked": "revoked",
    }
    clock.advance(days=1)
    assert {t.name: t.status(clock()) for t in service.list_tokens()} == {
        "keeps": "active",
        "expires": "expired",
        "revoked": "revoked",
    }
    assert keeps["status"] == expires["status"] == "active"


def test_the_token_routes_report_the_status_at_the_service_clock(
    client: TestClient, admin: Session, auth: AuthService, clock: Clock
) -> None:
    """The answer of the routes follows the injected clock, never the day the test runs."""
    made = make_token(client, admin, expires_in_days=1)
    assert made["status"] == "active"
    assert made["expires_at"] == "2026-10-23T08:00:00Z"
    clock.advance(hours=23, minutes=59)
    session = open_session(client, auth, "admin")
    listing = client.get("/tokens", headers=session.headers(csrf=False)).json()["tokens"]
    assert [entry["status"] for entry in listing] == ["active"]
    clock.advance(minutes=1)
    session = open_session(client, auth, "admin")
    listing = client.get("/tokens", headers=session.headers(csrf=False)).json()["tokens"]
    assert [entry["status"] for entry in listing] == ["expired"]
    assert listing[0]["expires_at"] == made["expires_at"]


# -- last use ---------------------------------------------------------------------------------


def test_the_last_use_is_stored_at_most_once_a_minute(
    client: TestClient, admin: Session, service: TokenService, clock: Clock
) -> None:
    value = make_token(client, admin)["token"]
    assert service.list_tokens()[0].last_used_at is None
    client.get("/api/v1/probe/read", headers=bearer(value))
    first = service.list_tokens()[0].last_used_at
    assert first == "2026-10-22T08:00:00Z"
    clock.advance(seconds=LAST_USED_REFRESH.total_seconds() - 1)
    client.get("/api/v1/probe/read", headers=bearer(value))
    assert service.list_tokens()[0].last_used_at == first
    clock.advance(seconds=1)
    client.get("/api/v1/probe/read", headers=bearer(value))
    assert service.list_tokens()[0].last_used_at == "2026-10-22T08:01:00Z"


def test_a_refused_request_does_not_count_as_a_use(
    client: TestClient, admin: Session, service: TokenService
) -> None:
    value = make_token(client, admin, "read")["token"]
    client.get("/api/v1/probe/enrich", headers=bearer(value))
    assert service.list_tokens()[0].last_used_at is None


# -- audit ------------------------------------------------------------------------------------


def test_creation_use_failure_and_revocation_are_audited_without_the_value(
    client: TestClient, admin: Session, store: Database
) -> None:
    made = make_token(client, admin, "read", expires_in_days=5)
    client.get("/api/v1/probe/enrich", headers=bearer(made["token"]))
    client.get("/api/v1/probe/read", headers=bearer("CANARY" + "z" * 37))
    client.post(f"/tokens/{made['id']}/revoke", headers=admin.headers())
    client.get("/api/v1/probe/read", headers=bearer(made["token"]))
    rows = [row for row in audit_rows(store) if row.action.startswith("token.")]
    assert [row.action for row in rows] == [
        "token.created",
        "token.forbidden",
        "token.rejected",
        "token.revoked",
        "token.rejected",
    ]
    created, _forbidden, unknown, revoked, after = rows
    assert created.actor == "admin"
    assert created.target == made["prefix"]
    assert created.detail == {"name": "ci", "scopes": ["read"], "expires_at": made["expires_at"]}
    assert unknown.actor == "token:unknown"
    assert unknown.detail == {"reason": "unknown", "scope": "read"}
    assert revoked.actor == "admin"
    assert after.detail == {"reason": "revoked", "scope": "read", "name": "ci"}
    assert made["token"] not in repr([tuple(row) for row in audit_rows(store)])


def test_refusals_of_anonymous_traffic_are_rate_limited_in_the_log(
    client: TestClient, store: Database, clock: Clock
) -> None:
    junk = "CANARY" + "q" * 37
    for _ in range(5):
        assert client.get("/api/v1/probe/read", headers=bearer(junk)).status_code == 401
    for _ in range(3):
        client.get("/api/v1/probe/read", headers={"Authorization": "Bearer nope"})
    rejected = [row for row in audit_rows(store) if row.action == "token.rejected"]
    assert [row.detail["reason"] for row in rejected] == ["unknown", "malformed"]
    clock.advance(seconds=FAILURE_AUDIT_INTERVAL.total_seconds())
    client.get("/api/v1/probe/read", headers=bearer(junk))
    rejected = [row for row in audit_rows(store) if row.action == "token.rejected"]
    assert len(rejected) == 3
    assert rejected[-1].detail == {"reason": "unknown", "scope": "read", "held_back": 4}


# -- logs -------------------------------------------------------------------------------------


def test_no_log_line_holds_a_token_value(
    client: TestClient, admin: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    made = make_token(client, admin, "read")
    client.get("/api/v1/probe/read", headers=bearer(made["token"]))
    client.get("/api/v1/probe/enrich", headers=bearer(made["token"]))
    client.post(f"/tokens/{made['id']}/revoke", headers=admin.headers())
    client.get("/api/v1/probe/read", headers=bearer(made["token"]))
    assert made["token"] not in caplog.text
    assert made["token"] not in json.dumps([record.getMessage() for record in caplog.records])


# -- without a service ------------------------------------------------------------------------


def test_without_a_token_service_the_routes_answer_503(auth: AuthService) -> None:
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}), auth=auth)
    app.include_router(probes)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as bare:
        response = bare.get("/api/v1/probe/read", headers=bearer("A" * 43))
        assert response.status_code == 503
        session = open_session(bare, auth, "admin")
        assert bare.get("/tokens", headers=session.headers(csrf=False)).status_code == 503


# -- the audit gate and a broken database -----------------------------------------------------


def test_the_audit_gate_keeps_its_memory_bounded(clock: Clock) -> None:
    gate = _FailureGate(clock)
    assert gate.admit("first") == 0
    assert gate.admit("first") is None
    for number in range(400):
        assert gate.admit(f"key-{number}") == 0
    # "first" was pushed out by newer keys, so it starts again instead of counting forever.
    assert gate.admit("first") == 0


def test_a_database_that_cannot_take_the_audit_event_still_gives_401(
    service: TokenService,
    store: Database,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken() -> None:
        raise sa.exc.OperationalError("INSERT", {}, Exception("database is locked"))

    monkeypatch.setattr(store, "write", broken)
    caplog.set_level(logging.WARNING)
    with pytest.raises(TokenRejectedError):
        service.authenticate("Bearer " + "A" * 43, "read")
    assert "could not be written" in caplog.text
