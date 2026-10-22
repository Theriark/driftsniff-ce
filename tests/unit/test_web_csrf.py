"""CSRF value, origin check, security headers and the API cookie rule (P9-T2).

The tests drive the real application with a migrated database and a cheap argon2 setting. The
CSRF values are random per session; a value taken from another session must not work.
"""

import asyncio
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, Request
from fastapi.testclient import TestClient
from httpx import Response
from starlette.types import Message

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.main import create_app
from driftsniff.web import csrf
from driftsniff.web.auth import SESSION_COOKIE, AuthService, Principal, make_password_hasher
from driftsniff.web.csrf import (
    CONTENT_SECURITY_POLICY,
    CSRF_FIELD,
    origin_allowed,
    origin_key,
    token_matches,
    wants_no_store,
)
from driftsniff.web.deps import require_operator, require_viewer

NOW = datetime(2026, 10, 22, 8, 0, 0, tzinfo=UTC)
CORRECT = "CANARY-correct horse battery"
ORIGIN = "http://testserver"
FORM = "application/x-www-form-urlencoded"
WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]

probes = APIRouter()


@probes.api_route("/probe/write", methods=WRITE_METHODS)
async def probe_write(
    request: Request, user: Annotated[Principal, Depends(require_operator)]
) -> dict[str, str]:
    """A state-changing route of the interface; it echoes the body it received."""
    return {"user": user.username, "body": (await request.body()).decode()}


@probes.get("/probe/read")
def probe_read(user: Annotated[Principal, Depends(require_viewer)]) -> dict[str, str]:
    return {"user": user.username}


@probes.api_route("/api/v1/probe", methods=["GET", "POST"])
def probe_api() -> dict[str, bool]:
    """An API route; it needs no session (a token is checked by the real routes)."""
    return {"ok": True}


@dataclass(frozen=True, slots=True)
class Session:
    cookie: str
    csrf: str

    def headers(self, *, csrf: bool = True, origin: str | None = ORIGIN) -> dict[str, str]:
        headers = {"Cookie": f"{SESSION_COOKIE}={self.cookie}"}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        if origin is not None:
            headers["Origin"] = origin
        return headers


@pytest.fixture
def auth(store: Database) -> AuthService:
    service = AuthService(
        store, clock=lambda: NOW, hasher=make_password_hasher(memory_kib=8, time_cost=1)
    )
    service.create_user("ada", CORRECT, "operator")
    service.create_user("bob", CORRECT, "operator")
    return service


@pytest.fixture
def client(auth: AuthService) -> Iterator[TestClient]:
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}), auth=auth)
    app.include_router(probes)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as test_client:
        yield test_client


def open_session(client: TestClient, auth: AuthService, username: str = "ada") -> Session:
    response = client.post("/login", data={"username": username, "password": CORRECT})
    assert response.status_code == 303
    match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
    assert match is not None
    client.cookies.clear()
    principal = auth.authenticate(match.group(1))
    assert principal is not None
    return Session(match.group(1), principal.csrf_token)


@pytest.fixture
def session(client: TestClient, auth: AuthService) -> Session:
    return open_session(client, auth)


# -- the CSRF value ----------------------------------------------------------------------------


@pytest.mark.parametrize("method", WRITE_METHODS)
def test_a_write_with_the_session_value_goes_through(
    client: TestClient, session: Session, method: str
) -> None:
    response = client.request(method, "/probe/write", headers=session.headers())
    assert response.status_code == 200
    assert response.json()["user"] == "ada"


@pytest.mark.parametrize("method", WRITE_METHODS)
def test_a_write_without_the_value_is_refused(
    client: TestClient, session: Session, method: str
) -> None:
    response = client.request(method, "/probe/write", headers=session.headers(csrf=False))
    assert response.status_code == 403
    assert response.json() == {"detail": "the CSRF value is missing or wrong"}


@pytest.mark.parametrize("method", WRITE_METHODS)
@pytest.mark.parametrize("wrong", ["x", "x" * 400, "CANARY-wrong", "0"])
def test_a_write_with_a_wrong_value_is_refused(
    client: TestClient, session: Session, method: str, wrong: str
) -> None:
    headers = session.headers(csrf=False) | {"X-CSRF-Token": wrong}
    response = client.request(method, "/probe/write", headers=headers)
    assert response.status_code == 403
    assert session.csrf not in response.text


def test_the_value_of_another_session_does_not_work(
    client: TestClient, auth: AuthService, session: Session
) -> None:
    other = open_session(client, auth, "bob")
    assert other.csrf != session.csrf
    headers = session.headers(csrf=False) | {"X-CSRF-Token": other.csrf}
    assert client.post("/probe/write", headers=headers).status_code == 403


def test_a_form_field_works_and_the_body_still_reaches_the_route(
    client: TestClient, session: Session
) -> None:
    form = {CSRF_FIELD: session.csrf, "note": "hello world"}
    response = client.post("/probe/write", headers=session.headers(csrf=False), data=form)
    assert response.status_code == 200
    assert "note=hello+world" in response.json()["body"]


def test_a_wrong_form_field_is_refused(client: TestClient, session: Session) -> None:
    form = {CSRF_FIELD: "CANARY-wrong", "note": "x"}
    response = client.post("/probe/write", headers=session.headers(csrf=False), data=form)
    assert response.status_code == 403


def test_the_value_in_a_json_body_does_not_count(client: TestClient, session: Session) -> None:
    response = client.post(
        "/probe/write", headers=session.headers(csrf=False), json={CSRF_FIELD: session.csrf}
    )
    assert response.status_code == 403


def test_a_malformed_form_is_refused_not_a_server_error(
    client: TestClient, session: Session
) -> None:
    headers = session.headers(csrf=False) | {"Content-Type": FORM}
    assert client.post("/probe/write", headers=headers, content=b"\xff\xfe=1").status_code == 403
    many = "&".join(f"f{n}=1" for n in range(40)).encode()
    assert client.post("/probe/write", headers=headers, content=many).status_code == 403


def test_a_large_form_without_the_value_gets_413(client: TestClient, session: Session) -> None:
    headers = session.headers(csrf=False) | {"Content-Type": FORM}
    declared = client.post("/probe/write", headers=headers, content=b"a=" + b"x" * 20000)
    assert declared.status_code == 413

    def chunks() -> Iterator[bytes]:
        for _ in range(10):
            yield b"a=" + b"x" * 2000

    streamed = client.post("/probe/write", headers=headers, content=chunks())
    assert streamed.status_code == 413


def test_reads_need_no_value(client: TestClient, session: Session) -> None:
    headers = session.headers(csrf=False)
    assert client.get("/probe/read", headers=headers).status_code == 200


def test_the_value_is_compared_in_constant_time(
    client: TestClient, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = csrf.hmac.compare_digest

    def spy(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return real(left, right)

    monkeypatch.setattr(csrf.hmac, "compare_digest", spy)
    assert client.post("/probe/write", headers=session.headers()).status_code == 200
    assert calls == [(session.csrf.encode(), session.csrf.encode())]


def test_token_matches_rejects_blank_values() -> None:
    assert not token_matches(None, "abc")
    assert not token_matches("", "abc")
    assert not token_matches("abc", "")
    assert token_matches("abc", "abc")


async def _disconnected() -> Message:
    return {"type": "http.disconnect"}


def test_a_disconnect_while_reading_ends_the_read() -> None:
    assert asyncio.run(csrf._read_limited(_disconnected)) == b""


def test_the_replayed_body_is_handed_on_once_then_the_real_receive_answers() -> None:
    async def both() -> tuple[Message, Message]:
        replay = csrf._replay(b"a=1", _disconnected)
        return await replay(), await replay()

    first, second = asyncio.run(both())
    assert first == {"type": "http.request", "body": b"a=1", "more_body": False}
    assert second == {"type": "http.disconnect"}


# -- requests with no usable session -----------------------------------------------------------


def test_a_write_without_a_session_falls_through_to_the_role_check(client: TestClient) -> None:
    response = client.post("/probe/write", headers={"Origin": ORIGIN})
    assert response.status_code == 401


def test_a_stale_cookie_is_treated_as_no_session(client: TestClient) -> None:
    headers = {"Cookie": f"{SESSION_COOKIE}=stale", "Origin": ORIGIN}
    assert client.post("/probe/write", headers=headers).status_code == 401


def test_login_and_setup_need_no_value_even_with_a_session(
    client: TestClient, session: Session
) -> None:
    headers = session.headers(csrf=False)
    form = {"username": "bob", "password": CORRECT}
    assert client.post("/login", headers=headers, data=form).status_code == 303
    setup = client.post("/setup", headers=headers, data={"code": "AAAA-AAAA-AAAA-AAAA"})
    assert setup.json() == {"detail": "the setup code is not valid"}


def test_logout_needs_the_value(client: TestClient, auth: AuthService, session: Session) -> None:
    refused = client.post("/logout", headers=session.headers(csrf=False))
    assert refused.status_code == 403
    assert auth.authenticate(session.cookie) is not None
    accepted = client.post("/logout", headers=session.headers())
    assert accepted.status_code == 303
    assert auth.authenticate(session.cookie) is None


def test_an_application_without_a_sign_in_service_still_checks_the_origin() -> None:
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}))
    app.include_router(probes)
    bare = TestClient(app, base_url=ORIGIN, follow_redirects=False)
    foreign = bare.post("/login", headers={"Origin": "http://evil.example"})
    assert foreign.status_code == 403
    assert bare.post("/login", headers={"Origin": ORIGIN}, data={"a": "b"}).status_code == 503


# -- the origin --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("origin", "allowed"),
    [
        ("http://testserver", True),
        ("http://testserver:80", True),
        ("HTTP://TESTSERVER", True),
        ("https://testserver", False),
        ("http://testserver:8080", False),
        ("http://evil.example", False),
        ("http://testserver.evil.example", False),
        ("http://evil.example/http://testserver", False),
        ("http://testserver@evil.example", False),
        ("http://testserver/path", False),
        ("null", False),
        ("file://", False),
    ],
)
def test_the_origin_must_be_the_configured_one(
    client: TestClient, session: Session, origin: str, allowed: bool
) -> None:
    response = client.post("/probe/write", headers=session.headers(origin=origin))
    assert response.status_code == (200 if allowed else 403)
    if not allowed:
        assert response.json() == {"detail": "the request does not come from this site"}


def test_a_foreign_origin_is_refused_before_login_too(client: TestClient) -> None:
    form = {"username": "ada", "password": CORRECT}
    response = client.post("/login", data=form, headers={"Origin": "http://evil.example"})
    assert response.status_code == 403
    assert SESSION_COOKIE not in response.headers.get("set-cookie", "")


def test_a_request_without_an_origin_still_needs_the_value(
    client: TestClient, session: Session
) -> None:
    assert client.post("/probe/write", headers=session.headers(origin=None)).status_code == 200
    headers = session.headers(csrf=False, origin=None)
    assert client.post("/probe/write", headers=headers).status_code == 403


def test_origin_helpers() -> None:
    secure = origin_key("https://Host.example:443", allow_path=False)
    assert secure == ("https", "host.example", 443)
    assert origin_key("http://host.example/base/", allow_path=True) == ("http", "host.example", 80)
    assert origin_key("http://host.example:99999", allow_path=True) is None
    assert origin_key("ftp://host.example", allow_path=True) is None
    assert not origin_allowed("http://host.example", "not a url")
    assert origin_allowed("https://host.example", "https://host.example/driftsniff")


# -- the API -----------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_the_api_refuses_the_session_cookie(
    client: TestClient, session: Session, method: str
) -> None:
    response = client.request(method, "/api/v1/probe", headers=session.headers())
    assert response.status_code == 403
    assert response.json() == {"detail": "the API takes an API token, not a session cookie"}


def test_the_api_refuses_a_cookie_even_without_a_valid_session(client: TestClient) -> None:
    headers = {"Cookie": f"{SESSION_COOKIE}=stale"}
    assert client.get("/api/v1/probe", headers=headers).status_code == 403


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_the_api_needs_no_csrf_value_without_a_cookie(client: TestClient, method: str) -> None:
    headers = {"Authorization": "Bearer CANARY-token"}
    response = client.request(method, "/api/v1/probe", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_an_other_cookie_does_not_trip_the_api_rule(client: TestClient) -> None:
    assert client.get("/api/v1/probe", headers={"Cookie": "other=CANARY-1"}).status_code == 200


# -- headers and CORS --------------------------------------------------------------------------


def _answers(client: TestClient, auth: AuthService, session: Session) -> dict[str, Response]:
    """One answer of every route class: ok, redirect, 401, 403, 404, 405, 413, 503 and the API."""
    form = {"username": "ada", "password": CORRECT}
    login = client.post("/login", data=form)
    # the login stored a session cookie in the client; the probes below must not carry it
    client.cookies.clear()
    return {
        "health 200": client.get("/healthz"),
        "login redirect 303": login,
        "not found 404": client.get("/no-such-page"),
        "method 405": client.put("/healthz"),
        "unauthenticated 401": client.get("/probe/read"),
        "csrf refusal 403": client.post("/probe/write", headers=session.headers(csrf=False)),
        "origin refusal 403": client.post("/probe/write", headers=session.headers(origin="null")),
        "too large 413": client.post(
            "/probe/write",
            headers=session.headers(csrf=False) | {"Content-Type": FORM},
            content=b"a=" + b"x" * 20000,
        ),
        "api ok 200": client.get("/api/v1/probe"),
        "api cookie 403": client.get("/api/v1/probe", headers=session.headers()),
        "push unavailable 503": client.post("/api/v1/push/1"),
        "page 200": client.get("/probe/read", headers=session.headers()),
    }


def test_every_response_carries_the_security_headers(
    client: TestClient, auth: AuthService, session: Session
) -> None:
    answers = _answers(client, auth, session)
    assert {r.status_code for r in answers.values()} >= {200, 303, 401, 403, 404, 405, 413, 503}
    for label, response in answers.items():
        headers = response.headers
        assert headers["content-security-policy"] == CONTENT_SECURITY_POLICY, label
        assert headers["x-content-type-options"] == "nosniff", label
        assert headers["referrer-policy"] == "no-referrer", label
        assert headers["cache-control"] == "no-store", label


def test_the_policy_allows_nothing_inline_and_nothing_foreign() -> None:
    directives = dict(part.strip().split(" ", 1) for part in CONTENT_SECURITY_POLICY.split(";"))
    assert directives == {
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self'",
        "img-src": "'self' data:",
        "frame-ancestors": "'none'",
        "base-uri": "'none'",
        "form-action": "'self'",
    }
    for forbidden in ("unsafe-inline", "unsafe-eval", "*", "http:", "https:"):
        assert forbidden not in CONTENT_SECURITY_POLICY


def test_no_response_has_a_cors_header(
    client: TestClient, auth: AuthService, session: Session
) -> None:
    probe = {
        "Origin": "http://evil.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-csrf-token",
    }
    preflight = client.options("/probe/write", headers=probe)
    answers = [*_answers(client, auth, session).values(), preflight]
    for response in answers:
        assert not [name for name in response.headers if name.lower().startswith("access-control")]
    assert client.get("/healthz", headers={"Origin": "http://evil.example"}).status_code == 200


def test_the_static_files_may_be_cached() -> None:
    assert wants_no_store("/healthz")
    assert wants_no_store("/")
    assert wants_no_store("/static")
    assert not wants_no_store("/static/app.css")
