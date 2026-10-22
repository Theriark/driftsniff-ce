"""The setup, sign-in and sign-out routes and the role checks, driven through the real application.

No network is involved: the test client talks to the application, which uses a migrated database
and a cheap argon2 setting. Passwords are canaries that must never come back in an answer or a log.
"""

import logging
import re
from datetime import UTC, datetime
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from httpx import Response

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.main import create_app
from driftsniff.web.auth import (
    ROLE_RANK,
    SESSION_COOKIE,
    AuthService,
    Principal,
    make_password_hasher,
)
from driftsniff.web.deps import require_admin, require_operator, require_viewer

NOW = datetime(2026, 10, 22, 8, 0, 0, tzinfo=UTC)
CORRECT = "CANARY-correct horse battery"
WRONG = "CANARY-wrong horse battery"
FORM = "application/x-www-form-urlencoded"
GENERIC = {"detail": "invalid user name or password"}
UNKNOWN_CODE = "AAAA-AAAA-AAAA-AAAA"

probes = APIRouter()


@probes.get("/probe/viewer")
def probe_viewer(user: Annotated[Principal, Depends(require_viewer)]) -> dict[str, str]:
    return {"user": user.username, "role": user.role}


@probes.get("/probe/operator")
def probe_operator(user: Annotated[Principal, Depends(require_operator)]) -> dict[str, str]:
    return {"user": user.username, "role": user.role}


@probes.get("/probe/admin")
def probe_admin(user: Annotated[Principal, Depends(require_admin)]) -> dict[str, str]:
    return {"user": user.username, "role": user.role}


@pytest.fixture
def auth(store: Database) -> AuthService:
    """A service on a frozen clock, so the sign-in waits do not depend on the speed of the run."""
    return AuthService(
        store, clock=lambda: NOW, hasher=make_password_hasher(memory_kib=8, time_cost=1)
    )


def make_client(
    auth: AuthService | None,
    *,
    trusted_proxy: bool = False,
    base_url: str = "http://testserver",
) -> TestClient:
    env = {"DRIFTSNIFF_TRUSTED_PROXY": "true" if trusted_proxy else "false"}
    app = create_app(Settings.from_env(env), auth=auth)
    app.include_router(probes)
    return TestClient(app, base_url=base_url, follow_redirects=False)


@pytest.fixture
def client(auth: AuthService) -> TestClient:
    return make_client(auth)


def cookie_value(response: Response) -> str:
    match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
    assert match is not None
    return match.group(1)


def as_user(value: str) -> dict[str, str]:
    """Send the cookie by hand, so the client's own cookie jar never takes part."""
    return {"Cookie": f"{SESSION_COOKIE}={value}"}


def sign_in(client: TestClient, username: str, password: str = CORRECT) -> str:
    response = client.post("/login", data={"username": username, "password": password})
    assert response.status_code == 303
    return cookie_value(response)


# -- the cookie --------------------------------------------------------------------------------


def test_login_redirects_and_sets_an_http_only_lax_cookie(
    auth: AuthService, client: TestClient
) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    response = client.post("/login", data={"username": "ada", "password": CORRECT})
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    header = response.headers["set-cookie"].lower()
    assert header.startswith(f"{SESSION_COOKIE}=")
    assert "httponly" in header
    assert "samesite=lax" in header
    assert "path=/" in header
    assert "secure" not in header
    assert len(cookie_value(response)) >= 43


def test_the_cookie_is_secure_when_the_request_came_over_https(auth: AuthService) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    client = make_client(auth, base_url="https://testserver")
    response = client.post("/login", data={"username": "ada", "password": CORRECT})
    assert "secure" in response.headers["set-cookie"].lower()


def test_a_forwarded_https_scheme_counts_only_behind_a_trusted_proxy(auth: AuthService) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    form = {"username": "ada", "password": CORRECT}
    forwarded = {"X-Forwarded-Proto": "https"}
    untrusted = make_client(auth, trusted_proxy=False)
    trusted = make_client(auth, trusted_proxy=True)
    refused = untrusted.post("/login", data=form, headers=forwarded)
    assert "secure" not in refused.headers["set-cookie"].lower()
    accepted = trusted.post("/login", data=form, headers=forwarded)
    assert "secure" in accepted.headers["set-cookie"].lower()
    plain = trusted.post("/login", data=form)
    assert "secure" not in plain.headers["set-cookie"].lower()


def test_a_json_body_signs_in_too(auth: AuthService, client: TestClient) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    response = client.post("/login", json={"username": "ada", "password": CORRECT})
    assert response.status_code == 303
    assert client.get("/probe/viewer", headers=as_user(cookie_value(response))).status_code == 200


# -- generic errors ----------------------------------------------------------------------------


def test_unknown_user_and_wrong_password_get_the_same_answer(
    auth: AuthService, client: TestClient
) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    unknown = client.post("/login", data={"username": "nobody", "password": WRONG})
    wrong = client.post("/login", data={"username": "ada", "password": WRONG})
    assert (unknown.status_code, wrong.status_code) == (401, 401)
    assert unknown.json() == wrong.json() == GENERIC
    for response in (unknown, wrong):
        assert "set-cookie" not in response.headers
        assert WRONG not in response.text


def test_five_failures_a_minute_give_429_with_a_retry_after(
    auth: AuthService, client: TestClient
) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    for _ in range(5):
        assert client.post("/login", data={"username": "ada", "password": WRONG}).status_code == 401
    response = client.post("/login", data={"username": "ada", "password": CORRECT})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "1"
    assert response.json() == {"detail": "too many failed attempts, try again later"}
    assert "set-cookie" not in response.headers


def test_a_disabled_user_cannot_sign_in_and_loses_the_cookie(
    auth: AuthService, client: TestClient
) -> None:
    user_id = auth.create_user("ada", CORRECT, "viewer")
    value = sign_in(client, "ada")
    assert client.get("/probe/viewer", headers=as_user(value)).status_code == 200
    auth.set_user_disabled(user_id, disabled=True, actor="system")
    assert client.get("/probe/viewer", headers=as_user(value)).status_code == 401
    response = client.post("/login", data={"username": "ada", "password": CORRECT})
    assert (response.status_code, response.json()) == (401, GENERIC)


# -- roles -------------------------------------------------------------------------------------


@pytest.mark.parametrize("route", ["viewer", "operator", "admin"])
@pytest.mark.parametrize("role", [None, "viewer", "operator", "admin"])
def test_each_route_answers_by_role(
    auth: AuthService, client: TestClient, route: str, role: str | None
) -> None:
    headers: dict[str, str] = {}
    if role is not None:
        auth.create_user(f"{role}-user", CORRECT, role)
        headers = as_user(sign_in(client, f"{role}-user"))
    response = client.get(f"/probe/{route}", headers=headers)
    if role is None:
        assert response.status_code == 401
    elif ROLE_RANK[role] >= ROLE_RANK[route]:
        assert response.status_code == 200
        assert response.json() == {"user": f"{role}-user", "role": role}
    else:
        assert response.status_code == 403


def test_a_stolen_database_row_is_no_cookie(
    auth: AuthService, client: TestClient, store: Database
) -> None:
    auth.create_user("ada", CORRECT, "admin")
    sign_in(client, "ada")
    with store.read() as connection:
        stored = connection.exec_driver_sql("SELECT token_hash FROM sessions").scalar_one()
    assert client.get("/probe/viewer", headers=as_user(stored)).status_code == 401


def test_the_cookie_cannot_be_replaced_by_a_header_of_another_name(
    auth: AuthService, client: TestClient
) -> None:
    auth.create_user("ada", CORRECT, "admin")
    value = sign_in(client, "ada")
    response = client.get("/probe/viewer", headers={"Authorization": f"Bearer {value}"})
    assert response.status_code == 401


def test_without_a_sign_in_service_every_guarded_route_answers_503() -> None:
    client = make_client(None)
    assert client.get("/probe/viewer").status_code == 503
    assert client.post("/login", data={"username": "a", "password": "b"}).status_code == 503
    assert client.post("/setup", data={"code": "a"}).status_code == 503
    assert client.post("/logout").status_code == 503


# -- logout ------------------------------------------------------------------------------------


def test_logout_ends_the_session_and_clears_the_cookie(
    auth: AuthService, client: TestClient
) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    value = sign_in(client, "ada")
    response = client.post("/logout", headers=as_user(value))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "max-age=0" in response.headers["set-cookie"].lower()
    assert client.get("/probe/viewer", headers=as_user(value)).status_code == 401


def test_logout_without_a_session_is_harmless(client: TestClient) -> None:
    response = client.post("/logout")
    assert response.status_code == 303
    assert "max-age=0" in response.headers["set-cookie"].lower()


# -- first-run setup ---------------------------------------------------------------------------


def setup_form(code: str, username: str = "ada", phrase: str = CORRECT) -> dict[str, str]:
    return {"code": code, "username": username, "password": phrase}


def test_setup_creates_the_first_admin_and_a_working_session(
    auth: AuthService, client: TestClient
) -> None:
    code = auth.issue_setup_code()
    response = client.post("/setup", data=setup_form(code))
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    headers = as_user(cookie_value(response))
    assert client.get("/probe/admin", headers=headers).json() == {"user": "ada", "role": "admin"}


def test_the_setup_route_is_404_once_an_admin_exists(auth: AuthService, client: TestClient) -> None:
    code = auth.issue_setup_code()
    assert client.post("/setup", data=setup_form(code)).status_code == 303
    again = client.post("/setup", data=setup_form(code, "bob", "another long password"))
    assert again.status_code == 404
    assert again.json() == client.get("/no-such-route").json() == {"detail": "Not Found"}


def test_setup_accepts_a_json_body(auth: AuthService, client: TestClient) -> None:
    code = auth.issue_setup_code()
    response = client.post("/setup", json=setup_form(code))
    assert response.status_code == 303


def test_a_wrong_setup_code_gets_403_and_the_real_code_still_works(
    auth: AuthService, client: TestClient
) -> None:
    code = auth.issue_setup_code()
    response = client.post("/setup", data=setup_form(UNKNOWN_CODE))
    assert response.status_code == 403
    assert response.json() == {"detail": "the setup code is not valid"}
    assert client.post("/setup", data=setup_form(code)).status_code == 303


def test_a_weak_password_or_bad_name_gets_422_with_the_rule(
    auth: AuthService, client: TestClient
) -> None:
    code = auth.issue_setup_code()
    weak = client.post("/setup", data=setup_form(code, phrase="short"))
    assert weak.status_code == 422
    assert "at least 12 characters" in weak.json()["detail"]
    bad_name = client.post("/setup", data=setup_form(code, username="a b"))
    assert bad_name.status_code == 422
    assert client.post("/setup", data=setup_form(code)).status_code == 303


def test_repeated_wrong_setup_codes_give_429(auth: AuthService, client: TestClient) -> None:
    code = auth.issue_setup_code()
    for _ in range(5):
        assert client.post("/setup", data=setup_form(UNKNOWN_CODE)).status_code == 403
    response = client.post("/setup", data=setup_form(code))
    assert response.status_code == 429
    assert response.headers["retry-after"] == "1"


# -- request bodies ----------------------------------------------------------------------------


def test_a_body_over_16_kb_is_refused(client: TestClient) -> None:
    declared = client.post("/login", content=b"a=" + b"x" * 20000, headers={"Content-Type": FORM})
    assert declared.status_code == 413
    chunks = iter([b"a=" + b"x" * 9000, b"x" * 9000])
    streamed = client.post("/login", content=chunks, headers={"Content-Type": FORM})
    assert streamed.status_code == 413


@pytest.mark.parametrize(
    ("content", "content_type", "status"),
    [
        (b"{not json", "application/json", 400),
        (b'["a"]', "application/json", 400),
        (b"[" * 15000, "application/json", 400),
        (b"\xff\xfe", FORM, 400),
        (b"a=b", "text/plain", 415),
        (b"a=b", "", 415),
    ],
)
def test_a_body_that_is_not_a_form_or_a_json_object_is_refused(
    client: TestClient, content: bytes, content_type: str, status: int
) -> None:
    for path in ("/login", "/setup"):
        headers = {"Content-Type": content_type} if content_type else {}
        assert client.post(path, content=content, headers=headers).status_code == status


def test_missing_fields_are_a_failed_sign_in_not_an_error(client: TestClient) -> None:
    response = client.post("/login", content=b"", headers={"Content-Type": FORM})
    assert (response.status_code, response.json()) == (401, GENERIC)
    non_text = client.post("/login", json={"username": 1, "password": ["x"]})
    assert (non_text.status_code, non_text.json()) == (401, GENERIC)


# -- logs --------------------------------------------------------------------------------------


def test_no_password_or_cookie_value_reaches_the_logs(
    auth: AuthService, client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    code = auth.issue_setup_code()
    created = client.post("/setup", data=setup_form(code))
    client.post("/login", data={"username": "ada", "password": WRONG})
    value = sign_in(client, "ada")
    client.post("/logout", headers=as_user(value))
    text = caplog.text
    for secret in (CORRECT, WRONG, code, value, cookie_value(created)):
        assert secret not in text
