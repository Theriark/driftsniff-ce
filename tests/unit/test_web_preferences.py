"""The row density preference (P10-T2): the cookie, the form post and where it sends you back."""

import re

import pytest
from fastapi.testclient import TestClient

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.main import create_app
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.preferences import (
    DENSITY_COOKIE,
    density_from_cookie,
    parse_density,
    safe_next,
)

CORRECT = "CANARY-correct horse battery"


@pytest.mark.parametrize(
    ("value", "expected"),
    [("compact", "compact"), (" Comfortable ", "comfortable"), ("COMPACT", "compact")],
)
def test_parse_density_accepts_the_two_words(value: str, expected: str) -> None:
    assert parse_density(value) == expected


@pytest.mark.parametrize("value", ["", "dense", "compact; path=/", "comfortable\n"])
def test_parse_density_refuses_anything_else(value: str) -> None:
    with pytest.raises(ValueError, match="comfortable or compact"):
        parse_density(value)


def test_density_from_cookie_falls_back_to_comfortable() -> None:
    assert density_from_cookie(None) == "comfortable"
    assert density_from_cookie("garbage") == "comfortable"
    assert density_from_cookie("compact") == "compact"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "/"),
        ("", "/"),
        ("/changes", "/changes"),
        ("/changes?page=2&status=open", "/changes?page=2&status=open"),
        ("/sources/3#runs", "/sources/3#runs"),
        ("//evil.example/x", "/"),
        ("https://evil.example/", "/"),
        ("changes", "/"),
        ("/chan ges", "/"),
        ("/x\\evil", "/"),
        ("/x\r\nSet-Cookie: a=b", "/"),
        ("/\x00", "/"),
    ],
)
def test_safe_next_keeps_only_a_local_path(value: str | None, expected: str) -> None:
    assert safe_next(value) == expected


# ---- the route ------------------------------------------------------------------------------


@pytest.fixture
def auth(store: Database) -> AuthService:
    return AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))


@pytest.fixture
def client(auth: AuthService) -> TestClient:
    app = create_app(Settings.from_env({}), auth=auth)
    return TestClient(app, base_url="http://testserver", follow_redirects=False)


def sign_in(client: TestClient, auth: AuthService, role: str = "viewer") -> dict[str, str]:
    """A viewer's cookie and CSRF value, sent by hand so the client's jar takes no part."""
    auth.create_user("ada", CORRECT, role)
    response = client.post("/login", data={"username": "ada", "password": CORRECT})
    assert response.status_code == 303
    match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
    assert match is not None
    client.cookies.clear()
    principal = auth.authenticate(match.group(1))
    assert principal is not None
    return {
        "Cookie": f"{SESSION_COOKIE}={match.group(1)}",
        "X-CSRF-Token": principal.csrf_token,
        "Origin": "http://testserver",
    }


def test_the_form_post_sets_the_cookie_and_goes_back(client: TestClient, auth: AuthService) -> None:
    headers = sign_in(client, auth)
    response = client.post(
        "/preferences/density",
        data={"density": "compact", "next": "/changes?page=2"},
        headers=headers,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/changes?page=2"
    header = response.headers["set-cookie"].lower()
    assert header.startswith(f"{DENSITY_COOKIE}=compact")
    assert "httponly" in header and "samesite=lax" in header and "path=/" in header
    assert "max-age=31536000" in header
    assert "secure" not in header


def test_the_cookie_is_secure_over_https(auth: AuthService) -> None:
    client = TestClient(
        create_app(Settings.from_env({}), auth=auth),
        base_url="https://testserver",
        follow_redirects=False,
    )
    headers = sign_in(client, auth)
    headers["Origin"] = "https://testserver"
    form = {"density": "comfortable"}
    response = client.post("/preferences/density", data=form, headers=headers)
    assert response.status_code == 303
    assert "secure" in response.headers["set-cookie"].lower()


def test_an_unknown_density_is_refused_and_nothing_is_set(
    client: TestClient, auth: AuthService
) -> None:
    headers = sign_in(client, auth)
    response = client.post("/preferences/density", data={"density": "dense"}, headers=headers)
    assert response.status_code == 422
    assert "set-cookie" not in response.headers


def test_a_foreign_next_address_goes_to_the_start_page(
    client: TestClient, auth: AuthService
) -> None:
    headers = sign_in(client, auth)
    response = client.post(
        "/preferences/density",
        data={"density": "compact", "next": "https://evil.example/"},
        headers=headers,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_without_a_session_the_route_asks_for_sign_in(client: TestClient) -> None:
    response = client.post("/preferences/density", data={"density": "compact"})
    assert response.status_code == 401
    assert "set-cookie" not in response.headers


def test_without_the_csrf_value_the_post_is_refused(client: TestClient, auth: AuthService) -> None:
    headers = sign_in(client, auth)
    del headers["X-CSRF-Token"]
    response = client.post("/preferences/density", data={"density": "compact"}, headers=headers)
    assert response.status_code == 403
    assert "set-cookie" not in response.headers
