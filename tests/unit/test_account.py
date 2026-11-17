"""The Account page: shown name, picture, password and theme of the signed-in user."""

import re

import pytest
from fastapi.testclient import TestClient

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.main import create_app
from driftsniff.web.auth import (
    SESSION_COOKIE,
    AccountInputError,
    AuthService,
    make_password_hasher,
    picture_type_of,
)

CORRECT = "CANARY-correct horse battery"
NEW = "CANARY-a new long passphrase"
ORIGIN = "http://testserver"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 32


@pytest.fixture
def auth(store: Database) -> AuthService:
    return AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))


@pytest.fixture
def client(auth: AuthService) -> TestClient:
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}), auth=auth)
    return TestClient(app, base_url=ORIGIN, follow_redirects=False)


def sign_in(client: TestClient, auth: AuthService) -> dict[str, str]:
    """A viewer's cookie, CSRF value and origin, sent by hand."""
    auth.create_user("ada", CORRECT, "viewer")
    response = client.post(
        "/login", data={"username": "ada", "password": CORRECT}, headers={"Origin": ORIGIN}
    )
    assert response.status_code == 303
    match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
    assert match is not None
    client.cookies.clear()
    principal = auth.authenticate(match.group(1))
    assert principal is not None
    return {
        "Cookie": f"{SESSION_COOKIE}={match.group(1)}",
        "X-CSRF-Token": principal.csrf_token,
        "Origin": ORIGIN,
    }


def cookie_of(headers: dict[str, str]) -> str:
    return headers["Cookie"].split("=", 1)[1]


def test_the_page_shows_the_three_cards_and_the_menu_links_to_it(
    client: TestClient, auth: AuthService
) -> None:
    headers = sign_in(client, auth)
    page = client.get("/account", headers=headers)
    assert page.status_code == 200
    for heading in ("Profile", "Password", "Theme"):
        assert f">{heading}</h2>" in page.text
    assert '<a href="/account">Account</a>' in page.text
    # the picture form shows only with script; no password is ever filled back in
    assert "data-account-picture" in page.text and "hidden" in page.text
    assert CORRECT not in page.text


def test_a_name_is_saved_shown_in_the_sidebar_and_audited_without_its_value(
    client: TestClient, auth: AuthService, store: Database
) -> None:
    headers = sign_in(client, auth)
    response = client.post(
        "/account/name", data={"display_name": "  Ada   Lovelace "}, headers=headers
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/account?done=name"
    page = client.get("/", headers=headers)
    assert '<span class="user-name">Ada Lovelace</span>' in page.text
    with store.read() as connection:
        rows = connection.exec_driver_sql(
            "SELECT action, detail FROM audit_events WHERE action = 'user.profile_changed'"
        ).all()
    assert len(rows) == 1 and "Lovelace" not in str(rows[0].detail)


def test_a_name_too_long_or_with_control_characters_is_refused(
    client: TestClient, auth: AuthService
) -> None:
    headers = sign_in(client, auth)
    for value in ("x" * 81, "a\x07b"):
        response = client.post("/account/name", data={"display_name": value}, headers=headers)
        assert response.status_code == 422
        assert "The name was not saved" in response.text


def test_the_password_changes_and_every_other_session_ends(
    client: TestClient, auth: AuthService
) -> None:
    headers = sign_in(client, auth)
    second = auth.login("ada", CORRECT, "192.0.2.9")
    form = {"current_password": CORRECT, "new_password": NEW, "confirm_password": NEW}
    response = client.post("/account/password", data=form, headers=headers)
    assert response.status_code == 303
    assert auth.authenticate(cookie_of(headers)) is not None
    assert auth.authenticate(second.cookie_value) is None
    assert auth.login("ada", NEW, "192.0.2.9").principal.username == "ada"


@pytest.mark.parametrize(
    ("form", "message"),
    [
        (
            {
                "current_password": "wrong one entirely",
                "new_password": NEW,
                "confirm_password": NEW,
            },
            "The current password is not right.",
        ),
        (
            {"current_password": CORRECT, "new_password": "short", "confirm_password": "short"},
            "at least 12 characters",
        ),
        (
            {"current_password": CORRECT, "new_password": NEW, "confirm_password": NEW + "x"},
            "The two new passwords do not match.",
        ),
    ],
)
def test_a_refused_password_change_says_why_and_changes_nothing(
    client: TestClient, auth: AuthService, form: dict[str, str], message: str
) -> None:
    headers = sign_in(client, auth)
    response = client.post("/account/password", data=form, headers=headers)
    assert response.status_code == 422
    assert message in response.text
    assert CORRECT not in response.text and NEW not in response.text
    assert auth.login("ada", CORRECT, "192.0.2.9").principal.username == "ada"


def test_the_theme_is_saved_and_set_on_every_page(client: TestClient, auth: AuthService) -> None:
    headers = sign_in(client, auth)
    assert '<html lang="en">' in client.get("/", headers=headers).text
    response = client.post("/account/theme", data={"theme": "dark"}, headers=headers)
    assert response.status_code == 303
    page = client.get("/", headers=headers).text
    assert '<html lang="en" data-theme="dark">' in page
    assert "logo-horizontal-dark-plain-1200x400.png" in page and "prefers-color-scheme" not in page
    refused = client.post("/account/theme", data={"theme": "neon"}, headers=headers)
    assert refused.status_code == 422


def test_a_picture_is_taken_by_its_bytes_served_and_removed(
    client: TestClient, auth: AuthService
) -> None:
    headers = sign_in(client, auth)
    sent = client.post(
        "/account/picture", content=PNG, headers={**headers, "Content-Type": "image/png"}
    )
    assert sent.status_code == 200 and sent.json() == {"location": "/account?done=picture"}
    principal = auth.authenticate(cookie_of(headers))
    assert principal is not None and principal.picture_version == 1
    page = client.get("/", headers=headers).text
    assert f'src="/account/picture/{principal.user_id}?v=1"' in page
    served = client.get(f"/account/picture/{principal.user_id}", headers=headers)
    assert served.status_code == 200 and served.content == PNG
    assert served.headers["content-type"] == "image/png"
    assert served.headers["x-content-type-options"] == "nosniff"
    removed = client.post("/account/picture/remove", data={}, headers=headers)
    assert removed.status_code == 303
    assert client.get(f"/account/picture/{principal.user_id}", headers=headers).status_code == 404


def test_a_picture_that_is_no_image_or_too_large_is_refused(
    client: TestClient, auth: AuthService
) -> None:
    headers = sign_in(client, auth)
    svg = client.post("/account/picture", content=b"<svg onload=x>", headers=headers)
    assert svg.status_code == 422 and "PNG, JPEG or WebP" in svg.json()["detail"]
    big = client.post("/account/picture", content=PNG + b"\x00" * (512 * 1024), headers=headers)
    assert big.status_code == 413


def test_the_picture_needs_the_csrf_header(client: TestClient, auth: AuthService) -> None:
    headers = sign_in(client, auth)
    without = {key: value for key, value in headers.items() if key != "X-CSRF-Token"}
    response = client.post(
        "/account/picture", content=PNG, headers={**without, "Content-Type": "image/png"}
    )
    assert response.status_code == 403


def test_picture_types_are_recognised_by_their_first_bytes() -> None:
    assert picture_type_of(PNG) == "image/png"
    assert picture_type_of(b"\xff\xd8\xff\xe0rest") == "image/jpeg"
    assert picture_type_of(WEBP) == "image/webp"
    assert picture_type_of(b"GIF89a") is None
    assert picture_type_of(b"") is None


def test_account_input_error_names_its_form() -> None:
    error = AccountInputError("theme", "the theme must be light, dark or system")
    assert error.field == "theme" and isinstance(error, ValueError)
