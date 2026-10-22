"""The first-run setup, sign-in and sign-out pages and the browser status pages (P10-T3).

The routes are driven through the real application with a migrated database and a cheap argon2
setting. A browser is a client that asks for ``text/html``; the plain client (``*/*``) must keep
the JSON answers of P9 (``test_web_auth.py``), so both are asked here. Passwords and codes are
canaries that must never come back in a page.
"""

import re
from collections.abc import Iterator
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from starlette.requests import Request

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.main import create_app
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.pages import sign_in_target, throttled_error, wants_html

ORIGIN = "http://testserver"
CORRECT = "CANARY-correct horse battery"
WRONG = "CANARY-wrong horse battery"
UNKNOWN_CODE = "AAAA-AAAA-AAAA-AAAA"
HOSTILE_NAME = "eve<script>alert(1)</script>"
BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


class Parsed(HTMLParser):
    """The tags of a page with their attributes, and its text, in document order."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[str] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        self.text.append(data)

    def find(self, name: str) -> list[dict[str, str | None]]:
        return [attrs for tag, attrs in self.tags if tag == name]

    def input(self, name: str) -> dict[str, str | None]:
        return next(attrs for attrs in self.find("input") if attrs.get("name") == name)


def assert_page(response: Response, status: int = 200) -> Parsed:
    """The answer is a page of the shell that obeys the content security policy."""
    assert response.status_code == status, response.text[:300]
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-store"
    assert "content-security-policy" in response.headers
    text = response.text
    assert text.startswith("<!doctype html>")
    parsed = Parsed(text)
    assert parsed.find("main") == [{"id": "main", "class": "page"}]
    for tag, attrs in parsed.tags:
        assert "style" not in attrs, f"<{tag}> carries a style attribute"
        assert not [name for name in attrs if name.startswith("on")], f"<{tag}> has a handler"
        if tag == "script":
            assert (attrs.get("src") or "").startswith("/static/")
    labelled = {attrs.get("for") for attrs in parsed.find("label")}
    for attrs in parsed.find("input"):
        if attrs.get("type") != "hidden":
            assert attrs.get("id") in labelled, f"unlabelled input {attrs}"
    return parsed


def banner_of(parsed: Parsed) -> dict[str, str | None] | None:
    banners = [attrs for attrs in parsed.find("div") if "banner" in (attrs.get("class") or "")]
    return banners[0] if banners else None


@pytest.fixture
def auth(store: Database) -> AuthService:
    return AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))


@pytest.fixture
def client(auth: AuthService) -> Iterator[TestClient]:
    app = create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN, "DRIFTSNIFF_ENVIRONMENT_LABEL": "Test"}),
        auth=auth,
    )
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as built:
        yield built


def cookie_of(response: Response) -> dict[str, str]:
    match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
    assert match is not None
    return {"Cookie": f"{SESSION_COOKIE}={match.group(1)}"}


def browser(headers: dict[str, str] | None = None) -> dict[str, str]:
    return {**BROWSER, **(headers or {})}


def complete_setup(client: TestClient, auth: AuthService, username: str = "ada") -> dict[str, str]:
    """Create the first admin through the setup post, as a browser; the session cookie."""
    code = auth.issue_setup_code()
    form = {"code": code, "username": username, "password": CORRECT}
    response = client.post("/setup", data=form, headers=browser())
    assert response.status_code == 303 and response.headers["location"] == "/"
    client.cookies.clear()
    return cookie_of(response)


# ---- helpers ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("accept", "expected"),
    [
        ("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", True),
        ("application/xhtml+xml", True),
        ("TEXT/HTML; charset=utf-8", True),
        ("*/*", False),
        ("application/json", False),
        ("", False),
        ("text/htmlx", False),
    ],
)
def test_wants_html_reads_the_accept_header(accept: str, expected: bool) -> None:
    headers = [(b"accept", accept.encode("ascii"))] if accept else []
    scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": headers}
    assert wants_html(Request(scope)) is expected


def test_sign_in_target_keeps_a_local_next_and_prefers_setup() -> None:
    assert sign_in_target("/changes?page=2", admin_exists=True) == "/login?next=/changes?page=2"
    assert sign_in_target("/c?a=1&b=2", admin_exists=True) == "/login?next=/c?a=1%26b=2"
    assert sign_in_target("/", admin_exists=True) == "/login"
    assert sign_in_target("https://evil.example/", admin_exists=True) == "/login"
    assert sign_in_target("//evil.example", admin_exists=True) == "/login"
    assert sign_in_target("/changes", admin_exists=False) == "/setup"


def test_throttled_error_names_the_wait() -> None:
    assert throttled_error(1).text.startswith("Wait 1 second,")
    assert throttled_error(8).text.startswith("Wait 8 seconds,")


# ---- the first run: setup, then the dashboard, then the page is gone -------------------------


def test_a_new_container_reaches_a_working_admin_session_through_the_setup_page_only(
    client: TestClient, auth: AuthService
) -> None:
    # 1. the start page sends a browser to the setup page while no admin exists
    start = client.get("/", headers=browser())
    assert (start.status_code, start.headers["location"]) == (303, "/setup")
    assert client.get("/login", headers=browser()).headers["location"] == "/setup"
    # 2. the setup page has the three labelled fields and the 12 character rule inline
    parsed = assert_page(client.get("/setup", headers=browser()))
    assert "Create the first admin" in "".join(parsed.text)
    code = parsed.input("code")
    assert code["autocomplete"] == "one-time-code" and "autofocus" in code
    assert code["class"] == "input mono" and "required" in code
    password = parsed.input("password")
    assert password["type"] == "password" and password["autocomplete"] == "new-password"
    assert "At least 12 characters" in "".join(parsed.text)
    assert {"class": "btn btn--primary", "type": "submit"} in parsed.find("button")
    assert [attrs["action"] for attrs in parsed.find("form")] == ["/setup"]
    # 3. the post creates the admin and signs them in; the start page is the dashboard
    cookie = complete_setup(client, auth)
    home = assert_page(client.get("/", headers=browser(cookie)))
    text = "".join(home.text)
    assert "Signed in as ada, admin" in text
    assert "Nothing to watch yet" in text
    assert {"class": "btn btn--primary", "href": "/sources/new"} in home.find("a")
    assert any(attrs.get("aria-label") == "Main" for attrs in home.find("nav"))
    assert {"method": "post", "action": "/logout"} in home.find("form")
    # 4. the setup page is 404 like an unknown route, for a browser and for a plain client
    gone = client.get("/setup", headers=browser())
    parsed = assert_page(gone, 404)
    assert "Page not found" in "".join(parsed.text)
    assert client.get("/setup").json() == {"detail": "Not Found"}
    # 5. a signed-in user who opens the sign-in page goes to the dashboard
    assert client.get("/login", headers=browser(cookie)).headers["location"] == "/"


def test_a_wrong_setup_code_marks_the_code_field_and_keeps_the_help(
    client: TestClient, auth: AuthService
) -> None:
    code = auth.issue_setup_code()
    form = {"code": UNKNOWN_CODE, "username": "ada", "password": CORRECT}
    response = client.post("/setup", data=form, headers=browser())
    parsed = assert_page(response, 403)
    field = parsed.input("code")
    assert field["aria-invalid"] == "true"
    assert field["aria-describedby"] == "code-help code-error"
    assert "value" not in field
    assert "This code is not valid" in "".join(parsed.text)
    assert "container log printed it once" in "".join(parsed.text)
    assert parsed.input("username")["value"] == "ada"
    assert "value" not in parsed.input("password")
    assert CORRECT not in response.text and UNKNOWN_CODE not in response.text
    assert "set-cookie" not in response.headers
    # the real code still works
    good = client.post("/setup", data={**form, "code": code}, headers=browser())
    assert good.status_code == 303


def test_a_rule_breaking_name_or_password_marks_that_field(
    client: TestClient, auth: AuthService
) -> None:
    code = auth.issue_setup_code()
    weak = client.post(
        "/setup", data={"code": code, "username": "ada", "password": "short"}, headers=browser()
    )
    parsed = assert_page(weak, 422)
    assert parsed.input("password")["aria-invalid"] == "true"
    assert "The password must have at least 12 characters." in "".join(parsed.text)
    assert "aria-invalid" not in parsed.input("username")
    bad_name = client.post(
        "/setup", data={"code": code, "username": "a b", "password": CORRECT}, headers=browser()
    )
    parsed = assert_page(bad_name, 422)
    assert parsed.input("username")["aria-invalid"] == "true"
    assert "aria-invalid" not in parsed.input("password")
    assert "The user name must have 3 to 64 characters" in "".join(parsed.text)
    assert code not in weak.text + bad_name.text


def test_repeated_wrong_setup_codes_show_the_wait_on_the_page(
    client: TestClient, auth: AuthService
) -> None:
    code = auth.issue_setup_code()
    form = {"code": UNKNOWN_CODE, "username": "ada", "password": CORRECT}
    for _ in range(5):
        assert client.post("/setup", data=form, headers=browser()).status_code == 403
    response = client.post("/setup", data={**form, "code": code}, headers=browser())
    parsed = assert_page(response, 429)
    assert response.headers["retry-after"] == "1"
    assert banner_of(parsed) == {"class": "banner banner--error", "role": "alert"}
    assert "Wait 1 second, then try again." in "".join(parsed.text)


# ---- sign in and sign out --------------------------------------------------------------------


def test_the_sign_in_page_has_the_mark_the_sentence_and_the_one_action(
    client: TestClient, auth: AuthService
) -> None:
    # An admin must exist, or the sign-in page sends every browser to the setup page.
    auth.create_user("ada", CORRECT, "admin")
    response = client.get("/login", headers=browser())
    parsed = assert_page(response)
    tile = next(attrs for attrs in parsed.find("img") if attrs.get("width") == "96")
    assert tile["src"] == "/static/brand/logo-mark-512x512.png" and tile["alt"] == ""
    assert parsed.find("h1") == [{"id": "auth-title"}]
    assert "See what changed since you last looked." in "".join(parsed.text)
    assert parsed.find("button") == [{"class": "btn btn--primary", "type": "submit"}]
    assert parsed.input("next")["value"] == "/"
    username = parsed.input("username")
    assert username["autocomplete"] == "username" and "autofocus" in username
    assert parsed.input("password")["autocomplete"] == "current-password"
    # no navigation, no user menu and no CSRF header before sign-in; the badge stays
    assert not any(attrs.get("aria-label") == "Main" for attrs in parsed.find("nav"))
    assert "hx-headers" not in parsed.find("body")[0]
    assert '<span class="env-badge">Test</span>' in response.text
    assert banner_of(parsed) is None


def test_wrong_credentials_show_the_generic_error_and_keep_the_name(
    client: TestClient, auth: AuthService
) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    unknown = client.post(
        "/login", data={"username": HOSTILE_NAME, "password": WRONG}, headers=browser()
    )
    wrong = client.post("/login", data={"username": "ada", "password": WRONG}, headers=browser())
    for response in (unknown, wrong):
        parsed = assert_page(response, 401)
        assert banner_of(parsed) == {"class": "banner banner--error", "role": "alert"}
        assert "Sign-in failed" in "".join(parsed.text)
        assert "Check the user name and password" in "".join(parsed.text)
        assert "set-cookie" not in response.headers
        assert WRONG not in response.text
        assert "value" not in parsed.input("password")
    # the name comes back escaped
    assert Parsed(unknown.text).input("username")["value"] == HOSTILE_NAME
    assert "<script>" not in unknown.text
    assert "&lt;script&gt;" in unknown.text
    # a plain client keeps the JSON answer of P9
    plain = client.post("/login", data={"username": "ada", "password": WRONG})
    assert plain.status_code == 401
    assert plain.json() == {"detail": "invalid user name or password"}


def test_five_failures_show_the_wait_on_the_page(client: TestClient, auth: AuthService) -> None:
    auth.create_user("ada", CORRECT, "viewer")
    for _ in range(5):
        client.post("/login", data={"username": "ada", "password": WRONG}, headers=browser())
    response = client.post(
        "/login", data={"username": "ada", "password": CORRECT}, headers=browser()
    )
    parsed = assert_page(response, 429)
    assert response.headers["retry-after"] == "1"
    assert "Too many attempts" in "".join(parsed.text)
    assert "set-cookie" not in response.headers


def test_sign_in_goes_back_to_the_page_that_asked_for_it(
    client: TestClient, auth: AuthService
) -> None:
    # /tokens is a guarded route (admin); an unknown path would be a plain 404 instead.
    auth.create_user("ada", CORRECT, "admin")
    asked = client.get("/tokens?page=2", headers=browser())
    assert asked.status_code == 303
    assert asked.headers["location"] == "/login?next=/tokens?page=2"
    parsed = assert_page(client.get(asked.headers["location"], headers=browser()))
    assert parsed.input("next")["value"] == "/tokens?page=2"
    form = {"username": "ada", "password": CORRECT, "next": "/tokens?page=2"}
    signed_in = client.post("/login", data=form, headers=browser())
    assert (signed_in.status_code, signed_in.headers["location"]) == (303, "/tokens?page=2")
    client.cookies.clear()
    foreign = {"username": "ada", "password": CORRECT, "next": "https://evil.example/"}
    assert client.post("/login", data=foreign, headers=browser()).headers["location"] == "/"
    client.cookies.clear()
    assert client.get("/", headers=browser()).headers["location"] == "/login"
    assert client.get("/").status_code == 401


def test_sign_out_confirms_on_the_sign_in_page(client: TestClient, auth: AuthService) -> None:
    cookie = complete_setup(client, auth)
    principal = auth.authenticate(cookie["Cookie"].split("=", 1)[1])
    assert principal is not None
    out = client.post(
        "/logout",
        headers=browser({**cookie, "X-CSRF-Token": principal.csrf_token, "Origin": ORIGIN}),
    )
    assert (out.status_code, out.headers["location"]) == (303, "/login?signed-out=1")
    parsed = assert_page(client.get("/login?signed-out=1", headers=browser()))
    assert banner_of(parsed) == {"class": "banner banner--success", "role": "status"}
    assert "Signed out" in "".join(parsed.text)
    assert "Sign in again when you need to." in "".join(parsed.text)
    assert client.get("/", headers=browser(cookie)).status_code == 303


# ---- status pages ----------------------------------------------------------------------------


def test_a_browser_gets_designed_not_found_and_not_allowed_pages(
    client: TestClient, auth: AuthService
) -> None:
    auth.create_user("vera", CORRECT, "viewer")
    response = client.post("/login", data={"username": "vera", "password": CORRECT})
    cookie = cookie_of(response)
    client.cookies.clear()
    missing = assert_page(client.get("/no-such-page", headers=browser(cookie)), 404)
    assert "Page not found" in "".join(missing.text)
    assert {"class": "btn btn--primary", "href": "/"} in missing.find("a")
    assert "Signed in as vera, viewer" in "".join(missing.text)
    forbidden = assert_page(client.get("/tokens", headers=browser(cookie)), 403)
    assert "Your role does not allow this" in "".join(forbidden.text)
    anonymous = assert_page(client.get("/no-such-page", headers=browser()), 404)
    assert "Go to the start page" in "".join(anonymous.text)
    assert "Signed in as" not in "".join(anonymous.text)


def test_plain_clients_and_the_api_keep_the_json_answers(
    client: TestClient, auth: AuthService
) -> None:
    auth.create_user("vera", CORRECT, "viewer")
    assert client.get("/no-such-page").json() == {"detail": "Not Found"}
    missing = client.get("/no-such-page", headers=browser())
    assert missing.headers["content-type"].startswith("text/html")
    # The test app has no token service, so the API answers 503; the point is that a browser
    # Accept header never turns an API answer into a page.
    api = client.get("/api/v1/changes", headers=browser())
    assert api.status_code == 503
    assert api.headers["content-type"].startswith("application/json")
    assert client.get("/", headers={"Accept": "application/json"}).json() == {
        "detail": "sign-in is required"
    }
