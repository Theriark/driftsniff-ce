"""Authentication of the whole application (P9-T6).

The unit tests of ``web/auth.py`` and ``web/bearer.py`` cover the services. These tests ask the
questions an attacker asks of the running application: what happens with no credential, a wrong
one, a forged one, one that has been ended, one in the wrong place. Every refusal must be the same
plain 401 (or 403 when the credential is fine and the role or scope is not), never a hint about
which part was wrong.
"""

import base64

from driftsniff.web.auth import SESSION_COOKIE, hash_cookie_value

from .appkit import CORRECT, Kit
from .routekit import ROLE_ACCESS, ROUTE_TABLE, Access, Caller, ask

ANONYMOUS = Caller("anonymous", "anonymous")
TOKEN_ACCESS = frozenset({Access.TOKEN_READ, Access.TOKEN_ENRICH})
WRONG = "CANARY-wrong password for the test"


def cookie_header(value: str) -> dict[str, str]:
    return {"Cookie": f"{SESSION_COOKIE}={value}"}


def test_no_credential_gets_401_on_every_route_that_needs_one(kit: Kit) -> None:
    needing = sorted(
        route for route, access in ROUTE_TABLE.items() if access in ROLE_ACCESS | TOKEN_ACCESS
    )
    assert needing, "the table has no route that needs a credential"
    for method, path in needing:
        assert ask(kit, method, path, ANONYMOUS) == 401, (method, path)


def test_a_refused_token_asks_for_a_bearer_token(kit: Kit) -> None:
    response = kit.client.get("/api/v1/changes")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_wrong_password_and_an_unknown_user_look_the_same(kit: Kit) -> None:
    wrong = kit.client.post("/login", data={"username": "admin", "password": WRONG})
    unknown = kit.client.post("/login", data={"username": "nobody-here", "password": WRONG})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert "set-cookie" not in wrong.headers
    assert "set-cookie" not in unknown.headers
    assert WRONG not in wrong.text + unknown.text


def test_a_forged_or_tampered_session_cookie_is_refused(kit: Kit) -> None:
    session = kit.new_session("admin")
    assert kit.client.get("/tokens", headers=cookie_header(session.cookie)).status_code == 200
    last = "A" if session.cookie[-1] != "A" else "B"
    forged = {
        "last character changed": session.cookie[:-1] + last,
        "made up": "x" * len(session.cookie),
        "the stored hash of a real cookie": hash_cookie_value(session.cookie),
        "the csrf value": session.csrf,
    }
    for name, value in forged.items():
        response = kit.client.get("/tokens", headers=cookie_header(value))
        assert response.status_code == 401, name


def test_logout_ends_the_session(kit: Kit) -> None:
    session = kit.new_session("admin")
    assert kit.client.get("/tokens", headers=session.headers()).status_code == 200
    response = kit.client.post("/logout", headers=session.headers())
    assert response.status_code == 303
    kit.client.cookies.clear()
    after = kit.client.get("/tokens", headers=cookie_header(session.cookie))
    assert after.status_code == 401


def test_a_disabled_user_loses_the_session_the_tokens_and_the_login(kit: Kit) -> None:
    user_id = kit.user_ids["operator"]
    session = kit.new_session("operator")
    value = kit.tokens.create(user_id=user_id, actor="test", name="op", scopes=["read"]).value
    bearer = {"Authorization": f"Bearer {value}"}
    # Alive: an operator is signed in (403, the role is too low) and the token reads.
    assert kit.client.get("/tokens", headers=session.headers()).status_code == 403
    assert kit.client.get("/api/v1/changes", headers=bearer).status_code == 200

    assert kit.auth.set_user_disabled(user_id, disabled=True, actor="test") is True

    assert kit.client.get("/tokens", headers=session.headers()).status_code == 401
    assert kit.client.get("/api/v1/changes", headers=bearer).status_code == 401
    login = kit.client.post("/login", data={"username": "operator", "password": CORRECT})
    assert login.status_code == 401
    kit.client.cookies.clear()


def test_a_session_cookie_never_works_on_the_api(kit: Kit) -> None:
    session = kit.new_session("admin")
    headers = {**cookie_header(session.cookie), **kit.bearer("read")}
    assert kit.client.get("/api/v1/changes", headers=headers).status_code == 403
    assert kit.client.get("/api/v1/changes", headers=kit.bearer("read")).status_code == 200


def test_the_api_token_is_accepted_only_in_the_authorization_header(kit: Kit) -> None:
    value = kit.token_values["read"]
    basic = base64.b64encode(f"{value}:".encode()).decode("ascii")
    elsewhere: dict[str, tuple[str, dict[str, str]]] = {
        "the query string (access_token)": ("/api/v1/changes?access_token=" + value, {}),
        "the query string (token)": ("/api/v1/changes?token=" + value, {}),
        "the Basic scheme": ("/api/v1/changes", {"Authorization": f"Basic {basic}"}),
        "another scheme word": ("/api/v1/changes", {"Authorization": f"Token {value}"}),
        "a key header": ("/api/v1/changes", {"X-API-Key": value}),
        "a cookie": ("/api/v1/changes", {"Cookie": f"api_token={value}"}),
    }
    for name, (url, headers) in elsewhere.items():
        assert kit.client.get(url, headers=headers).status_code == 401, name
    assert kit.client.get("/api/v1/changes", headers=kit.bearer("read")).status_code == 200


def test_every_kind_of_bad_token_gets_the_same_answer(kit: Kit) -> None:
    gone = kit.tokens.create(user_id=kit.user_ids["admin"], actor="test", name="g", scopes=["read"])
    kit.tokens.revoke(gone.info.token_id, actor="test")
    bad = {
        "revoked": gone.value,
        "unknown": "y" * 43,
        "malformed": "short",
    }
    answers = {
        name: kit.client.get("/api/v1/changes", headers={"Authorization": f"Bearer {value}"})
        for name, value in bad.items()
    }
    assert {response.status_code for response in answers.values()} == {401}
    assert len({response.text for response in answers.values()}) == 1
    for response in answers.values():
        for word in ("revoked", "unknown", "expired", "malformed"):
            assert word not in response.text
