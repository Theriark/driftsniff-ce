"""The admin settings routes (P10-T8 slice A): roles, CSRF, input rules, audit and the 503.

The routes are data routes (JSON) for the settings page of slice B. Every one is admin only: a
viewer and an operator get 403, nobody gets 401. A write needs the session CSRF value and the
configured origin. A value that breaks its rule answers 422 with the rule and the field, repeats
nothing that was typed and stores nothing.
"""

from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from driftsniff import __version__
from driftsniff.config import Settings
from driftsniff.db.tables import audit_events, settings, users
from driftsniff.main import create_app

from .appkit import CORRECT, ORIGIN, Kit, Session

NEW_PASSWORD = "CANARY-new user password"  # noqa: S105
SHORT_PASSWORD = "short"  # noqa: S105
SETTING_KEYS = ("retention_days", "storage_warning_gb")


def writes(kit: Kit) -> list[tuple[str, dict[str, str]]]:
    """Every write route of the settings, with a body that would be accepted from an admin."""
    viewer = kit.user_ids["viewer"]
    return [
        ("/settings/retention", {"retention_days": "90"}),
        ("/settings/storage-warning", {"storage_warning_gb": "5"}),
        ("/settings/users", {"username": "ada", "password": NEW_PASSWORD, "role": "viewer"}),
        (f"/settings/users/{viewer}/disable", {}),
        (f"/settings/users/{viewer}/enable", {}),
    ]


def stored_settings(kit: Kit) -> dict[str, str]:
    with kit.store.read() as connection:
        query = sa.select(settings.c.key, settings.c.value).where(settings.c.key.in_(SETTING_KEYS))
        return {str(row.key): str(row.value) for row in connection.execute(query)}


def user_names(kit: Kit) -> list[str]:
    with kit.store.read() as connection:
        rows = connection.execute(sa.select(users.c.username).order_by(users.c.username))
        return [str(row.username) for row in rows]


def disabled_users(kit: Kit) -> list[str]:
    with kit.store.read() as connection:
        rows = connection.execute(sa.select(users.c.username).where(users.c.disabled.is_(True)))
        return sorted(str(row.username) for row in rows)


def audit_actions(kit: Kit) -> list[tuple[str, str, str | None]]:
    with kit.store.read() as connection:
        rows = connection.execute(sa.select(audit_events).order_by(audit_events.c.id))
        return [(str(row.actor), str(row.action), row.target) for row in rows]


def post(kit: Kit, session: Session, path: str, body: dict[str, Any]) -> Any:
    return kit.client.post(path, headers=session.headers(), json=body)


# -- who may call ---------------------------------------------------------------------------


def test_an_admin_reads_the_settings(kit: Kit) -> None:
    admin = kit.new_session("admin")
    response = kit.client.get("/settings", headers=admin.headers())
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["retention"] == {
        "days": 365,
        "default": 365,
        "min": 30,
        "max": 365,
        "runs_at_utc": "03:30",
    }
    storage = body["storage_warning"]
    assert (storage["gb"], storage["default"], storage["min"], storage["max"]) == (2, 2, 1, 1000)
    assert storage["used_bytes"] == body["about"]["database_bytes"] > 0
    assert [(user["username"], user["role"]) for user in body["users"]] == [
        ("admin", "admin"),
        ("operator", "operator"),
        ("viewer", "viewer"),
    ]
    for user in body["users"]:
        assert set(user) == {"id", "username", "role", "disabled", "locked", "created_at"}
    about = body["about"]
    assert about["version"] == __version__
    assert about["commit"]
    assert about["schema_revision"]
    # The kit's database has one push source and three users and has never run retention.
    assert (about["sources"], about["users"], about["last_retention_run"]) == (1, 3, None)


def test_the_answer_holds_no_hash_no_cookie_and_no_csrf_value(kit: Kit) -> None:
    admin = kit.new_session("admin")
    response = kit.client.get("/settings", headers=admin.headers())
    with kit.store.read() as connection:
        hashes = [str(row[0]) for row in connection.execute(sa.select(users.c.password_hash))]
    text = response.text + str(dict(response.headers))
    assert hashes
    for hidden in (*hashes, admin.cookie, admin.csrf, CORRECT, "argon2"):
        assert hidden not in text


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_a_viewer_and_an_operator_are_refused_everywhere_and_change_nothing(
    kit: Kit, role: str
) -> None:
    session = kit.new_session(role)
    assert kit.client.get("/settings", headers=session.headers()).status_code == 403
    for path, body in writes(kit):
        assert post(kit, session, path, body).status_code == 403, path
    assert stored_settings(kit) == {}
    assert user_names(kit) == ["admin", "operator", "viewer"]
    assert disabled_users(kit) == []


def test_nobody_gets_401_everywhere(kit: Kit) -> None:
    assert kit.client.get("/settings").status_code == 401
    for path, body in writes(kit):
        assert kit.client.post(path, json=body).status_code == 401, path
    assert stored_settings(kit) == {}
    assert user_names(kit) == ["admin", "operator", "viewer"]


def test_a_write_needs_the_csrf_value_and_the_configured_origin(kit: Kit) -> None:
    admin = kit.new_session("admin")
    attempts = {
        "no CSRF value": admin.headers(csrf=False),
        "a wrong CSRF value": {**admin.headers(), "X-CSRF-Token": "x" * len(admin.csrf)},
        "another origin": admin.headers(origin="https://evil.example"),
    }
    for name, headers in attempts.items():
        for path, body in writes(kit):
            response = kit.client.post(path, headers=headers, json=body)
            assert response.status_code == 403, (name, path)
    assert stored_settings(kit) == {}
    assert user_names(kit) == ["admin", "operator", "viewer"]
    assert disabled_users(kit) == []


def test_a_form_post_with_the_csrf_field_works_like_a_json_post(kit: Kit) -> None:
    admin = kit.new_session("admin")
    fields = {"retention_days": "120", "csrf_token": admin.csrf}
    response = kit.client.post(
        "/settings/retention", headers=admin.headers(csrf=False), data=fields
    )
    assert response.status_code == 200
    assert response.json() == {"retention_days": 120}
    assert stored_settings(kit) == {"retention_days": "120"}


# -- the two settings -----------------------------------------------------------------------


@pytest.mark.parametrize("value", ["30", "365", " 90 ", 45])
def test_a_retention_window_from_30_to_365_is_accepted(kit: Kit, value: Any) -> None:
    admin = kit.new_session("admin")
    response = post(kit, admin, "/settings/retention", {"retention_days": value})
    assert response.status_code == 200, response.text
    assert response.json() == {"retention_days": int(value)}
    assert stored_settings(kit) == {"retention_days": str(int(value))}
    shown = kit.client.get("/settings", headers=admin.headers()).json()
    assert shown["retention"]["days"] == int(value)


@pytest.mark.parametrize("value", ["29", "366", "abc", "", "3e1", "-30", "30.5", "9" * 30])
def test_a_bad_retention_window_is_422_with_the_field_and_stores_nothing(
    kit: Kit, value: str
) -> None:
    admin = kit.new_session("admin")
    response = post(kit, admin, "/settings/retention", {"retention_days": value})
    assert response.status_code == 422
    body = response.json()
    assert body["field"] == "retention_days"
    assert "30 to 365" in body["detail"]
    if value:
        assert value not in response.text
    assert stored_settings(kit) == {}


def test_a_missing_or_misshapen_retention_field_is_refused(kit: Kit) -> None:
    admin = kit.new_session("admin")
    assert post(kit, admin, "/settings/retention", {}).status_code == 422
    for body in ({"retention_days": 90.5}, {"retention_days": True}, {"retention_days": None}):
        assert post(kit, admin, "/settings/retention", body).status_code == 400, body
    assert stored_settings(kit) == {}


def test_an_unknown_field_is_refused_so_a_misspelt_value_is_never_ignored(kit: Kit) -> None:
    admin = kit.new_session("admin")
    for path, body in (
        ("/settings/retention", {"retention_days": "90", "retention_day": "1"}),
        ("/settings/storage-warning", {"storage_warning_gb": "9", "gb": "1"}),
        ("/settings/users", {"username": "ada", "password": NEW_PASSWORD, "admin": "yes"}),
    ):
        response = post(kit, admin, path, body)
        assert response.status_code == 422, path
        assert "unknown field" in response.json()["detail"]
    assert stored_settings(kit) == {}
    assert user_names(kit) == ["admin", "operator", "viewer"]


@pytest.mark.parametrize("value", ["1", "2", "1000", " 7 "])
def test_a_storage_warning_from_1_to_1000_gb_is_accepted(kit: Kit, value: str) -> None:
    admin = kit.new_session("admin")
    response = post(kit, admin, "/settings/storage-warning", {"storage_warning_gb": value})
    assert response.status_code == 200
    assert response.json() == {"storage_warning_gb": int(value)}
    shown = kit.client.get("/settings", headers=admin.headers()).json()
    assert shown["storage_warning"]["gb"] == int(value)


@pytest.mark.parametrize("value", ["0", "1001", "abc", "", "-1", "1.5"])
def test_a_bad_storage_warning_is_422_with_the_field_and_stores_nothing(
    kit: Kit, value: str
) -> None:
    admin = kit.new_session("admin")
    response = post(kit, admin, "/settings/storage-warning", {"storage_warning_gb": value})
    assert response.status_code == 422
    assert response.json()["field"] == "storage_warning_gb"
    assert stored_settings(kit) == {}


# -- users ----------------------------------------------------------------------------------


def test_an_admin_adds_a_user_who_can_then_sign_in(kit: Kit) -> None:
    admin = kit.new_session("admin")
    body = {"username": "Ada", "password": NEW_PASSWORD, "role": "operator"}
    response = post(kit, admin, "/settings/users", body)
    assert response.status_code == 201, response.text
    user = response.json()["user"]
    assert (user["username"], user["role"], user["disabled"], user["locked"]) == (
        "ada",
        "operator",
        False,
        False,
    )
    assert NEW_PASSWORD not in response.text
    assert "ada" in user_names(kit)
    login = kit.client.post("/login", data={"username": "ada", "password": NEW_PASSWORD})
    assert login.status_code == 303
    kit.client.cookies.clear()


def test_a_taken_name_is_409_and_a_bad_field_is_422_with_its_name(kit: Kit) -> None:
    admin = kit.new_session("admin")
    taken = post(kit, admin, "/settings/users", {"username": "VIEWER", "password": CORRECT})
    assert taken.status_code == 409
    assert "already taken" in taken.json()["detail"]
    cases = {
        "username": {"username": "ab", "password": NEW_PASSWORD, "role": "viewer"},
        "password": {"username": "ada", "password": SHORT_PASSWORD, "role": "viewer"},
        "role": {"username": "ada", "password": NEW_PASSWORD, "role": "root"},
    }
    for field, case in cases.items():
        response = post(kit, admin, "/settings/users", case)
        assert response.status_code == 422, field
        assert response.json()["field"] == field
        assert NEW_PASSWORD not in response.text
        assert SHORT_PASSWORD not in response.text
    assert user_names(kit) == ["admin", "operator", "viewer"]


def test_disabling_a_user_ends_their_session_and_enabling_restores_the_sign_in(kit: Kit) -> None:
    admin = kit.new_session("admin")
    operator = kit.new_session("operator")
    operator_id = kit.user_ids["operator"]
    assert kit.auth.authenticate(operator.cookie) is not None

    response = post(kit, admin, f"/settings/users/{operator_id}/disable", {})
    assert response.status_code == 200
    assert response.json() == {"id": operator_id, "disabled": True}
    assert kit.auth.authenticate(operator.cookie) is None
    assert disabled_users(kit) == ["operator"]
    login = kit.client.post("/login", data={"username": "operator", "password": CORRECT})
    assert login.status_code == 401

    response = post(kit, admin, f"/settings/users/{operator_id}/enable", {})
    assert response.status_code == 200
    assert response.json() == {"id": operator_id, "disabled": False}
    assert disabled_users(kit) == []
    login = kit.client.post("/login", data={"username": "operator", "password": CORRECT})
    assert login.status_code == 303
    kit.client.cookies.clear()


def test_an_unknown_user_is_404_and_a_bad_id_is_422(kit: Kit) -> None:
    admin = kit.new_session("admin")
    for action in ("disable", "enable"):
        assert post(kit, admin, f"/settings/users/99999/{action}", {}).status_code == 404
        assert post(kit, admin, f"/settings/users/0/{action}", {}).status_code == 422
        assert post(kit, admin, f"/settings/users/abc/{action}", {}).status_code == 422


def test_an_admin_cannot_disable_their_own_account_and_stays_signed_in(kit: Kit) -> None:
    admin = kit.new_session("admin")
    response = post(kit, admin, f"/settings/users/{kit.user_ids['admin']}/disable", {})
    assert response.status_code == 409
    assert "your own account" in response.json()["detail"]
    assert disabled_users(kit) == []
    assert kit.client.get("/settings", headers=admin.headers()).status_code == 200


def test_a_second_admin_may_disable_the_first_whose_session_then_ends(kit: Kit) -> None:
    admin = kit.new_session("admin")
    body = {"username": "boss", "password": NEW_PASSWORD, "role": "admin"}
    created = post(kit, admin, "/settings/users", body)
    assert created.status_code == 201
    boss_id = created.json()["user"]["id"]
    boss = kit.auth.login("boss", NEW_PASSWORD, "127.0.0.1")
    boss_session = Session(boss.cookie_value, boss.principal.csrf_token)
    first = post(kit, boss_session, f"/settings/users/{kit.user_ids['admin']}/disable", {})
    assert first.status_code == 200
    # The first admin's session ended with the disabling, so it cannot disable the second.
    assert post(kit, admin, f"/settings/users/{boss_id}/disable", {}).status_code == 401
    assert disabled_users(kit) == ["admin"]


# -- audit ----------------------------------------------------------------------------------


def test_every_write_is_audited_with_the_admin_as_actor_and_no_secret(kit: Kit) -> None:
    admin = kit.new_session("admin")
    viewer = kit.user_ids["viewer"]
    already = len(audit_actions(kit))  # the kit's own tokens were audited when it was built
    for path, body in (
        ("/settings/retention", {"retention_days": "90"}),
        ("/settings/storage-warning", {"storage_warning_gb": "5"}),
        ("/settings/users", {"username": "ada", "password": NEW_PASSWORD, "role": "viewer"}),
        (f"/settings/users/{viewer}/disable", {}),
        (f"/settings/users/{viewer}/enable", {}),
    ):
        assert post(kit, admin, path, body).status_code in (200, 201), path
    assert audit_actions(kit)[already:] == [
        ("admin", "settings.retention_days_changed", None),
        ("admin", "settings.storage_warning_changed", None),
        ("admin", "user.created", "ada"),
        ("admin", "user.disabled", "viewer"),
        ("admin", "user.enabled", "viewer"),
    ]
    with kit.store.read() as connection:
        text = str([tuple(row) for row in connection.execute(sa.select(audit_events))])
    assert NEW_PASSWORD not in text


def test_a_refused_write_leaves_no_audit_event(kit: Kit) -> None:
    admin = kit.new_session("admin")
    before = audit_actions(kit)
    assert post(kit, admin, "/settings/retention", {"retention_days": "29"}).status_code == 422
    assert post(kit, admin, "/settings/users", {"username": "x"}).status_code == 422
    assert audit_actions(kit) == before


# -- an application without the service -----------------------------------------------------


def test_the_routes_answer_503_when_the_application_has_no_settings_service(kit: Kit) -> None:
    grant = kit.auth.login("admin", CORRECT, "127.0.0.1")
    session = Session(grant.cookie_value, grant.principal.csrf_token)
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}), auth=kit.auth)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        assert client.get("/settings", headers=session.headers()).status_code == 503
        for path, body in writes(kit):
            response = client.post(path, headers=session.headers(), json=body)
            assert response.status_code == 503, path
