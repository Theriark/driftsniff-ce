"""The admin settings service (P10-T8 slice A): retention window, storage warning, users, About.

The service runs on a migrated database with a cheap argon2 setting and a frozen clock. Passwords
are canaries that must never reach an audit event or a listed user.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pytest
import sqlalchemy as sa

from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    build_manifest,
    store_if_changed,
)
from driftsniff.db.engine import Database
from driftsniff.db.tables import audit_events, change_events, settings, users
from driftsniff.sources.retention import (
    DEFAULT_RETENTION_DAYS,
    RETENTION_DAYS_SETTING,
    retention_days,
    run_retention,
)
from driftsniff.web.auth import AuthService, make_password_hasher, stamp
from driftsniff.web.dashboard import STORAGE_WARNING_BYTES, DashboardService
from driftsniff.web.settings_service import SettingConflictError, SettingsService
from driftsniff.web.settings_store import (
    DEFAULT_STORAGE_WARNING_GB,
    STORAGE_WARNING_SETTING,
    SettingInputError,
    storage_warning_bytes,
    storage_warning_gb,
)

NOW: Final = datetime(2026, 10, 25, 3, 30, tzinfo=UTC)
CORRECT: Final = "CANARY-correct horse battery"
OTHER: Final = "CANARY-another horse battery"
RETENTION_RULE: Final = "the retention window in days must be a whole number from 30 to 365"
STORAGE_RULE: Final = "the storage warning size in gigabytes must be a whole number from 1 to 1000"
# Text that is never a whole number of days or gigabytes, whatever the range.
NOT_A_NUMBER: Final = (
    "",
    " ",
    "abc",
    "-30",
    "+30",
    "30.5",
    "3e1",
    "0x1e",
    "٣٠",  # Arabic-Indic digits that read 30
    "1" * 40,
    "0",
)


@pytest.fixture
def auth(store: Database) -> AuthService:
    return AuthService(
        store, clock=lambda: NOW, hasher=make_password_hasher(memory_kib=8, time_cost=1)
    )


@pytest.fixture
def service(store: Database, auth: AuthService) -> SettingsService:
    return SettingsService(store, auth)


@pytest.fixture
def admin_id(auth: AuthService) -> int:
    return auth.create_user("root", CORRECT, "admin")


def stored(store: Database, key: str) -> str | None:
    with store.read() as connection:
        query = sa.select(settings.c.value).where(settings.c.key == key)
        value = connection.execute(query).scalar_one_or_none()
    return None if value is None else str(value)


def audit(store: Database, action: str) -> list[Any]:
    with store.read() as connection:
        query = sa.select(audit_events).where(audit_events.c.action == action)
        return list(connection.execute(query))


def add_old_event(store: Database, days_old: int) -> None:
    created = stamp(NOW - timedelta(days=days_old))
    objects = [CollectedObject("n1", {"_id": "n1", "vlan": 10}, "Lab")]
    manifest = build_manifest({"networks": CollectedResource(objects)}, controller_version="10.0.1")
    with store.write() as connection:
        outcome = store_if_changed(connection, 1, manifest, taken_at=created)
        assert outcome.snapshot_id is not None
        connection.execute(
            sa.insert(change_events).values(
                source_id=1,
                snapshot_id=outcome.snapshot_id,
                window_start=created,
                window_end=created,
                max_severity="low",
                item_count=0,
                summary="a change",
                rule_pack_version="pack-1",
                status="open",
                created_at=created,
            )
        )


def event_count(store: Database) -> int:
    with store.read() as connection:
        count = connection.execute(sa.select(sa.func.count()).select_from(change_events))
        return int(count.scalar_one())


# -- the overview ---------------------------------------------------------------------------


def test_the_overview_of_a_new_installation_shows_the_defaults(
    service: SettingsService, admin_id: int
) -> None:
    view = service.overview()
    assert view.retention_days == DEFAULT_RETENTION_DAYS == 365
    assert view.storage_warning_gb == DEFAULT_STORAGE_WARNING_GB == 2
    assert view.retention_run_utc == "03:30"
    assert [user.username for user in view.users] == ["root"]
    assert view.about.users == 1
    assert view.about.sources == 1
    assert view.about.last_retention_run is None
    assert view.about.database_bytes > 0
    assert view.about.schema_revision is not None
    assert view.about.version


def test_the_default_storage_warning_matches_the_dashboard_constant() -> None:
    assert DEFAULT_STORAGE_WARNING_GB * 1024**3 == STORAGE_WARNING_BYTES


def test_the_overview_reports_the_last_retention_run_with_counts_only(
    store: Database, service: SettingsService
) -> None:
    run_retention(store, now=NOW - timedelta(days=1))
    result = run_retention(store, now=NOW)
    last = service.overview().about.last_retention_run
    assert last is not None
    assert last.at == stamp(NOW)
    assert last.retention_days == result.retention_days
    assert last.events_deleted == 0
    assert last.freed_bytes == result.freed_bytes


def test_a_damaged_retention_audit_row_reads_as_zero_counts(
    store: Database, service: SettingsService
) -> None:
    detail = {"events_deleted": "many", "freed_bytes": True}
    with store.write() as connection:
        connection.execute(
            sa.insert(audit_events).values(
                at=stamp(NOW), actor="system", action="retention.run", target=None, detail=detail
            )
        )
    last = service.overview().about.last_retention_run
    assert last is not None
    assert (last.events_deleted, last.freed_bytes) == (0, 0)
    assert last.retention_days == DEFAULT_RETENTION_DAYS


# -- the retention window -------------------------------------------------------------------


@pytest.mark.parametrize("value", ["30", "365", " 90 ", "100"])
def test_a_retention_window_from_30_to_365_is_stored(
    store: Database, service: SettingsService, value: str
) -> None:
    days = service.set_retention_days(value, actor="root")
    assert days == int(value)
    assert stored(store, RETENTION_DAYS_SETTING) == str(days)
    with store.read() as connection:
        assert retention_days(connection) == days


@pytest.mark.parametrize("value", [*NOT_A_NUMBER, "29", "366", None])
def test_a_bad_retention_window_is_refused_and_nothing_is_stored(
    store: Database, service: SettingsService, value: str | None
) -> None:
    with pytest.raises(SettingInputError) as caught:
        service.set_retention_days(value, actor="root")
    assert caught.value.field == "retention_days"
    assert str(caught.value) == RETENTION_RULE
    assert stored(store, RETENTION_DAYS_SETTING) is None
    assert audit(store, "settings.retention_days_changed") == []


def test_a_bad_value_keeps_the_window_that_was_set_before(
    store: Database, service: SettingsService
) -> None:
    service.set_retention_days("60", actor="root")
    with pytest.raises(SettingInputError):
        service.set_retention_days("29", actor="root")
    assert stored(store, RETENTION_DAYS_SETTING) == "60"


def test_each_retention_change_writes_one_audit_event_with_old_and_new(
    store: Database, service: SettingsService
) -> None:
    service.set_retention_days("90", actor="root")
    service.set_retention_days("45", actor="ada")
    rows = audit(store, "settings.retention_days_changed")
    changes = [(row.actor, row.target, row.detail) for row in rows]
    assert changes == [
        ("root", None, {"from": 365, "to": 90}),
        ("ada", None, {"from": 90, "to": 45}),
    ]
    assert rows[0].at == stamp(NOW)


def test_the_nightly_job_uses_the_window_an_admin_set(
    store: Database, service: SettingsService
) -> None:
    add_old_event(store, 40)
    run_retention(store, now=NOW)
    assert event_count(store) == 1  # 365 days by default keeps a 40 day old event
    service.set_retention_days("30", actor="root")
    result = run_retention(store, now=NOW)
    assert result.retention_days == 30
    assert result.events_deleted == 1
    assert event_count(store) == 0


# -- the storage warning --------------------------------------------------------------------


@pytest.mark.parametrize("value", ["1", "2", "1000", " 5 "])
def test_a_storage_warning_from_1_to_1000_gb_is_stored(
    store: Database, service: SettingsService, value: str
) -> None:
    gigabytes = service.set_storage_warning_gb(value, actor="root")
    assert gigabytes == int(value)
    assert stored(store, STORAGE_WARNING_SETTING) == str(gigabytes)
    with store.read() as connection:
        assert storage_warning_gb(connection) == gigabytes
        assert storage_warning_bytes(connection) == gigabytes * 1024**3


@pytest.mark.parametrize("value", [*NOT_A_NUMBER, "1001", None])
def test_a_bad_storage_warning_is_refused_and_nothing_is_stored(
    store: Database, service: SettingsService, value: str | None
) -> None:
    with pytest.raises(SettingInputError) as caught:
        service.set_storage_warning_gb(value, actor="root")
    assert caught.value.field == "storage_warning_gb"
    assert str(caught.value) == STORAGE_RULE
    assert stored(store, STORAGE_WARNING_SETTING) is None
    assert audit(store, "settings.storage_warning_changed") == []


def test_a_stored_garbage_storage_warning_reads_as_the_default(store: Database) -> None:
    with store.write() as connection:
        connection.execute(sa.insert(settings).values(key=STORAGE_WARNING_SETTING, value="lots"))
    with store.read() as connection:
        assert storage_warning_gb(connection) == DEFAULT_STORAGE_WARNING_GB


def test_a_storage_warning_change_is_audited_and_the_dashboard_card_follows_it(
    store: Database, service: SettingsService
) -> None:
    dashboard = DashboardService(store, clock=lambda: NOW)
    before = dashboard.load().stats[-1]
    assert "of the 2 GB warning size" in before.delta
    service.set_storage_warning_gb("7", actor="root")
    after = dashboard.load().stats[-1]
    assert "of the 7 GB warning size" in after.delta
    rows = audit(store, "settings.storage_warning_changed")
    assert [(row.actor, row.detail) for row in rows] == [("root", {"from": 2, "to": 7})]


# -- users ----------------------------------------------------------------------------------


def test_an_added_user_is_listed_without_a_hash_and_audited_with_the_admin_as_actor(
    store: Database, service: SettingsService, admin_id: int
) -> None:
    created = service.add_user(" Ada ", OTHER, " Operator ", actor="root")
    assert (created.username, created.role) == ("ada", "operator")
    assert created.disabled is False
    assert created.locked is False
    assert created.created_at == stamp(NOW)
    assert not hasattr(created, "password_hash")
    assert [user.username for user in service.overview().users] == ["ada", "root"]
    rows = audit(store, "user.created")
    created_rows = [(row.actor, row.target, row.detail) for row in rows if row.target == "ada"]
    assert created_rows == [("root", "ada", {"role": "operator"})]
    assert OTHER not in json.dumps([str(row) for row in rows])


def test_the_new_user_can_sign_in_with_the_password(
    service: SettingsService, auth: AuthService
) -> None:
    service.add_user("ada", OTHER, "viewer", actor="root")
    grant = auth.login("ada", OTHER, "127.0.0.1")
    assert grant.principal.role == "viewer"


def test_a_taken_user_name_is_a_conflict_whatever_its_case(
    service: SettingsService, admin_id: int
) -> None:
    with pytest.raises(SettingConflictError, match="already taken"):
        service.add_user("ROOT", OTHER, "viewer", actor="root")


@pytest.mark.parametrize(
    ("username", "password", "role", "field"),
    [
        ("ab", OTHER, "viewer", "username"),
        ("-ada", OTHER, "viewer", "username"),
        ("ada lovelace", OTHER, "viewer", "username"),
        ("ada", "short", "viewer", "password"),
        ("ada", "x" * 257, "viewer", "password"),
        ("ada", OTHER, "superuser", "role"),
        ("ada", OTHER, "", "role"),
    ],
)
def test_input_that_breaks_a_rule_names_its_field_and_adds_nobody(
    store: Database, service: SettingsService, username: str, password: str, role: str, field: str
) -> None:
    with pytest.raises(SettingInputError) as caught:
        service.add_user(username, password, role, actor="root")
    assert caught.value.field == field
    assert password not in str(caught.value)
    with store.read() as connection:
        assert connection.execute(sa.select(sa.func.count()).select_from(users)).scalar_one() == 0


def test_disabling_a_user_ends_their_sessions_and_enabling_lets_them_in_again(
    store: Database, service: SettingsService, auth: AuthService, admin_id: int
) -> None:
    ada_id = auth.create_user("ada", CORRECT, "operator")
    cookie = auth.login("ada", CORRECT, "127.0.0.1").cookie_value
    assert auth.authenticate(cookie) is not None
    assert service.set_user_disabled(ada_id, disabled=True, actor_id=admin_id, actor="root")
    assert auth.authenticate(cookie) is None
    listed = {user.username: user.disabled for user in service.overview().users}
    assert listed["ada"] is True
    assert service.set_user_disabled(ada_id, disabled=False, actor_id=admin_id, actor="root")
    assert auth.login("ada", CORRECT, "127.0.0.1").principal.username == "ada"
    assert [(row.actor, row.target) for row in audit(store, "user.disabled")] == [("root", "ada")]
    assert [(row.actor, row.target) for row in audit(store, "user.enabled")] == [("root", "ada")]


def test_an_unknown_user_is_reported_as_missing(service: SettingsService, admin_id: int) -> None:
    found = service.set_user_disabled(99999, disabled=True, actor_id=admin_id, actor="root")
    assert found is False


def test_an_admin_cannot_disable_their_own_account(
    store: Database, service: SettingsService, admin_id: int
) -> None:
    with pytest.raises(SettingConflictError, match="your own account"):
        service.set_user_disabled(admin_id, disabled=True, actor_id=admin_id, actor="root")
    assert audit(store, "user.disabled") == []


def test_the_last_enabled_admin_cannot_be_disabled_by_anyone(
    service: SettingsService, auth: AuthService, admin_id: int
) -> None:
    other_id = auth.create_user("boss", CORRECT, "admin")
    assert service.set_user_disabled(admin_id, disabled=True, actor_id=other_id, actor="boss")
    with pytest.raises(SettingConflictError, match="at least one admin"):
        service.set_user_disabled(other_id, disabled=True, actor_id=admin_id, actor="root")
    states = {user.username: user.disabled for user in service.overview().users}
    assert states == {"root": True, "boss": False}


def test_a_viewer_can_be_disabled_when_only_one_admin_exists(
    service: SettingsService, auth: AuthService, admin_id: int
) -> None:
    viewer_id = auth.create_user("vera", CORRECT, "viewer")
    assert service.set_user_disabled(viewer_id, disabled=True, actor_id=admin_id, actor="root")


def test_the_user_list_marks_a_running_lock(store: Database, auth: AuthService) -> None:
    ada_id = auth.create_user("ada", CORRECT, "viewer")
    auth.create_user("bob", CORRECT, "viewer")
    with store.write() as connection:
        locked_until = stamp(NOW + timedelta(minutes=15))
        connection.execute(
            sa.update(users).where(users.c.id == ada_id).values(locked_until=locked_until)
        )
    assert {user.username: user.locked for user in auth.list_users()} == {"ada": True, "bob": False}
    with store.write() as connection:
        connection.execute(
            sa.update(users).where(users.c.id == ada_id).values(locked_until=stamp(NOW))
        )
    assert {user.username: user.locked for user in auth.list_users()}["ada"] is False
