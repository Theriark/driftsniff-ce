"""The admin settings service (P10-T8 slice A, docs/settings.md): retention, storage warning, users.

Everything here is for an admin; the routes (``driftsniff.web.routes_settings``) check the role.
The service reads and writes through the one ``Database`` and writes one audit event for each
change, with the old and the new value of a setting (numbers) or the user name and role of a user
change. An audit event never holds a password, a hash or a token.

* Retention window: ``retention_days``, 30 to 365; the nightly job reads the row.
* Storage warning: ``storage_warning_gb``, 1 to 1000; the storage card of the start page reads it.
* Users: list, add, disable and enable. Disabling ends the user's sessions (``AuthService``). The
  admin cannot disable their own account, and the last enabled admin cannot be disabled by anyone.
* About: version, schema revision, database size, counts and the last retention run (counts only).
"""

from dataclasses import dataclass
from typing import Any, Final

import sqlalchemy as sa

from driftsniff import __version__
from driftsniff.db.engine import Database
from driftsniff.db.migrate import current_revisions
from driftsniff.db.tables import USER_ROLES, audit_events, sources
from driftsniff.sources.retention import (
    ACTION_RETENTION_RUN,
    DEFAULT_RETENTION_DAYS,
    RETENTION_DAYS_SETTING,
    RUN_HOUR_UTC,
    RUN_MINUTE_UTC,
    retention_days,
)
from driftsniff.web.auth import (
    AuthService,
    LastAdminError,
    PasswordPolicyError,
    UsernameError,
    UsernameTakenError,
    UserSummary,
    stamp,
)
from driftsniff.web.dashboard import storage_bytes
from driftsniff.web.settings_store import (
    DEFAULT_STORAGE_WARNING_GB,
    MAX_STORAGE_WARNING_GB,
    MIN_STORAGE_WARNING_GB,
    STORAGE_WARNING_SETTING,
    SettingInputError,
    parse_retention_days,
    parse_storage_warning_gb,
    storage_warning_gb,
    write_setting,
)

ACTION_RETENTION_CHANGED: Final = "settings.retention_days_changed"
ACTION_STORAGE_CHANGED: Final = "settings.storage_warning_changed"
FIELD_USERNAME: Final = "username"
FIELD_PASSWORD: Final = "password"  # noqa: S105 - a form field name, not a password
FIELD_ROLE: Final = "role"
_LAST_RUN_KEYS: Final = ("events_deleted", "snapshots_thinned", "states_removed", "freed_bytes")


class SettingConflictError(Exception):
    """The change cannot be made now (a name is taken, the last admin, your own account)."""


@dataclass(frozen=True, slots=True)
class RetentionRun:
    """The last retention run the audit trail knows: when, and what it removed (counts only)."""

    at: str
    retention_days: int
    events_deleted: int
    snapshots_thinned: int
    states_removed: int
    freed_bytes: int


@dataclass(frozen=True, slots=True)
class About:
    """The About section: what runs, how big the database is and what it holds."""

    version: str
    schema_revision: str | None
    database_bytes: int
    sources: int
    users: int
    last_retention_run: RetentionRun | None


@dataclass(frozen=True, slots=True)
class Overview:
    """Everything the settings page shows."""

    retention_days: int
    default_retention_days: int
    retention_run_utc: str
    storage_warning_gb: int
    default_storage_warning_gb: int
    min_storage_warning_gb: int
    max_storage_warning_gb: int
    users: tuple[UserSummary, ...]
    about: About


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _last_run(row: Any) -> RetentionRun | None:
    if row is None:
        return None
    detail = row.detail if isinstance(row.detail, dict) else {}
    counts = {key: _int(detail.get(key)) for key in _LAST_RUN_KEYS}
    return RetentionRun(
        at=str(row.at),
        retention_days=_int(detail.get("retention_days")) or DEFAULT_RETENTION_DAYS,
        **counts,
    )


class SettingsService:
    """Reads and changes the admin settings and the users, on behalf of a named admin."""

    def __init__(self, database: Database, auth: AuthService) -> None:
        self._db = database
        self._auth = auth

    # -- reading -------------------------------------------------------------------------------

    def overview(self) -> Overview:
        """The settings, the users and the About data as of now."""
        users = self._auth.list_users()
        with self._db.read() as connection:
            days = retention_days(connection)
            warning = storage_warning_gb(connection)
            source_total = int(
                connection.execute(sa.select(sa.func.count()).select_from(sources)).scalar_one()
            )
            last = connection.execute(
                sa.select(audit_events.c.at, audit_events.c.detail)
                .where(audit_events.c.action == ACTION_RETENTION_RUN)
                .order_by(audit_events.c.id.desc())
                .limit(1)
            ).first()
        revisions = current_revisions(self._db)
        about = About(
            version=__version__,
            schema_revision=revisions[0] if revisions else None,
            database_bytes=storage_bytes(self._db.path),
            sources=source_total,
            users=len(users),
            last_retention_run=_last_run(last),
        )
        return Overview(
            retention_days=days,
            default_retention_days=DEFAULT_RETENTION_DAYS,
            retention_run_utc=f"{RUN_HOUR_UTC:02d}:{RUN_MINUTE_UTC:02d}",
            storage_warning_gb=warning,
            default_storage_warning_gb=DEFAULT_STORAGE_WARNING_GB,
            min_storage_warning_gb=MIN_STORAGE_WARNING_GB,
            max_storage_warning_gb=MAX_STORAGE_WARNING_GB,
            users=users,
            about=about,
        )

    # -- the two settings ----------------------------------------------------------------------

    def set_retention_days(self, raw: str | None, *, actor: str) -> int:
        """Store the retention window; SettingInputError (nothing stored) unless 30 to 365."""
        days = parse_retention_days(raw)
        with self._db.write() as connection:
            before = retention_days(connection)
            write_setting(connection, RETENTION_DAYS_SETTING, str(days))
            self._audit(connection, actor, ACTION_RETENTION_CHANGED, before, days)
        return days

    def set_storage_warning_gb(self, raw: str | None, *, actor: str) -> int:
        """Store the storage warning size; SettingInputError (nothing stored) unless 1 to 1000."""
        gigabytes = parse_storage_warning_gb(raw)
        with self._db.write() as connection:
            before = storage_warning_gb(connection)
            write_setting(connection, STORAGE_WARNING_SETTING, str(gigabytes))
            self._audit(connection, actor, ACTION_STORAGE_CHANGED, before, gigabytes)
        return gigabytes

    def _audit(
        self, connection: sa.Connection, actor: str, action: str, before: int, after: int
    ) -> None:
        # No target: the action names the setting, the detail holds the two numbers.
        connection.execute(
            sa.insert(audit_events).values(
                at=stamp(self._auth.now()),
                actor=actor,
                action=action,
                target=None,
                detail={"from": before, "to": after},
            )
        )

    # -- users ---------------------------------------------------------------------------------

    def add_user(self, username: str, password: str, role: str, *, actor: str) -> UserSummary:
        """Add a user. SettingInputError for a rule the input breaks (the message never holds the
        password), SettingConflictError when the name is taken.
        """
        wanted_role = role.strip().lower()
        if wanted_role not in USER_ROLES:
            allowed = ", ".join(USER_ROLES)
            raise SettingInputError(FIELD_ROLE, f"the role must be one of: {allowed}")
        try:
            user_id = self._auth.create_user(username, password, wanted_role, actor=actor)
        except UsernameTakenError as error:
            raise SettingConflictError(str(error)) from None
        except UsernameError as error:
            raise SettingInputError(FIELD_USERNAME, str(error)) from None
        except PasswordPolicyError as error:
            raise SettingInputError(FIELD_PASSWORD, str(error)) from None
        for user in self._auth.list_users():
            if user.user_id == user_id:
                return user
        raise SettingConflictError("the user was added and removed again")

    def set_user_disabled(self, user_id: int, *, disabled: bool, actor_id: int, actor: str) -> bool:
        """Disable or enable a user; False when there is no such user.

        SettingConflictError when an admin disables their own account or the last enabled admin.
        """
        if disabled and user_id == actor_id:
            raise SettingConflictError("you cannot disable your own account")
        try:
            return self._auth.set_user_disabled(
                user_id, disabled=disabled, actor=actor, keep_one_admin=True
            )
        except LastAdminError as error:
            raise SettingConflictError(str(error)) from None
