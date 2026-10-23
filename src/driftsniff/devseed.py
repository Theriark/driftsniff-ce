"""Development-only test accounts for browser checks (docs/dev-test-accounts.md).

One account per role (admin, operator, viewer) lets the crew sign in to the Development site in a
real browser. The passwords are not made here: the deployment controller generates them from the
``token24`` entries of ``deploy/dokploy.json`` and hands them to the container as
``DRIFTSNIFF_DEV_<ROLE>_PASSWORD``. Rules, and why:

- At start-up the application seeds the accounts by itself, but only when all three password
  variables are set and ``DRIFTSNIFF_BASE_URL`` is a ``ce-dev-<name>.theriark.dev`` address (and no
  other environment badge is set). Stage and Production are prepared from the same manifest, so
  the address, not the presence of the variables, decides; their addresses are refused.
- The command ``driftsniff seed-dev-accounts`` does the same on request and additionally needs
  ``DRIFTSNIFF_DEV_SEED=development-only`` in its own environment (nothing in the repository sets
  it). ``--reset-passwords`` puts the configured passwords on accounts that already exist.
- It is safe to run on every start: an account that exists is left alone, so users and data are
  preserved and a second run changes nothing.
- A password is never printed, logged, written to a file or put in an error message.
"""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urlsplit

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy.exc import SQLAlchemyError

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import audit_events, sessions, users
from driftsniff.web.auth import (
    ACTOR_SYSTEM,
    AuthService,
    PasswordPolicyError,
    UsernameError,
    check_password_policy,
    make_password_hasher,
    stamp,
)

MARKER_VARIABLE: Final = "DRIFTSNIFF_DEV_SEED"
MARKER_VALUE: Final = "development-only"
ACTION_CREDENTIALS_RESET: Final = "user.credentials_reset"

# The roles of the product, highest first. The user name of each account is the role itself; the
# same names are the ``email`` and ``label`` of ``browserAccounts`` in deploy/dokploy.json.
SEED_ROLES: Final = ("admin", "operator", "viewer")

_DEV_HOST_PREFIX: Final = "ce-dev-"
_DEV_HOST_SUFFIX: Final = ".theriark.dev"
_LOCAL_HOSTS: Final = ("localhost", "127.0.0.1", "::1")

_LOG = logging.getLogger(__name__)


class DevSeedError(Exception):
    """The seed cannot run or cannot finish; messages never hold a password."""


class DevSeedRefusedError(DevSeedError):
    """The installation is not marked as Development, so nothing was changed."""


@dataclass(frozen=True, slots=True)
class SeedReport:
    """What a run did, by role.

    ``differing`` lists existing accounts whose stored password is not the configured one; they
    are left alone (use ``--reset-passwords``).
    """

    created: tuple[str, ...]
    reset: tuple[str, ...]
    existing: tuple[str, ...]
    differing: tuple[str, ...] = ()


def username_for(role: str) -> str:
    """The user name of a role's test account (the role itself)."""
    return role


def password_variable_for(role: str) -> str:
    """The environment variable that holds the password of a role's test account."""
    return f"DRIFTSNIFF_DEV_{role.upper()}_PASSWORD"


def _check_address(settings: Settings, *, allow_local: bool) -> None:
    host = (urlsplit(settings.base_url).hostname or "").lower()
    is_dev_host = host.startswith(_DEV_HOST_PREFIX) and host.endswith(_DEV_HOST_SUFFIX)
    if not is_dev_host and not (allow_local and host in _LOCAL_HOSTS):
        raise DevSeedRefusedError(
            "refused: DRIFTSNIFF_BASE_URL is not a Development address "
            f"(expected {_DEV_HOST_PREFIX}<name>{_DEV_HOST_SUFFIX}"
            f"{' or localhost' if allow_local else ''})"
        )
    label = settings.environment_label.lower()
    if label and "dev" not in label:
        raise DevSeedRefusedError(
            "refused: DRIFTSNIFF_ENVIRONMENT_LABEL names an environment other than Development"
        )


def check_development_only(settings: Settings, env: Mapping[str, str]) -> None:
    """The command's guard: the switch must be set and the address a Development one.

    A Development address is ``ce-dev-<name>.theriark.dev`` or localhost; otherwise
    DevSeedRefusedError is raised.
    """
    if env.get(MARKER_VARIABLE, "").strip() != MARKER_VALUE:
        raise DevSeedRefusedError(
            f"refused: this command is for Development only; set {MARKER_VARIABLE}={MARKER_VALUE} "
            "in the Development container (never on Stage or Production)"
        )
    _check_address(settings, allow_local=True)


def check_development_startup(settings: Settings) -> None:
    """The start-up guard: only a ``ce-dev-<name>.theriark.dev`` address passes (not localhost)."""
    _check_address(settings, allow_local=False)


def passwords_from_env(env: Mapping[str, str]) -> dict[str, str]:
    """The three configured passwords by role; DevSeedError (naming variables only) otherwise."""
    found = {role: env.get(password_variable_for(role), "") for role in SEED_ROLES}
    missing = [password_variable_for(role) for role, value in found.items() if not value]
    if missing:
        raise DevSeedError(f"the Development passwords are not configured: {', '.join(missing)}")
    for role, value in found.items():
        try:
            check_password_policy(value)
        except PasswordPolicyError as error:
            raise DevSeedError(
                f"{password_variable_for(role)} does not meet the password rules: {error}"
            ) from error
    return found


def seed_dev_accounts(
    database: Database,
    passwords: Mapping[str, str],
    *,
    reset_passwords: bool = False,
    hasher: PasswordHasher | None = None,
) -> SeedReport:
    """Create the missing test accounts with the configured passwords.

    An account that exists is left alone; with ``reset_passwords`` its password is replaced by the
    configured one, a lock and a disabled flag are cleared and its sessions end. The database must
    be migrated. A user name that exists with another role stops the run before any change.
    """
    hasher = make_password_hasher() if hasher is None else hasher
    auth = AuthService(database, hasher=hasher)
    found = _existing_accounts(database)
    for role in SEED_ROLES:
        row = found.get(role)
        if row is not None and row[1] != role:
            raise DevSeedError(
                f"the user {username_for(role)} exists with another role; not changed"
            )
    created: list[str] = []
    reset: list[str] = []
    existing: list[str] = []
    differing: list[str] = []
    for role in SEED_ROLES:
        row = found.get(role)
        if row is None:
            try:
                auth.create_user(username_for(role), passwords[role], role)
            except UsernameError as error:
                raise DevSeedError(
                    f"the user {username_for(role)} appeared while seeding; run it again"
                ) from error
            created.append(role)
        elif reset_passwords:
            _reset_password(database, hasher, row[0], username_for(role), passwords[role])
            reset.append(role)
        else:
            existing.append(role)
            if not _matches(hasher, row[2], passwords[role]):
                differing.append(role)
    return SeedReport(
        created=tuple(created),
        reset=tuple(reset),
        existing=tuple(existing),
        differing=tuple(differing),
    )


def seed_at_startup(
    settings: Settings, env: Mapping[str, str], database: Database
) -> SeedReport | None:
    """Seed the Development accounts when the container is configured for them.

    Returns None without any change or log line when no password variable is set (every
    Production start), and after one warning (variable names only) when the configuration is
    incomplete or the address is not a Development one (Stage). A failure is logged and never
    stops the application from starting; the database must be migrated.
    """
    configured = [role for role in SEED_ROLES if env.get(password_variable_for(role), "")]
    if not configured:
        return None
    try:
        check_development_startup(settings)
        report = seed_dev_accounts(database, passwords_from_env(env))
    except DevSeedRefusedError:
        _LOG.warning("development test accounts not seeded: this is not a Development address")
        return None
    except (DevSeedError, SQLAlchemyError) as error:
        _LOG.error("development test accounts not seeded: %s", error)
        return None
    for role in report.created:
        _LOG.info("development test account %s created", username_for(role))
    for role in report.differing:
        _LOG.warning(
            "development test account %s exists with another password than configured; "
            "run `driftsniff seed-dev-accounts --reset-passwords` to replace it",
            username_for(role),
        )
    if not report.created:
        _LOG.info("development test accounts already exist, unchanged")
    return report


def _existing_accounts(database: Database) -> dict[str, tuple[int, str, str]]:
    """The seed accounts that exist, by role: ``(user id, stored role, password hash)``."""
    names = {username_for(role): role for role in SEED_ROLES}
    query = sa.select(users.c.id, users.c.username, users.c.role, users.c.password_hash)
    query = query.where(users.c.username.in_(list(names)))
    with database.read() as connection:
        rows = connection.execute(query).all()
    return {
        names[row.username]: (int(row.id), str(row.role), str(row.password_hash)) for row in rows
    }


def _matches(hasher: PasswordHasher, stored_hash: str, password: str) -> bool:
    try:
        return hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def _reset_password(
    database: Database, hasher: PasswordHasher, user_id: int, username: str, password: str
) -> None:
    new_hash = hasher.hash(password)
    with database.write() as connection:
        connection.execute(
            sa.update(users)
            .where(users.c.id == user_id)
            .values(password_hash=new_hash, failed_logins=0, locked_until=None, disabled=False)
        )
        connection.execute(sa.delete(sessions).where(sessions.c.user_id == user_id))
        connection.execute(
            sa.insert(audit_events).values(
                at=stamp(datetime.now(UTC)),
                actor=ACTOR_SYSTEM,
                action=ACTION_CREDENTIALS_RESET,
                target=username,
                detail=None,
            )
        )
