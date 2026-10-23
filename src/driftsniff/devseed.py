"""Development-only test accounts for browser checks (docs/dev-test-accounts.md).

The command ``driftsniff seed-dev-accounts`` makes one account per role (admin, operator, viewer)
so the crew can sign in to the Development site in a real browser. Rules, and why:

- It refuses to run unless ``DRIFTSNIFF_DEV_SEED=development-only`` is set and the installation
  looks like Development (a ``ce-dev-<name>.theriark.dev`` address or localhost, and no other
  environment badge).
  Stage and Production never set the switch, and their addresses are refused even when it leaks.
- Passwords are made at run time (32 random characters from letters, digits and ``- _ . +``) and
  are never printed or logged. They go into one file in the data directory that only the process
  user can read; whoever registers the accounts reads that file once and deletes it.
- It is safe to run twice: an account that exists is left alone (its password is not known, so
  nothing is written for it). ``--reset-passwords`` replaces the password of the three accounts,
  clears a lock and ends their sessions; that is the way to get new credentials after a loss.
"""

import json
import os
import secrets
import string
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import sqlalchemy as sa
from argon2 import PasswordHasher

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import audit_events, sessions, users
from driftsniff.web.auth import (
    ACTOR_SYSTEM,
    AuthService,
    UsernameError,
    make_password_hasher,
    stamp,
)

MARKER_VARIABLE: Final = "DRIFTSNIFF_DEV_SEED"
MARKER_VALUE: Final = "development-only"
CREDENTIALS_FILE_NAME: Final = "dev-seed-credentials.json"
ACTION_CREDENTIALS_RESET: Final = "user.credentials_reset"

# The roles of the product, highest first; each gets one account named dev-<role>@theriark.dev.
SEED_ROLES: Final = ("admin", "operator", "viewer")
USERNAME_DOMAIN: Final = "theriark.dev"
PASSWORD_CHARS: Final = 32

_DEV_HOST_PREFIX: Final = "ce-dev-"
_DEV_HOST_SUFFIX: Final = ".theriark.dev"
_LOCAL_HOSTS: Final = ("localhost", "127.0.0.1", "::1")
_ALNUM: Final = string.ascii_letters + string.digits
_CHAR_POOL: Final = _ALNUM + "-_.+"


class DevSeedError(Exception):
    """The seed cannot run or cannot finish; messages never hold a password."""


class DevSeedRefusedError(DevSeedError):
    """The installation is not marked as Development, so nothing was changed."""


@dataclass(frozen=True, slots=True)
class SeedReport:
    """What a run did, by role; ``credentials_path`` is set when passwords were written."""

    created: tuple[str, ...]
    reset: tuple[str, ...]
    existing: tuple[str, ...]
    credentials_path: Path | None


def username_for(role: str) -> str:
    """The user name of a role's test account."""
    return f"dev-{role}@{USERNAME_DOMAIN}"


def new_password() -> str:
    """A throwaway password; it starts with a letter or digit so a command line takes it."""
    middle = "".join(secrets.choice(_CHAR_POOL) for _ in range(PASSWORD_CHARS - 2))
    return secrets.choice(_ALNUM) + middle + secrets.choice(_ALNUM)


def check_development_only(settings: Settings, env: Mapping[str, str]) -> None:
    """Raise DevSeedRefusedError unless the switch is set and the address is a Development one."""
    if env.get(MARKER_VARIABLE, "").strip() != MARKER_VALUE:
        raise DevSeedRefusedError(
            f"refused: this command is for Development only; set {MARKER_VARIABLE}={MARKER_VALUE} "
            "in the Development container (never on Stage or Production)"
        )
    host = (urlsplit(settings.base_url).hostname or "").lower()
    is_dev_host = host.startswith(_DEV_HOST_PREFIX) and host.endswith(_DEV_HOST_SUFFIX)
    if host not in _LOCAL_HOSTS and not is_dev_host:
        raise DevSeedRefusedError(
            "refused: DRIFTSNIFF_BASE_URL is not a Development address "
            f"(expected {_DEV_HOST_PREFIX}<name>{_DEV_HOST_SUFFIX} or localhost)"
        )
    label = settings.environment_label.lower()
    if label and "dev" not in label:
        raise DevSeedRefusedError(
            "refused: DRIFTSNIFF_ENVIRONMENT_LABEL names an environment other than Development"
        )


def seed_dev_accounts(
    database: Database,
    credentials_path: Path,
    *,
    reset_passwords: bool = False,
    hasher: PasswordHasher | None = None,
) -> SeedReport:
    """Create the missing test accounts (and, on request, replace the passwords of all three).

    The database must be migrated. New passwords are written to ``credentials_path`` before any
    account is changed, so a failure never loses a password that is in use.
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
    planned = {
        role: new_password() for role in SEED_ROLES if found.get(role) is None or reset_passwords
    }
    if planned:
        _write_credentials(credentials_path, planned)
    created: list[str] = []
    reset: list[str] = []
    existing: list[str] = []
    for role in SEED_ROLES:
        row = found.get(role)
        if row is None:
            try:
                auth.create_user(username_for(role), planned[role], role)
            except UsernameError as error:
                raise DevSeedError(
                    f"the user {username_for(role)} appeared while seeding; run the command again"
                ) from error
            created.append(role)
        elif reset_passwords:
            _reset_password(database, hasher, row[0], username_for(role), planned[role])
            reset.append(role)
        else:
            existing.append(role)
    return SeedReport(
        created=tuple(created),
        reset=tuple(reset),
        existing=tuple(existing),
        credentials_path=credentials_path if planned else None,
    )


def _existing_accounts(database: Database) -> dict[str, tuple[int, str]]:
    """The seed accounts that exist, by role: ``(user id, stored role)``."""
    names = {username_for(role): role for role in SEED_ROLES}
    query = sa.select(users.c.id, users.c.username, users.c.role)
    query = query.where(users.c.username.in_(list(names)))
    with database.read() as connection:
        rows = connection.execute(query).all()
    return {names[row.username]: (int(row.id), str(row.role)) for row in rows}


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


def _write_credentials(path: Path, passwords: Mapping[str, str]) -> None:
    """Merge the new passwords into the file and replace it in one step (mode 0600)."""
    accounts: dict[str, dict[str, str]] = {}
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = None
    if isinstance(previous, dict) and isinstance(previous.get("accounts"), dict):
        accounts.update(
            {
                role: entry
                for role, entry in previous["accounts"].items()
                if role in SEED_ROLES and isinstance(entry, dict)
            }
        )
    for role, password in passwords.items():
        accounts[role] = {"username": username_for(role), "password": password}
    document = json.dumps({"version": 1, "accounts": accounts}, indent=2, sort_keys=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.unlink(missing_ok=True)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(document + "\n")
        os.replace(temporary, path)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise DevSeedError(f"could not write the credentials file: {error.strerror}") from error
