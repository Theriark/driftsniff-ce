"""Users, passwords, sign-in limits, sessions and the first-run setup code (docs/auth.md).

Rules, and why:

- Passwords are hashed with argon2id (64 MiB, 3 passes, 1 lane). They have 12 to 256 characters.
- A sign-in that fails gives one generic answer whatever the reason (unknown user, wrong password,
  disabled user, locked user), and an unknown user costs the same hashing work as a known one.
- At most 5 failures a minute per user name and per client address; after that every further
  failure doubles the wait (1, 2, 4 ... 60 seconds). 10 failures in a row lock the user for
  15 minutes. The per-address and per-name counters live in memory (the application runs one
  worker); the lock is stored with the user.
- The cookie value is 32 random bytes; the database keeps only its SHA-256. A session ends after
  8 hours without a request or 7 days after sign-in, on logout, or when its user is disabled.
- The first admin is created through the setup route, which needs a one-time code. Only the
  SHA-256 of the code is stored, the code is deleted when it is used, and once any admin exists
  the setup route does not exist (404).

Nothing here writes a password, a cookie value or a setup code to a log.
"""

import hashlib
import hmac
import math
import re
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Request, Response
from sqlalchemy import Connection
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError

from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    DEFAULT_WORKSPACE_ID,
    USER_ROLES,
    audit_events,
    sessions,
    settings,
    users,
)

SESSION_COOKIE: Final = "ds_session"
ROLE_RANK: Final = {role: rank for rank, role in enumerate(USER_ROLES, start=1)}

ARGON2_MEMORY_KIB: Final = 64 * 1024
ARGON2_TIME_COST: Final = 3
ARGON2_PARALLELISM: Final = 1
MIN_PASSWORD_CHARS: Final = 12
MAX_PASSWORD_CHARS: Final = 256

FAILURES_PER_MINUTE: Final = 5
THROTTLE_WINDOW: Final = timedelta(seconds=60)
MAX_DELAY_SECONDS: Final = 60
LOCK_AFTER_FAILURES: Final = 10
LOCK_DURATION: Final = timedelta(minutes=15)
_MAX_THROTTLE_KEYS: Final = 4096
_MAX_NAME_KEY_CHARS: Final = 128

IDLE_TIMEOUT: Final = timedelta(hours=8)
ABSOLUTE_LIFETIME: Final = timedelta(days=7)
LAST_SEEN_REFRESH: Final = timedelta(seconds=60)
_MAX_COOKIE_CHARS: Final = 128
_TOKEN_BYTES: Final = 32

SETUP_CODE_SETTING: Final = "setup_code_hash"
_CODE_ALPHABET: Final = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_GROUPS: Final = 4
_CODE_GROUP_CHARS: Final = 4

ACTOR_SYSTEM: Final = "system"
ACTION_SETUP_COMPLETED: Final = "setup.completed"
ACTION_USER_CREATED: Final = "user.created"
ACTION_USER_LOCKED: Final = "user.locked"
ACTION_USER_DISABLED: Final = "user.disabled"
ACTION_USER_ENABLED: Final = "user.enabled"

_TIME_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"
_ACCOUNT_COLUMNS: Final = (
    users.c.id,
    users.c.username,
    users.c.password_hash,
    users.c.role,
    users.c.disabled,
    users.c.locked_until,
)
_SESSION_COLUMNS: Final = (
    sessions.c.id,
    sessions.c.user_id,
    sessions.c.csrf_token,
    sessions.c.last_seen_at,
    sessions.c.expires_at,
    users.c.username,
    users.c.role,
    users.c.disabled,
)
_USERNAME: Final = re.compile(r"[a-z0-9][a-z0-9._@+-]{2,63}")


class AuthError(Exception):
    """Base class of the errors the sign-in code raises; messages never hold secrets."""


class LoginFailedError(AuthError):
    """The sign-in failed. The reason is deliberately not told."""


class LoginThrottledError(AuthError):
    """Too many failures: try again after ``retry_after`` seconds."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("too many failed attempts")
        self.retry_after = retry_after


class SetupUnavailableError(AuthError):
    """An admin already exists, so the setup code and the setup route are gone."""


class SetupCodeError(AuthError):
    """The setup code is wrong, already used or was never issued."""


class UsernameError(AuthError, ValueError):
    """The user name does not follow the rules, or is already taken."""


class UsernameTakenError(UsernameError):
    """The user name follows the rules but another user already has it."""


class PasswordPolicyError(AuthError, ValueError):
    """The password is shorter than 12 or longer than 256 characters."""


class LastAdminError(AuthError):
    """The change would leave no enabled admin."""


@dataclass(frozen=True, slots=True)
class UserSummary:
    """A user as an admin may list them: never the password hash."""

    user_id: int
    username: str
    role: str
    disabled: bool
    locked: bool
    created_at: str


@dataclass(frozen=True, slots=True)
class Principal:
    """The signed-in user a request belongs to."""

    user_id: int
    username: str
    role: str
    session_id: int
    csrf_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class SessionGrant:
    """A new session: the cookie value (shown once, to the browser) and who it belongs to."""

    cookie_value: str = field(repr=False)
    principal: Principal


def make_password_hasher(
    *,
    memory_kib: int = ARGON2_MEMORY_KIB,
    time_cost: int = ARGON2_TIME_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> PasswordHasher:
    """The argon2id hasher; the defaults are the production parameters."""
    return PasswordHasher(time_cost=time_cost, memory_cost=memory_kib, parallelism=parallelism)


def check_password_policy(password: str) -> None:
    """Raise PasswordPolicyError unless the password has 12 to 256 characters."""
    if len(password) < MIN_PASSWORD_CHARS:
        raise PasswordPolicyError(
            f"the password must have at least {MIN_PASSWORD_CHARS} characters"
        )
    if len(password) > MAX_PASSWORD_CHARS:
        raise PasswordPolicyError(f"the password must have at most {MAX_PASSWORD_CHARS} characters")


def normalise_username(raw: str) -> str:
    """The stored form of a user name (trimmed, lower case); UsernameError for a bad name."""
    name = raw.strip().lower()
    if _USERNAME.fullmatch(name) is None:
        raise UsernameError(
            "the user name must have 3 to 64 characters: letters, digits and . _ @ + - "
            "(it starts with a letter or a digit)"
        )
    return name


def stamp(moment: datetime) -> str:
    """UTC ISO 8601 text ending in Z, the format of every stored timestamp."""
    return moment.astimezone(UTC).strftime(_TIME_FORMAT)


def parse_stamp(text: str) -> datetime:
    """The inverse of :func:`stamp`."""
    return datetime.strptime(text, _TIME_FORMAT).replace(tzinfo=UTC)


def hash_cookie_value(value: str) -> str:
    """The SHA-256 (hex) of a session cookie value: the only form that is stored."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalise_code(code: str) -> str:
    return re.sub(r"[\s-]", "", code).upper()


def _hash_code(code: str) -> str:
    return hashlib.sha256(_normalise_code(code).encode("utf-8")).hexdigest()


def new_setup_code() -> str:
    """A fresh code of 16 characters (about 79 bits) in four groups, easy to read aloud."""
    groups = [
        "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_GROUP_CHARS))
        for _ in range(_CODE_GROUPS)
    ]
    return "-".join(groups)


def request_is_https(request: Request, *, trusted_proxy: bool) -> bool:
    """True when the request reached the application over HTTPS.

    The forwarded scheme counts only when DRIFTSNIFF_TRUSTED_PROXY says the proxy is trusted.
    """
    if request.url.scheme == "https":
        return True
    if trusted_proxy:
        forwarded = request.headers.get("x-forwarded-proto", "")
        return forwarded.split(",")[0].strip().lower() == "https"
    return False


def set_session_cookie(response: Response, value: str, *, secure: bool) -> None:
    """Attach the session cookie: HttpOnly, SameSite Lax, Secure over HTTPS."""
    response.set_cookie(
        SESSION_COOKIE, value, httponly=True, samesite="lax", secure=secure, path="/"
    )


def clear_session_cookie(response: Response, *, secure: bool) -> None:
    """Ask the browser to drop the session cookie."""
    response.delete_cookie(SESSION_COOKIE, httponly=True, samesite="lax", secure=secure, path="/")


@dataclass(slots=True)
class _Failures:
    times: list[datetime] = field(default_factory=list)
    blocked_until: datetime | None = None


class LoginThrottle:
    """Failure counters per key (a user name or a client address), with an exponential wait.

    A key with 5 failures inside the last minute is refused until ``blocked_until``; the wait
    starts at 1 second and doubles with every further failure, up to 60 seconds. A key that has
    been quiet for a minute starts again.
    """

    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, _Failures] = OrderedDict()

    def retry_after(self, key: str) -> int:
        """Seconds to wait before the key may try again; 0 when it may."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.blocked_until is None:
                return 0
            remaining = (entry.blocked_until - self._clock()).total_seconds()
            return math.ceil(remaining) if remaining > 0 else 0

    def record_failure(self, key: str) -> None:
        """Count one failure and, from the fifth in a minute on, start or double the wait."""
        now = self._clock()
        with self._lock:
            entry = self._entries.pop(key, None) or _Failures()
            entry.times = [t for t in entry.times if now - t < THROTTLE_WINDOW]
            entry.times.append(now)
            excess = len(entry.times) - FAILURES_PER_MINUTE
            if excess >= 0:
                delay = min(2 ** min(excess, 6), MAX_DELAY_SECONDS)
                entry.blocked_until = now + timedelta(seconds=delay)
            self._entries[key] = entry
            while len(self._entries) > _MAX_THROTTLE_KEYS:
                self._entries.popitem(last=False)

    def clear(self, key: str) -> None:
        """Forget the key (after a successful sign-in)."""
        with self._lock:
            self._entries.pop(key, None)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuthService:
    """Everything about who may sign in: users, sessions, throttling and the setup code."""

    def __init__(
        self,
        database: Database,
        *,
        clock: Callable[[], datetime] = _utc_now,
        hasher: PasswordHasher | None = None,
    ) -> None:
        self._db = database
        self._clock = clock
        self._hasher = make_password_hasher() if hasher is None else hasher
        self._throttle = LoginThrottle(clock)
        self._dummy_hash: str | None = None

    # -- passwords -----------------------------------------------------------------------------

    def _dummy(self) -> str:
        """A hash of a random password, checked when the user is unknown, disabled or locked."""
        if self._dummy_hash is None:
            self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(24))
        return self._dummy_hash

    def _verify(self, stored_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(stored_hash, password)
        except (VerificationError, InvalidHashError):
            return False

    def now(self) -> datetime:
        """The current time of this service (its injected clock)."""
        return self._clock()

    # -- users ---------------------------------------------------------------------------------

    def has_admin(self) -> bool:
        """True when any user has the admin role (a disabled admin still counts)."""
        with self._db.read() as connection:
            return _admin_exists(connection)

    def create_user(
        self, username: str, password: str, role: str, *, actor: str = ACTOR_SYSTEM
    ) -> int:
        """Add a user and return the id; UsernameError, PasswordPolicyError or ValueError.

        ``actor`` is the user name the audit event ``user.created`` is written for.
        """
        if role not in ROLE_RANK:
            raise ValueError(f"the role must be one of: {', '.join(USER_ROLES)}")
        name = normalise_username(username)
        check_password_policy(password)
        password_hash = self._hasher.hash(password)
        now = self._clock()
        with self._db.write() as connection:
            user_id = _insert_user(connection, name, password_hash, role, now)
            _audit(connection, now, actor, ACTION_USER_CREATED, name, {"role": role})
        return user_id

    def list_users(self) -> tuple[UserSummary, ...]:
        """Every user, by name, with the role, the disabled flag and whether a lock is running."""
        now = self._clock()
        with self._db.read() as connection:
            rows = connection.execute(
                sa.select(
                    users.c.id,
                    users.c.username,
                    users.c.role,
                    users.c.disabled,
                    users.c.locked_until,
                    users.c.created_at,
                ).order_by(users.c.username)
            ).all()
        return tuple(
            UserSummary(
                user_id=int(row.id),
                username=str(row.username),
                role=str(row.role),
                disabled=bool(row.disabled),
                locked=row.locked_until is not None and now < parse_stamp(row.locked_until),
                created_at=str(row.created_at),
            )
            for row in rows
        )

    def set_user_disabled(
        self, user_id: int, *, disabled: bool, actor: str, keep_one_admin: bool = False
    ) -> bool:
        """Disable or enable a user. Disabling ends every session of the user at once.

        Returns False when no such user exists. With ``keep_one_admin``, disabling the only
        enabled admin raises LastAdminError and changes nothing (checked in the same transaction).
        """
        now = self._clock()
        with self._db.write() as connection:
            row = connection.execute(
                sa.select(users.c.username, users.c.role, users.c.disabled).where(
                    users.c.id == user_id
                )
            ).first()
            if row is None:
                return False
            if keep_one_admin and disabled and row.role == "admin" and not row.disabled:
                others = connection.execute(
                    sa.select(users.c.id)
                    .where(users.c.role == "admin", users.c.disabled.is_(False))
                    .where(users.c.id != user_id)
                    .limit(1)
                ).first()
                if others is None:
                    raise LastAdminError("at least one admin must stay enabled")
            connection.execute(
                sa.update(users).where(users.c.id == user_id).values(disabled=disabled)
            )
            if disabled:
                connection.execute(sa.delete(sessions).where(sessions.c.user_id == user_id))
            action = ACTION_USER_DISABLED if disabled else ACTION_USER_ENABLED
            _audit(connection, now, actor, action, row.username, None)
        return True

    # -- sign-in -------------------------------------------------------------------------------

    def login(self, username: str, password: str, address: str) -> SessionGrant:
        """Check the credentials and start a session.

        Raises LoginThrottledError while the user name or the address must wait, and
        LoginFailedError (always the same message) for every other failure.
        """
        name = username.strip().lower()
        keys = (f"ip:{address}", f"user:{name[:_MAX_NAME_KEY_CHARS]}")
        wait = max(self._throttle.retry_after(key) for key in keys)
        if wait > 0:
            raise LoginThrottledError(wait)
        with self._db.read() as connection:
            query = sa.select(*_ACCOUNT_COLUMNS).where(users.c.username == name)
            row = connection.execute(query).first()
        now = self._clock()
        account = row
        if account is not None and (
            account.disabled
            or (account.locked_until is not None and now < parse_stamp(account.locked_until))
        ):
            account = None
        candidate = password if len(password) <= MAX_PASSWORD_CHARS else ""
        stored_hash = self._dummy() if account is None else account.password_hash
        verified = self._verify(stored_hash, candidate)
        if account is None or not verified:
            self._register_failure(keys, None if account is None else account.id, now)
            raise LoginFailedError("invalid user name or password")
        new_hash = None
        if self._hasher.check_needs_rehash(stored_hash):
            new_hash = self._hasher.hash(password)
        with self._db.write() as connection:
            values: dict[str, Any] = {"failed_logins": 0, "locked_until": None}
            if new_hash is not None:
                values["password_hash"] = new_hash
            connection.execute(sa.update(users).where(users.c.id == account.id).values(**values))
            grant = _start_session(connection, account.id, account.username, account.role, now)
        self._throttle.clear(keys[1])
        return grant

    def _register_failure(self, keys: tuple[str, str], user_id: int | None, now: datetime) -> None:
        for key in keys:
            self._throttle.record_failure(key)
        if user_id is None:
            return
        with self._db.write() as connection:
            connection.execute(
                sa.update(users)
                .where(users.c.id == user_id)
                .values(failed_logins=users.c.failed_logins + 1)
            )
            row = connection.execute(
                sa.select(users.c.username, users.c.failed_logins).where(users.c.id == user_id)
            ).one()
            if row.failed_logins >= LOCK_AFTER_FAILURES:
                connection.execute(
                    sa.update(users)
                    .where(users.c.id == user_id)
                    .values(failed_logins=0, locked_until=stamp(now + LOCK_DURATION))
                )
                _audit(connection, now, ACTOR_SYSTEM, ACTION_USER_LOCKED, row.username, None)

    # -- sessions ------------------------------------------------------------------------------

    def authenticate(self, cookie_value: str | None) -> Principal | None:
        """The user a cookie value belongs to, or None (unknown, expired, idle, user disabled)."""
        if not cookie_value or len(cookie_value) > _MAX_COOKIE_CHARS:
            return None
        token_hash = hash_cookie_value(cookie_value)
        with self._db.read() as connection:
            query = sa.select(*_SESSION_COLUMNS).join(users, users.c.id == sessions.c.user_id)
            row = connection.execute(query.where(sessions.c.token_hash == token_hash)).first()
        if row is None:
            return None
        now = self._clock()
        last_seen = parse_stamp(row.last_seen_at)
        ended = now >= parse_stamp(row.expires_at) or now - last_seen >= IDLE_TIMEOUT
        if row.disabled or ended:
            with self._db.write() as connection:
                connection.execute(sa.delete(sessions).where(sessions.c.id == row.id))
            return None
        if now - last_seen >= LAST_SEEN_REFRESH:
            with self._db.write() as connection:
                connection.execute(
                    sa.update(sessions)
                    .where(sessions.c.id == row.id)
                    .values(last_seen_at=stamp(now))
                )
        return Principal(row.user_id, row.username, row.role, row.id, row.csrf_token)

    def logout(self, cookie_value: str) -> None:
        """Delete the session of the cookie value (nothing happens when there is none)."""
        with self._db.write() as connection:
            connection.execute(
                sa.delete(sessions).where(sessions.c.token_hash == hash_cookie_value(cookie_value))
            )

    # -- first-run setup -----------------------------------------------------------------------

    def issue_setup_code(self) -> str:
        """Make a new one-time setup code and return it, replacing an earlier code.

        Only the hash is stored, so this is the one time the code is visible. Raises
        SetupUnavailableError when an admin exists.
        """
        code = new_setup_code()
        with self._db.write() as connection:
            if _admin_exists(connection):
                raise SetupUnavailableError("an admin already exists")
            _store_code_hash(connection, code)
        return code

    def ensure_setup_code(self) -> str | None:
        """Issue a code when there is no admin and no unused code; None otherwise."""
        code = new_setup_code()
        with self._db.write() as connection:
            if _admin_exists(connection) or _stored_code_hash(connection) is not None:
                return None
            _store_code_hash(connection, code)
        return code

    def complete_setup(self, code: str, username: str, password: str, address: str) -> SessionGrant:
        """Create the first admin with the setup code and sign them in.

        SetupUnavailableError when an admin exists (the route answers 404), LoginThrottledError
        after repeated wrong codes, SetupCodeError for a wrong code, UsernameError or
        PasswordPolicyError for input that breaks the rules (the code stays valid then).
        """
        if self.has_admin():
            raise SetupUnavailableError("an admin already exists")
        throttle_key = f"setup:{address}"
        wait = self._throttle.retry_after(throttle_key)
        if wait > 0:
            raise LoginThrottledError(wait)
        with self._db.read() as connection:
            code_ok = _code_matches(_stored_code_hash(connection), code)
        if not code_ok:
            self._throttle.record_failure(throttle_key)
            raise SetupCodeError("the setup code is not valid")
        name = normalise_username(username)
        check_password_policy(password)
        password_hash = self._hasher.hash(password)
        now = self._clock()
        with self._db.write() as connection:
            if _admin_exists(connection):
                raise SetupUnavailableError("an admin already exists")
            # Deleting the row is the single use: a second request finds nothing to delete.
            used = connection.execute(
                sa.delete(settings).where(
                    settings.c.workspace_id == DEFAULT_WORKSPACE_ID,
                    settings.c.key == SETUP_CODE_SETTING,
                    settings.c.value == _hash_code(code),
                )
            )
            if used.rowcount != 1:
                raise SetupCodeError("the setup code is not valid")
            user_id = _insert_user(connection, name, password_hash, "admin", now)
            _audit(connection, now, name, ACTION_SETUP_COMPLETED, name, None)
            grant = _start_session(connection, user_id, name, "admin", now)
        self._throttle.clear(throttle_key)
        return grant


def _admin_exists(connection: Connection) -> bool:
    found = connection.execute(sa.select(users.c.id).where(users.c.role == "admin").limit(1))
    return found.first() is not None


def _stored_code_hash(connection: Connection) -> str | None:
    value = connection.execute(
        sa.select(settings.c.value).where(
            settings.c.workspace_id == DEFAULT_WORKSPACE_ID, settings.c.key == SETUP_CODE_SETTING
        )
    ).scalar()
    return None if value is None else str(value)


def _store_code_hash(connection: Connection, code: str) -> None:
    statement = sqlite_insert(settings).values(
        workspace_id=DEFAULT_WORKSPACE_ID, key=SETUP_CODE_SETTING, value=_hash_code(code)
    )
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=["workspace_id", "key"], set_={"value": statement.excluded.value}
        )
    )


def _code_matches(stored_hash: str | None, code: str) -> bool:
    presented = _hash_code(code)
    return stored_hash is not None and hmac.compare_digest(stored_hash, presented)


def _insert_user(
    connection: Connection, username: str, password_hash: str, role: str, now: datetime
) -> int:
    try:
        result = connection.execute(
            sa.insert(users).values(
                username=username,
                password_hash=password_hash,
                role=role,
                created_at=stamp(now),
            )
        )
    except IntegrityError as error:
        raise UsernameTakenError("that user name is already taken") from error
    return _inserted_id(result)


def _inserted_id(result: Any) -> int:
    """The primary key of the row an insert just made."""
    return int(result.inserted_primary_key[0])


def _start_session(
    connection: Connection, user_id: int, username: str, role: str, now: datetime
) -> SessionGrant:
    """Insert a session row and return its cookie value; ended sessions are cleaned up here."""
    connection.execute(
        sa.delete(sessions).where(
            sa.or_(
                sessions.c.expires_at <= stamp(now),
                sessions.c.last_seen_at <= stamp(now - IDLE_TIMEOUT),
            )
        )
    )
    cookie_value = secrets.token_urlsafe(_TOKEN_BYTES)
    csrf_token = secrets.token_urlsafe(_TOKEN_BYTES)
    result = connection.execute(
        sa.insert(sessions).values(
            user_id=user_id,
            token_hash=hash_cookie_value(cookie_value),
            csrf_token=csrf_token,
            created_at=stamp(now),
            last_seen_at=stamp(now),
            expires_at=stamp(now + ABSOLUTE_LIFETIME),
        )
    )
    session_id = _inserted_id(result)
    return SessionGrant(cookie_value, Principal(user_id, username, role, session_id, csrf_token))


def _audit(
    connection: Connection,
    now: datetime,
    actor: str,
    action: str,
    target: str | None,
    detail: dict[str, str] | None,
) -> None:
    connection.execute(
        sa.insert(audit_events).values(
            at=stamp(now), actor=actor, action=action, target=target, detail=detail
        )
    )
