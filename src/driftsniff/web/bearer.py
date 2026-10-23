"""API bearer tokens: creation, listing, revocation and the check of a presented one.

Rules, and why (docs/api-access.md):

- A token is 32 random bytes in URL-safe base64 (43 characters). The full value is returned once,
  when it is made. The database keeps only its SHA-256 and the first 8 characters (the visible
  prefix), so a copy of the ``api_tokens`` table cannot be turned back into a token.
- A token has one or both scopes, ``read`` and ``enrich``. A scope is never implied by another one:
  a token that may only enrich cannot read the lists. It may carry an expiry and can be revoked;
  the last use is stored (at most once a minute).
- Clients send the token as ``Authorization: Bearer <token>``. The token is found by its hash (an
  indexed equality on a value the caller cannot choose), so no timing of a byte-by-byte
  comparison of the token exists to measure. The stored hash is compared once more in constant
  time.
- A missing, malformed, unknown, expired or revoked token, or one of a disabled user, is refused
  with one generic answer (401). A token without the scope a route needs gets 403.
- Creation, revocation and refusals write audit events. The events never hold a token value.
  Refusals of unknown or malformed tokens are anonymous traffic, so at most one event per kind a
  minute is written (the event says how many more were left out); a missing header writes none.

Nothing here writes a token value to a log.
"""

import hashlib
import hmac
import logging
import re
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, NoReturn

import sqlalchemy as sa
from sqlalchemy import Connection
from sqlalchemy.exc import SQLAlchemyError

from driftsniff.db.engine import Database
from driftsniff.db.tables import api_tokens, audit_events, users
from driftsniff.web.auth import parse_stamp, stamp

logger = logging.getLogger(__name__)

TOKEN_SCOPES: Final = ("read", "enrich")
TOKEN_BYTES: Final = 32
PREFIX_CHARS: Final = 8
MAX_NAME_CHARS: Final = 80
MAX_EXPIRY_DAYS: Final = 3650
LAST_USED_REFRESH: Final = timedelta(seconds=60)
FAILURE_AUDIT_INTERVAL: Final = timedelta(seconds=60)
_MAX_GATE_KEYS: Final = 256
# 32 bytes in unpadded URL-safe base64 are always 43 characters.
_TOKEN_SHAPE: Final = re.compile(r"[A-Za-z0-9_-]{43}")
_BEARER: Final = "bearer"

# Audit action and actor names, not secrets (the S105 hits are about the word "token").
ACTION_TOKEN_CREATED: Final = "token.created"  # noqa: S105
ACTION_TOKEN_REVOKED: Final = "token.revoked"  # noqa: S105
ACTION_TOKEN_REJECTED: Final = "token.rejected"  # noqa: S105
ACTION_TOKEN_FORBIDDEN: Final = "token.forbidden"  # noqa: S105
ACTOR_UNKNOWN_TOKEN: Final = "token:unknown"  # noqa: S105

STATUS_ACTIVE: Final = "active"
STATUS_EXPIRED: Final = "expired"
STATUS_REVOKED: Final = "revoked"

_TOKEN_COLUMNS: Final = (
    api_tokens.c.id,
    api_tokens.c.name,
    api_tokens.c.token_prefix,
    api_tokens.c.token_hash,
    api_tokens.c.scopes,
    api_tokens.c.last_used_at,
    api_tokens.c.expires_at,
    api_tokens.c.revoked_at,
    users.c.username,
    users.c.disabled,
)


class TokenError(Exception):
    """Base class of the errors this module raises; messages never hold a token value."""


class TokenInputError(TokenError, ValueError):
    """The name, scopes or expiry of a new token do not follow the rules."""


class TokenRejectedError(TokenError):
    """The presented token is missing, malformed, unknown, expired, revoked or its user is off.

    ``reason`` is for the audit log only; the answer to the client never tells it.
    """

    def __init__(self, reason: str) -> None:
        super().__init__("the API token is not valid")
        self.reason = reason


class TokenScopeError(TokenError):
    """The token is valid but does not carry the scope the route needs."""

    def __init__(self, scope: str) -> None:
        super().__init__("the API token does not have the scope this route needs")
        self.scope = scope


@dataclass(frozen=True, slots=True)
class TokenPrincipal:
    """The API token a request was made with (never its value)."""

    token_id: int
    name: str
    prefix: str
    scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TokenInfo:
    """What the list shows about a token: never the value and never the stored hash."""

    token_id: int
    name: str
    prefix: str
    scopes: tuple[str, ...]
    created_by: str
    last_used_at: str | None
    expires_at: str | None
    revoked_at: str | None

    def status(self, now: datetime) -> str:
        """``revoked``, ``expired`` or ``active`` at the given time."""
        if self.revoked_at is not None:
            return STATUS_REVOKED
        if self.expires_at is not None and now >= parse_stamp(self.expires_at):
            return STATUS_EXPIRED
        return STATUS_ACTIVE


@dataclass(frozen=True, slots=True)
class CreatedToken:
    """A new token: the value (shown once, to the admin who made it) and its list entry."""

    value: str = field(repr=False)
    info: TokenInfo


def hash_token(value: str) -> str:
    """The SHA-256 (hex) of a token: the only form that is stored."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalise_name(raw: str) -> str:
    """The stored form of a token name (trimmed, 1 to 80 printable characters)."""
    name = raw.strip()
    if not name or len(name) > MAX_NAME_CHARS or not name.isprintable():
        raise TokenInputError(
            f"the token name must have 1 to {MAX_NAME_CHARS} printable characters"
        )
    return name


def normalise_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    """The scopes of a new token, without duplicates and in a fixed order; TokenInputError."""
    wanted = set(scopes)
    if not wanted or wanted - set(TOKEN_SCOPES):
        raise TokenInputError(f"the scopes must be one or both of: {', '.join(TOKEN_SCOPES)}")
    return tuple(scope for scope in TOKEN_SCOPES if scope in wanted)


def bearer_value(header: str) -> str | None:
    """The token of an ``Authorization: Bearer <token>`` value; None when it has another shape."""
    scheme, _, rest = header.partition(" ")
    candidate = rest.strip()
    if scheme.lower() != _BEARER or _TOKEN_SHAPE.fullmatch(candidate) is None:
        return None
    return candidate


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _audit(
    connection: Connection,
    now: datetime,
    actor: str,
    action: str,
    target: str | None,
    detail: dict[str, Any] | None,
) -> None:
    connection.execute(
        sa.insert(audit_events).values(
            at=stamp(now), actor=actor, action=action, target=target, detail=detail
        )
    )


@dataclass(slots=True)
class _GateEntry:
    last_written: datetime
    suppressed: int = 0


class _FailureGate:
    """At most one audit event per key and minute; counts what it held back."""

    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, _GateEntry] = OrderedDict()

    def admit(self, key: str) -> int | None:
        """None when the event is held back; else how many were held back since the last one."""
        now = self._clock()
        with self._lock:
            entry = self._entries.pop(key, None)
            if entry is not None and now - entry.last_written < FAILURE_AUDIT_INTERVAL:
                entry.suppressed += 1
                self._entries[key] = entry
                return None
            held_back = 0 if entry is None else entry.suppressed
            self._entries[key] = _GateEntry(now)
            while len(self._entries) > _MAX_GATE_KEYS:
                self._entries.popitem(last=False)
            return held_back


class TokenService:
    """Makes, lists, revokes and checks API tokens."""

    def __init__(self, database: Database, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._db = database
        self._clock = clock
        self._gate = _FailureGate(clock)

    # -- management ----------------------------------------------------------------------------

    def create(
        self,
        *,
        user_id: int,
        actor: str,
        name: str,
        scopes: Iterable[str],
        expires_in_days: int | None = None,
    ) -> CreatedToken:
        """Make a token for a user and return its value, which is not stored and not shown again.

        TokenInputError for a name, scope list or expiry that breaks the rules.
        """
        clean_name = normalise_name(name)
        clean_scopes = normalise_scopes(scopes)
        if expires_in_days is not None and not 1 <= expires_in_days <= MAX_EXPIRY_DAYS:
            raise TokenInputError(f"the expiry must be 1 to {MAX_EXPIRY_DAYS} days")
        now = self._clock()
        expires_at = (
            None if expires_in_days is None else stamp(now + timedelta(days=expires_in_days))
        )
        value = secrets.token_urlsafe(TOKEN_BYTES)
        prefix = value[:PREFIX_CHARS]
        with self._db.write() as connection:
            result = connection.execute(
                sa.insert(api_tokens).values(
                    user_id=user_id,
                    name=clean_name,
                    token_prefix=prefix,
                    token_hash=hash_token(value),
                    scopes=list(clean_scopes),
                    expires_at=expires_at,
                )
            )
            primary_key = result.inserted_primary_key
            if primary_key is None:
                raise RuntimeError("the database returned no id for the new token")
            token_id = int(primary_key[0])
            _audit(
                connection,
                now,
                actor,
                ACTION_TOKEN_CREATED,
                prefix,
                {"name": clean_name, "scopes": list(clean_scopes), "expires_at": expires_at},
            )
        info = TokenInfo(token_id, clean_name, prefix, clean_scopes, actor, None, expires_at, None)
        return CreatedToken(value, info)

    def now(self) -> datetime:
        """The time of this service's clock; the admin routes report status at this time."""
        return self._clock()

    def list_tokens(self) -> list[TokenInfo]:
        """Every token, newest first; revoked and expired ones stay in the list."""
        query = (
            sa.select(*_TOKEN_COLUMNS)
            .join(users, users.c.id == api_tokens.c.user_id)
            .order_by(api_tokens.c.id.desc())
        )
        with self._db.read() as connection:
            rows = connection.execute(query).all()
        return [
            TokenInfo(
                row.id,
                row.name,
                row.token_prefix,
                tuple(row.scopes),
                row.username,
                row.last_used_at,
                row.expires_at,
                row.revoked_at,
            )
            for row in rows
        ]

    def revoke(self, token_id: int, *, actor: str) -> bool:
        """Revoke a token for good; False when it does not exist. A second call changes nothing."""
        now = self._clock()
        with self._db.write() as connection:
            row = connection.execute(
                sa.select(api_tokens.c.token_prefix, api_tokens.c.revoked_at).where(
                    api_tokens.c.id == token_id
                )
            ).first()
            if row is None:
                return False
            if row.revoked_at is None:
                connection.execute(
                    sa.update(api_tokens)
                    .where(api_tokens.c.id == token_id)
                    .values(revoked_at=stamp(now))
                )
                _audit(connection, now, actor, ACTION_TOKEN_REVOKED, row.token_prefix, None)
        return True

    # -- use -----------------------------------------------------------------------------------

    def authenticate(self, header: str | None, scope: str) -> TokenPrincipal:
        """The token of an ``Authorization`` value, when it is valid and carries ``scope``.

        Raises TokenRejectedError (401) or TokenScopeError (403).
        """
        if not header:
            raise TokenRejectedError("missing")
        presented = bearer_value(header)
        if presented is None:
            self._reject("malformed", scope)
        digest = hash_token(presented)
        query = (
            sa.select(*_TOKEN_COLUMNS)
            .join(users, users.c.id == api_tokens.c.user_id)
            .where(api_tokens.c.token_hash == digest)
        )
        with self._db.read() as connection:
            row = connection.execute(query).first()
        if row is None or not hmac.compare_digest(row.token_hash, digest):
            self._reject("unknown", scope)
        now = self._clock()
        if row.revoked_at is not None:
            self._reject(STATUS_REVOKED, scope, row)
        if row.expires_at is not None and now >= parse_stamp(row.expires_at):
            self._reject(STATUS_EXPIRED, scope, row)
        if row.disabled:
            self._reject("user disabled", scope, row)
        scopes = tuple(row.scopes)
        if scope not in scopes:
            self._note_failure(ACTION_TOKEN_FORBIDDEN, "scope", scope, row)
            raise TokenScopeError(scope)
        if row.last_used_at is None or now - parse_stamp(row.last_used_at) >= LAST_USED_REFRESH:
            self._record_use(row.id, now)
        return TokenPrincipal(row.id, row.name, row.token_prefix, scopes)

    def _record_use(self, token_id: int, now: datetime) -> None:
        """Store the time of use. The token is valid, so a database that cannot take this write
        (busy, full, read only) must not turn the request into a 500: the time is just not moved.
        """
        try:
            with self._db.write() as connection:
                connection.execute(
                    sa.update(api_tokens)
                    .where(api_tokens.c.id == token_id)
                    .values(last_used_at=stamp(now))
                )
        except SQLAlchemyError:
            logger.warning("the last use of an API token could not be stored")

    def _reject(self, reason: str, scope: str, row: Any = None) -> NoReturn:
        self._note_failure(ACTION_TOKEN_REJECTED, reason, scope, row)
        raise TokenRejectedError(reason)

    def _note_failure(self, action: str, reason: str, scope: str, row: Any) -> None:
        """Write one audit event for a refusal, unless one of its kind was written this minute."""
        prefix = None if row is None else row.token_prefix
        held_back = self._gate.admit(f"{action}:{reason}:{prefix}")
        if held_back is None:
            return
        actor = ACTOR_UNKNOWN_TOKEN if prefix is None else f"token:{prefix}"
        detail: dict[str, Any] = {"reason": reason, "scope": scope}
        if row is not None:
            detail["name"] = row.name
        if held_back:
            detail["held_back"] = held_back
        try:
            with self._db.write() as connection:
                _audit(connection, self._clock(), actor, action, prefix, detail)
        except SQLAlchemyError:
            # The refusal stands; a database that cannot take the event must not turn it into a 500.
            logger.warning("the audit event for a refused API token could not be written")
