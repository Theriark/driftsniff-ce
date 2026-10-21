"""Source service: create, update, enable, disable and delete the systems driftsniff watches.

Rules this module enforces (docs/sources.md has the user view):

* A credential is encrypted with the credential key before it is stored and is never part of a
  return value, an audit event, a log line or an error message. ``SourceView`` only says whether
  one is stored. ``credential_for_collector`` is the single way to read it back; it is meant for
  the run pipeline that needs it to call the controller, not for anything a user sees.
* A base address must be https unless the source has the option ``allow_plain_http``. Setting
  that option writes the audit event ``source.allow_plain_http``. Addresses in the metadata and
  link-local ranges are refused in every case (``driftsniff.sources.addresses``).
* Deleting a source removes every row that belongs to it and the states that no snapshot refers
  to any more, in one transaction, and writes the audit event ``source.delete``.

Every change is a single transaction on the one writer connection (``Database.write()``).
"""

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.core.snapshots import gc_unreferenced_states
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    DEFAULT_WORKSPACE_ID,
    SOURCE_TYPES,
    acknowledgements,
    audit_events,
    change_events,
    change_items,
    enrichments,
    notes,
    notification_deliveries,
    objects,
    resource_coverage,
    runs,
    snapshots,
    sources,
)
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.sources.addresses import AddressError, validate_base_url

logger = logging.getLogger(__name__)

MAX_NAME_CHARS = 100
OPTION_ALLOW_PLAIN_HTTP = "allow_plain_http"
OPTION_INTERVAL_SECONDS = "interval_seconds"
DEFAULT_INTERVAL_SECONDS = 300
MIN_INTERVAL_SECONDS = 60
MAX_INTERVAL_SECONDS = 3600
# Option name to the type its value must have. Later phases add their options here.
ALLOWED_OPTIONS: Mapping[str, type] = {OPTION_ALLOW_PLAIN_HTTP: bool, OPTION_INTERVAL_SECONDS: int}
# Source types that read a controller and therefore need an address and a credential.
POLLED_TYPES = ("unifi", "xo")

ACTION_CREATE = "source.create"
ACTION_UPDATE = "source.update"
ACTION_ENABLE = "source.enable"
ACTION_DISABLE = "source.disable"
ACTION_DELETE = "source.delete"
ACTION_ALLOW_PLAIN_HTTP = "source.allow_plain_http"


class SourceError(Exception):
    """Base class for source service errors; messages never contain a credential."""


class SourceValidationError(SourceError, ValueError):
    """A value given for a source is not acceptable."""


class SourceNotFoundError(SourceError, LookupError):
    """No source has that id."""


class SourceNameTakenError(SourceValidationError):
    """Another source already has that name."""


def utc_now() -> str:
    """The current time as UTC ISO 8601 text ending in Z."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class SourceView:
    """What the service returns for a source. It has no credential, only ``has_credential``."""

    id: int
    name: str
    type: str
    base_url: str | None
    options: dict[str, object]
    enabled: bool
    state: str
    has_credential: bool
    last_checked_at: str | None
    last_success_at: str | None
    controller_version: str | None


@dataclass(frozen=True, slots=True)
class DeleteResult:
    """What deleting a source removed besides the source row and its own rows."""

    removed_states: int
    freed_bytes: int


def _check_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise SourceValidationError("a source needs a name")
    if len(cleaned) > MAX_NAME_CHARS:
        raise SourceValidationError(f"a source name is at most {MAX_NAME_CHARS} characters")
    if not cleaned.isprintable():
        raise SourceValidationError("a source name must not contain control characters")
    return cleaned


def _check_options(options: Mapping[str, object]) -> dict[str, object]:
    checked: dict[str, object] = {}
    for key, value in options.items():
        expected = ALLOWED_OPTIONS.get(key)
        if expected is None:
            raise SourceValidationError(f"unknown source option {key!r}")
        if type(value) is not expected:
            raise SourceValidationError(f"the source option {key} must be {expected.__name__}")
        if key == OPTION_INTERVAL_SECONDS and not (
            isinstance(value, int) and MIN_INTERVAL_SECONDS <= value <= MAX_INTERVAL_SECONDS
        ):
            raise SourceValidationError(
                f"the source option {key} must be from {MIN_INTERVAL_SECONDS} "
                f"to {MAX_INTERVAL_SECONDS} seconds"
            )
        checked[key] = value
    return checked


def _check_credential(credential: str | bytes) -> bytes:
    data = credential.encode("utf-8") if isinstance(credential, str) else credential
    if not data.strip():
        raise SourceValidationError("a credential must not be blank")
    return data


def _check_address(base_url: str, options: Mapping[str, object]) -> str:
    try:
        return validate_base_url(
            base_url, allow_plain_http=options.get(OPTION_ALLOW_PLAIN_HTTP) is True
        )
    except AddressError as error:
        raise SourceValidationError(str(error)) from None


def _audit(
    connection: Connection,
    at: str,
    actor: str,
    action: str,
    source_id: int,
    detail: dict[str, object],
) -> None:
    """Write an audit event. ``detail`` names fields and counts, never values of secrets."""
    connection.execute(
        sa.insert(audit_events).values(
            at=at, actor=actor, action=action, target=f"source:{source_id}", detail=detail
        )
    )


def _audit_plain_http(connection: Connection, at: str, actor: str, source_id: int) -> None:
    _audit(connection, at, actor, ACTION_ALLOW_PLAIN_HTTP, source_id, {"set": True})


def interval_of(options: Mapping[str, object]) -> int:
    """The seconds between two runs of a source: its ``interval_seconds`` option, else 300.

    A stored value outside 60 to 3600 (the service refuses to store one) also gives the default.
    """
    value = options.get(OPTION_INTERVAL_SECONDS)
    if type(value) is int and MIN_INTERVAL_SECONDS <= value <= MAX_INTERVAL_SECONDS:
        return value
    return DEFAULT_INTERVAL_SECONDS


class SourceService:
    """The operations on sources, on one database with one credential key."""

    def __init__(
        self,
        database: Database,
        cipher: CredentialCipher,
        *,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._database = database
        self._cipher = cipher
        self._clock = clock

    def create(
        self,
        *,
        name: str,
        source_type: str,
        actor: str,
        base_url: str | None = None,
        credential: str | bytes | None = None,
        options: Mapping[str, object] | None = None,
    ) -> SourceView:
        """Add a source. unifi and xo need an address and a credential; push takes neither."""
        if source_type not in SOURCE_TYPES:
            raise SourceValidationError(f"unknown source type {source_type!r}")
        cleaned_name = _check_name(name)
        checked_options = _check_options(options or {})
        address: str | None = None
        sealed_input: bytes | None = None
        if source_type in POLLED_TYPES:
            if base_url is None or credential is None:
                raise SourceValidationError(
                    f"a {source_type} source needs an address and a credential"
                )
            address = _check_address(base_url, checked_options)
            sealed_input = _check_credential(credential)
        elif base_url is not None or credential is not None:
            raise SourceValidationError("a push source has no address and no credential")
        now = self._clock()
        try:
            with self._database.write() as connection:
                self._require_free_name(connection, cleaned_name, except_id=None)
                insert = (
                    sa.insert(sources)
                    .values(
                        workspace_id=DEFAULT_WORKSPACE_ID,
                        name=cleaned_name,
                        type=source_type,
                        base_url=address,
                        options=checked_options,
                    )
                    .returning(sources.c.id)
                )
                source_id = int(connection.execute(insert).scalar_one())
                if sealed_input is not None:
                    self._store_credential(connection, source_id, sealed_input)
                detail: dict[str, object] = {"type": source_type, "name": cleaned_name}
                _audit(connection, now, actor, ACTION_CREATE, source_id, detail)
                if checked_options.get(OPTION_ALLOW_PLAIN_HTTP) is True:
                    _audit_plain_http(connection, now, actor, source_id)
                view = self._view(connection, source_id)
        except sa.exc.IntegrityError:
            raise SourceNameTakenError("another source already has that name") from None
        logger.info("source %s created (type %s)", view.id, view.type)
        return view

    def update(
        self,
        source_id: int,
        *,
        actor: str,
        name: str | None = None,
        base_url: str | None = None,
        credential: str | bytes | None = None,
        options: Mapping[str, object] | None = None,
    ) -> SourceView:
        """Change the given fields of a source; a field left as None stays as it is.

        ``options`` replaces all options. A new credential replaces the stored one; there is no
        way to remove a credential, delete the source instead.
        """
        cleaned_name = None if name is None else _check_name(name)
        checked_options = None if options is None else _check_options(options)
        sealed_input = None if credential is None else _check_credential(credential)
        now = self._clock()
        try:
            with self._database.write() as connection:
                row = self._row(connection, source_id)
                changed: list[str] = []
                values: dict[str, object] = {}
                if cleaned_name is not None and cleaned_name != row.name:
                    self._require_free_name(connection, cleaned_name, except_id=source_id)
                    values["name"] = cleaned_name
                    changed.append("name")
                effective = row.options if checked_options is None else checked_options
                has_polled_fields = base_url is not None or credential is not None
                if row.type not in POLLED_TYPES and has_polled_fields:
                    raise SourceValidationError("a push source has no address and no credential")
                if base_url is not None or checked_options is not None:
                    current = base_url if base_url is not None else row.base_url
                    if current is not None:
                        address = _check_address(current, effective)
                        if address != row.base_url:
                            values["base_url"] = address
                            changed.append("base_url")
                if checked_options is not None and checked_options != row.options:
                    values["options"] = checked_options
                    changed.append("options")
                if values:
                    connection.execute(
                        sa.update(sources).where(sources.c.id == source_id).values(**values)
                    )
                if sealed_input is not None:
                    self._store_credential(connection, source_id, sealed_input)
                    changed.append("credential")
                if changed:
                    _audit(connection, now, actor, ACTION_UPDATE, source_id, {"changed": changed})
                if (
                    effective.get(OPTION_ALLOW_PLAIN_HTTP) is True
                    and row.options.get(OPTION_ALLOW_PLAIN_HTTP) is not True
                ):
                    _audit_plain_http(connection, now, actor, source_id)
                view = self._view(connection, source_id)
        except sa.exc.IntegrityError:
            raise SourceNameTakenError("another source already has that name") from None
        logger.info("source %s updated", source_id)
        return view

    def set_enabled(self, source_id: int, enabled: bool, *, actor: str) -> SourceView:
        """Enable or disable a source. A disabled source is not collected."""
        now = self._clock()
        with self._database.write() as connection:
            self._row(connection, source_id)
            connection.execute(
                sa.update(sources).where(sources.c.id == source_id).values(enabled=enabled)
            )
            action = ACTION_ENABLE if enabled else ACTION_DISABLE
            _audit(connection, now, actor, action, source_id, {})
            view = self._view(connection, source_id)
        logger.info("source %s %s", source_id, "enabled" if enabled else "disabled")
        return view

    def delete(self, source_id: int, *, actor: str) -> DeleteResult:
        """Delete a source, everything recorded for it, and the states nothing refers to now."""
        now = self._clock()
        with self._database.write() as connection:
            row = self._row(connection, source_id)
            events = sa.select(change_events.c.id).where(change_events.c.source_id == source_id)
            # Children first, in dependency order, so no delete depends on a cascade.
            for table in (
                change_items,
                notification_deliveries,
                acknowledgements,
                notes,
                enrichments,
            ):
                connection.execute(sa.delete(table).where(table.c.event_id.in_(events)))
            for table in (change_events, snapshots, objects, resource_coverage, runs):
                connection.execute(sa.delete(table).where(table.c.source_id == source_id))
            connection.execute(sa.delete(sources).where(sources.c.id == source_id))
            collected = gc_unreferenced_states(connection)
            detail: dict[str, object] = {
                "type": row.type,
                "name": row.name,
                "removed_states": collected.removed_count,
            }
            _audit(connection, now, actor, ACTION_DELETE, source_id, detail)
        logger.info("source %s deleted", source_id)
        return DeleteResult(collected.removed_count, collected.freed_bytes)

    def get(self, source_id: int) -> SourceView:
        """One source, without its credential."""
        with self._database.read() as connection:
            return self._view(connection, source_id)

    def list_sources(self) -> list[SourceView]:
        """Every source in name order, without credentials."""
        with self._database.read() as connection:
            ids = connection.execute(sa.select(sources.c.id).order_by(sources.c.name)).scalars()
            return [self._view(connection, int(source_id)) for source_id in ids.all()]

    def credential_for_collector(self, source_id: int) -> bytes | None:
        """Decrypt the credential of a source for the run pipeline; None when none is stored.

        The result must go to the controller request and nowhere else: not to a log, an event,
        a stored state or an error message.
        """
        with self._database.read() as connection:
            row = self._row(connection, source_id)
        if row.credential_ciphertext is None or row.key_id is None:
            return None
        return self._cipher.decrypt(source_id, row.credential_ciphertext, row.key_id)

    def _store_credential(self, connection: Connection, source_id: int, plaintext: bytes) -> None:
        sealed = self._cipher.encrypt(source_id, plaintext)
        connection.execute(
            sa.update(sources)
            .where(sources.c.id == source_id)
            .values(credential_ciphertext=sealed.ciphertext, key_id=sealed.key_id)
        )

    @staticmethod
    def _require_free_name(connection: Connection, name: str, *, except_id: int | None) -> None:
        query = sa.select(sources.c.id).where(
            sources.c.workspace_id == DEFAULT_WORKSPACE_ID, sources.c.name == name
        )
        if except_id is not None:
            query = query.where(sources.c.id != except_id)
        if connection.execute(query).first() is not None:
            raise SourceNameTakenError("another source already has that name")

    @staticmethod
    def _row(connection: Connection, source_id: int) -> sa.Row[tuple[object, ...]]:
        row = connection.execute(sa.select(sources).where(sources.c.id == source_id)).first()
        if row is None:
            raise SourceNotFoundError(f"source {source_id} does not exist")
        return row

    def _view(self, connection: Connection, source_id: int) -> SourceView:
        row = self._row(connection, source_id)
        return SourceView(
            id=int(row.id),
            name=str(row.name),
            type=str(row.type),
            base_url=row.base_url,
            options=dict(row.options),
            enabled=bool(row.enabled),
            state=str(row.state),
            has_credential=row.credential_ciphertext is not None,
            last_checked_at=row.last_checked_at,
            last_success_at=row.last_success_at,
            controller_version=row.controller_version,
        )
