"""The notification channel and its deliveries (P9-T4, docs/notifications.md).

``NotificationService`` keeps the one channel (a webhook or an SMTP account), decides which change
events are sent, sends them with retries and stores every attempt.

* **One channel.** Saving a channel replaces the one that exists. Its configuration is encrypted
  with the credential key (bound to the channel id) and re-encrypted by a rekey.
* **What is sent.** An event whose highest severity is at least the channel's minimum (default
  high), on an enabled channel. The message holds no before or after value and no object path
  (``message.py``).
* **Retries.** The first attempt and three retries after 1, 2 and 4 seconds, then the event is
  given up. A blocked target, a redirect, a refused request (4xx other than 429) and a TLS error
  are not retried. Every attempt is a row of ``notification_deliveries`` with a status
  (``delivered``, ``failed`` or ``blocked``), the HTTP status when there is one and an error class.
* **Never in the run.** ``notify_event`` is what the run pipeline calls after the commit; it only
  hands the event to a small background pool, so a slow receiver never delays a collection.
* **Test button.** ``send_test`` sends a sample message marked as a test, once, and writes an audit
  event with the outcome; it is not an event delivery and stores no delivery row.

Nothing here puts a URL, a password, the signing key or message text into a log or an audit event.
"""

import logging
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy import Connection
from sqlalchemy.exc import SQLAlchemyError

from driftsniff.collectors.resolve import Resolver, system_resolver
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    CHANNEL_TYPES,
    DEFAULT_WORKSPACE_ID,
    SEVERITIES,
    audit_events,
    change_events,
    notification_channel,
    notification_deliveries,
    sources,
)
from driftsniff.notify.config import (
    CHANNEL_WEBHOOK,
    ChannelConfig,
    ChannelConfigError,
    SmtpConfig,
    WebhookConfig,
    describe,
    dump_config,
    load_config,
    parse_smtp,
    parse_webhook,
)
from driftsniff.notify.message import NotificationMessage, build_message, sample_message
from driftsniff.notify.smtp import send_mail
from driftsniff.notify.webhook import SendResult, send_webhook
from driftsniff.secrets.crypto import CredentialCipher, CredentialCryptoError
from driftsniff.secrets.keys import WEBHOOK_LABEL, MasterKey

logger = logging.getLogger(__name__)

DEFAULT_MIN_SEVERITY: Final = "high"
RETRY_BACKOFF_SECONDS: Final = (1.0, 2.0, 4.0)
MAX_ATTEMPTS: Final = 1 + len(RETRY_BACKOFF_SECONDS)
BACKGROUND_WORKERS: Final = 2
MAX_LISTED_DELIVERIES: Final = 200

STATUS_DELIVERED: Final = "delivered"
STATUS_FAILED: Final = "failed"
STATUS_BLOCKED: Final = "blocked"
ERROR_BLOCKED: Final = "blocked_address"
ERROR_CONFIG_UNREADABLE: Final = "config_unreadable"

ACTION_CHANNEL_SAVED: Final = "notification.channel_saved"
ACTION_CHANNEL_REMOVED: Final = "notification.channel_removed"
ACTION_TEST_SENT: Final = "notification.test"
ACTION_KEY_SHOWN: Final = "notification.signing_key_shown"


class NotificationError(Exception):
    """Base class of the errors this module raises; messages never hold a secret."""


class NotificationInputError(NotificationError, ValueError):
    """The channel type, severity or a configuration field does not follow the rules."""


class NoChannelError(NotificationError):
    """There is no channel to send through."""


class ChannelUnreadableError(NotificationError):
    """The stored configuration cannot be decrypted (a lost key); enter it again."""


@dataclass(frozen=True, slots=True)
class ChannelView:
    """The channel as an admin may see it: no URL path, no password."""

    channel_id: int
    type: str
    enabled: bool
    min_severity: str
    details: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        """The JSON form of the view."""
        return {
            "id": self.channel_id,
            "type": self.type,
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            **self.details,
        }


@dataclass(frozen=True, slots=True)
class DeliveryRecord:
    """One stored attempt."""

    delivery_id: int
    event_id: int
    attempt: int
    status: str
    http_status: int | None
    error_class: str | None
    created_at: str

    def as_dict(self) -> dict[str, object]:
        """The JSON form of the record."""
        return {
            "id": self.delivery_id,
            "event_id": self.event_id,
            "attempt": self.attempt,
            "status": self.status,
            "http_status": self.http_status,
            "error_class": self.error_class,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    """What ``deliver_event`` did for one event."""

    event_id: int
    sent: bool
    attempts: int
    status: str | None
    error_class: str | None = None


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def severity_rank(severity: str) -> int:
    """0 for low up to 3 for critical."""
    return SEVERITIES.index(severity)


def _status_of(result: SendResult) -> str:
    if result.ok:
        return STATUS_DELIVERED
    if result.error_class == ERROR_BLOCKED:
        return STATUS_BLOCKED
    return STATUS_FAILED


class NotificationService:
    """The notification channel of one database.

    ``clock`` gives the stored timestamps, ``wall_clock`` the signed time and ``sleep`` the wait
    between attempts; tests replace them. ``resolver`` and ``ssl_context`` are for tests too.
    """

    def __init__(
        self,
        database: Database,
        master_key: MasterKey,
        *,
        base_url: str,
        clock: Callable[[], str] = _utc_stamp,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        resolver: Resolver = system_resolver,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._db = database
        self._cipher = CredentialCipher.from_master(master_key)
        self._signing_key = master_key.derive(WEBHOOK_LABEL)
        self._base_url = base_url
        self._clock = clock
        self._wall_clock = wall_clock
        self._sleep = sleep
        self._resolver = resolver
        self._ssl_context = ssl_context
        self._executor: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()
        self._in_flight: set[int] = set()

    # -- the channel ---------------------------------------------------------------------------

    def channel(self) -> ChannelView | None:
        """The channel, or None when none is set. A damaged configuration shows only the type."""
        row = self._channel_row()
        if row is None:
            return None
        try:
            details = describe(self._config_of(row))
        except (ChannelUnreadableError, ChannelConfigError):
            details = {"config_unreadable": True}
        return ChannelView(row.id, row.type, bool(row.enabled), row.min_severity, details)

    def configure(
        self,
        *,
        actor: str,
        channel_type: str,
        fields: Mapping[str, str],
        min_severity: str | None = None,
        enabled: bool = True,
    ) -> ChannelView:
        """Set the one channel (replacing any other). NotificationInputError for bad input.

        ``fields`` are the text fields of the form or JSON body of the channel type: ``url`` for
        a webhook; ``host``, ``port``, ``security``, ``username``, ``password``, ``from_address``
        and ``to_addresses`` for SMTP. A password left out is kept when the user name is the same.
        """
        if channel_type not in CHANNEL_TYPES:
            raise NotificationInputError(f"type must be one of: {', '.join(CHANNEL_TYPES)}")
        severity = (min_severity or "").strip().lower() or DEFAULT_MIN_SEVERITY
        if severity not in SEVERITIES:
            raise NotificationInputError(f"min_severity must be one of: {', '.join(SEVERITIES)}")
        try:
            config = self._parse(channel_type, fields, self._channel_row())
        except ChannelConfigError as error:
            raise NotificationInputError(str(error)) from None
        with self._db.write() as connection:
            row = connection.execute(
                sa.select(notification_channel.c.id).where(
                    notification_channel.c.workspace_id == DEFAULT_WORKSPACE_ID
                )
            ).first()
            if row is None:
                channel_id = self._insert_channel(connection, channel_type, severity, enabled)
            else:
                channel_id = int(row.id)
                connection.execute(
                    sa.update(notification_channel)
                    .where(notification_channel.c.id == channel_id)
                    .values(type=channel_type, min_severity=severity, enabled=enabled)
                )
            sealed = self._cipher.encrypt_channel(channel_id, dump_config(config))
            connection.execute(
                sa.update(notification_channel)
                .where(notification_channel.c.id == channel_id)
                .values(config_ciphertext=sealed.ciphertext, key_id=sealed.key_id)
            )
            self._audit(
                connection,
                actor,
                ACTION_CHANNEL_SAVED,
                channel_type,
                {"min_severity": severity, "enabled": enabled},
            )
        view = self.channel()
        if view is None:  # pragma: no cover - the row was just written
            raise NotificationError("the channel could not be read back")
        return view

    def remove(self, *, actor: str) -> bool:
        """Delete the channel (and, with it, its stored deliveries); False when none exists."""
        with self._db.write() as connection:
            row = connection.execute(
                sa.select(notification_channel.c.id, notification_channel.c.type)
            ).first()
            if row is None:
                return False
            connection.execute(
                sa.delete(notification_channel).where(notification_channel.c.id == row.id)
            )
            self._audit(connection, actor, ACTION_CHANNEL_REMOVED, row.type, None)
        return True

    def signing_key_hex(self, *, actor: str) -> str:
        """The key a receiver verifies the webhook signature with, as hex; the use is audited.

        It is derived from the master key, so it is the same for every channel of this
        installation and it changes after a rekey.
        """
        with self._db.write() as connection:
            self._audit(connection, actor, ACTION_KEY_SHOWN, None, None)
        return self._signing_key.hex()

    # -- sending -------------------------------------------------------------------------------

    def send_test(self, *, actor: str) -> SendResult:
        """Send the sample message once. NoChannelError, ChannelUnreadableError."""
        row = self._channel_row()
        if row is None:
            raise NoChannelError("there is no notification channel")
        try:
            config = self._config_of(row)
        except ChannelConfigError:
            raise ChannelUnreadableError("the stored channel configuration is damaged") from None
        result = self._send(config, sample_message(self._base_url))
        detail: dict[str, object] = {"ok": result.ok}
        if result.error_class is not None:
            detail["error_class"] = result.error_class
        if result.http_status is not None:
            detail["http_status"] = result.http_status
        with self._db.write() as connection:
            self._audit(connection, actor, ACTION_TEST_SENT, row.type, detail)
        return result

    def notify_event(self, event_id: int) -> None:
        """What the run pipeline calls after a commit: send in the background, never block."""
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=BACKGROUND_WORKERS, thread_name_prefix="notify"
                )
            executor = self._executor
        executor.submit(self._deliver_quietly, event_id)

    def close(self) -> None:
        """Wait for the deliveries that are running and stop the background pool."""
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=True)

    def deliver_event(self, event_id: int) -> DeliveryOutcome:
        """Send one event now (with retries) and store each attempt.

        Nothing is sent, and nothing stored, when there is no enabled channel, when the event is
        below the minimum severity, when it was delivered before or is being sent right now.
        """
        row = self._channel_row()
        if row is None or not row.enabled:
            return DeliveryOutcome(event_id, False, 0, None)
        event = self._event(event_id)
        if event is None or severity_rank(event.max_severity) < severity_rank(row.min_severity):
            return DeliveryOutcome(event_id, False, 0, None)
        with self._lock:
            if event_id in self._in_flight:
                return DeliveryOutcome(event_id, False, 0, None)
            self._in_flight.add(event_id)
        try:
            if self._already_delivered(event_id, row.id):
                return DeliveryOutcome(event_id, False, 0, STATUS_DELIVERED)
            return self._deliver(row, event)
        finally:
            with self._lock:
                self._in_flight.discard(event_id)

    def deliveries(self, event_id: int | None = None, limit: int = 50) -> list[DeliveryRecord]:
        """Stored attempts, newest first; at most ``MAX_LISTED_DELIVERIES``."""
        query = sa.select(notification_deliveries).order_by(notification_deliveries.c.id.desc())
        if event_id is not None:
            query = query.where(notification_deliveries.c.event_id == event_id)
        capped = max(1, min(limit, MAX_LISTED_DELIVERIES))
        with self._db.read() as connection:
            rows = connection.execute(query.limit(capped)).all()
        return [
            DeliveryRecord(
                row.id,
                row.event_id,
                row.attempt,
                row.status,
                row.http_status,
                row.error_class,
                row.created_at,
            )
            for row in rows
        ]

    # -- inside --------------------------------------------------------------------------------

    def _deliver_quietly(self, event_id: int) -> None:
        try:
            self.deliver_event(event_id)
        except Exception as error:
            logger.warning("delivering event %s failed: %s", event_id, type(error).__name__)

    def _deliver(self, row: Any, event: Any) -> DeliveryOutcome:
        try:
            config = self._config_of(row)
        except (ChannelUnreadableError, ChannelConfigError):
            self._store(event.id, row.id, 1, STATUS_FAILED, None, ERROR_CONFIG_UNREADABLE)
            return DeliveryOutcome(event.id, False, 1, STATUS_FAILED, ERROR_CONFIG_UNREADABLE)
        message = build_message(
            event_id=event.id,
            source=event.source_name,
            severity=event.max_severity,
            summary=event.summary,
            item_count=event.item_count,
            base_url=self._base_url,
        )
        attempt = 0
        while True:
            attempt += 1
            result = self._send(config, message)
            status = _status_of(result)
            self._store(event.id, row.id, attempt, status, result.http_status, result.error_class)
            if result.ok or not result.retry or attempt == MAX_ATTEMPTS:
                return DeliveryOutcome(event.id, result.ok, attempt, status, result.error_class)
            self._sleep(RETRY_BACKOFF_SECONDS[attempt - 1])

    def _send(self, config: ChannelConfig, message: NotificationMessage) -> SendResult:
        if isinstance(config, WebhookConfig):
            return send_webhook(
                config.url,
                message,
                self._signing_key,
                resolver=self._resolver,
                now=self._wall_clock,
                ssl_context=self._ssl_context,
            )
        return send_mail(config, message, resolver=self._resolver, ssl_context=self._ssl_context)

    def _channel_row(self) -> Any:
        with self._db.read() as connection:
            return connection.execute(
                sa.select(notification_channel)
                .where(notification_channel.c.workspace_id == DEFAULT_WORKSPACE_ID)
                .order_by(notification_channel.c.id)
            ).first()

    def _event(self, event_id: int) -> Any:
        with self._db.read() as connection:
            return connection.execute(
                sa.select(
                    change_events.c.id,
                    change_events.c.max_severity,
                    change_events.c.item_count,
                    change_events.c.summary,
                    sources.c.name.label("source_name"),
                )
                .join(sources, sources.c.id == change_events.c.source_id)
                .where(change_events.c.id == event_id)
            ).first()

    def _already_delivered(self, event_id: int, channel_id: int) -> bool:
        with self._db.read() as connection:
            found = connection.execute(
                sa.select(notification_deliveries.c.id).where(
                    notification_deliveries.c.event_id == event_id,
                    notification_deliveries.c.channel_id == channel_id,
                    notification_deliveries.c.status == STATUS_DELIVERED,
                )
            ).first()
        return found is not None

    def _store(
        self,
        event_id: int,
        channel_id: int,
        attempt: int,
        status: str,
        http_status: int | None,
        error_class: str | None,
    ) -> None:
        try:
            with self._db.write() as connection:
                connection.execute(
                    sa.insert(notification_deliveries).values(
                        event_id=event_id,
                        channel_id=channel_id,
                        attempt=attempt,
                        status=status,
                        http_status=http_status,
                        error_class=error_class,
                        created_at=self._clock(),
                    )
                )
        except SQLAlchemyError as error:
            logger.warning("a delivery attempt could not be stored: %s", type(error).__name__)

    def _insert_channel(
        self, connection: Connection, channel_type: str, severity: str, enabled: bool
    ) -> int:
        result = connection.execute(
            sa.insert(notification_channel).values(
                type=channel_type,
                config_ciphertext="",
                key_id=None,
                enabled=enabled,
                min_severity=severity,
            )
        )
        primary_key = result.inserted_primary_key
        if primary_key is None:  # pragma: no cover - SQLite always returns the id
            raise NotificationError("the database returned no id for the new channel")
        return int(primary_key[0])

    def _parse(
        self, channel_type: str, fields: Mapping[str, str], existing_row: Any
    ) -> ChannelConfig:
        if channel_type == CHANNEL_WEBHOOK:
            return parse_webhook(fields)
        previous: SmtpConfig | None = None
        if existing_row is not None and existing_row.type == channel_type:
            try:
                loaded = self._config_of(existing_row)
            except (ChannelUnreadableError, ChannelConfigError):
                loaded = None
            if isinstance(loaded, SmtpConfig):
                previous = loaded
        return parse_smtp(fields, previous)

    def _config_of(self, row: Any) -> ChannelConfig:
        if row.key_id is None or not row.config_ciphertext:
            raise ChannelUnreadableError("the channel has no stored configuration")
        try:
            plaintext = self._cipher.decrypt_channel(row.id, row.config_ciphertext, row.key_id)
        except CredentialCryptoError:
            raise ChannelUnreadableError(
                "the stored channel configuration cannot be decrypted; enter it again"
            ) from None
        return load_config(row.type, plaintext)

    def _audit(
        self,
        connection: Connection,
        actor: str,
        action: str,
        target: str | None,
        detail: dict[str, object] | None,
    ) -> None:
        connection.execute(
            sa.insert(audit_events).values(
                at=self._clock(), actor=actor, action=action, target=target, detail=detail
            )
        )
