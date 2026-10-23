"""Acknowledge, note and mute: what a person does to a change (P10-T6, backend slice).

Every action needs the ``operator`` role or higher (a viewer reads only); the service checks it
itself, so a route that forgets the dependency still cannot write. Every action runs in one write
transaction together with its audit event, and a refusal stores nothing.

- ``acknowledge`` appends an acknowledgement row and sets the change to ``acknowledged``. It is
  append only: acknowledging again adds a second row, nothing is overwritten or reopened.
- ``add_note`` appends a note row.
- ``mute_path`` stores the path of one item as a mute of its resource type (table ``path_mutes``,
  applied by ``driftsniff.rules.engine.is_muted`` in the list views). A critical item cannot be
  muted. A mute applies to every source of the workspace that has the resource type. Muting a
  path that is already muted changes nothing and says so.
- ``remove_mute`` deletes a mute; the items it hid show in the list again.

The audit events (table ``audit_events``) are ``change.acknowledged``, ``change.note_added``,
``mute.added`` and ``mute.removed``. They name the actor and the target and hold ids and counts,
never the text of a comment or a note.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.changes.errors import (
    ActionForbiddenError,
    EntryLimitError,
    InvalidTextError,
    NotMutableError,
    UnknownChangeError,
    UnknownItemError,
    UnknownMuteError,
)
from driftsniff.changes.paths import mute_refusal
from driftsniff.changes.queries import mute_row
from driftsniff.changes.views import AcknowledgementRow, MuteResult, MuteRow, NoteRow
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    acknowledgements,
    audit_events,
    change_events,
    change_items,
    notes,
    path_mutes,
    sources,
    users,
)
from driftsniff.rules.schema import normalize_path
from driftsniff.web.auth import ROLE_RANK, Principal, stamp

ACK_COMMENT_MAX_CHARS: Final = 2000
NOTE_MAX_CHARS: Final = 4000
MUTE_REASON_MAX_CHARS: Final = 500
MAX_ENTRIES_PER_CHANGE: Final = 500

ACTION_ACKNOWLEDGED: Final = "change.acknowledged"
ACTION_NOTE_ADDED: Final = "change.note_added"
ACTION_MUTE_ADDED: Final = "mute.added"
ACTION_MUTE_REMOVED: Final = "mute.removed"

_MINIMUM_ROLE: Final = "operator"
_ALLOWED_CONTROLS: Final = frozenset("\n\r\t")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def clean_text(value: object, *, max_chars: int, required: bool) -> str:
    """The text without surrounding blanks, or InvalidTextError (the error never quotes it).

    Markup is allowed: the text is plain text and the page escapes it when it prints it. What is
    refused is text that is too long, empty when it must not be, holds control characters other
    than a line break or tab, or cannot be stored as UTF-8.
    """
    if not isinstance(value, str):
        raise InvalidTextError("the text is not text")
    text = value.strip()
    if required and not text:
        raise InvalidTextError("the text is empty")
    if len(text) > max_chars:
        raise InvalidTextError(f"the text is longer than {max_chars} characters")
    for character in text:
        is_control = ord(character) < 32 or ord(character) == 127
        if is_control and character not in _ALLOWED_CONTROLS:
            raise InvalidTextError("the text has control characters")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise InvalidTextError("the text has characters that cannot be stored") from error
    return text


def _require_operator(principal: Principal) -> None:
    if ROLE_RANK.get(principal.role, 0) < ROLE_RANK[_MINIMUM_ROLE]:
        raise ActionForbiddenError("your role may read changes but not act on them")


def _exists(connection: Connection, table: sa.Table, row_id: int) -> bool:
    found = connection.execute(sa.select(table.c.id).where(table.c.id == row_id)).first()
    return found is not None


def _append_entry(
    connection: Connection,
    table: sa.Table,
    column: str,
    event_id: int,
    principal: Principal,
    text: str,
    now: str,
) -> int:
    """Insert one acknowledgement or note row and return its id; EntryLimitError at the cap."""
    counted = sa.select(sa.func.count()).select_from(table).where(table.c.event_id == event_id)
    if int(connection.execute(counted).scalar_one()) >= MAX_ENTRIES_PER_CHANGE:
        raise EntryLimitError("this change already holds the most entries it may hold")
    values = {"event_id": event_id, "user_id": principal.user_id, column: text, "created_at": now}
    statement = sa.insert(table).values(**values).returning(table.c.id)
    return int(connection.execute(statement).scalar_one())


def _audit(
    connection: Connection,
    now: str,
    actor: str,
    action: str,
    target: str,
    detail: dict[str, Any],
) -> None:
    statement = sa.insert(audit_events).values(
        at=now, actor=actor, action=action, target=target, detail=detail
    )
    connection.execute(statement)


class ChangeActions:
    """Writes acknowledgements, notes and mutes, each with its audit event."""

    def __init__(self, database: Database, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._db = database
        self._clock = clock

    def acknowledge(
        self, principal: Principal, event_id: int, comment: str = ""
    ) -> AcknowledgementRow:
        """Append an acknowledgement (the comment may be empty) and mark the change acknowledged."""
        _require_operator(principal)
        text = clean_text(comment, max_chars=ACK_COMMENT_MAX_CHARS, required=False)
        now = stamp(self._clock())
        actor, target = principal.username, f"event:{event_id}"
        with self._db.write() as connection:
            if not _exists(connection, change_events, event_id):
                raise UnknownChangeError("no such change")
            row_id = _append_entry(
                connection, acknowledgements, "comment", event_id, principal, text, now
            )
            mark = sa.update(change_events).where(change_events.c.id == event_id)
            mark = mark.where(change_events.c.status == "open")
            connection.execute(mark.values(status="acknowledged"))
            detail = {"acknowledgement_id": row_id, "comment_chars": len(text)}
            _audit(connection, now, actor, ACTION_ACKNOWLEDGED, target, detail)
        return AcknowledgementRow(row_id, actor, text, now)

    def add_note(self, principal: Principal, event_id: int, body: str) -> NoteRow:
        """Append a note to a change."""
        _require_operator(principal)
        text = clean_text(body, max_chars=NOTE_MAX_CHARS, required=True)
        now = stamp(self._clock())
        actor, target = principal.username, f"event:{event_id}"
        with self._db.write() as connection:
            if not _exists(connection, change_events, event_id):
                raise UnknownChangeError("no such change")
            row_id = _append_entry(connection, notes, "body", event_id, principal, text, now)
            detail = {"note_id": row_id, "body_chars": len(text)}
            _audit(connection, now, actor, ACTION_NOTE_ADDED, target, detail)
        return NoteRow(row_id, actor, text, now)

    def mute_path(self, principal: Principal, item_id: int, reason: str = "") -> MuteResult:
        """Mute the path of one change item for its resource type."""
        _require_operator(principal)
        why = clean_text(reason, max_chars=MUTE_REASON_MAX_CHARS, required=False)
        now = stamp(self._clock())
        with self._db.write() as connection:
            item = connection.execute(
                sa.select(change_items).where(change_items.c.id == item_id)
            ).first()
            if item is None:
                raise UnknownItemError("no such change item")
            problem = mute_refusal(str(item.severity), str(item.change_kind), str(item.path))
            if problem is not None:
                raise NotMutableError(problem)
            workspace = connection.execute(
                sa.select(sources.c.workspace_id)
                .join(change_events, change_events.c.source_id == sources.c.id)
                .where(change_events.c.id == item.event_id)
            ).scalar_one()
            wanted = normalize_path(str(item.path))
            held = connection.execute(
                sa.select(path_mutes, users.c.username)
                .join(users, users.c.id == path_mutes.c.user_id)
                .where(path_mutes.c.workspace_id == workspace)
                .where(path_mutes.c.resource == item.resource)
            ).all()
            for row in held:
                if normalize_path(str(row.path_pattern).strip()) == wanted:
                    return MuteResult(mute_row(row), created=False)
            resource, path, actor = str(item.resource), str(item.path), principal.username
            statement = sa.insert(path_mutes).values(
                workspace_id=workspace,
                resource=resource,
                path_pattern=path,
                user_id=principal.user_id,
                reason=why or None,
                created_at=now,
            )
            mute_id = int(connection.execute(statement.returning(path_mutes.c.id)).scalar_one())
            detail = {"resource": resource, "path_pattern": path, "item_id": item_id}
            _audit(connection, now, actor, ACTION_MUTE_ADDED, f"mute:{mute_id}", detail)
        return MuteResult(MuteRow(mute_id, resource, path, why or None, actor, now), created=True)

    def remove_mute(self, principal: Principal, mute_id: int) -> None:
        """Delete a mute; UnknownMuteError when it does not exist."""
        _require_operator(principal)
        now = stamp(self._clock())
        with self._db.write() as connection:
            by_id = path_mutes.c.id == mute_id
            found = connection.execute(
                sa.select(path_mutes.c.resource, path_mutes.c.path_pattern).where(by_id)
            ).first()
            if found is None:
                raise UnknownMuteError("no such mute")
            connection.execute(sa.delete(path_mutes).where(by_id))
            detail = {"resource": found.resource, "path_pattern": found.path_pattern}
            actor = principal.username
            _audit(connection, now, actor, ACTION_MUTE_REMOVED, f"mute:{mute_id}", detail)
