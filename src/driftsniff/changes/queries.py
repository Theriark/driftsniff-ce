"""The change list and the change detail, as SQL (P10-T6, backend slice; docs/changes-service.md).

``ChangeQueries.list_changes`` answers the list page (search, filters, sort, 50 per page) and
``ChangeQueries.get_change`` the detail page. Both read on one read connection and return the
frozen views of ``driftsniff.changes.views``; they never write.

Mutes. A mute (table ``path_mutes``, check ``driftsniff.rules.engine.is_muted``) hides an item
from a list. In the list, a change whose items are all muted is hidden unless the filter says
``include_muted``; a change with no items, or with one item that is not muted, stays. A critical
item is never muted, so a critical change is never hidden. In the detail every item is shown and
flagged ``muted``. Because a mute is a path pattern that SQL cannot evaluate, a list with mutes
checks the newest ``MUTE_SCAN_LIMIT`` matching changes in Python and pages over the visible ones;
``mute_scan_truncated`` says when more than that matched.

Every filter value reaches SQL as a bound parameter; the search text has ``%``, ``_`` and the
escape character escaped, so it is matched literally.
"""

import math
from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from typing import Any, Final, cast

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.changes.paths import mute_refusal
from driftsniff.changes.views import (
    FINGERPRINT_SHOWN_CHARS,
    PAGE_SIZE,
    UNRATED_RATIONALE,
    UNRATED_RULE_ID,
    AcknowledgementRow,
    ChangeDetailView,
    ChangeFilters,
    ChangePageView,
    ChangeRow,
    EnrichmentRow,
    ItemView,
    MoveView,
    MuteRow,
    NoteRow,
    ObjectGroup,
)
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    acknowledgements,
    change_events,
    change_items,
    enrichments,
    notes,
    path_mutes,
    sources,
    users,
)
from driftsniff.rules.engine import PathMute, is_muted
from driftsniff.rules.schema import Severity
from driftsniff.secrets.fingerprint import Fingerprint
from driftsniff.secrets.redact import scrub_text

MUTE_SCAN_LIMIT: Final = 5000
MAX_ITEMS_PER_CHANGE: Final = 1000
SEARCH_MAX_CHARS: Final = 200
_SCAN_CHUNK: Final = 500
_ESCAPE: Final = "\\"
_SECRET_CLASSES: Final = frozenset({"secret", "unclassified"})
_SEVERITY_RANK: Final = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _like_pattern(text: str) -> str:
    """``text`` as a contains-pattern with its wildcard characters escaped."""
    escaped = text.replace(_ESCAPE, _ESCAPE * 2)
    escaped = escaped.replace("%", _ESCAPE + "%").replace("_", _ESCAPE + "_")
    return f"%{escaped}%"


def _has_item(*conditions: sa.ColumnElement[bool]) -> sa.ColumnElement[bool]:
    """An EXISTS over the items of the change being filtered."""
    same_change = change_items.c.event_id == change_events.c.id
    return sa.exists().where(same_change, *conditions).correlate(change_events)


def _day_start(day: date) -> str:
    return f"{day.isoformat()}T00:00:00Z"


def _conditions(filters: ChangeFilters) -> list[sa.ColumnElement[bool]]:
    found: list[sa.ColumnElement[bool]] = []
    if filters.source_id is not None:
        found.append(change_events.c.source_id == filters.source_id)
    if filters.severities:
        found.append(change_events.c.max_severity.in_(filters.severities))
    if filters.status is not None:
        found.append(change_events.c.status == filters.status)
    if filters.resource is not None:
        found.append(_has_item(change_items.c.resource == filters.resource))
    if filters.created_from is not None:
        found.append(change_events.c.created_at >= _day_start(filters.created_from))
    if filters.created_to is not None:
        after_last_day: date | None
        try:
            after_last_day = filters.created_to + timedelta(days=1)
        except OverflowError:
            after_last_day = None
        if after_last_day is not None:
            found.append(change_events.c.created_at < _day_start(after_last_day))
    search = filters.search.strip()[:SEARCH_MAX_CHARS]
    if search:
        pattern = _like_pattern(search)
        by_summary = change_events.c.summary.ilike(pattern, escape=_ESCAPE)
        by_object = _has_item(change_items.c.object_name_at_time.ilike(pattern, escape=_ESCAPE))
        found.append(sa.or_(by_summary, by_object))
    return found


def _order(sort: str) -> tuple[sa.ColumnElement[Any], ...]:
    created, identity = change_events.c.created_at, change_events.c.id
    if sort == "oldest":
        return (created.asc(), identity.asc())
    if sort == "severity":
        severity = change_events.c.max_severity
        whens = [(severity == name, value) for name, value in _SEVERITY_RANK.items()]
        rank = sa.case(*whens, else_=0)
        return (rank.desc(), created.desc(), identity.desc())
    return (created.desc(), identity.desc())


def _page_bounds(page: int, total: int) -> tuple[int, int]:
    """The page to show (clamped into range) and how many pages there are."""
    pages = max(1, math.ceil(total / PAGE_SIZE))
    return min(max(page, 1), pages), pages


def _load_mutes(connection: Connection) -> tuple[PathMute, ...]:
    rows = connection.execute(sa.select(path_mutes.c.resource, path_mutes.c.path_pattern)).all()
    return tuple(PathMute(str(row.resource), str(row.path_pattern)) for row in rows)


def _unmuted(
    connection: Connection, event_ids: Sequence[int], mutes: Sequence[PathMute]
) -> list[int]:
    """The ids (in their order) of the changes that have no items or at least one unmuted item."""
    hidden: set[int] = set()
    for start in range(0, len(event_ids), _SCAN_CHUNK):
        chunk = event_ids[start : start + _SCAN_CHUNK]
        rows = connection.execute(
            sa.select(
                change_items.c.event_id,
                change_items.c.resource,
                change_items.c.path,
                change_items.c.severity,
            ).where(change_items.c.event_id.in_(chunk))
        ).all()
        every_item_muted: dict[int, bool] = {}
        for row in rows:
            muted = is_muted(cast(Severity, row.severity), row.resource, row.path, mutes)
            key = int(row.event_id)
            every_item_muted[key] = every_item_muted.get(key, True) and muted
        hidden.update(key for key, all_muted in every_item_muted.items() if all_muted)
    return [event_id for event_id in event_ids if event_id not in hidden]


def _counts(connection: Connection, table: sa.Table, event_ids: Sequence[int]) -> dict[int, int]:
    rows = connection.execute(
        sa.select(table.c.event_id, sa.func.count())
        .where(table.c.event_id.in_(event_ids))
        .group_by(table.c.event_id)
    ).all()
    return {int(row[0]): int(row[1]) for row in rows}


def _change_row(row: Any, counts: tuple[int, int, int]) -> ChangeRow:
    return ChangeRow(
        id=int(row.id),
        source_id=int(row.source_id),
        source_name=str(row.source_name),
        severity=str(row.max_severity),
        status=str(row.status),
        summary=str(row.summary),
        item_count=int(row.item_count),
        window_start=str(row.window_start),
        window_end=str(row.window_end),
        created_at=str(row.created_at),
        rule_pack_version=str(row.rule_pack_version),
        acknowledgement_count=counts[0],
        note_count=counts[1],
        enrichment_count=counts[2],
    )


def _rows(connection: Connection, event_ids: Sequence[int]) -> tuple[ChangeRow, ...]:
    """The list rows of ``event_ids``, in that order."""
    if not event_ids:
        return ()
    found = connection.execute(
        sa.select(change_events, sources.c.name.label("source_name"))
        .join(sources, sources.c.id == change_events.c.source_id)
        .where(change_events.c.id.in_(event_ids))
    ).all()
    by_id = {int(row.id): row for row in found}
    acks = _counts(connection, acknowledgements, event_ids)
    note_counts = _counts(connection, notes, event_ids)
    enrichment_counts = _counts(connection, enrichments, event_ids)
    result: list[ChangeRow] = []
    for event_id in event_ids:
        if event_id in by_id:
            counts = (
                acks.get(event_id, 0),
                note_counts.get(event_id, 0),
                enrichment_counts.get(event_id, 0),
            )
            result.append(_change_row(by_id[event_id], counts))
    return tuple(result)


def _text_of(value: Any) -> str | None:
    """A text shown to people: the log scrubber has seen it; None stays None."""
    return None if value is None else scrub_text(str(value))


def _scrubbed_json(value: Any) -> Any:
    """The same JSON with every text (and every key) passed through the log scrubber."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, list):
        return [_scrubbed_json(member) for member in value]
    if isinstance(value, dict):
        return {scrub_text(str(key)): _scrubbed_json(member) for key, member in value.items()}
    return value


def _short_fingerprint(stored: str | None) -> str | None:
    """The first 12 characters of a stored fingerprint; text of any other shape is dropped."""
    if stored is None:
        return None
    parsed = Fingerprint.parse(stored)
    return None if parsed is None else parsed.short(FINGERPRINT_SHOWN_CHARS)


def _move(detail: Mapping[str, Any]) -> MoveView:
    return MoveView(
        key=_text_of(detail.get("key")),
        from_after=_text_of(detail.get("from_after")),
        from_before=_text_of(detail.get("from_before")),
        to_after=_text_of(detail.get("to_after")),
        to_before=_text_of(detail.get("to_before")),
        summary=_text_of(detail.get("summary")),
    )


def item_view(row: Any, mutes: Sequence[PathMute]) -> ItemView:
    """One stored item as the detail shows it: no secret value, always a rule id and rationale."""
    secret = row.field_class in _SECRET_CLASSES
    rationale_text = None if row.rationale is None else str(row.rationale).strip()
    recorded = bool(row.rule_id) and bool(rationale_text)
    detail = row.order_detail if isinstance(row.order_detail, dict) else None
    severity = str(row.severity)
    resource = str(row.resource)
    path = str(row.path)
    kind = str(row.change_kind)
    return ItemView(
        id=int(row.id),
        resource=resource,
        object_name=_text_of(row.object_name_at_time),
        change_kind=kind,
        path=scrub_text(path),
        field_class=str(row.field_class),
        severity=severity,
        rule_id=scrub_text(str(row.rule_id)) if row.rule_id else UNRATED_RULE_ID,
        rationale=scrub_text(rationale_text) if rationale_text else UNRATED_RATIONALE,
        rationale_recorded=recorded,
        before=None if secret else row.before_value,
        after=None if secret else row.after_value,
        before_fingerprint=_short_fingerprint(row.before_fp),
        after_fingerprint=_short_fingerprint(row.after_fp),
        secret=secret,
        muted=is_muted(cast(Severity, severity), resource, path, mutes),
        mutable=mute_refusal(severity, kind, path) is None,
        move=_move(detail) if kind == "moved" and detail is not None else None,
        order_detail=_scrubbed_json(detail),
    )


def _groups(item_rows: Sequence[Any], mutes: Sequence[PathMute]) -> tuple[ObjectGroup, ...]:
    """The items grouped by object, the groups in the order their first item was stored."""
    order: list[tuple[int | None, str, str | None]] = []
    members: dict[tuple[int | None, str, str | None], list[ItemView]] = {}
    for row in item_rows:
        key = (row.object_id, str(row.resource), row.object_name_at_time)
        if key not in members:
            members[key] = []
            order.append(key)
        members[key].append(item_view(row, mutes))
    groups: list[ObjectGroup] = []
    for key in order:
        object_id, resource, name = key
        groups.append(ObjectGroup(resource, object_id, _text_of(name), tuple(members[key])))
    return tuple(groups)


def _acknowledgement(row: Any) -> AcknowledgementRow:
    return AcknowledgementRow(int(row.id), str(row.username), str(row.comment), str(row.created_at))


def _note(row: Any) -> NoteRow:
    return NoteRow(int(row.id), str(row.username), str(row.body), str(row.created_at))


def _enrichment(row: Any) -> EnrichmentRow:
    return EnrichmentRow(
        int(row.id), str(row.provider_label), str(row.summary), row.payload, str(row.created_at)
    )


def mute_row(row: Any) -> MuteRow:
    """A mute from a row of ``path_mutes`` joined with ``users.username``."""
    return MuteRow(
        int(row.id),
        str(row.resource),
        str(row.path_pattern),
        None if row.reason is None else str(row.reason),
        str(row.username),
        str(row.created_at),
    )


class ChangeQueries:
    """Reads the change list and the change detail."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def list_changes(self, filters: ChangeFilters | None = None) -> ChangePageView:
        """One page of the change list; a page past the end is the last page."""
        wanted = filters or ChangeFilters()
        where = sa.and_(sa.true(), *_conditions(wanted))
        identifiers = sa.select(change_events.c.id).where(where).order_by(*_order(wanted.sort))
        with self._db.read() as connection:
            mutes = () if wanted.include_muted else _load_mutes(connection)
            muted_hidden, truncated = 0, False
            if not mutes:
                counted = sa.select(sa.func.count()).select_from(change_events).where(where)
                total = int(connection.execute(counted).scalar_one())
                page, pages = _page_bounds(wanted.page, total)
                window = identifiers.limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)
                page_ids = [int(found) for found in connection.execute(window).scalars()]
            else:
                scan = connection.execute(identifiers.limit(MUTE_SCAN_LIMIT + 1)).scalars()
                scanned = [int(found) for found in scan]
                truncated = len(scanned) > MUTE_SCAN_LIMIT
                scanned = scanned[:MUTE_SCAN_LIMIT]
                visible = _unmuted(connection, scanned, mutes)
                muted_hidden = len(scanned) - len(visible)
                total = len(visible)
                page, pages = _page_bounds(wanted.page, total)
                page_ids = visible[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
            rows = _rows(connection, page_ids)
        return ChangePageView(
            rows=rows,
            total=total,
            page=page,
            pages=pages,
            page_size=PAGE_SIZE,
            muted_hidden=muted_hidden,
            mute_scan_truncated=truncated,
        )

    def get_change(self, event_id: int) -> ChangeDetailView | None:
        """One change with its items, acknowledgements, notes and enrichments, or None."""
        with self._db.read() as connection:
            head = _rows(connection, [event_id])
            if not head:
                return None
            item_rows = connection.execute(
                sa.select(change_items)
                .where(change_items.c.event_id == event_id)
                .order_by(change_items.c.id)
                .limit(MAX_ITEMS_PER_CHANGE + 1)
            ).all()
            ack_rows = connection.execute(
                sa.select(acknowledgements, users.c.username)
                .join(users, users.c.id == acknowledgements.c.user_id)
                .where(acknowledgements.c.event_id == event_id)
                .order_by(acknowledgements.c.id)
            ).all()
            note_rows = connection.execute(
                sa.select(notes, users.c.username)
                .join(users, users.c.id == notes.c.user_id)
                .where(notes.c.event_id == event_id)
                .order_by(notes.c.id)
            ).all()
            enrichment_rows = connection.execute(
                sa.select(enrichments)
                .where(enrichments.c.event_id == event_id)
                .order_by(enrichments.c.id)
            ).all()
            mutes = _load_mutes(connection)
        groups = _groups(item_rows[:MAX_ITEMS_PER_CHANGE], mutes)
        return ChangeDetailView(
            change=head[0],
            groups=groups,
            items_truncated=len(item_rows) > MAX_ITEMS_PER_CHANGE,
            acknowledgements=tuple(_acknowledgement(row) for row in ack_rows),
            notes=tuple(_note(row) for row in note_rows),
            enrichments=tuple(_enrichment(row) for row in enrichment_rows),
            muted_item_count=sum(item.muted for group in groups for item in group.items),
        )

    def list_mutes(self) -> tuple[MuteRow, ...]:
        """Every mute, newest first, with the name of the person who made it."""
        with self._db.read() as connection:
            rows = connection.execute(
                sa.select(path_mutes, users.c.username)
                .join(users, users.c.id == path_mutes.c.user_id)
                .order_by(path_mutes.c.id.desc())
            ).all()
        return tuple(mute_row(row) for row in rows)
