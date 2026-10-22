"""The change and enrichment API under ``/api/v1`` (P9-T5, docs/enrichment-api.md).

Routes, and the scope each needs (a scope is never implied by another one):

- ``GET /api/v1/changes`` and ``GET /api/v1/changes/{id}``: scope ``read``.
- ``POST /api/v1/changes/{id}/enrichments``: scope ``enrich``. Appends one enrichment; it never
  changes the severity or the status of the change and nothing can edit or delete it.
- ``GET /api/v1/openapi.json``: public. It describes the routes under ``/api/v1`` and holds no
  data of this installation.

What an answer shows of a change is what the interface shows: the value of a ``config`` field,
a short fingerprint for a ``secret`` or unclassified field. A value of a ``secret`` or
unclassified item is never returned, whatever the row holds. The text of the ``path``, the object
name, the rationale and the order detail is vendor data or free text, so it passes the log
scrubber of ``driftsniff.secrets.redact`` (credential-shaped text becomes ``***REDACTED***``).

The token check runs before the body is read, so a caller without the scope costs nothing.
Every refused enrichment stores nothing: the whole request is checked first, then written in one
transaction together with its audit event.
"""

import base64
import binascii
import copy
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Final, Literal

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    audit_events,
    change_events,
    change_items,
    enrichments,
    notes,
    sources,
    users,
)
from driftsniff.enrich.models import (
    PAYLOAD_MAX_BYTES,
    PAYLOAD_MAX_DEPTH,
    REQUEST_MAX_BYTES,
    ChangeDetail,
    ChangeItemView,
    ChangePage,
    ChangeSummary,
    EnrichmentRequest,
    EnrichmentView,
    NoteView,
    SourceRef,
    payload_depth,
)
from driftsniff.secrets.fingerprint import Fingerprint
from driftsniff.secrets.redact import scrub_text
from driftsniff.web.auth import parse_stamp, stamp
from driftsniff.web.bearer import TokenPrincipal
from driftsniff.web.csrf import is_api_path
from driftsniff.web.deps import require_enrich_token, require_read_token

DEFAULT_PAGE_SIZE: Final = 50
MAX_PAGE_SIZE: Final = 100
MAX_ITEMS_PER_CHANGE: Final = 1000
MAX_ENRICHMENTS_PER_CHANGE: Final = 100
FINGERPRINT_SHOWN_CHARS: Final = 12
ACTION_ENRICHMENT_ADDED: Final = "enrichment.added"

_MAX_ID: Final = 2**31 - 1
_CURSOR_PREFIX: Final = "v1:"
_SINCE_SHAPE: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_JSON_TYPE: Final = "application/json"
_SECRET_CLASSES: Final = frozenset({"secret", "unclassified"})
_BEARER_SECURITY: Final[list[dict[str, list[str]]]] = [{"bearerAuth": []}]

Severity = Literal["low", "medium", "high", "critical"]
EventStatus = Literal["open", "acknowledged"]


class ChangeNotFoundError(Exception):
    """No change event has this id."""


class EnrichmentLimitError(Exception):
    """The change already holds the most enrichments it may hold."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def encode_cursor(event_id: int) -> str:
    """An opaque cursor for 'older than this event'."""
    raw = f"{_CURSOR_PREFIX}{event_id}".encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> int:
    """The event id inside a cursor; ValueError when it is not one this API made."""
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError) as error:
        raise ValueError("the cursor is not valid") from error
    digits = raw.removeprefix(_CURSOR_PREFIX)
    valid = raw != digits and digits.isascii() and digits.isdigit()
    if not valid or not 1 <= int(digits) <= _MAX_ID:
        raise ValueError("the cursor is not valid")
    return int(digits)


def _short_fingerprint(stored: str | None) -> str | None:
    """The first 12 characters of a stored fingerprint; text of any other shape is dropped."""
    if stored is None:
        return None
    parsed = Fingerprint.parse(stored)
    return None if parsed is None else parsed.short(FINGERPRINT_SHOWN_CHARS)


def _summary(row: Any) -> ChangeSummary:
    return ChangeSummary(
        id=row.id,
        source=SourceRef(id=row.source_id, name=row.source_name),
        severity=row.max_severity,
        status=row.status,
        summary=row.summary,
        item_count=row.item_count,
        window_start=row.window_start,
        window_end=row.window_end,
        created_at=row.created_at,
        rule_pack_version=row.rule_pack_version,
    )


def _scrubbed(text: str | None) -> str | None:
    return None if text is None else scrub_text(text)


def _scrubbed_json(value: Any) -> Any:
    """The same JSON with every text (and every key) passed through the scrubber."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, list):
        return [_scrubbed_json(member) for member in value]
    if isinstance(value, dict):
        return {scrub_text(str(key)): _scrubbed_json(member) for key, member in value.items()}
    return value


def _item(row: Any) -> ChangeItemView:
    shown = row.field_class not in _SECRET_CLASSES
    return ChangeItemView(
        id=row.id,
        resource=row.resource,
        object_name=_scrubbed(row.object_name_at_time),
        change_kind=row.change_kind,
        path=scrub_text(row.path),
        field_class=row.field_class,
        before=row.before_value if shown else None,
        after=row.after_value if shown else None,
        before_fingerprint=_short_fingerprint(row.before_fp),
        after_fingerprint=_short_fingerprint(row.after_fp),
        severity=row.severity,
        rule_id=row.rule_id,
        rationale=_scrubbed(row.rationale),
        order_detail=_scrubbed_json(row.order_detail),
    )


class ChangeService:
    """Reads changes and appends enrichments."""

    def __init__(self, database: Database, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._db = database
        self._clock = clock

    def list_changes(
        self,
        *,
        source_id: int | None = None,
        severity: str | None = None,
        status: str | None = None,
        since: str | None = None,
        before_id: int | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
    ) -> ChangePage:
        """One page of changes, newest first, without their items."""
        query = (
            sa.select(change_events, sources.c.name.label("source_name"))
            .join(sources, sources.c.id == change_events.c.source_id)
            .order_by(change_events.c.id.desc())
            .limit(limit + 1)
        )
        if source_id is not None:
            query = query.where(change_events.c.source_id == source_id)
        if severity is not None:
            query = query.where(change_events.c.max_severity == severity)
        if status is not None:
            query = query.where(change_events.c.status == status)
        if since is not None:
            query = query.where(change_events.c.created_at >= since)
        if before_id is not None:
            query = query.where(change_events.c.id < before_id)
        with self._db.read() as connection:
            rows = connection.execute(query).all()
        page = rows[:limit]
        more = len(rows) > limit and bool(page)
        return ChangePage(
            changes=[_summary(row) for row in page],
            next_cursor=encode_cursor(page[-1].id) if more else None,
        )

    def get_change(self, event_id: int) -> ChangeDetail | None:
        """One change with its items, notes and enrichments; None when it does not exist."""
        with self._db.read() as connection:
            row = connection.execute(
                sa.select(change_events, sources.c.name.label("source_name"))
                .join(sources, sources.c.id == change_events.c.source_id)
                .where(change_events.c.id == event_id)
            ).first()
            if row is None:
                return None
            item_rows = connection.execute(
                sa.select(change_items)
                .where(change_items.c.event_id == event_id)
                .order_by(change_items.c.id)
                .limit(MAX_ITEMS_PER_CHANGE + 1)
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
        return ChangeDetail(
            **_summary(row).model_dump(),
            items=[_item(item) for item in item_rows[:MAX_ITEMS_PER_CHANGE]],
            items_truncated=len(item_rows) > MAX_ITEMS_PER_CHANGE,
            notes=[
                NoteView(id=n.id, author=n.username, body=n.body, created_at=n.created_at)
                for n in note_rows
            ],
            enrichments=[_enrichment(found) for found in enrichment_rows],
        )

    def add_enrichment(
        self, event_id: int, token: TokenPrincipal, request: EnrichmentRequest
    ) -> EnrichmentView:
        """Append one enrichment; ChangeNotFoundError or EnrichmentLimitError store nothing."""
        now = stamp(self._clock())
        with self._db.write() as connection:
            found = connection.execute(
                sa.select(change_events.c.id).where(change_events.c.id == event_id)
            ).first()
            if found is None:
                raise ChangeNotFoundError
            held = connection.execute(
                sa.select(sa.func.count())
                .select_from(enrichments)
                .where(enrichments.c.event_id == event_id)
            ).scalar_one()
            if held >= MAX_ENRICHMENTS_PER_CHANGE:
                raise EnrichmentLimitError
            enrichment_id = int(
                connection.execute(
                    sa.insert(enrichments)
                    .values(
                        event_id=event_id,
                        token_id=token.token_id,
                        provider_label=request.provider_label,
                        summary=request.summary,
                        payload=request.payload,
                        created_at=now,
                    )
                    .returning(enrichments.c.id)
                ).scalar_one()
            )
            connection.execute(
                sa.insert(audit_events).values(
                    at=now,
                    actor=f"token:{token.prefix}",
                    action=ACTION_ENRICHMENT_ADDED,
                    target=f"event:{event_id}",
                    detail={
                        "enrichment_id": enrichment_id,
                        "provider_label": request.provider_label,
                    },
                )
            )
        return EnrichmentView(
            id=enrichment_id,
            provider_label=request.provider_label,
            summary=request.summary,
            payload=request.payload,
            created_at=now,
        )


def _enrichment(row: Any) -> EnrichmentView:
    return EnrichmentView(
        id=row.id,
        provider_label=row.provider_label,
        summary=row.summary,
        payload=row.payload,
        created_at=row.created_at,
    )


def get_change_service(request: Request) -> ChangeService:
    """The application's change service; 503 when the application was built without one."""
    service: ChangeService | None = request.app.state.changes
    if service is None:
        raise HTTPException(status_code=503, detail="the change API is not available")
    return service


router = APIRouter(prefix="/api/v1")

_AUTH_ANSWERS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"description": "The API token is missing, malformed, unknown, expired or revoked."},
    403: {"description": "The API token does not carry the scope this route needs."},
}


def _problem(status: int, detail: str, **extra: object) -> JSONResponse:
    return JSONResponse({"detail": detail, **extra}, status_code=status)


@router.get(
    "/changes",
    response_model=ChangePage,
    responses=_AUTH_ANSWERS,
    openapi_extra={"security": _BEARER_SECURITY},
)
def list_changes(
    _token: Annotated[TokenPrincipal, Depends(require_read_token)],
    service: Annotated[ChangeService, Depends(get_change_service)],
    source: Annotated[int | None, Query(ge=1, le=_MAX_ID, description="Source id.")] = None,
    severity: Annotated[Severity | None, Query(description="Highest severity.")] = None,
    status: Annotated[EventStatus | None, Query()] = None,
    since: Annotated[
        str | None,
        Query(
            max_length=20,
            description="Only changes recorded at or after this UTC time (2026-10-01T00:00:00Z).",
        ),
    ] = None,
    cursor: Annotated[str | None, Query(max_length=64, description="From next_cursor.")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> Response:
    """Changes, newest first, without their items. Needs the ``read`` scope."""
    if since is not None:
        try:
            if _SINCE_SHAPE.fullmatch(since) is None:
                raise ValueError("since has the wrong shape")
            parse_stamp(since)
        except ValueError:
            return _problem(422, "since must be a UTC time like 2026-10-01T00:00:00Z")
    before_id: int | None = None
    if cursor is not None:
        try:
            before_id = decode_cursor(cursor)
        except ValueError:
            return _problem(422, "the cursor is not valid")
    page = service.list_changes(
        source_id=source,
        severity=severity,
        status=status,
        since=since,
        before_id=before_id,
        limit=limit,
    )
    return JSONResponse(page.model_dump(mode="json"))


@router.get(
    "/changes/{event_id}",
    response_model=ChangeDetail,
    responses={**_AUTH_ANSWERS, 404: {"description": "No such change."}},
    openapi_extra={"security": _BEARER_SECURITY},
)
def get_change(
    event_id: Annotated[int, Path(ge=1, le=_MAX_ID)],
    _token: Annotated[TokenPrincipal, Depends(require_read_token)],
    service: Annotated[ChangeService, Depends(get_change_service)],
) -> Response:
    """One change with its items, notes and enrichments. Needs the ``read`` scope."""
    detail = service.get_change(event_id)
    if detail is None:
        return _problem(404, "no such change")
    return JSONResponse(detail.model_dump(mode="json"))


async def _read_limited(request: Request) -> bytes | None:
    """The request body, or None when it is larger than the request limit."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > REQUEST_MAX_BYTES:
        return None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > REQUEST_MAX_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _compact_json(value: object) -> bytes:
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return text.encode("utf-8")


def _field_problems(error: ValidationError) -> list[dict[str, str]]:
    """Where and what is wrong, never the value the caller sent."""
    return [
        {"field": ".".join(str(part) for part in found["loc"]) or "body", "problem": found["type"]}
        for found in error.errors(include_input=False, include_url=False, include_context=False)
    ]


_ENRICH_ANSWERS: Final[dict[int | str, dict[str, Any]]] = {
    **_AUTH_ANSWERS,
    404: {"description": "No such change."},
    409: {"description": "The change already holds 100 enrichments."},
    413: {"description": "The request is over 64 KB or the payload is over 32 KB."},
    415: {"description": "The body is not application/json."},
    422: {"description": "A field breaks its rule; the answer names the field, not its value."},
}


@router.post(
    "/changes/{event_id}/enrichments",
    status_code=201,
    response_model=EnrichmentView,
    responses=_ENRICH_ANSWERS,
    openapi_extra={
        "security": _BEARER_SECURITY,
        "requestBody": {
            "required": True,
            "content": {_JSON_TYPE: {"schema": EnrichmentRequest.model_json_schema()}},
        },
    },
)
async def add_enrichment(
    request: Request,
    event_id: Annotated[int, Path(ge=1, le=_MAX_ID)],
    token: Annotated[TokenPrincipal, Depends(require_enrich_token)],
    service: Annotated[ChangeService, Depends(get_change_service)],
) -> Response:
    """Append an enrichment to a change. Needs the ``enrich`` scope.

    Append only: it never changes the severity or the status. The interface shows it under
    "External analysis, not verified by the product", as escaped text.
    """
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type != _JSON_TYPE:
        return _problem(415, "the body must be application/json")
    body = await _read_limited(request)
    if body is None:
        return _problem(413, "the request is larger than 64 KB")
    try:
        parsed = EnrichmentRequest.model_validate_json(body)
    except ValidationError as error:
        return _problem(422, "the request is not valid", errors=_field_problems(error))
    if parsed.payload is not None:
        if payload_depth(parsed.payload) > PAYLOAD_MAX_DEPTH:
            return _problem(422, f"the payload is nested deeper than {PAYLOAD_MAX_DEPTH} levels")
        try:
            size = len(_compact_json(parsed.payload))
        except (ValueError, TypeError):
            return _problem(422, "the payload is not plain JSON")
        if size > PAYLOAD_MAX_BYTES:
            return _problem(413, "the payload is larger than 32 KB")
    try:
        created = await run_in_threadpool(service.add_enrichment, event_id, token, parsed)
    except ChangeNotFoundError:
        return _problem(404, "no such change")
    except EnrichmentLimitError:
        return _problem(409, "this change already holds the most enrichments it may hold")
    return JSONResponse(created.model_dump(mode="json"), status_code=201)


def build_openapi(app: Any) -> dict[str, Any]:
    """The OpenAPI document of the routes under ``/api/v1`` of this application."""
    # ``app.openapi()`` follows nested routers; the application's own cache is cleared around the
    # call so a route added later shows up.
    app.openapi_schema = None
    full = app.openapi()
    app.openapi_schema = None
    document: dict[str, Any] = {
        "openapi": full["openapi"],
        "info": {
            "title": "driftsniff API",
            "version": app.version,
            "summary": "Read changes and append enrichments.",
        },
        "paths": copy.deepcopy(
            {path: item for path, item in full["paths"].items() if is_api_path(path)}
        ),
        "components": copy.deepcopy(full.get("components", {})),
    }
    components = document["components"]
    components.setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "description": "An API token, sent as Authorization: Bearer <token>.",
    }
    return document


@router.get("/openapi.json", response_model=None)
def openapi_document(request: Request) -> JSONResponse:
    """The OpenAPI document of ``/api/v1``. Public: it holds no data of this installation."""
    app = request.app
    key = tuple(id(route) for route in app.routes)
    cached = getattr(app.state, "openapi_cache", None)
    if cached is None or cached[0] != key:
        cached = (key, build_openapi(app))
        app.state.openapi_cache = cached
    return JSONResponse(cached[1])
