"""The change pages (P10-T6, frontend slice): the list, the detail and the three actions.

Roles (P9-T1): a viewer reads the change list and the change detail; an operator also
acknowledges, writes notes, mutes a path and removes a mute. The role check is a dependency of
each route, so it runs before anything else, and the services refuse a lower role again on
their own. The security suite lists every route here in its route table.

Every page works without JavaScript: the forms are plain posts and every answer is a page or
a redirect (post, redirect, get). Content negotiation is the one of ``driftsniff.web.pages``: a
browser gets pages, every other client gets JSON with the same status codes. The CSRF value
travels in every form; the origin and CSRF checks are the middleware's.

Every text that reaches a template is the plain text of ``driftsniff.changes.views``; the
templates print it through autoescape, never through the ``safe`` filter (the template scan
test enforces that), so markup in a note, a name or an enrichment comes out as text.
"""

import dataclasses
from collections.abc import Iterable, Mapping
from typing import Annotated, Any, Final
from urllib.parse import parse_qsl, urlencode

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse, Response

from driftsniff.changes.actions import (
    ACK_COMMENT_MAX_CHARS,
    MUTE_REASON_MAX_CHARS,
    NOTE_MAX_CHARS,
)
from driftsniff.changes.errors import (
    ActionForbiddenError,
    EntryLimitError,
    InvalidTextError,
    NotMutableError,
    UnknownChangeError,
    UnknownItemError,
    UnknownMuteError,
)
from driftsniff.changes.filters import parse_filters
from driftsniff.changes.paths import mute_refusal
from driftsniff.changes.views import ChangeDetailView, ChangeFilters
from driftsniff.web.auth import ROLE_RANK, Principal
from driftsniff.web.change_pages import (
    EXACT_SEVERITIES,
    LIST_PATH,
    SEVERITY_FLOOR_LABELS,
    STATUS_LABELS,
    ChangePages,
    Choice,
    count_words,
    display_value,
    field_label,
    filter_query,
    filters_text,
    fingerprint_words,
    item_summary,
    kind_label,
    move_text,
    page_summary,
    pager_links,
    severity_choice,
    severity_params,
    split_difference,
)
from driftsniff.web.dashboard import parse_stamp, resource_label, window_text
from driftsniff.web.deps import require_operator, require_viewer
from driftsniff.web.pages import page, shell_for, wants_html
from driftsniff.web.preferences import safe_next
from driftsniff.web.routes_ui import read_fields

router = APIRouter()

_MAX_ID: Final = 2**31 - 1
RowId = Annotated[int, Path(ge=1, le=_MAX_ID)]

ACK_FIELD: Final = "comment"
NOTE_FIELD: Final = "note"
REASON_FIELD: Final = "reason"
EVENT_FIELD: Final = "event"
NEXT_FIELD: Final = "next"

# The messages a redirect may ask the next page to show; any other word shows nothing.
NOTICES: Final = {
    "acknowledged": (
        "Change acknowledged",
        "Your name and the time are recorded. The severity is unchanged, and every "
        "acknowledgement is kept.",
    ),
    "note-added": ("Note saved", "It is kept with this change; notes are never edited."),
    "muted": (
        "Path muted",
        "It is hidden from the change list for every source of this type. Nothing was "
        "deleted, and a critical item is never hidden.",
    ),
    "mute-exists": ("Already muted", "This path was muted before. Nothing was changed."),
    "unmuted": ("Mute removed", "The changes it hid show in the list again."),
}


def _text_refusals() -> dict[str, str]:
    """The service's reason for a refused text, and what the page says instead."""
    refusals = {"the text is empty": "Write the note first."}
    for noun, limit in (
        ("comment", ACK_COMMENT_MAX_CHARS),
        ("note", NOTE_MAX_CHARS),
        ("reason", MUTE_REASON_MAX_CHARS),
    ):
        refusals[f"the text is longer than {limit} characters"] = (
            f"Keep the {noun} under {limit:,} characters."
        )
    return refusals


# What a refused text says, by reason. The service never quotes the text; neither does the page.
TEXT_REFUSALS: Final = _text_refusals()
GENERIC_TEXT_REFUSAL: Final = "The text cannot be stored: remove control characters and try again."
ENTRY_LIMIT: Final = (
    "This change holds as many entries as it may",
    "No more acknowledgements or notes can be added to it. Nothing was changed.",
)


def get_change_pages(request: Request) -> ChangePages:
    """The change pages service; 503 when the application was built without one."""
    pages: ChangePages | None = request.app.state.change_pages
    if pages is None:
        raise HTTPException(status_code=503, detail="changes are not available")
    return pages


Pages = Annotated[ChangePages, Depends(get_change_pages)]


def _can_operate(user: Principal) -> bool:
    return ROLE_RANK[user.role] >= ROLE_RANK["operator"]


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _notice(request: Request) -> tuple[str, str] | None:
    return NOTICES.get(request.query_params.get("notice", ""))


def _refusal_text(error: InvalidTextError) -> str:
    return TEXT_REFUSALS.get(str(error), GENERIC_TEXT_REFUSAL)


def _query(request: Request) -> dict[str, list[str]]:
    """The query string as a name to all its values, the shape ``parse_filters`` reads."""
    grouped: dict[str, list[str]] = {}
    for name, value in request.query_params.multi_items():
        grouped.setdefault(name, []).append(value)
    return grouped


def _filters(request: Request) -> ChangeFilters:
    return parse_filters(severity_params(_query(request)))


def _json(value: Any) -> Any:
    return dataclasses.asdict(value)


def _choices(choices: Iterable[Choice]) -> list[dict[str, str]]:
    """The options of a select of the filter bar: All first, then the choices."""
    return [{"value": "", "label": "All"}] + [
        {"value": choice.value, "label": choice.label} for choice in choices
    ]


# ---- the list ---------------------------------------------------------------------------------


@router.get("/changes")
async def list_changes(
    request: Request, user: Annotated[Principal, Depends(require_viewer)], pages: Pages
) -> Response:
    """One page of the change list: search, filters, sort, 50 per page; JSON for a script."""
    filters = _filters(request)
    listing = await run_in_threadpool(pages.queries.list_changes, filters)
    if not wants_html(request):
        return JSONResponse(
            {
                "changes": [_json(row) for row in listing.rows],
                "total": listing.total,
                "page": listing.page,
                "pages": listing.pages,
                "muted_hidden": listing.muted_hidden,
                "mute_scan_truncated": listing.mute_scan_truncated,
            }
        )
    options = await run_in_threadpool(pages.filter_options)
    mutes = await run_in_threadpool(pages.queries.list_mutes)
    now = pages.now()
    shell = shell_for(request, user, "Changes", "changes")
    exact = severity_choice(filters) == EXACT_SEVERITIES
    return page(
        "changes/list.html",
        shell,
        listing=listing,
        filters=filters,
        options=options,
        mutes=mutes,
        now=now,
        notice=_notice(request),
        severity_choice=severity_choice(filters),
        severity_floors=list(SEVERITY_FLOOR_LABELS.items()),
        exact_severities=list(filters.severities) if exact else [],
        exact_label=" or ".join(name.capitalize() for name in filters.severities),
        source_options=_choices(options.sources),
        status_options=_choices(Choice(value, label) for value, label in STATUS_LABELS.items()),
        resource_options=_choices(options.resources),
        active_filters=filters_text(filters, options.source_names()),
        summary=page_summary(listing),
        pager=pager_links(filters, listing),
        sort_hrefs={
            "severity": filter_query(filters, sort="severity", page=None),
            "newest": filter_query(filters, sort=None, page=None),
            "oldest": filter_query(filters, sort="oldest", page=None),
        },
        show_muted_href=filter_query(filters, muted="1", page=None),
        hide_muted_href=filter_query(filters, muted=None, page=None),
        clear_href="/changes",
        parse_stamp=parse_stamp,
        count_words=count_words,
        resource_label=resource_label,
        can_operate=_can_operate(user),
    )


# ---- the detail -------------------------------------------------------------------------------


async def _detail(pages: ChangePages, event_id: int) -> ChangeDetailView:
    found = await run_in_threadpool(pages.queries.get_change, event_id)
    if found is None:
        raise HTTPException(status_code=404, detail="there is no such change")
    return found


def _detail_page(
    request: Request,
    user: Principal,
    pages: ChangePages,
    detail: ChangeDetailView,
    *,
    notice: tuple[str, str] | None = None,
    problem: tuple[str, str] | None = None,
    ack_error: str = "",
    note_error: str = "",
    ack_comment: str = "",
    note_body: str = "",
    status: int = 200,
) -> Response:
    """The change detail in every state: plain, after a redirect, or after a refused form."""
    now = pages.now()
    change = detail.change
    start, end = parse_stamp(change.window_start), parse_stamp(change.window_end)
    objects = count_words(len(detail.groups), "object")
    items = count_words(change.item_count, "item")
    shell = shell_for(request, user, change.summary, "changes")
    return page(
        "changes/detail.html",
        shell,
        status=status,
        detail=detail,
        change=change,
        now=now,
        window=window_text(start, end, now),
        counts=f"{items} in {objects}",
        notice=notice,
        problem=problem,
        ack_error=ack_error,
        note_error=note_error,
        ack_comment=ack_comment,
        note_body=note_body,
        ack_limit=ACK_COMMENT_MAX_CHARS,
        note_limit=NOTE_MAX_CHARS,
        reason_limit=MUTE_REASON_MAX_CHARS,
        parse_stamp=parse_stamp,
        resource_label=resource_label,
        field_label=field_label,
        kind_label=kind_label,
        item_summary=item_summary,
        move_text=move_text,
        fingerprint_words=fingerprint_words,
        display_value=display_value,
        split_difference=split_difference,
        mute_refusal=mute_refusal,
        count_words=count_words,
        can_operate=_can_operate(user),
    )


@router.get("/changes/{event_id}")
async def change_page(
    request: Request,
    user: Annotated[Principal, Depends(require_viewer)],
    pages: Pages,
    event_id: RowId,
) -> Response:
    """The change detail: the items by object, the acknowledgements, notes and enrichments."""
    detail = await _detail(pages, event_id)
    if not wants_html(request):
        return JSONResponse({"change": _json(detail)})
    return _detail_page(request, user, pages, detail, notice=_notice(request))


# ---- acknowledge and notes --------------------------------------------------------------------


@router.post("/changes/{event_id}/acknowledge")
async def acknowledge_change(
    request: Request,
    user: Annotated[Principal, Depends(require_operator)],
    pages: Pages,
    event_id: RowId,
) -> Response:
    """Append an acknowledgement (the comment may be empty); acknowledging again adds a row."""
    fields = await read_fields(request)
    comment = fields.get(ACK_FIELD, "")
    html = wants_html(request)
    try:
        row = await run_in_threadpool(pages.actions.acknowledge, user, event_id, comment)
    except UnknownChangeError as error:
        raise HTTPException(status_code=404, detail="there is no such change") from error
    except ActionForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except InvalidTextError as error:
        if not html:
            return JSONResponse({"detail": _refusal_text(error)}, status_code=422)
        detail = await _detail(pages, event_id)
        return _detail_page(
            request,
            user,
            pages,
            detail,
            ack_error=_refusal_text(error),
            ack_comment=comment,
            status=422,
        )
    except EntryLimitError:
        return await _entry_limit(request, user, pages, event_id, html)
    if html:
        return _redirect(f"/changes/{event_id}?notice=acknowledged#acknowledge")
    return JSONResponse({"acknowledgement": _json(row)}, status_code=201)


@router.post("/changes/{event_id}/notes")
async def add_note(
    request: Request,
    user: Annotated[Principal, Depends(require_operator)],
    pages: Pages,
    event_id: RowId,
) -> Response:
    """Append a note to a change; an empty note is refused with the field marked."""
    fields = await read_fields(request)
    body = fields.get(NOTE_FIELD, "")
    html = wants_html(request)
    try:
        row = await run_in_threadpool(pages.actions.add_note, user, event_id, body)
    except UnknownChangeError as error:
        raise HTTPException(status_code=404, detail="there is no such change") from error
    except ActionForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except InvalidTextError as error:
        if not html:
            return JSONResponse({"detail": _refusal_text(error)}, status_code=422)
        detail = await _detail(pages, event_id)
        return _detail_page(
            request,
            user,
            pages,
            detail,
            note_error=_refusal_text(error),
            note_body=body,
            status=422,
        )
    except EntryLimitError:
        return await _entry_limit(request, user, pages, event_id, html)
    if html:
        return _redirect(f"/changes/{event_id}?notice=note-added#notes")
    return JSONResponse({"note": _json(row)}, status_code=201)


async def _entry_limit(
    request: Request, user: Principal, pages: ChangePages, event_id: int, html: bool
) -> Response:
    if not html:
        return JSONResponse({"detail": f"{ENTRY_LIMIT[0]}. {ENTRY_LIMIT[1]}"}, status_code=409)
    detail = await _detail(pages, event_id)
    return _detail_page(request, user, pages, detail, problem=ENTRY_LIMIT, status=409)


# ---- mutes --------------------------------------------------------------------------------------


def _event_of(fields: Mapping[str, str]) -> int | None:
    """The change the mute form sits on, to go back to it; None for anything else."""
    raw = fields.get(EVENT_FIELD, "").strip()
    if raw.isascii() and raw.isdigit() and 1 <= int(raw) <= _MAX_ID:
        return int(raw)
    return None


@router.post("/changes/items/{item_id}/mute")
async def mute_item_path(
    request: Request,
    user: Annotated[Principal, Depends(require_operator)],
    pages: Pages,
    item_id: RowId,
) -> Response:
    """Mute the path of one item for its resource type (never a critical item)."""
    fields = await read_fields(request)
    reason = fields.get(REASON_FIELD, "")
    html = wants_html(request)
    event_id = _event_of(fields)
    try:
        result = await run_in_threadpool(pages.actions.mute_path, user, item_id, reason)
    except UnknownItemError as error:
        raise HTTPException(status_code=404, detail="there is no such change item") from error
    except ActionForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except (NotMutableError, InvalidTextError) as error:
        title = "This path was not muted"
        text = (
            _refusal_text(error)
            if isinstance(error, InvalidTextError)
            else f"{str(error)[:1].upper()}{str(error)[1:]}. Nothing was changed."
        )
        if not html:
            return JSONResponse({"detail": f"{title}. {text}"}, status_code=409)
        if event_id is None:
            raise HTTPException(status_code=409, detail=f"{title}. {text}") from error
        detail = await _detail(pages, event_id)
        return _detail_page(request, user, pages, detail, problem=(title, text), status=409)
    if html:
        word = "muted" if result.created else "mute-exists"
        target = f"/changes/{event_id}" if event_id is not None else "/changes"
        return _redirect(f"{target}?notice={word}")
    status = 201 if result.created else 200
    return JSONResponse({"mute": _json(result.mute), "created": result.created}, status_code=status)


def _with_notice(back: str, word: str) -> str:
    """``back`` (a safe local path; the start page means the change list) with one notice.

    A notice already in the query (the page the form sat on was itself shown after a redirect)
    is replaced, so the address never collects them.
    """
    path, _mark, query = (LIST_PATH if back == "/" else back).partition("?")
    kept = [(name, value) for name, value in parse_qsl(query) if name != "notice"]
    return f"{path}?{urlencode([*kept, ('notice', word)])}"


@router.post("/mutes/{mute_id}/remove")
async def remove_mute(
    request: Request,
    user: Annotated[Principal, Depends(require_operator)],
    pages: Pages,
    mute_id: RowId,
) -> Response:
    """Delete a mute; the changes it hid show in the list again."""
    fields = await read_fields(request)
    try:
        await run_in_threadpool(pages.actions.remove_mute, user, mute_id)
    except UnknownMuteError as error:
        raise HTTPException(status_code=404, detail="there is no such mute") from error
    except ActionForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    if wants_html(request):
        return _redirect(_with_notice(safe_next(fields.get(NEXT_FIELD)), "unmuted"))
    return JSONResponse({"removed": mute_id})
