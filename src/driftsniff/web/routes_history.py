"""The History and Configuration routes (P10-T7): who may read what, the data and the pages.

Roles (P9-T1): a viewer reads both pages; nothing here writes, so no route needs a higher role and
no audit event is written. The role check is a dependency of each route, so it runs before
anything else. The security suite lists every route here in its route table. The pages offer an
operator Run now (a post to the source's own run route, with the CSRF value) and an admin Edit
source; both are links or forms to routes of ``driftsniff.web.routes_sources``, which check the
role again.

* ``GET /history`` and ``GET /configuration``: the sources with their snapshot count and the time
  of the newest snapshot (the picker of both pages).
* ``GET /history/{source_id}?page=N``: the snapshots of a source, newest first, 50 a page, each
  with its kind (a baseline is marked), controller version and the number of changes found.
* ``GET /configuration/{source_id}?resource=&q=&page=``: the newest snapshot of a source, one
  resource at a time, 50 objects a page; ``q`` searches the shown text.

Content negotiation is the one of ``driftsniff.web.pages``: a browser (or an HTMX request of the
configuration page) gets a page, every other client gets JSON with the same status codes: 401
without a session, 403 below viewer, 404 for an unknown source, 503 when the application was
built without the service and 500 when a stored manifest or state is damaged (a browser gets the
designed error page with a retry button for that one).

Every text in an answer is the plain text of ``driftsniff.history.views``; a page prints it
through autoescape, never through the ``safe`` filter (the template scan test enforces that).
"""

import dataclasses
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from driftsniff.history.errors import StoredConfigurationError
from driftsniff.history.service import HistoryService
from driftsniff.history.views import SEARCH_MAX_CHARS, SourceHistoryRow, SourceRef
from driftsniff.sources.service import POLLED_TYPES
from driftsniff.web.auth import ROLE_RANK, Principal
from driftsniff.web.change_pages import count_words, fingerprint_words
from driftsniff.web.dashboard import parse_stamp, resource_label, source_type_label
from driftsniff.web.deps import require_viewer
from driftsniff.web.history_pages import (
    PICKERS,
    configuration_href,
    field_state,
    hidden_text,
    history_href,
    ledger_mark,
    object_title,
    page_links,
    range_text,
    size_text,
    utc_now,
)
from driftsniff.web.pages import page, shell_for, wants_html

router = APIRouter()

_MAX_ID: Final = 2**31 - 1
_MAX_PAGE_DIGITS: Final = 9
RESOURCE_MAX_CHARS: Final = 200
SourceId = Annotated[int, Path(ge=1, le=_MAX_ID)]

UNREADABLE: Final = (
    "The stored configuration cannot be read",
    "The newest reading of this source is damaged, so it is not shown. Nothing was changed; "
    "try again, and if it stays like this restore the last backup.",
)


def get_history_service(request: Request) -> HistoryService:
    """The history service; 503 when the application was built without one."""
    service: HistoryService | None = request.app.state.history
    if service is None:
        raise HTTPException(status_code=503, detail="history is not available")
    return service


History = Annotated[HistoryService, Depends(get_history_service)]


def _json(value: Any) -> Any:
    return dataclasses.asdict(value)


def _page_of(request: Request) -> int:
    """The ``page`` of the query; anything that is not a plain number is the first page."""
    raw = request.query_params.get("page", "")
    if raw.isascii() and raw.isdigit() and len(raw) <= _MAX_PAGE_DIGITS:
        return max(1, int(raw))
    return 1


def _wants_page(request: Request) -> bool:
    """A browser, or an HTMX request of the configuration page (it swaps a part of the page)."""
    return wants_html(request) or request.headers.get("hx-request") == "true"


def _roles(user: Principal) -> dict[str, bool]:
    return {
        "can_operate": ROLE_RANK[user.role] >= ROLE_RANK["operator"],
        "can_admin": ROLE_RANK[user.role] >= ROLE_RANK["admin"],
    }


def _source_context(request: Request, user: Principal, source: SourceRef) -> dict[str, Any]:
    """What the head of both source pages needs: the type, the actions the role allows."""
    return {
        "type_label": source_type_label(source.type),
        "polled": source.type in POLLED_TYPES,
        "scheduled": request.app.state.scheduler is not None,
        **_roles(user),
    }


# ---- the pickers ------------------------------------------------------------------------------


def _picker(request: Request, user: Principal, rows: list[SourceHistoryRow], key: str) -> Response:
    title, purpose = PICKERS[key]
    shell = shell_for(request, user, title, key)
    return page(
        "history/sources.html",
        shell,
        rows=rows,
        mode=key,
        title=title,
        purpose=purpose,
        now=utc_now(),
        parse_stamp=parse_stamp,
        type_label=source_type_label,
        count_words=count_words,
        **_roles(user),
    )


@router.get("/history")
async def history_sources(
    request: Request, user: Annotated[Principal, Depends(require_viewer)], service: History
) -> Response:
    """The sources with their number of snapshots and the time of the newest."""
    rows = await run_in_threadpool(service.history.list_sources)
    if not wants_html(request):
        return JSONResponse({"sources": [_json(row) for row in rows]})
    return _picker(request, user, list(rows), "history")


@router.get("/configuration")
async def configuration_sources(
    request: Request, user: Annotated[Principal, Depends(require_viewer)], service: History
) -> Response:
    """The sources whose current configuration can be browsed."""
    rows = await run_in_threadpool(service.history.list_sources)
    if not wants_html(request):
        return JSONResponse({"sources": [_json(row) for row in rows]})
    return _picker(request, user, list(rows), "configuration")


# ---- the history of a source ------------------------------------------------------------------


@router.get("/history/{source_id}")
async def source_history(
    request: Request,
    user: Annotated[Principal, Depends(require_viewer)],
    service: History,
    source_id: SourceId,
) -> Response:
    """The snapshots of one source, newest first, 50 a page."""
    view = await run_in_threadpool(service.history.list_snapshots, source_id, _page_of(request))
    if view is None:
        raise HTTPException(status_code=404, detail="there is no such source")
    if not wants_html(request):
        return JSONResponse({"history": _json(view)})
    shell = shell_for(request, user, f"History of {view.source.name}", "history")
    return page(
        "history/snapshots.html",
        shell,
        view=view,
        now=utc_now(),
        pager=page_links(view.page, view.pages, lambda number: history_href(source_id, number)),
        summary=range_text(view.total, view.page, view.page_size, "reading"),
        ledger_mark=ledger_mark,
        size_text=size_text,
        parse_stamp=parse_stamp,
        count_words=count_words,
        configuration_href=configuration_href(source_id),
        **_source_context(request, user, view.source),
    )


# ---- the current configuration of a source ----------------------------------------------------


@router.get("/configuration/{source_id}")
async def source_configuration(
    request: Request,
    user: Annotated[Principal, Depends(require_viewer)],
    service: History,
    source_id: SourceId,
) -> Response:
    """The newest snapshot of one source: a resource at a time, searchable, 50 objects a page."""
    params = request.query_params
    resource = params.get("resource", "")[:RESOURCE_MAX_CHARS] or None
    search = params.get("q", "")[:SEARCH_MAX_CHARS]
    page_number = _page_of(request)
    html = _wants_page(request)
    try:
        view = await run_in_threadpool(
            lambda: service.configuration.current(
                source_id, resource=resource, search=search, page=page_number
            )
        )
    except StoredConfigurationError as error:
        if not html:
            raise HTTPException(status_code=500, detail=str(error)) from error
        return await _unreadable(request, user, service, source_id)
    if view is None:
        raise HTTPException(status_code=404, detail="there is no such source")
    if not html:
        return JSONResponse({"configuration": _json(view)})
    selected = view.selected_resource
    shown_search = view.search
    summary = next((row for row in view.resources if row.resource == selected), None)

    def href(number: int) -> str:
        return configuration_href(source_id, resource=selected, search=shown_search, page=number)

    shell = shell_for(request, user, f"Configuration of {view.source.name}", "configuration")
    return page(
        "history/configuration.html",
        shell,
        view=view,
        selected=summary,
        now=utc_now(),
        pager=page_links(view.page, view.pages, href),
        summary=range_text(view.total, view.page, view.page_size, "object"),
        clear_href=configuration_href(source_id, resource=selected),
        resource_href=lambda name: configuration_href(source_id, resource=name),
        history_href=history_href(source_id),
        unreadable=None,
        field_state=field_state,
        object_title=object_title,
        hidden_text=hidden_text,
        fingerprint_words=fingerprint_words,
        resource_label=resource_label,
        parse_stamp=parse_stamp,
        count_words=count_words,
        **_source_context(request, user, view.source),
    )


async def _unreadable(
    request: Request, user: Principal, service: HistoryService, source_id: int
) -> Response:
    """The designed error page of a damaged store: the source, what happened, and Try again.

    The history reads rows, not manifests, so it still names the source; the text is fixed and
    never quotes stored data.
    """
    history = await run_in_threadpool(service.history.list_snapshots, source_id, 1)
    if history is None:
        raise HTTPException(status_code=404, detail="there is no such source")
    shell = shell_for(request, user, f"Configuration of {history.source.name}", "configuration")
    return page(
        "history/configuration.html",
        shell,
        status=500,
        view=None,
        source=history.source,
        unreadable=UNREADABLE,
        retry_href=configuration_href(source_id),
        history_href=history_href(source_id),
        **_source_context(request, user, history.source),
    )
