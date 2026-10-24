"""The History and Configuration routes (P10-T7, backend slice): who may read what, and the data.

Roles (P9-T1): a viewer reads both pages; nothing here writes, so no route needs a higher role and
no audit event is written. The role check is a dependency of each route, so it runs before
anything else. The security suite lists every route here in its route table.

* ``GET /history`` and ``GET /configuration``: the sources with their snapshot count and the time
  of the newest snapshot (the picker of both pages).
* ``GET /history/{source_id}?page=N``: the snapshots of a source, newest first, 50 a page, each
  with its kind (a baseline is marked), controller version and the number of changes found.
* ``GET /configuration/{source_id}?resource=&q=&page=``: the newest snapshot of a source, one
  resource at a time, 50 objects a page; ``q`` searches the shown text.

Every client gets JSON for now, with the status codes the pages will keep: 401 without a session,
403 below viewer, 404 for an unknown source, 503 when the application was built without the
service and 500 when a stored manifest or state is damaged. The frontend slice adds the HTML
answer next to it, the way ``driftsniff.web.routes_changes`` does with ``wants_html``.

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
from driftsniff.history.views import SEARCH_MAX_CHARS
from driftsniff.web.auth import Principal
from driftsniff.web.deps import require_viewer

router = APIRouter()

_MAX_ID: Final = 2**31 - 1
_MAX_PAGE_DIGITS: Final = 9
RESOURCE_MAX_CHARS: Final = 200
SourceId = Annotated[int, Path(ge=1, le=_MAX_ID)]


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


@router.get("/history")
async def history_sources(
    _viewer: Annotated[Principal, Depends(require_viewer)], service: History
) -> Response:
    """The sources with their number of snapshots and the time of the newest."""
    rows = await run_in_threadpool(service.history.list_sources)
    return JSONResponse({"sources": [_json(row) for row in rows]})


@router.get("/history/{source_id}")
async def source_history(
    request: Request,
    _viewer: Annotated[Principal, Depends(require_viewer)],
    service: History,
    source_id: SourceId,
) -> Response:
    """The snapshots of one source, newest first, 50 a page."""
    view = await run_in_threadpool(service.history.list_snapshots, source_id, _page_of(request))
    if view is None:
        raise HTTPException(status_code=404, detail="there is no such source")
    return JSONResponse({"history": _json(view)})


@router.get("/configuration")
async def configuration_sources(
    _viewer: Annotated[Principal, Depends(require_viewer)], service: History
) -> Response:
    """The sources whose current configuration can be browsed."""
    rows = await run_in_threadpool(service.history.list_sources)
    return JSONResponse({"sources": [_json(row) for row in rows]})


@router.get("/configuration/{source_id}")
async def source_configuration(
    request: Request,
    _viewer: Annotated[Principal, Depends(require_viewer)],
    service: History,
    source_id: SourceId,
) -> Response:
    """The newest snapshot of one source: a resource at a time, searchable, 50 objects a page."""
    params = request.query_params
    resource = params.get("resource", "")[:RESOURCE_MAX_CHARS] or None
    search = params.get("q", "")[:SEARCH_MAX_CHARS]
    page = _page_of(request)
    try:
        view = await run_in_threadpool(
            lambda: service.configuration.current(
                source_id, resource=resource, search=search, page=page
            )
        )
    except StoredConfigurationError as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    if view is None:
        raise HTTPException(status_code=404, detail="there is no such source")
    return JSONResponse({"configuration": _json(view)})
