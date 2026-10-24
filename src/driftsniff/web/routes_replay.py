"""The Change Replay data route (WP4a of the interface revision): who may read it, and the answer.

``GET /sources/{source_id}/replay?days=N`` returns the change items of a source counted per UTC
day, resource type and severity (``driftsniff.web.replay``). Roles (P9-T1): a viewer reads it;
nothing here writes, so no route needs a higher role and no audit event is written. The role
check is a dependency of the route, so it runs before anything else. The security suite lists the
route in its route table.

The answer is JSON for every client, with the status codes of the other source routes: 401 without
a session, 403 below viewer, 404 for an unknown source, 503 when the application was built without
the service. ``days`` is the length of the window (default 30, at most 90); anything that is not a
plain number is the default. The answer holds counts, ids, severity words and resource type names
only, never a stored value.
"""

from typing import Annotated, Final

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from driftsniff.web.auth import Principal
from driftsniff.web.deps import require_viewer
from driftsniff.web.replay import DEFAULT_DAYS, ReplayService

router = APIRouter()

_MAX_ID: Final = 2**31 - 1
_MAX_DAYS_DIGITS: Final = 4
SourceId = Annotated[int, Path(ge=1, le=_MAX_ID)]


def get_replay_service(request: Request) -> ReplayService:
    """The replay service; 503 when the application was built without one."""
    service: ReplayService | None = request.app.state.replay
    if service is None:
        raise HTTPException(status_code=503, detail="the change replay is not available")
    return service


Replays = Annotated[ReplayService, Depends(get_replay_service)]


def _days_of(request: Request) -> int:
    """The ``days`` of the query; anything that is not a plain number is the default window."""
    raw = request.query_params.get("days", "")
    if raw.isascii() and raw.isdigit() and len(raw) <= _MAX_DAYS_DIGITS:
        return int(raw)
    return DEFAULT_DAYS


@router.get("/sources/{source_id}/replay")
async def source_replay(
    request: Request,
    _viewer: Annotated[Principal, Depends(require_viewer)],
    service: Replays,
    source_id: SourceId,
) -> Response:
    """The change items of one source per UTC day, resource type and severity."""
    replay = await run_in_threadpool(service.load, source_id, _days_of(request))
    if replay is None:
        raise HTTPException(status_code=404, detail="there is no such source")
    return JSONResponse(
        {
            "replay": {
                "source_id": replay.source_id,
                "first_day": replay.first_day,
                "last_day": replay.last_day,
                "days": replay.days,
                "severities": list(replay.severities),
                "total": replay.total,
                "resources": [
                    {"resource": r.resource, "label": r.label, "count": r.count}
                    for r in replay.resources
                ],
                "cells": [
                    {"day": c.day, "resource": c.resource, "severity": c.severity, "count": c.count}
                    for c in replay.cells
                ],
            }
        }
    )
