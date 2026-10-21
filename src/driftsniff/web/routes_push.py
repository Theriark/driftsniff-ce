"""The push endpoint: ``POST /api/v1/push/{source_id}`` (docs/push.md).

Order of work, and why:

1. The sender key (header ``X-Driftsniff-Push-Key``) is checked first, against the SHA-256 stored
   for the source, in constant time. A wrong, missing or unknown key (an unknown source, a source
   that is not a push source, a source without a key) all get the same 401, and the body is not
   read.
2. The size is checked next: a declared length over 10 MB, or a body that grows past 10 MB while
   it streams, gets 413 and nothing is stored.
3. The body is parsed, cut down to the declared fields by :class:`PushCollector` and run through
   the same pipeline as a polled source.

Answers never repeat the body, a field name or a key. The pipeline's error summary is already
scrubbed.
"""

import logging
from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import APIRouter, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from driftsniff.collectors.push import (
    MAX_PUSH_BODY_BYTES,
    PUSH_HEADER,
    PushBodyError,
    PushCollector,
    parse_push_body,
)
from driftsniff.sources.runs import RunPipeline
from driftsniff.sources.service import SourceNotFoundError, SourceService, push_key_matches

logger = logging.getLogger(__name__)

router = APIRouter()

_MAX_SOURCE_ID: Final = 2**31 - 1


@dataclass(frozen=True, slots=True)
class PushGateway:
    """What the endpoint needs: the source service and the shared run pipeline."""

    service: SourceService
    pipeline: RunPipeline


def _answer(status: int, detail: str, **extra: object) -> JSONResponse:
    return JSONResponse({"detail": detail, **extra}, status_code=status)


async def _read_body(request: Request) -> bytes | None:
    """The request body, or None when it is larger than the limit."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_PUSH_BODY_BYTES:
        return None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_PUSH_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/api/v1/push/{source_id}")
async def push(
    request: Request, source_id: Annotated[int, Path(ge=1, le=_MAX_SOURCE_ID)]
) -> JSONResponse:
    """Accept one pushed document for a push source and run it through the pipeline."""
    gateway: PushGateway | None = request.app.state.push_gateway
    if gateway is None:
        return _answer(503, "push is not available")
    target = await run_in_threadpool(gateway.service.push_target, source_id)
    presented = request.headers.get(PUSH_HEADER, "")
    matches = push_key_matches(presented, None if target is None else target.key_hash)
    if target is None or not matches:
        return _answer(401, "the push key is missing or wrong")
    body = await _read_body(request)
    if body is None:
        return _answer(413, "the body is larger than 10 MB")
    if not target.fields:
        return _answer(409, "the source declares no fields to keep")
    try:
        document = parse_push_body(body)
    except PushBodyError as error:
        return _answer(400, str(error))
    collector = PushCollector(document, target.fields, body_bytes=len(body))
    if not collector.resources():
        return _answer(422, "the body has none of the declared resources")
    ignored = collector.ignored_resources
    try:
        report = await run_in_threadpool(gateway.pipeline.run, source_id, collector)
    except SourceNotFoundError:
        return _answer(404, "the source no longer exists")
    if report.status == "skipped":
        return _answer(409, report.error_summary or "the run was skipped", run_id=report.run_id)
    if report.status == "failed":
        return _answer(
            422,
            report.error_summary or "the run failed",
            run_id=report.run_id,
            error_class=report.error_class,
        )
    logger.info("push for source %s stored as run %s (%s)", source_id, report.run_id, report.status)
    return JSONResponse(
        {
            "run_id": report.run_id,
            "status": report.status,
            "stored_new_snapshot": report.stored_new_snapshot,
            "event_id": report.event_id,
            "object_count": report.object_count,
            "ignored_resources": ignored,
        }
    )
