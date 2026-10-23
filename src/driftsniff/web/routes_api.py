"""Admin routes for API tokens: list, create, revoke (docs/api-access.md).

These are routes of the interface, not of ``/api/v1``: an admin uses them with a session, so they
need the session CSRF value on writes, and the API refuses a session cookie anyway. The pages that
show them are built in P10; the routes take a form post or a JSON object and answer with JSON.

The full token value is in the answer of ``POST /tokens`` only, once. The list shows the visible
prefix, never the value and never the stored hash. A token is revoked, never deleted, so the
history of what it did (enrichments, audit events) keeps its meaning.
"""

import re
from datetime import datetime
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from driftsniff.web.auth import Principal
from driftsniff.web.bearer import MAX_EXPIRY_DAYS, TokenInfo, TokenInputError, TokenService
from driftsniff.web.deps import get_token_service, require_admin
from driftsniff.web.routes_ui import read_fields

router = APIRouter()

_MAX_TOKEN_ID: Final = 2**31 - 1
_ALLOWED_FIELDS: Final = frozenset({"name", "scopes", "expires_in_days", "csrf_token"})
_SCOPE_SEPARATOR: Final = re.compile(r"[\s,]+")


def _describe(info: TokenInfo, now: datetime) -> dict[str, Any]:
    return {
        "id": info.token_id,
        "name": info.name,
        "prefix": info.prefix,
        "scopes": list(info.scopes),
        "status": info.status(now),
        "created_by": info.created_by,
        "last_used_at": info.last_used_at,
        "expires_at": info.expires_at,
        "revoked_at": info.revoked_at,
    }


def _expiry_days(raw: str | None) -> int | None:
    """The ``expires_in_days`` field: absent or blank means no expiry; else a whole number."""
    if raw is None or not raw.strip():
        return None
    text = raw.strip()
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= MAX_EXPIRY_DAYS:
        raise TokenInputError(f"the expiry must be 1 to {MAX_EXPIRY_DAYS} days")
    return int(text)


@router.get("/tokens")
async def list_tokens(
    _admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[TokenService, Depends(get_token_service)],
) -> JSONResponse:
    """Every API token with its prefix, scopes, status and last use; never a value."""
    tokens = await run_in_threadpool(service.list_tokens)
    now = service.now()
    return JSONResponse({"tokens": [_describe(info, now) for info in tokens]})


@router.post("/tokens")
async def create_token(
    request: Request,
    admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[TokenService, Depends(get_token_service)],
) -> JSONResponse:
    """Make a token. Fields: ``name``, ``scopes`` (``read``, ``enrich`` or both) and an optional
    ``expires_in_days``. The answer holds the token value; it is not shown again.
    """
    fields = await read_fields(request, structured=True)
    unknown = sorted(set(fields) - _ALLOWED_FIELDS)
    if unknown:
        # A misspelt expiry must not quietly make a token that never expires.
        return JSONResponse({"detail": f"unknown field: {unknown[0][:40]}"}, status_code=422)
    try:
        created = await run_in_threadpool(
            service.create,
            user_id=admin.user_id,
            actor=admin.username,
            name=fields.get("name", ""),
            scopes=[part for part in _SCOPE_SEPARATOR.split(fields.get("scopes", "")) if part],
            expires_in_days=_expiry_days(fields.get("expires_in_days")),
        )
    except TokenInputError as error:
        return JSONResponse({"detail": str(error)}, status_code=422)
    body = _describe(created.info, service.now())
    body["token"] = created.value
    body["note"] = "this is the only time the token is shown; store it now"
    return JSONResponse(body, status_code=201)


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(
    token_id: Annotated[int, Path(ge=1, le=_MAX_TOKEN_ID)],
    admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[TokenService, Depends(get_token_service)],
) -> JSONResponse:
    """Revoke a token for good; revoking it again changes nothing."""
    found = await run_in_threadpool(service.revoke, token_id, actor=admin.username)
    if not found:
        raise HTTPException(status_code=404, detail="no such token")
    return JSONResponse({"id": token_id, "status": "revoked"})
