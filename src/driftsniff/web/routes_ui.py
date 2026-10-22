"""Browser-facing routes: the health check and the first-run setup, sign-in and sign-out posts.

The pages that show the forms are built in P10; these routes take the form post (or a JSON body)
and answer with a redirect, a cookie or a plain error. Every failure text is generic.
"""

import json
import os
import re
from typing import Annotated, Literal
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from driftsniff import __version__
from driftsniff.web.auth import (
    SESSION_COOKIE,
    AuthService,
    LoginFailedError,
    LoginThrottledError,
    SessionGrant,
    SetupCodeError,
    SetupUnavailableError,
    clear_session_cookie,
    request_is_https,
    set_session_cookie,
)
from driftsniff.web.deps import get_auth_service

router = APIRouter()

MAX_FORM_BYTES = 16 * 1024
_MAX_FORM_FIELDS = 20
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_JSON_CONTENT_TYPE = "application/json"

COMMIT_ENV = "DRIFTSNIFF_COMMIT"
UNKNOWN_COMMIT = "unknown"
# The image build sets the full 40-character commit SHA; other short tokens (for example the
# smoke test value) are passed through. Anything else is reported as unknown.
_COMMIT_TOKEN = re.compile(r"[0-9A-Za-z._-]{1,64}")


def build_commit() -> str:
    """Return the commit this image was built from, or "unknown" when unset or malformed."""
    value = os.environ.get(COMMIT_ENV, "").strip()
    if _COMMIT_TOKEN.fullmatch(value) and value != UNKNOWN_COMMIT:
        return value
    return UNKNOWN_COMMIT


class Healthz(BaseModel):
    """Body of GET /healthz: status, version and the build commit, nothing else."""

    status: Literal["ok"]
    version: str
    commit: str


@router.get("/healthz")
def healthz() -> Healthz:
    """Report liveness; the container health check and the release script call it."""
    return Healthz(status="ok", version=__version__, commit=build_commit())


def _json_fields(document: dict[str, object], *, structured: bool) -> dict[str, str]:
    """The fields of a JSON object body.

    Only text values are kept (the sign-in routes ignore the rest). With ``structured`` a whole
    number becomes its text and a list of text becomes comma separated text; any other value is an
    error, so a field is never dropped without a word.
    """
    fields: dict[str, str] = {}
    for key, value in document.items():
        if isinstance(value, str):
            fields[key] = value
        elif not structured:
            continue
        elif isinstance(value, int) and not isinstance(value, bool):
            fields[key] = str(value)
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            fields[key] = ",".join(str(item) for item in value)
        else:
            raise ValueError(f"field {key} must be text, a whole number or a list of text")
    return fields


async def read_fields(request: Request, *, structured: bool = False) -> dict[str, str]:
    """The text fields of a form post or a JSON object body (at most 16 KB).

    ``structured`` also accepts whole numbers and lists of text in a JSON body (see
    :func:`_json_fields`).
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_FORM_BYTES:
        raise HTTPException(status_code=413, detail="the request body is too large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_FORM_BYTES:
            raise HTTPException(status_code=413, detail="the request body is too large")
        chunks.append(chunk)
    body = b"".join(chunks)
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    try:
        if content_type == _JSON_CONTENT_TYPE:
            document = json.loads(body)
            if not isinstance(document, dict):
                raise ValueError("not an object")
            return _json_fields(document, structured=structured)
        if content_type == _FORM_CONTENT_TYPE:
            parsed = parse_qs(
                body.decode("utf-8"), keep_blank_values=True, max_num_fields=_MAX_FORM_FIELDS
            )
            return {key: values[0] for key, values in parsed.items()}
    except (ValueError, RecursionError) as error:
        raise HTTPException(status_code=400, detail="the request body is not valid") from error
    raise HTTPException(status_code=415, detail="send a form post or a JSON object")


def _client_address(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


def _is_secure(request: Request) -> bool:
    return request_is_https(request, trusted_proxy=request.app.state.settings.trusted_proxy)


def _throttled(error: LoginThrottledError) -> JSONResponse:
    return JSONResponse(
        {"detail": "too many failed attempts, try again later"},
        status_code=429,
        headers={"Retry-After": str(error.retry_after)},
    )


def _signed_in(request: Request, grant: SessionGrant) -> Response:
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, grant.cookie_value, secure=_is_secure(request))
    return response


@router.post("/setup")
async def setup(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Response:
    """Create the first admin with the one-time setup code; 404 once any admin exists."""
    fields = await read_fields(request)
    try:
        grant = await run_in_threadpool(
            auth.complete_setup,
            fields.get("code", ""),
            fields.get("username", ""),
            fields.get("password", ""),
            _client_address(request),
        )
    except SetupUnavailableError as error:
        raise HTTPException(status_code=404, detail="Not Found") from error
    except LoginThrottledError as error:
        return _throttled(error)
    except SetupCodeError:
        return JSONResponse({"detail": "the setup code is not valid"}, status_code=403)
    except ValueError as error:
        return JSONResponse({"detail": str(error)}, status_code=422)
    return _signed_in(request, grant)


@router.post("/login")
async def login(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Response:
    """Check the user name and password and start a session."""
    fields = await read_fields(request)
    try:
        grant = await run_in_threadpool(
            auth.login,
            fields.get("username", ""),
            fields.get("password", ""),
            _client_address(request),
        )
    except LoginThrottledError as error:
        return _throttled(error)
    except LoginFailedError:
        return JSONResponse({"detail": "invalid user name or password"}, status_code=401)
    return _signed_in(request, grant)


@router.post("/logout")
async def logout(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Response:
    """End the session of the cookie (if any) and drop the cookie."""
    cookie_value = request.cookies.get(SESSION_COOKIE)
    if cookie_value:
        await run_in_threadpool(auth.logout, cookie_value)
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response, secure=_is_secure(request))
    return response
