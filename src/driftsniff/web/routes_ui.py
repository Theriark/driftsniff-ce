"""Browser-facing routes: the health check, the start page, setup, sign-in and sign-out.

``GET /setup`` and ``GET /login`` show the forms (P10-T3); the posts take a form post (or a JSON
body) and answer with a redirect and a cookie, or with the failure. A browser (one that asks for
``text/html``) gets the page again with the failure drawn in; every other client gets the plain
JSON answer. Every failure text is generic. ``GET /`` is the dashboard (its data arrives in
P10-T4; for now it shows the designed empty state).
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
    PasswordPolicyError,
    Principal,
    SessionGrant,
    SetupCodeError,
    SetupUnavailableError,
    UsernameError,
    clear_session_cookie,
    request_is_https,
    set_session_cookie,
)
from driftsniff.web.deps import get_auth_service, require_viewer
from driftsniff.web.pages import (
    LOGIN_PATH,
    LOGOUT_QUERY,
    SETUP_CODE_WRONG,
    SETUP_PATH,
    SIGN_IN_FAILED,
    PageError,
    page,
    render_login,
    render_setup,
    shell_for,
    throttled_error,
    wants_html,
)
from driftsniff.web.preferences import parse_density, safe_next, set_density_cookie

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


def _signed_in(request: Request, grant: SessionGrant, next_path: str = "/") -> Response:
    response = RedirectResponse(safe_next(next_path), status_code=303)
    set_session_cookie(response, grant.cookie_value, secure=_is_secure(request))
    return response


def _retry_after(error: LoginThrottledError) -> dict[str, str]:
    return {"Retry-After": str(error.retry_after)}


def _sentence(message: str) -> str:
    """A rule from the sign-in service as a sentence next to a field."""
    text = message[:1].upper() + message[1:]
    return text if text.endswith(".") else text + "."


@router.get("/")
async def dashboard(
    request: Request, user: Annotated[Principal, Depends(require_viewer)]
) -> Response:
    """The start page of a signed-in user. Without a session a browser is sent to sign in."""
    return page("dashboard.html", shell_for(request, user, "Dashboard", "dashboard"))


@router.get("/setup")
async def setup_page(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Response:
    """The first-run setup form; 404 like an unknown route once any admin exists."""
    if await run_in_threadpool(auth.has_admin):
        raise HTTPException(status_code=404, detail="Not Found")
    return render_setup(request)


@router.post("/setup")
async def setup(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Response:
    """Create the first admin with the one-time setup code; 404 once any admin exists."""
    fields = await read_fields(request)
    username = fields.get("username", "")
    html = wants_html(request)
    try:
        grant = await run_in_threadpool(
            auth.complete_setup,
            fields.get("code", ""),
            username,
            fields.get("password", ""),
            _client_address(request),
        )
    except SetupUnavailableError as error:
        raise HTTPException(status_code=404, detail="Not Found") from error
    except LoginThrottledError as error:
        if html:
            wait = throttled_error(error.retry_after)
            return render_setup(
                request, username=username, error=wait, status=429, headers=_retry_after(error)
            )
        return _throttled(error)
    except SetupCodeError:
        if html:
            errors = {"code": SETUP_CODE_WRONG}
            return render_setup(request, username=username, field_errors=errors, status=403)
        return JSONResponse({"detail": "the setup code is not valid"}, status_code=403)
    except ValueError as error:
        if html:
            field = "password" if isinstance(error, PasswordPolicyError) else "username"
            if not isinstance(error, UsernameError | PasswordPolicyError):
                field = "code"
            errors = {field: _sentence(str(error))}
            return render_setup(request, username=username, field_errors=errors, status=422)
        return JSONResponse({"detail": str(error)}, status_code=422)
    return _signed_in(request, grant)


@router.get("/login")
async def login_page(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Response:
    """The sign-in form. A signed-in user goes to the start page; with no admin yet, to setup."""
    principal = await run_in_threadpool(auth.authenticate, request.cookies.get(SESSION_COOKIE))
    if principal is not None:
        return RedirectResponse("/", status_code=303)
    if not await run_in_threadpool(auth.has_admin):
        return RedirectResponse(SETUP_PATH, status_code=303)
    return render_login(
        request,
        next_path=request.query_params.get("next", "/"),
        signed_out=request.query_params.get(LOGOUT_QUERY) == "1",
    )


@router.post("/login")
async def login(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Response:
    """Check the user name and password and start a session."""
    fields = await read_fields(request)
    username = fields.get("username", "")
    next_path = safe_next(fields.get("next"))
    html = wants_html(request)
    try:
        grant = await run_in_threadpool(
            auth.login,
            username,
            fields.get("password", ""),
            _client_address(request),
        )
    except LoginThrottledError as error:
        if html:
            wait = throttled_error(error.retry_after)
            return render_login(
                request,
                next_path=next_path,
                username=username,
                error=wait,
                status=429,
                headers=_retry_after(error),
            )
        return _throttled(error)
    except LoginFailedError:
        if html:
            failed = PageError(*SIGN_IN_FAILED)
            return render_login(
                request, next_path=next_path, username=username, error=failed, status=401
            )
        return JSONResponse({"detail": "invalid user name or password"}, status_code=401)
    return _signed_in(request, grant, next_path)


@router.post("/logout")
async def logout(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Response:
    """End the session of the cookie (if any), drop the cookie and confirm on the sign-in page."""
    cookie_value = request.cookies.get(SESSION_COOKIE)
    if cookie_value:
        await run_in_threadpool(auth.logout, cookie_value)
    response = RedirectResponse(f"{LOGIN_PATH}?{LOGOUT_QUERY}=1", status_code=303)
    clear_session_cookie(response, secure=_is_secure(request))
    return response


@router.post("/preferences/density")
async def set_density(
    request: Request, _user: Annotated[Principal, Depends(require_viewer)]
) -> Response:
    """Remember the row density of data tables (comfortable or compact) in a cookie.

    A normal form post from the density switch of P10-T2; ``next`` is the page to go back to
    and is only ever a path of this site.
    """
    fields = await read_fields(request)
    try:
        density = parse_density(fields.get("density", ""))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    response = RedirectResponse(safe_next(fields.get("next")), status_code=303)
    set_density_cookie(response, density, secure=_is_secure(request))
    return response
