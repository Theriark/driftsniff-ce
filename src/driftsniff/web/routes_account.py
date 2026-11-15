"""The Account page of the signed-in user: shown name, picture, password and theme (docs/auth.md).

Reached from the user menu of the sidebar (base.html), by every role: each person changes only
their own account. Each part posts on its own, so a refused password leaves the name as it was;
a saved change comes back to the page with a notice (303), a refused one draws the page again
with the form marked (422, or 429 while the password form must wait).

* ``GET /account``: the page.
* ``POST /account/name``: field ``display_name``, at most 80 characters; empty shows the user name.
* ``POST /account/password``: ``current_password``, ``new_password`` and ``confirm_password``. A
  wrong current password counts like a failed sign-in of the user name. Every other session of
  the user ends; this one stays.
* ``POST /account/theme``: ``theme``, one of light, dark or system.
* ``POST /account/picture``: the picture itself as the request body (PNG, JPEG or WebP, at most
  512 KB, recognised by its first bytes), sent by account.js with the session's CSRF value in the
  ``X-CSRF-Token`` header; the answer is JSON. A form post could not carry it: the browser-write
  check reads a form body only up to 16 KB.
* ``POST /account/picture/remove``: back to the initials.
* ``GET /account/picture/{user_id}``: a user's picture, for any signed-in user (the shell shows it).

No answer repeats a password; the audit trail records each change without its value.
"""

from typing import Annotated, Final

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse, Response

from driftsniff.web.auth import (
    MAX_DISPLAY_NAME_CHARS,
    MAX_PICTURE_BYTES,
    MIN_PASSWORD_CHARS,
    AccountInputError,
    AuthService,
    LoginThrottledError,
    Principal,
)
from driftsniff.web.deps import get_auth_service, require_viewer
from driftsniff.web.pages import page, shell_for
from driftsniff.web.routes_ui import read_fields

router = APIRouter()

Viewer = Annotated[Principal, Depends(require_viewer)]
Auth = Annotated[AuthService, Depends(get_auth_service)]

ACCOUNT_PATH: Final = "/account"
_MAX_USER_ID: Final = 2**31 - 1
DONE: Final = {
    "name": "Your name is saved.",
    "picture": "Your picture is saved.",
    "picture-removed": "Your picture is removed.",
    "password": "Your password is changed. Your other sessions have ended.",
    "theme": "Your theme is saved.",
}


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:] + ("" if text.endswith(".") else ".")


def render_account(
    request: Request,
    principal: Principal,
    *,
    done: str = "",
    errors: dict[str, str] | None = None,
    name_value: str | None = None,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """The account page, plain, after a saved change, or with one form marked."""
    shell = shell_for(request, principal, "Account")
    return page(
        "account.html",
        shell,
        status=status,
        headers=headers,
        done=DONE.get(done, ""),
        errors=errors or {},
        username=principal.username,
        role=principal.role,
        name_value=principal.display_name if name_value is None else name_value,
        has_picture=bool(principal.picture_version),
        min_password=MIN_PASSWORD_CHARS,
        max_name=MAX_DISPLAY_NAME_CHARS,
        max_picture_kb=MAX_PICTURE_BYTES // 1024,
    )


def _saved(done: str) -> RedirectResponse:
    return RedirectResponse(f"{ACCOUNT_PATH}?done={done}", status_code=303)


@router.get(ACCOUNT_PATH)
async def account(request: Request, principal: Viewer, done: str = "") -> Response:
    """The page of the signed-in user's own account."""
    return render_account(request, principal, done=done)


@router.post(f"{ACCOUNT_PATH}/name")
async def account_name(request: Request, principal: Viewer, auth: Auth) -> Response:
    """Save the shown name."""
    raw = (await read_fields(request)).get("display_name", "")
    try:
        await run_in_threadpool(auth.set_display_name, principal, raw)
    except AccountInputError as error:
        errors = {"name": _sentence(str(error))}
        return render_account(request, principal, errors=errors, name_value=raw, status=422)
    return _saved("name")


@router.post(f"{ACCOUNT_PATH}/password")
async def account_password(request: Request, principal: Viewer, auth: Auth) -> Response:
    """Change the password; the other sessions of the user end."""
    fields = await read_fields(request)
    new = fields.get("new_password", "")
    if new != fields.get("confirm_password", ""):
        errors = {"password": "The two new passwords do not match."}
        return render_account(request, principal, errors=errors, status=422)
    try:
        await run_in_threadpool(
            auth.change_password, principal, fields.get("current_password", ""), new
        )
    except LoginThrottledError as error:
        wait = error.retry_after
        unit = "second" if wait == 1 else "seconds"
        errors = {"password": f"Too many attempts. Wait {wait} {unit}, then try again."}
        return render_account(
            request, principal, errors=errors, status=429, headers={"Retry-After": str(wait)}
        )
    except AccountInputError as error:
        errors = {"password": _sentence(str(error))}
        return render_account(request, principal, errors=errors, status=422)
    return _saved("password")


@router.post(f"{ACCOUNT_PATH}/theme")
async def account_theme(request: Request, principal: Viewer, auth: Auth) -> Response:
    """Save the theme: light, dark or the device's own setting."""
    theme = (await read_fields(request)).get("theme", "")
    try:
        await run_in_threadpool(auth.set_theme, principal, theme)
    except AccountInputError as error:
        errors = {"theme": _sentence(str(error))}
        return render_account(request, principal, errors=errors, status=422)
    return _saved("theme")


@router.post(f"{ACCOUNT_PATH}/picture")
async def account_picture(request: Request, principal: Viewer, auth: Auth) -> Response:
    """Save the picture sent as the request body; JSON answer for account.js."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_PICTURE_BYTES:
        return _too_large()
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_PICTURE_BYTES:
            return _too_large()
        chunks.append(chunk)
    try:
        await run_in_threadpool(auth.set_picture, principal, b"".join(chunks))
    except AccountInputError as error:
        return JSONResponse({"detail": _sentence(str(error))}, status_code=422)
    return JSONResponse({"location": f"{ACCOUNT_PATH}?done=picture"})


def _too_large() -> JSONResponse:
    detail = f"The picture must be at most {MAX_PICTURE_BYTES // 1024} KB."
    return JSONResponse({"detail": detail}, status_code=413)


@router.post(f"{ACCOUNT_PATH}/picture/remove")
async def account_picture_remove(principal: Viewer, auth: Auth) -> Response:
    """Remove the picture."""
    await run_in_threadpool(auth.remove_picture, principal)
    return _saved("picture-removed")


@router.get(f"{ACCOUNT_PATH}/picture/{{user_id}}")
async def account_picture_file(
    _principal: Viewer,
    auth: Auth,
    user_id: Annotated[int, Path(ge=1, le=_MAX_USER_ID)],
) -> Response:
    """A user's picture by id, for any signed-in user; 404 when there is none."""
    found = await run_in_threadpool(auth.picture, user_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Not Found")
    data, media_type = found
    return Response(content=data, media_type=media_type)
