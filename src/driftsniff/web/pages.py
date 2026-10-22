"""The browser pages of the interface (P10-T3): rendering, content negotiation and status pages.

A browser asks for ``text/html`` and gets a page; every other client (the tests, scripts, the
API) keeps the JSON answers of the routes. The decision is :func:`wants_html`, read from the
``Accept`` header of the request, and nothing else changes between the two: the same status
codes, the same cookies, the same checks.

Three things live here:

* :func:`shell_for` builds the :class:`~driftsniff.web.templating.Shell` of a request (who is
  signed in, the density cookie, the environment badge, the current path).
* :func:`render_login` and :func:`render_setup` draw the two pre-session pages in every state
  (plain, signed out, failed, throttled, field errors).
* :func:`handle_http_exception` is the application's handler for ``HTTPException``: for a
  browser it turns a 401 into the sign-in redirect (or the setup page while no admin exists), a
  403 into the not-allowed page and a 404 into the not-found page; for everyone else it is the
  default JSON answer.
"""

from dataclasses import dataclass
from typing import Final
from urllib.parse import quote

from fastapi.concurrency import run_in_threadpool
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from driftsniff.web.auth import SESSION_COOKIE, AuthService, Principal
from driftsniff.web.preferences import DENSITY_COOKIE, density_from_cookie, safe_next
from driftsniff.web.templating import Shell, render

HTML_TYPES: Final = frozenset({"text/html", "application/xhtml+xml"})
# The API is never a page, whatever the client asks for.
_API_PREFIX: Final = "/api/v1"

LOGIN_PATH: Final = "/login"
SETUP_PATH: Final = "/setup"
LOGOUT_QUERY: Final = "signed-out"

# The one generic sign-in failure, whatever the reason (docs/auth.md).
SIGN_IN_FAILED: Final = ("Sign-in failed", "Check the user name and password, then try again.")
SETUP_CODE_WRONG: Final = "This code is not valid. Check it against the container log."

STATUS_PAGES: Final = {
    403: (
        "Your role does not allow this",
        "Ask an admin for a higher role if you need it. Nothing was changed.",
    ),
    404: (
        "Page not found",
        "There is nothing at this address. It may have been removed, or the link is wrong.",
    ),
}


@dataclass(frozen=True, slots=True)
class PageError:
    """A page-level message: the title and one sentence that says what to do."""

    title: str
    text: str


def wants_html(request: Request) -> bool:
    """True when the client asks for a page: ``text/html`` is among its ``Accept`` media ranges.

    A bare ``*/*`` (the test client, curl, scripts) is not a request for a page.
    """
    accept = request.headers.get("accept", "")
    for part in accept.split(","):
        media = part.split(";", 1)[0].strip().lower()
        if media in HTML_TYPES:
            return True
    return False


def is_page_path(path: str) -> bool:
    """Every path except the API can be answered with a page."""
    return not (path == _API_PREFIX or path.startswith(_API_PREFIX + "/"))


def current_path(request: Request) -> str:
    """The path of the request with its query, the place a form sends the user back to."""
    query = request.url.query
    return request.url.path + ("?" + query if query else "")


def shell_for(
    request: Request, principal: Principal | None, title: str, nav_current: str = ""
) -> Shell:
    """The shell of a page: the signed-in user (if any), the cookie preferences, the badge."""
    settings = request.app.state.settings
    return Shell(
        title=title,
        nav_current=nav_current,
        user_name="" if principal is None else principal.username,
        user_role="" if principal is None else principal.role,
        csrf_token="" if principal is None else principal.csrf_token,
        density=density_from_cookie(request.cookies.get(DENSITY_COOKIE)),
        environment_label=settings.environment_label,
        path=current_path(request),
    )


def page(
    template: str,
    shell: Shell,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    **context: object,
) -> HTMLResponse:
    """A rendered page with its status and extra headers."""
    return HTMLResponse(render(template, shell, **context), status_code=status, headers=headers)


def throttled_error(retry_after: int) -> PageError:
    """The message of a 429: it names the wait so the person does not keep trying."""
    unit = "second" if retry_after == 1 else "seconds"
    return PageError(
        "Too many attempts", f"Wait {retry_after} {unit}, then try again. Nothing was changed."
    )


def render_login(
    request: Request,
    *,
    next_path: str = "/",
    username: str = "",
    error: PageError | None = None,
    signed_out: bool = False,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """The sign-in page: plain, after sign-out, or after a failed or throttled attempt."""
    shell = shell_for(request, None, "Sign in")
    return page(
        "login.html",
        shell,
        status=status,
        headers=headers,
        next_path=safe_next(next_path),
        username=username,
        error=error,
        signed_out=signed_out,
    )


def render_setup(
    request: Request,
    *,
    username: str = "",
    field_errors: dict[str, str] | None = None,
    error: PageError | None = None,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """The first-run setup page: plain, with a field in error, or after a throttled attempt.

    ``field_errors`` maps ``code``, ``username`` or ``password`` to the message shown next to
    that field; the help text stays. The code and the password are never filled back in.
    """
    shell = shell_for(request, None, "Create the first admin")
    return page(
        "setup.html",
        shell,
        status=status,
        headers=headers,
        username=username,
        field_errors=field_errors or {},
        error=error,
    )


def sign_in_target(path: str, *, admin_exists: bool) -> str:
    """Where a browser without a session goes: the setup page first, else the sign-in page.

    The page it asked for is carried in ``next`` so the sign-in brings it back there, unless it
    was the start page or not a local path.
    """
    if not admin_exists:
        return SETUP_PATH
    local = safe_next(path)
    if local == "/" or local != path:
        return LOGIN_PATH
    return f"{LOGIN_PATH}?next={quote(local, safe='/?=')}"


def status_page(request: Request, principal: Principal | None, status: int) -> HTMLResponse:
    """The designed not-allowed (403) or not-found (404) page."""
    title, text = STATUS_PAGES[status]
    shell = shell_for(request, principal, title)
    return page("status.html", shell, status=status, error=PageError(title, text))


async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> Response:
    """Pages for a browser, the default JSON answer for everyone else.

    401 sends the browser to sign in (or to the setup page while no admin exists); 403 and 404
    render their status page with the shell of whoever is signed in. Every other status, every
    API path and every non-browser client get FastAPI's own answer, unchanged.
    """
    path = request.url.path
    auth: AuthService | None = request.app.state.auth
    if wants_html(request) and is_page_path(path):
        if exc.status_code == 401 and auth is not None:
            admin_exists = await run_in_threadpool(auth.has_admin)
            target = sign_in_target(current_path(request), admin_exists=admin_exists)
            return RedirectResponse(target, status_code=303)
        if exc.status_code in STATUS_PAGES:
            principal = None
            if auth is not None:
                principal = await run_in_threadpool(
                    auth.authenticate, request.cookies.get(SESSION_COOKIE)
                )
            return status_page(request, principal, exc.status_code)
    return await http_exception_handler(request, exc)
