"""CSRF protection, security headers and the API cookie rule (P9-T2, docs/csrf-and-headers.md).

One middleware (:class:`BrowserHardeningMiddleware`, added in ``main.py``) does three things:

1. **Headers.** Every response, whatever the route and whatever the status, carries the content
   security policy, ``X-Content-Type-Options``, ``Referrer-Policy`` and, outside ``/static/``,
   ``Cache-Control: no-store``. There is no CORS middleware and no ``Access-Control-*`` header:
   no other origin may read an answer.
2. **Browser writes.** A POST, PUT, PATCH or DELETE outside ``/api/v1/`` must come from the
   configured origin (the ``Origin`` header, when the browser sends one, has to equal
   ``DRIFTSNIFF_BASE_URL``). When the request belongs to a signed-in session it must also carry
   that session's CSRF value, in the ``X-CSRF-Token`` header (HTMX) or in the ``csrf_token`` field
   of a form post. A form post is read here (at most 16 KB) and handed on unchanged.
   ``/login`` and ``/setup`` make the session, so they have no CSRF value to show; they get the
   origin check only.
3. **API.** Routes under ``/api/v1/`` are authenticated by a key or token in a request header, not
   by a cookie, so they are exempt from the CSRF value. They also refuse a request that carries
   the session cookie, so a browser session can never act on the API.

The CSRF value is the one stored in the session row at sign-in (``Principal.csrf_token``). It is
compared in constant time, never logged and never repeated in an answer.
"""

import hmac
from typing import Final
from urllib.parse import parse_qs, urlsplit

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from driftsniff.web.auth import SESSION_COOKIE
from driftsniff.web.routes_ui import MAX_FORM_BYTES

CSRF_FIELD: Final = "csrf_token"
CSRF_HEADER: Final = "x-csrf-token"

UNSAFE_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})
API_PREFIX: Final = "/api/v1"
STATIC_PREFIX: Final = "/static/"
# The two routes that create a session cannot hold a per-session value; they keep the origin check.
PRE_SESSION_PATHS: Final = frozenset({"/login", "/setup"})

CONTENT_SECURITY_POLICY: Final = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
SECURITY_HEADERS: Final = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
NO_STORE: Final = "no-store"

_FORM_CONTENT_TYPE: Final = "application/x-www-form-urlencoded"
_MAX_FORM_FIELDS: Final = 20
_DEFAULT_PORTS: Final = {"http": 80, "https": 443}

_WRONG_ORIGIN: Final = "the request does not come from this site"
_BAD_VALUE: Final = "the CSRF value is missing or wrong"
_API_COOKIE: Final = "the API takes an API token, not a session cookie"
_TOO_LARGE: Final = "the request body is too large"


class _BodyTooLargeError(Exception):
    """A form post is larger than the limit."""


def is_api_path(path: str) -> bool:
    """True for ``/api/v1`` and everything below it."""
    return path == API_PREFIX or path.startswith(API_PREFIX + "/")


def wants_no_store(path: str) -> bool:
    """True when the response must not be cached: every route except the static files."""
    return not path.startswith(STATIC_PREFIX)


def origin_key(text: str, *, allow_path: bool) -> tuple[str, str, int] | None:
    """Scheme, host and port of an origin or base address; None when it is not a plain one.

    ``http://host`` and ``http://host:80`` are the same origin. A browser's ``Origin`` header has
    no path, query, fragment or credentials (``allow_path=False``); the configured base address
    may have a path.
    """
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname
    if scheme not in _DEFAULT_PORTS or not host or "@" in parts.netloc:
        return None
    if not allow_path and (parts.path or parts.query or parts.fragment):
        return None
    return scheme, host, _DEFAULT_PORTS[scheme] if port is None else port


def origin_allowed(origin: str, base_url: str) -> bool:
    """True when the ``Origin`` header names the same origin as the configured base address."""
    presented = origin_key(origin, allow_path=False)
    expected = origin_key(base_url, allow_path=True)
    return presented is not None and presented == expected


def token_matches(presented: str | None, expected: str) -> bool:
    """Constant-time comparison of the presented CSRF value with the session's value."""
    if not presented or not expected:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def _refuse(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


def _replay(body: bytes, receive: Receive) -> Receive:
    """A receive callable that hands the already-read body on once, then defers to the real one."""
    pending = True

    async def replay() -> Message:
        nonlocal pending
        if pending:
            pending = False
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


async def _read_limited(receive: Receive) -> bytes:
    """The whole request body; raises _BodyTooLargeError past the form limit."""
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunk: bytes = message.get("body", b"")
        total += len(chunk)
        if total > MAX_FORM_BYTES:
            raise _BodyTooLargeError
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _form_token(body: bytes) -> str | None:
    try:
        fields = parse_qs(
            body.decode("utf-8"), keep_blank_values=True, max_num_fields=_MAX_FORM_FIELDS
        )
    except ValueError:  # UnicodeDecodeError is a ValueError
        return None
    values = fields.get(CSRF_FIELD)
    return values[0] if values else None


async def _presented_token(request: Request, receive: Receive) -> tuple[str | None, Receive]:
    """The CSRF value of the request (header first, then a form field) and the receive to use."""
    header = request.headers.get(CSRF_HEADER)
    if header is not None:
        return header, receive
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != _FORM_CONTENT_TYPE:
        return None, receive
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_FORM_BYTES:
        raise _BodyTooLargeError
    body = await _read_limited(receive)
    return _form_token(body), _replay(body, receive)


async def _screen(scope: Scope, receive: Receive) -> tuple[JSONResponse | None, Receive]:
    """Decide whether the request may go on; the receive callable to give the application."""
    request = Request(scope, receive)
    path: str = scope["path"]
    if is_api_path(path):
        if request.cookies.get(SESSION_COOKIE):
            return _refuse(403, _API_COOKIE), receive
        return None, receive
    if scope["method"] not in UNSAFE_METHODS:
        return None, receive
    app = scope["app"]
    origin = request.headers.get("origin")
    if origin is not None and not origin_allowed(origin, app.state.settings.base_url):
        return _refuse(403, _WRONG_ORIGIN), receive
    cookie = request.cookies.get(SESSION_COOKIE)
    auth = app.state.auth
    if path in PRE_SESSION_PATHS or not cookie or auth is None:
        return None, receive
    principal = await run_in_threadpool(auth.authenticate, cookie)
    if principal is None:
        return None, receive
    try:
        presented, receive = await _presented_token(request, receive)
    except _BodyTooLargeError:
        return _refuse(413, _TOO_LARGE), receive
    if not token_matches(presented, principal.csrf_token):
        return _refuse(403, _BAD_VALUE), receive
    return None, receive


def _with_security_headers(send: Send, path: str) -> Send:
    async def send_with_headers(message: Message) -> None:
        if message["type"] == "http.response.start":
            headers = MutableHeaders(scope=message)
            for name, value in SECURITY_HEADERS.items():
                headers[name] = value
            if wants_no_store(path):
                headers.setdefault("Cache-Control", NO_STORE)
        await send(message)

    return send_with_headers


class BrowserHardeningMiddleware:
    """Security headers on every response, and the origin and CSRF checks of browser writes."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        send = _with_security_headers(send, scope["path"])
        refusal, receive = await _screen(scope, receive)
        if refusal is not None:
            await refusal(scope, receive, send)
            return
        await self.app(scope, receive, send)
