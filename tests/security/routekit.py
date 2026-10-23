"""The route table and the checks of the security suite (P9-T6): who may call what.

``ROUTE_TABLE`` lists every route of the application with the access it requires; ``violations``
calls a route as every kind of caller and reports each caller that is treated wrongly. The tests
in ``test_route_table.py`` and ``test_authn.py`` use them.
"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from fastapi import FastAPI
from starlette.routing import Mount

from driftsniff.web.auth import ROLE_RANK
from driftsniff.web.csrf import UNSAFE_METHODS, is_api_path

from .appkit import A_TOKEN_THAT_IS_NOT_ONE, ROLES, TOKEN_KINDS, Kit


class Access(StrEnum):
    PUBLIC = "public"
    PUSH_KEY = "push key"
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"
    TOKEN_READ = "token read"  # noqa: S105
    TOKEN_ENRICH = "token enrich"  # noqa: S105


ROLE_ACCESS = frozenset({Access.VIEWER, Access.OPERATOR, Access.ADMIN})
IMPLICIT_METHODS = frozenset({"HEAD", "OPTIONS"})
# They make the session, so a refusal there is about the submitted credentials, not about a role.
CREDENTIAL_ROUTES = frozenset({("POST", "/login"), ("POST", "/setup")})

ROUTE_TABLE: dict[tuple[str, str], Access] = {
    ("GET", "/healthz"): Access.PUBLIC,
    # The dashboard: a browser without a session is redirected to sign in by the page handler;
    # every other client gets the plain 401 the table expects.
    ("GET", "/"): Access.VIEWER,
    # The setup page is 404 for everyone once an admin exists (the kit has three users).
    ("GET", "/setup"): Access.PUBLIC,
    ("POST", "/setup"): Access.PUBLIC,
    ("GET", "/login"): Access.PUBLIC,
    ("POST", "/login"): Access.PUBLIC,
    ("POST", "/logout"): Access.PUBLIC,
    ("GET", "/static/{path:path}"): Access.PUBLIC,
    ("POST", "/preferences/density"): Access.VIEWER,
    # The sources pages (P10-T5): a viewer reads, an operator also runs now, an admin changes.
    ("GET", "/sources"): Access.VIEWER,
    ("GET", "/sources/new"): Access.ADMIN,
    ("POST", "/sources/new"): Access.ADMIN,
    ("POST", "/sources/test"): Access.ADMIN,
    ("GET", "/sources/{source_id}"): Access.VIEWER,
    ("GET", "/sources/{source_id}/edit"): Access.ADMIN,
    ("POST", "/sources/{source_id}/edit"): Access.ADMIN,
    ("POST", "/sources/{source_id}/test"): Access.ADMIN,
    ("POST", "/sources/{source_id}/run"): Access.OPERATOR,
    ("POST", "/sources/{source_id}/enable"): Access.ADMIN,
    ("POST", "/sources/{source_id}/disable"): Access.ADMIN,
    ("POST", "/sources/{source_id}/delete"): Access.ADMIN,
    ("POST", "/sources/{source_id}/push-key"): Access.ADMIN,
    ("GET", "/tokens"): Access.ADMIN,
    ("POST", "/tokens"): Access.ADMIN,
    ("POST", "/tokens/{token_id}/revoke"): Access.ADMIN,
    ("GET", "/notifications/channel"): Access.ADMIN,
    ("PUT", "/notifications/channel"): Access.ADMIN,
    ("DELETE", "/notifications/channel"): Access.ADMIN,
    ("POST", "/notifications/test"): Access.ADMIN,
    ("POST", "/notifications/signing-key"): Access.ADMIN,
    ("GET", "/notifications/deliveries"): Access.ADMIN,
    ("GET", "/api/v1/changes"): Access.TOKEN_READ,
    ("GET", "/api/v1/changes/{event_id}"): Access.TOKEN_READ,
    ("POST", "/api/v1/changes/{event_id}/enrichments"): Access.TOKEN_ENRICH,
    ("GET", "/api/v1/openapi.json"): Access.PUBLIC,
    ("POST", "/api/v1/push/{source_id}"): Access.PUSH_KEY,
}


@dataclass(frozen=True, slots=True)
class Caller:
    """A kind of caller: nobody, a signed-in role, an API token or a made-up token."""

    name: str
    kind: str
    role: str = ""
    token_kind: str = ""


CALLERS = (
    Caller("anonymous", "anonymous"),
    *(Caller(f"{role} session", "session", role=role) for role in ROLES),
    *(Caller(f"{kind} token", "token", token_kind=kind) for kind in TOKEN_KINDS),
    Caller("made-up token", "made-up"),
)


def leaf_routes(routes: Iterable[Any], prefix: str = "") -> Iterator[tuple[Any, str]]:
    """The routes themselves, each with the path prefix of the routers it was included through.

    FastAPI wraps an included router in a container (``original_router`` and the prefix of the
    inclusion), so ``app.routes`` does not list its routes. A container is entered; a mounted
    application is handed back as it is, so ``real_routes`` fails on it and the table gets a
    decision about it.
    """
    for route in routes:
        inner = getattr(route, "original_router", None)
        nested = getattr(inner, "routes", None)
        if nested is None:
            nested = getattr(route, "routes", None)
        if nested is not None and not isinstance(route, Mount):
            context = getattr(route, "include_context", None)
            yield from leaf_routes(nested, prefix + str(getattr(context, "prefix", "") or ""))
        else:
            yield route, prefix


def real_routes(app: FastAPI) -> set[tuple[str, str]]:
    """Every (method, path) the application answers; a route of an unknown kind fails."""
    found: set[tuple[str, str]] = set()
    for route, prefix in leaf_routes(app.routes):
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if not methods or not isinstance(path, str):
            raise AssertionError(f"a route of a kind the table does not know: {route!r}")
        found.update(
            (method, prefix + path) for method in methods if method not in IMPLICIT_METHODS
        )
    return found


def may_pass(access: Access, path: str, caller: Caller) -> bool:
    """Whether ``access`` lets ``caller`` through (the push key is held by nobody here)."""
    if caller.kind == "session" and is_api_path(path):
        return False
    if access is Access.PUBLIC:
        return True
    if access in ROLE_ACCESS:
        return caller.kind == "session" and ROLE_RANK[caller.role] >= ROLE_RANK[access.value]
    if caller.kind != "token":
        return False
    scopes = TOKEN_KINDS[caller.token_kind]
    if access is Access.TOKEN_READ:
        return "read" in scopes
    if access is Access.TOKEN_ENRICH:
        return "enrich" in scopes
    return False


def concrete(path: str) -> str:
    """The path with every parameter filled by an id that exists nowhere."""
    for name in ("token_id", "event_id", "source_id"):
        path = path.replace("{" + name + "}", "99999")
    return path


def ask(kit: Kit, method: str, path: str, caller: Caller) -> int:
    """The status of the route for the caller (a session is signed in fresh for each call)."""
    headers: dict[str, str] = {}
    if caller.kind == "session":
        headers = kit.new_session(caller.role).headers()
    elif caller.kind == "token":
        headers = kit.bearer(caller.token_kind)
    elif caller.kind == "made-up":
        headers = {"Authorization": f"Bearer {A_TOKEN_THAT_IS_NOT_ONE}"}
    unsafe = method in UNSAFE_METHODS
    body: dict[str, str] | None = {} if unsafe else None
    response = kit.client.request(method, concrete(path), headers=headers, json=body)
    kit.client.cookies.clear()
    return response.status_code


def violations(kit: Kit, method: str, path: str, access: Access) -> list[str]:
    """What is wrong with the route's protection; empty when every caller is treated right."""
    problems: list[str] = []
    for caller in CALLERS:
        status = ask(kit, method, path, caller)
        if status >= 500:
            problems.append(f"{caller.name}: the route failed with {status}")
        elif (method, path) in CREDENTIAL_ROUTES:
            continue
        elif may_pass(access, path, caller) and status in (401, 403):
            problems.append(f"{caller.name}: refused with {status} but {access.value} allows it")
        elif not may_pass(access, path, caller) and status not in (401, 403):
            problems.append(f"{caller.name}: got {status} where {access.value} must refuse it")
    return problems
