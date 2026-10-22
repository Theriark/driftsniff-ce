"""Request dependencies: the signed-in user and the role a route needs.

A route that needs a role lists ``Depends(require_role("operator"))`` (or one of the shortcuts
below). No session gives 401, a session whose role ranks lower gives 403. The role order is
viewer, operator, admin; each role may do everything the lower ones may.
"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from driftsniff.web.auth import ROLE_RANK, SESSION_COOKIE, AuthService, Principal


def get_auth_service(request: Request) -> AuthService:
    """The application's sign-in service; 503 when the application was built without one."""
    auth: AuthService | None = request.app.state.auth
    if auth is None:
        raise HTTPException(status_code=503, detail="sign-in is not available")
    return auth


def current_principal(
    request: Request, auth: Annotated[AuthService, Depends(get_auth_service)]
) -> Principal | None:
    """The user of the session cookie, or None."""
    return auth.authenticate(request.cookies.get(SESSION_COOKIE))


def require_role(minimum: str) -> Callable[[Principal | None], Principal]:
    """A dependency that returns the signed-in user when their role is at least ``minimum``."""
    if minimum not in ROLE_RANK:
        raise ValueError(f"unknown role {minimum!r}")

    def dependency(principal: Annotated[Principal | None, Depends(current_principal)]) -> Principal:
        if principal is None:
            raise HTTPException(status_code=401, detail="sign-in is required")
        if ROLE_RANK[principal.role] < ROLE_RANK[minimum]:
            raise HTTPException(status_code=403, detail="your role does not allow this")
        return principal

    return dependency


require_viewer = require_role("viewer")
require_operator = require_role("operator")
require_admin = require_role("admin")
