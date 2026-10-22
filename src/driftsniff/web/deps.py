"""Request dependencies: the signed-in user and the role a route needs, or the API token and scope.

A route of the interface that needs a role lists ``Depends(require_role("operator"))`` (or one of
the shortcuts below). No session gives 401, a session whose role ranks lower gives 403. The role
order is viewer, operator, admin; each role may do everything the lower ones may.

A route under ``/api/v1`` lists ``Depends(require_token("read"))`` (or ``require_read_token``,
``require_enrich_token``). A missing, wrong, expired or revoked token gives 401, a token without
the scope gives 403. Scopes are never implied by one another.
"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from driftsniff.notify.deliveries import NotificationService
from driftsniff.web.auth import ROLE_RANK, SESSION_COOKIE, AuthService, Principal
from driftsniff.web.bearer import (
    TOKEN_SCOPES,
    TokenPrincipal,
    TokenRejectedError,
    TokenScopeError,
    TokenService,
)


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


def get_token_service(request: Request) -> TokenService:
    """The application's API token service; 503 when the application was built without one."""
    service: TokenService | None = request.app.state.tokens
    if service is None:
        raise HTTPException(status_code=503, detail="API tokens are not available")
    return service


def get_notification_service(request: Request) -> NotificationService:
    """The notification service; 503 when the application was built without one."""
    service: NotificationService | None = request.app.state.notifications
    if service is None:
        raise HTTPException(status_code=503, detail="notifications are not available")
    return service


def require_token(scope: str) -> Callable[[Request, TokenService], TokenPrincipal]:
    """A dependency that returns the API token of the request when it carries ``scope``."""
    if scope not in TOKEN_SCOPES:
        raise ValueError(f"unknown token scope {scope!r}")

    def dependency(
        request: Request, service: Annotated[TokenService, Depends(get_token_service)]
    ) -> TokenPrincipal:
        try:
            return service.authenticate(request.headers.get("authorization"), scope)
        except TokenScopeError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        except TokenRejectedError as error:
            raise HTTPException(
                status_code=401, detail=str(error), headers={"WWW-Authenticate": "Bearer"}
            ) from error

    return dependency


require_read_token = require_token("read")
require_enrich_token = require_token("enrich")
