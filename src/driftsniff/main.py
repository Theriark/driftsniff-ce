"""Application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from driftsniff import __version__
from driftsniff.config import Settings
from driftsniff.enrich import api as enrich_api
from driftsniff.notify.deliveries import NotificationService
from driftsniff.plugins.registry import PluginRegistry
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.retention import RetentionJob
from driftsniff.sources.scheduler import Scheduler
from driftsniff.web import (
    routes_api,
    routes_changes,
    routes_notifications,
    routes_push,
    routes_sources,
    routes_static,
)
from driftsniff.web.auth import AuthService
from driftsniff.web.bearer import TokenService
from driftsniff.web.change_pages import ChangePages
from driftsniff.web.csrf import BrowserHardeningMiddleware
from driftsniff.web.dashboard import DashboardService
from driftsniff.web.pages import handle_http_exception
from driftsniff.web.routes_ui import router as ui_router
from driftsniff.web.source_pages import SourcePages


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start the scheduler and the retention job with the application; stop them with it."""
    scheduler: Scheduler | None = app.state.scheduler
    retention: RetentionJob | None = app.state.retention
    notifications: NotificationService | None = app.state.notifications
    if scheduler is not None:
        await scheduler.start()
    try:
        if retention is not None:
            await retention.start()
        yield
    finally:
        if retention is not None:
            await retention.stop()
        if scheduler is not None:
            await scheduler.stop()
        if notifications is not None:
            await run_in_threadpool(notifications.close)


def create_app(
    settings: Settings | None = None,
    master_key: MasterKey | None = None,
    scheduler: Scheduler | None = None,
    push_gateway: routes_push.PushGateway | None = None,
    retention: RetentionJob | None = None,
    auth: AuthService | None = None,
    tokens: TokenService | None = None,
    notifications: NotificationService | None = None,
    changes: enrich_api.ChangeService | None = None,
    plugins: PluginRegistry | None = None,
    dashboard: DashboardService | None = None,
    sources: SourcePages | None = None,
    change_pages: ChangePages | None = None,
) -> FastAPI:
    """Build the application; settings default to the DRIFTSNIFF_ environment.

    ``master_key`` is the key ``serve`` loaded at start; it is kept in ``app.state`` for the
    modules that derive keys from it. Its repr shows only the key id. A ``scheduler`` is started
    and stopped with the application (``serve`` passes none until the collectors exist). The
    ``push_gateway`` serves ``POST /api/v1/push/{source_id}``; without one the endpoint answers
    503. A ``retention`` job (the daily clean-up of old history) is started and stopped the same
    way. The ``auth`` service (users, sessions, the setup code) serves ``/setup``, ``/login`` and
    ``/logout`` and the role checks of ``driftsniff.web.deps``; without one they answer 503.
    The ``tokens`` service (API tokens) serves the admin routes under ``/tokens`` and the token
    checks of the ``/api/v1`` routes; without one they answer 503.
    The ``notifications`` service (the webhook or mail channel) serves the admin routes under
    ``/notifications``; without one they answer 503. It is stopped with the application, after
    the deliveries that are running have finished. The run pipeline sends events through its
    ``notify_event`` (the ``notifier`` of ``RunPipeline``).
    The ``changes`` service serves ``GET /api/v1/changes`` and the enrichment route; without one
    they answer 503 (the OpenAPI document at ``/api/v1/openapi.json`` needs no service). The
    ``plugins`` registry holds the implementation of every extension point, checked at start.
    The ``dashboard`` service reads the figures of the start page; without one the start page
    shows its empty state.
    The ``sources`` pages (``/sources`` and below: the list, the add and edit forms, test
    connection, run now, enable, disable, delete) read and act through it; without one they
    answer 503. Run now uses the ``scheduler`` and answers that runs are not scheduled without
    one; test connection uses the probe factory of ``sources`` the same way.
    The ``change_pages`` service (``/changes`` and below, and ``/mutes``: the change list, the
    change detail, acknowledge, notes and mutes) reads and acts through it; without one they
    answer 503.
    Every response gets the security headers and every browser write the origin and CSRF checks
    of ``driftsniff.web.csrf``. The stylesheet, the vendored htmx and the brand copies are served
    under ``/static/`` by ``driftsniff.web.routes_static``. A browser that meets a 401, 403 or
    404 outside the API gets the sign-in redirect or a status page (``driftsniff.web.pages``);
    every other client gets the plain JSON answer.
    """
    resolved = Settings.from_env() if settings is None else settings
    app = FastAPI(
        title="driftsniff",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_lifespan,
    )
    app.state.settings = resolved
    app.state.master_key = master_key
    app.state.scheduler = scheduler
    app.state.push_gateway = push_gateway
    app.state.retention = retention
    app.state.auth = auth
    app.state.tokens = tokens
    app.state.notifications = notifications
    app.state.changes = changes
    app.state.plugins = plugins
    app.state.dashboard = dashboard
    app.state.sources = sources
    app.state.change_pages = change_pages
    app.state.openapi_cache = None
    app.add_middleware(BrowserHardeningMiddleware)
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)
    app.include_router(ui_router)
    app.include_router(routes_sources.router)
    app.include_router(routes_changes.router)
    app.include_router(routes_static.router)
    app.include_router(routes_push.router)
    app.include_router(routes_api.router)
    app.include_router(routes_notifications.router)
    app.include_router(enrich_api.router)
    return app
