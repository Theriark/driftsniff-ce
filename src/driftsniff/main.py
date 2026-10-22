"""Application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from driftsniff import __version__
from driftsniff.config import Settings
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.retention import RetentionJob
from driftsniff.sources.scheduler import Scheduler
from driftsniff.web import routes_push
from driftsniff.web.auth import AuthService
from driftsniff.web.csrf import BrowserHardeningMiddleware
from driftsniff.web.routes_ui import router as ui_router


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start the scheduler and the retention job with the application; stop them with it."""
    scheduler: Scheduler | None = app.state.scheduler
    retention: RetentionJob | None = app.state.retention
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


def create_app(
    settings: Settings | None = None,
    master_key: MasterKey | None = None,
    scheduler: Scheduler | None = None,
    push_gateway: routes_push.PushGateway | None = None,
    retention: RetentionJob | None = None,
    auth: AuthService | None = None,
) -> FastAPI:
    """Build the application; settings default to the DRIFTSNIFF_ environment.

    ``master_key`` is the key ``serve`` loaded at start; it is kept in ``app.state`` for the
    modules that derive keys from it. Its repr shows only the key id. A ``scheduler`` is started
    and stopped with the application (``serve`` passes none until the collectors exist). The
    ``push_gateway`` serves ``POST /api/v1/push/{source_id}``; without one the endpoint answers
    503. A ``retention`` job (the daily clean-up of old history) is started and stopped the same
    way. The ``auth`` service (users, sessions, the setup code) serves ``/setup``, ``/login`` and
    ``/logout`` and the role checks of ``driftsniff.web.deps``; without one they answer 503.
    Every response gets the security headers and every browser write the origin and CSRF checks
    of ``driftsniff.web.csrf``.
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
    app.add_middleware(BrowserHardeningMiddleware)
    app.include_router(ui_router)
    app.include_router(routes_push.router)
    return app
