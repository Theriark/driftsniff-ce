"""Application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from driftsniff import __version__
from driftsniff.config import Settings
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.scheduler import Scheduler
from driftsniff.web.routes_ui import router as ui_router


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start the scheduler with the application and stop it when the application stops."""
    scheduler: Scheduler | None = app.state.scheduler
    if scheduler is not None:
        await scheduler.start()
    try:
        yield
    finally:
        if scheduler is not None:
            await scheduler.stop()


def create_app(
    settings: Settings | None = None,
    master_key: MasterKey | None = None,
    scheduler: Scheduler | None = None,
) -> FastAPI:
    """Build the application; settings default to the DRIFTSNIFF_ environment.

    ``master_key`` is the key ``serve`` loaded at start; it is kept in ``app.state`` for the
    modules that derive keys from it. Its repr shows only the key id. A ``scheduler`` is started
    and stopped with the application (``serve`` passes none until the collectors exist).
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
    app.include_router(ui_router)
    return app
