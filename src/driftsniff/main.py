"""Application factory."""

from fastapi import FastAPI

from driftsniff import __version__
from driftsniff.config import Settings
from driftsniff.web.routes_ui import router as ui_router


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application; settings default to the DRIFTSNIFF_ environment."""
    resolved = Settings.from_env() if settings is None else settings
    app = FastAPI(
        title="driftsniff",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = resolved
    app.include_router(ui_router)
    return app
