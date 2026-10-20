"""Application factory."""

from fastapi import FastAPI

from driftsniff import __version__
from driftsniff.config import Settings
from driftsniff.secrets.keys import MasterKey
from driftsniff.web.routes_ui import router as ui_router


def create_app(settings: Settings | None = None, master_key: MasterKey | None = None) -> FastAPI:
    """Build the application; settings default to the DRIFTSNIFF_ environment.

    ``master_key`` is the key ``serve`` loaded at start; it is kept in ``app.state`` for the
    modules that derive keys from it. Its repr shows only the key id.
    """
    resolved = Settings.from_env() if settings is None else settings
    app = FastAPI(
        title="driftsniff",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = resolved
    app.state.master_key = master_key
    app.include_router(ui_router)
    return app
