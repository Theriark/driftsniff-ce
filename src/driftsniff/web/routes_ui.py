"""Browser-facing routes. The scaffold only has the health check."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from driftsniff import __version__

router = APIRouter()


class Healthz(BaseModel):
    """Body of GET /healthz: status and version, nothing else."""

    status: Literal["ok"]
    version: str


@router.get("/healthz")
def healthz() -> Healthz:
    """Report liveness; the container health check calls it."""
    return Healthz(status="ok", version=__version__)
