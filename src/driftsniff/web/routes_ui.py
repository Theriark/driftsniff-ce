"""Browser-facing routes. The scaffold only has the health check."""

import os
import re
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from driftsniff import __version__

router = APIRouter()

COMMIT_ENV = "DRIFTSNIFF_COMMIT"
UNKNOWN_COMMIT = "unknown"
# The image build sets the full 40-character commit SHA; other short tokens (for example the
# smoke test value) are passed through. Anything else is reported as unknown.
_COMMIT_TOKEN = re.compile(r"[0-9A-Za-z._-]{1,64}")


def build_commit() -> str:
    """Return the commit this image was built from, or "unknown" when unset or malformed."""
    value = os.environ.get(COMMIT_ENV, "").strip()
    if _COMMIT_TOKEN.fullmatch(value) and value != UNKNOWN_COMMIT:
        return value
    return UNKNOWN_COMMIT


class Healthz(BaseModel):
    """Body of GET /healthz: status, version and the build commit, nothing else."""

    status: Literal["ok"]
    version: str
    commit: str


@router.get("/healthz")
def healthz() -> Healthz:
    """Report liveness; the container health check and the release script call it."""
    return Healthz(status="ok", version=__version__, commit=build_commit())
