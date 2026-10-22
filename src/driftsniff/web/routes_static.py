"""The static files of the interface: the stylesheet, the vendored htmx and the brand copies.

One explicit route instead of a mounted application, so it sits in the route table of the
security suite like every other route. A path is served only when it resolves to a file inside
the ``static`` folder of this package: no parent references, no absolute paths, no symbolic
link that leaves the folder. The middleware leaves ``/static/`` out of its ``no-store`` rule; the
route sets a short public cache time instead.
"""

from pathlib import Path
from typing import Final

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

STATIC_DIR: Final = (Path(__file__).parent / "static").resolve()
STATIC_PREFIX: Final = "/static/"
CACHE_CONTROL: Final = "public, max-age=600"

router = APIRouter()


def resolve_static(path: str) -> Path | None:
    """The file ``/static/<path>`` names, or None when there is no such file inside the folder."""
    if not path or "\x00" in path or "\\" in path or path.startswith("/"):
        return None
    if any(part in ("", ".", "..") for part in path.split("/")):
        return None
    candidate = (STATIC_DIR / path).resolve()
    if not candidate.is_relative_to(STATIC_DIR) or not candidate.is_file():
        return None
    return candidate


@router.get("/static/{path:path}", include_in_schema=False)
def static_file(path: str) -> FileResponse:
    """Serve one file of the static folder."""
    target = resolve_static(path)
    if target is None:
        raise HTTPException(status_code=404, detail="Not Found")
    return FileResponse(target, headers={"Cache-Control": CACHE_CONTROL})
