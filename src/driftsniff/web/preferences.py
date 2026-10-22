"""Interface preferences kept in cookies (P10-T2): the row density of data tables.

The density switch is a normal form post to ``POST /preferences/density`` that sets the
``ds_density`` cookie and sends the user back to the page they were on. The cookie holds one of
two words and nothing else; anything else reads as the default. It is not a session and carries
no identity, so it is set for a year.
"""

import re
from typing import TYPE_CHECKING, Final

from driftsniff.web.templating import DENSITIES

if TYPE_CHECKING:
    from starlette.responses import Response

DENSITY_COOKIE: Final = "ds_density"
DEFAULT_DENSITY: Final = "comfortable"
DENSITY_MAX_AGE: Final = 365 * 24 * 3600

# A place to go back to: a path of this site, never another origin or a scheme.
_LOCAL_PATH: Final = re.compile(r"/(?!/)[\x21-\x7e]*")


def parse_density(value: str) -> str:
    """The density a form or cookie asks for; raises ValueError for anything else."""
    lowered = value.strip().lower()
    if lowered not in DENSITIES:
        raise ValueError("density must be comfortable or compact")
    return lowered


def density_from_cookie(value: str | None) -> str:
    """The density of a request from its cookie, the default when absent or not a density."""
    if value is None:
        return DEFAULT_DENSITY
    try:
        return parse_density(value)
    except ValueError:
        return DEFAULT_DENSITY


def set_density_cookie(response: "Response", density: str, *, secure: bool) -> None:
    """Attach the density cookie: HttpOnly, SameSite Lax, Secure over HTTPS, one year."""
    response.set_cookie(
        DENSITY_COOKIE,
        parse_density(density),
        max_age=DENSITY_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


def safe_next(value: str | None) -> str:
    """The path to send the user back to: a local path, else the start page.

    A value that could leave the site (a scheme, a protocol-relative ``//host``, a backslash,
    whitespace or a control character) is replaced by ``/``.
    """
    if value is None:
        return "/"
    if "\\" in value or not _LOCAL_PATH.fullmatch(value):
        return "/"
    return value
