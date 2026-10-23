"""The query string of the change list, read into :class:`ChangeFilters`.

The parser never raises: a value that is not one of the allowed words, not a number or not a date
is dropped, so a stale or hand-edited link still opens the list. The names are ``q`` (search),
``source``, ``severity`` (may repeat), ``status``, ``resource``, ``from`` and ``to`` (dates like
2026-10-22), ``sort`` (newest, oldest or severity), ``page`` and ``muted`` (``1`` shows changes
whose every item is muted).
"""

import re
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Final

from driftsniff.changes.views import SORTS, ChangeFilters
from driftsniff.db.tables import EVENT_STATUSES, SEVERITIES

MAX_SOURCE_ID: Final = 2**31 - 1
MAX_PAGE: Final = 1_000_000
MAX_RESOURCE_CHARS: Final = 100
_DATE_SHAPE: Final = re.compile(r"\d{4}-\d{2}-\d{2}")
_TRUE_WORDS: Final = frozenset({"1", "true", "on", "yes"})


def _first(params: Mapping[str, Sequence[str]], name: str) -> str:
    values = params.get(name, ())
    return values[0].strip() if values else ""


def _number(text: str, largest: int) -> int | None:
    if not (text.isascii() and text.isdigit()) or len(text) > 9:
        return None
    value = int(text)
    return value if 1 <= value <= largest else None


def _day(text: str) -> date | None:
    if _DATE_SHAPE.fullmatch(text) is None:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def parse_filters(params: Mapping[str, Sequence[str]]) -> ChangeFilters:
    """The filters of a query string (``params`` maps a name to all its values)."""
    severities: list[str] = []
    for word in params.get("severity", ()):
        clean = word.strip().lower()
        if clean in SEVERITIES and clean not in severities:
            severities.append(clean)
    status = _first(params, "status").lower()
    resource = _first(params, "resource")
    sort = _first(params, "sort").lower()
    return ChangeFilters(
        search=_first(params, "q"),
        source_id=_number(_first(params, "source"), MAX_SOURCE_ID),
        severities=tuple(severities),
        status=status if status in EVENT_STATUSES else None,
        resource=resource if 0 < len(resource) <= MAX_RESOURCE_CHARS else None,
        created_from=_day(_first(params, "from")),
        created_to=_day(_first(params, "to")),
        sort=sort if sort in SORTS else "newest",
        page=_number(_first(params, "page"), MAX_PAGE) or 1,
        include_muted=_first(params, "muted").lower() in _TRUE_WORDS,
    )
