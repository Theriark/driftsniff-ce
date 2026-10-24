"""The words and the links of the History and Configuration pages (P10-T7, frontend slice).

The queries are ``driftsniff.history`` (slice A). This module adds what the pages need on top of
them: the mark and the word of each reading in the ledger, the links of the pager and of the
resource rail, the line that counts what is shown, a stored size in words, and how a field of
the current configuration is shown (its value, or a fingerprint for a secret or an unclassified
field).

Everything here is pure: values in, plain text or small frozen values out. The templates print
the text through autoescape, never through the ``safe`` filter.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urlencode

from driftsniff.history.views import ConfigObject, FieldView, SnapshotRow

HISTORY_PATH: Final = "/history"
CONFIGURATION_PATH: Final = "/configuration"
PAGER_WINDOW: Final = 2

# The two pickers share one template; this is what each one is called and what it is for.
PICKERS: Final = {
    "history": (
        "History",
        "When driftsniff read each source, which readings start a comparison and where it "
        "found changes.",
    ),
    "configuration": (
        "Configuration",
        "What each source holds now, from its newest reading. Secrets show as fingerprints only.",
    ),
}


def utc_now() -> datetime:
    return datetime.now(UTC)


# ---- the ledger -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LedgerMark:
    """How a reading is drawn on the rail of the history and the word beside it.

    ``shapes`` names the drawn marks: ``baseline`` is a square (the comparison starts here),
    ``current`` a ring (the reading the configuration page shows), ``reading`` a dot. The word
    always stands next to the mark, so the shape is never the only signal.
    """

    shapes: tuple[str, ...]
    word: str


def ledger_mark(row: SnapshotRow) -> LedgerMark:
    """The mark and the word of one reading of the history."""
    if row.is_baseline and row.is_current:
        return LedgerMark(("baseline", "current"), "Baseline, current")
    if row.is_baseline:
        return LedgerMark(("baseline",), "Baseline")
    if row.is_current:
        return LedgerMark(("current",), "Current")
    return LedgerMark(("reading",), "Reading")


def size_text(size: int) -> str:
    """A stored size in bytes as words: ``812 B``, ``4.2 KB``, ``1.3 MB``."""
    if size < 1024:
        return f"{max(size, 0):,} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


# ---- links ------------------------------------------------------------------------------------


def history_href(source_id: int, page: int = 1) -> str:
    """The history of a source at ``page``; the first page has no query."""
    base = f"{HISTORY_PATH}/{source_id}"
    return f"{base}?{urlencode({'page': page})}" if page > 1 else base


def configuration_href(
    source_id: int, *, resource: str | None = None, search: str = "", page: int = 1
) -> str:
    """The configuration of a source with the resource, the search and the page given.

    Only the values passed are written, so a link made here never copies what was typed in the
    address bar; an empty value is left out.
    """
    values: dict[str, str | int] = {}
    if resource:
        values["resource"] = resource
    if search:
        values["q"] = search
    if page > 1:
        values["page"] = page
    base = f"{CONFIGURATION_PATH}/{source_id}"
    return f"{base}?{urlencode(values)}" if values else base


@dataclass(frozen=True, slots=True)
class PageLink:
    label: str
    href: str
    current: bool = False


def page_links(page: int, pages: int, href: Callable[[int], str]) -> tuple[PageLink, ...]:
    """Previous, a window of page numbers around the current one, and Next."""
    if pages <= 1:
        return ()
    numbers = sorted({1, pages, *range(page - PAGER_WINDOW, page + PAGER_WINDOW + 1)})
    links: list[PageLink] = []
    if page > 1:
        links.append(PageLink("Previous", href(page - 1)))
    for number in numbers:
        if 1 <= number <= pages:
            links.append(PageLink(str(number), href(number), number == page))
    if page < pages:
        links.append(PageLink("Next", href(page + 1)))
    return tuple(links)


def range_text(total: int, page: int, page_size: int, singular: str, plural: str = "") -> str:
    """``2 readings`` on one page, ``Showing 51 to 100 of 231 readings`` on several."""
    noun = singular if total == 1 else (plural or singular + "s")
    if total <= page_size:
        return f"{total:,} {noun}"
    first = (page - 1) * page_size + 1
    last = min(page * page_size, total)
    return f"Showing {first:,} to {last:,} of {total:,} {noun}"


# ---- the configuration ------------------------------------------------------------------------


def object_title(obj: ConfigObject) -> str:
    """The heading of an object sheet: its name, or its key when it has none."""
    return obj.name if obj.name else obj.key


def field_state(field: FieldView) -> str:
    """How a field is shown: ``value``, ``secret`` or ``unclassified``.

    A field whose ``value`` is ``None`` is never shown in clear, whatever its class says; the
    page then prints its fingerprint and the word that says why.
    """
    if field.value is not None:
        return "value"
    if field.field_class == "unclassified":
        return "unclassified"
    return "secret"


def hidden_text(paths: Iterable[str]) -> str:
    """The fields Xen Orchestra hides, as one list for the warning of a resource."""
    return ", ".join(paths)
