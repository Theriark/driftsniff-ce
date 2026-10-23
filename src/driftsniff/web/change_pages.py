"""The words and the small reads of the change pages (P10-T6, frontend slice).

The queries and the actions are ``driftsniff.changes`` (slice A). This module adds what the
pages need on top of them and what the plan says is our own code (nothing ported): the readable
field labels, the one-line summary of an item, the words of an order move, the two parts of a
before and after pair with the differing part marked, the filter options, the links of the
filter bar and the pager, and the sentence that names the filters in force.

Everything here is pure except :class:`ChangePages`, which holds the two services and reads the
filter options (the sources and the resource types that have changes) on one read connection.
Every text returned is plain text; the templates print it through autoescape.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import urlencode

import sqlalchemy as sa

from driftsniff.changes.actions import ChangeActions
from driftsniff.changes.queries import ChangeQueries
from driftsniff.changes.views import ChangeFilters, ChangePageView, ItemView, MoveView
from driftsniff.db.engine import Database
from driftsniff.db.tables import SEVERITIES, change_items, sources
from driftsniff.web.dashboard import resource_label
from driftsniff.web.templating import SEVERITY_LABELS

LIST_PATH: Final = "/changes"

# The severity select of the filter bar is a floor: the chosen severity and every worse one.
SEVERITY_FLOORS: Final[dict[str, tuple[str, ...]]] = {
    "critical": ("critical",),
    "high": ("critical", "high"),
    "medium": ("critical", "high", "medium"),
    "low": ("critical", "high", "medium", "low"),
}
SEVERITY_FLOOR_LABELS: Final = {
    "critical": "Critical",
    "high": "High and above",
    "medium": "Medium and above",
    "low": "Low and above",
}
# The value of the select that keeps a severity set which is not a floor (a dashboard link).
EXACT_SEVERITIES: Final = "exact"

STATUS_LABELS: Final = {"open": "Open", "acknowledged": "Acknowledged"}
SORT_LABELS: Final = {"newest": "Newest first", "oldest": "Oldest first", "severity": "Severity"}

# What a change kind did, in one word (the stored kinds of driftsniff.core.diff).
KIND_LABELS: Final = {
    "added": "Added",
    "removed": "Removed",
    "modified": "Changed",
    "moved": "Moved",
    "order_changed": "Order changed",
    "schema_drift": "New fields",
}

# Readable labels of the field names both type tables keep (our own table, nothing ported).
# The last segment of a path is looked up here; a name that is not here is spelled out.
FIELD_LABELS: Final = {
    "": "Whole object",
    "name": "Name",
    "name_label": "Name",
    "name_description": "Description",
    "description": "Description",
    "enabled": "Enabled",
    "security": "Security",
    "security_type": "Security type",
    "passphrase": "Passphrase",
    "x_passphrase": "Passphrase",
    "hidden": "Hidden",
    "band": "Band",
    "vlan": "VLAN",
    "action": "Action",
    "position": "Position",
    "order": "Order",
    "mtu": "MTU",
    "MTU": "MTU",
    "secureBoot": "Secure boot",
    "auto_poweron": "Auto power on",
    "high_availability": "High availability",
    "HA_enabled": "High availability",
    "permission": "Permission",
    "email": "Email",
    "username": "User name",
    "allowUnauthorized": "Allow unauthorized certificates",
    "readOnly": "Read only",
    "retention": "Retention",
    "reportRecipients": "Report recipients",
    "cron": "Schedule",
    "timezone": "Time zone",
    "remotes": "Backup repositories",
    "supplementalPacks": "Supplemental packs",
    "version": "Version",
    "firmware": "Firmware",
    "model": "Model",
    "tags": "Tags",
    "notes": "Notes",
    "shared_secret": "Shared secret",
    "x_shared_secret": "Shared secret",
    "psk": "Pre-shared key",
    "ip": "IP address",
    "subnet": "Subnet",
    "gateway": "Gateway",
    "dns": "DNS servers",
}

PAGER_WINDOW: Final = 2


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ---- words ------------------------------------------------------------------------------------


def _spell_out(name: str) -> str:
    """A field name as words: ``secureBoot`` and ``secure_boot`` both read Secure boot."""
    letters: list[str] = []
    previous = ""
    for character in name:
        if character in "_-":
            letters.append(" ")
        elif character.isupper() and previous and (previous.islower() or previous.isdigit()):
            letters.append(" " + character.lower())
        else:
            letters.append(character)
        previous = character
    words = " ".join("".join(letters).split())
    return words[:1].upper() + words[1:]


def field_label(path: str) -> str:
    """The readable label of a field path (the last segment names the field).

    A list member such as ``dns.1`` reads as its list field with the position; a whole-object
    item (empty path) reads Whole object; a path of several paths (schema drift) is left to
    :func:`item_summary`.
    """
    clean = path.strip()
    if clean in FIELD_LABELS:
        return FIELD_LABELS[clean]
    segments = [part for part in clean.replace("/", ".").split(".") if part]
    if not segments:
        return FIELD_LABELS[""]
    last = segments[-1]
    if last.isdigit() and len(segments) > 1:
        return f"{field_label('.'.join(segments[:-1]))}, entry {int(last) + 1}"
    if last in FIELD_LABELS:
        return FIELD_LABELS[last]
    return _spell_out(last) or clean


def kind_label(change_kind: str) -> str:
    """What the item did, in one or two words; an unknown kind is spelled out."""
    return KIND_LABELS.get(change_kind, _spell_out(change_kind))


def move_text(move: MoveView) -> str:
    """An order move in words: ``X moved from after A to before B``; the ends are named."""
    subject = move.key if move.key else "An entry"
    origin = f"after {move.from_after}" if move.from_after else "the start"
    target = f"before {move.to_before}" if move.to_before else "the end"
    return f"{subject} moved from {origin} to {target}."


def item_summary(item: ItemView) -> str:
    """The one line that says what an item is: the field and what happened to it."""
    if item.change_kind == "schema_drift":
        return "New fields appeared with this version"
    if item.change_kind == "moved":
        return move_text(item.move) if item.move is not None else "Entry moved"
    if item.change_kind == "order_changed":
        return "The order of the list changed"
    label = field_label(item.path)
    if item.path.strip() == "":
        return f"Object {kind_label(item.change_kind).lower()}"
    if item.secret:
        return f"{label} (secret) {kind_label(item.change_kind).lower()}"
    return f"{label} {kind_label(item.change_kind).lower()}"


def fingerprint_words(fingerprint: str | None) -> str:
    """A short fingerprint in groups of four, or the word none for a side that had no value."""
    if not fingerprint:
        return "none"
    return " ".join(fingerprint[start : start + 4] for start in range(0, len(fingerprint), 4))


@dataclass(frozen=True, slots=True)
class DiffParts:
    """One side of a before and after pair: the unchanged ends and the part that differs."""

    prefix: str
    changed: str
    suffix: str


def split_difference(before: str, after: str) -> tuple[DiffParts, DiffParts]:
    """Both texts split into the common start, the differing middle and the common end.

    The middle is marked on the page; when the texts are equal nothing is marked, and when one
    is empty the whole other text is the difference.
    """
    start = 0
    limit = min(len(before), len(after))
    while start < limit and before[start] == after[start]:
        start += 1
    end = 0
    while end < limit - start and before[-1 - end] == after[-1 - end]:
        end += 1
    prefix = before[:start]
    suffix = before[len(before) - end :] if end else ""
    return (
        DiffParts(prefix, before[start : len(before) - end], suffix),
        DiffParts(prefix, after[start : len(after) - end], suffix),
    )


def count_words(count: int, singular: str, plural: str = "") -> str:
    """``1 note``, ``2 notes``."""
    noun = singular if count == 1 else (plural or singular + "s")
    return f"{count:,} {noun}"


# ---- the filter bar, the links and the pager -------------------------------------------------


def severity_choice(filters: ChangeFilters) -> str:
    """The value of the severity select: a floor, ``exact`` for another set, or empty."""
    chosen = frozenset(filters.severities)
    if not chosen:
        return ""
    for floor, members in SEVERITY_FLOORS.items():
        if chosen == frozenset(members):
            return floor
    return EXACT_SEVERITIES


def severity_params(params: Mapping[str, Sequence[str]]) -> Mapping[str, Sequence[str]]:
    """The query with the ``min`` select of the filter bar turned into ``severity`` values.

    A floor wins over explicit ``severity`` values; an empty select (Any) drops them; ``exact``
    keeps them (the hidden inputs of a dashboard link whose set is not a floor); no ``min`` at
    all (a link from the dashboard) leaves the query as it is.
    """
    if "min" not in params:
        return params
    choice = (params["min"][0] if params["min"] else "").strip().lower()
    kept = {name: list(values) for name, values in params.items() if name != "min"}
    if choice in SEVERITY_FLOORS:
        kept["severity"] = list(SEVERITY_FLOORS[choice])
    elif choice != EXACT_SEVERITIES:
        kept.pop("severity", None)
    return kept


def filter_query(filters: ChangeFilters, **changes: Any) -> str:
    """The query string of ``filters`` with ``changes`` applied (``page=None`` drops a name).

    Only valid values are emitted, so a link made here is never a copy of what was typed.
    """
    values: dict[str, Any] = {
        "q": filters.search or None,
        "source": filters.source_id,
        "severity": list(filters.severities) or None,
        "status": filters.status,
        "resource": filters.resource,
        "from": filters.created_from.isoformat() if filters.created_from else None,
        "to": filters.created_to.isoformat() if filters.created_to else None,
        "sort": filters.sort if filters.sort != "newest" else None,
        "page": filters.page if filters.page > 1 else None,
        "muted": "1" if filters.include_muted else None,
    }
    values.update(changes)
    present = {name: value for name, value in values.items() if value not in (None, "", [])}
    encoded = urlencode(present, doseq=True)
    return f"{LIST_PATH}?{encoded}" if encoded else LIST_PATH


@dataclass(frozen=True, slots=True)
class PagerLink:
    label: str
    href: str
    current: bool = False


def pager_links(filters: ChangeFilters, page: ChangePageView) -> tuple[PagerLink, ...]:
    """Previous, a window of page numbers around the current one, and Next."""
    if page.pages <= 1:
        return ()
    low, high = page.page - PAGER_WINDOW, page.page + PAGER_WINDOW
    numbers = sorted({1, page.pages, *range(low, high + 1)})
    links: list[PagerLink] = []
    if page.page > 1:
        links.append(PagerLink("Previous", filter_query(filters, page=page.page - 1)))
    for number in numbers:
        if not 1 <= number <= page.pages:
            continue
        current = number == page.page
        links.append(PagerLink(str(number), filter_query(filters, page=number), current))
    if page.page < page.pages:
        links.append(PagerLink("Next", filter_query(filters, page=page.page + 1)))
    return tuple(links)


def page_summary(page: ChangePageView) -> str:
    """``Showing 1 to 50 of 231`` or ``No changes match``."""
    if page.total == 0:
        return "No changes match"
    first = (page.page - 1) * page.page_size + 1
    last = min(page.page * page.page_size, page.total)
    if page.total <= page.page_size:
        return count_words(page.total, "change")
    return f"Showing {first:,} to {last:,} of {page.total:,}"


def filters_text(filters: ChangeFilters, source_names: Mapping[int, str]) -> str:
    """The filters in force as one sentence, so a dashboard link is readable at a glance."""
    parts: list[str] = []
    if filters.status:
        parts.append(STATUS_LABELS[filters.status].lower())
    if filters.severities:
        choice = severity_choice(filters)
        if choice in SEVERITY_FLOOR_LABELS:
            parts.append(SEVERITY_FLOOR_LABELS[choice].lower())
        else:
            ordered = [name for name in reversed(SEVERITIES) if name in filters.severities]
            parts.append(" or ".join(SEVERITY_LABELS[name].lower() for name in ordered))
    if filters.source_id is not None:
        parts.append(f"source {source_names.get(filters.source_id, filters.source_id)}")
    if filters.resource:
        parts.append(resource_label(filters.resource).lower())
    if filters.created_from and filters.created_to:
        parts.append(f"from {filters.created_from} to {filters.created_to}")
    elif filters.created_from:
        parts.append(f"since {filters.created_from}")
    elif filters.created_to:
        parts.append(f"up to {filters.created_to}")
    if filters.search:
        parts.append(f"matching {filters.search!r}")
    if filters.include_muted:
        parts.append("muted included")
    return ", ".join(parts)


# ---- the services behind the pages --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Choice:
    value: str
    label: str


@dataclass(frozen=True, slots=True)
class FilterOptions:
    """What the selects of the filter bar offer: the sources and the resource types seen."""

    sources: tuple[Choice, ...]
    resources: tuple[Choice, ...]

    def source_names(self) -> dict[int, str]:
        return {int(choice.value): choice.label for choice in self.sources}


class ChangePages:
    """The two services of the change pages and the reads the filter bar needs."""

    def __init__(self, database: Database, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._db = database
        self._clock = clock
        self.queries = ChangeQueries(database)
        self.actions = ChangeActions(database, clock=clock)

    def now(self) -> datetime:
        return self._clock()

    def filter_options(self) -> FilterOptions:
        """Every source by name, and every resource type that has at least one change item."""
        with self._db.read() as connection:
            source_rows = connection.execute(
                sa.select(sources.c.id, sources.c.name).order_by(sources.c.name, sources.c.id)
            ).all()
            resource_rows = connection.execute(sa.select(change_items.c.resource).distinct()).all()
        resources = sorted(
            (Choice(str(row.resource), resource_label(str(row.resource))) for row in resource_rows),
            key=lambda choice: (choice.label.lower(), choice.value),
        )
        return FilterOptions(
            sources=tuple(Choice(str(int(row.id)), str(row.name)) for row in source_rows),
            resources=tuple(resources),
        )
