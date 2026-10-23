"""What the change list and the change detail hand to the interface (P10-T6, backend slice).

These are plain frozen dataclasses. The route that renders them and the templates belong to the
frontend slice; this module fixes the data contract between the two.

The escaping contract
---------------------
Every text field below is **plain text**. It holds exactly the characters that were stored, never
HTML: nothing here is escaped, nothing is wrapped in ``markupsafe.Markup`` and no field means
"safe to print as markup". A note, an acknowledgement comment, an object name, a rule rationale,
an enrichment label or summary and every text inside an enrichment payload can therefore hold
``<script>`` or any other markup, and it is the template's job to print it through Jinja's
autoescape (the templates never use the ``safe`` filter, a scan test enforces that). The unit test
``test_every_text_is_plain_text_and_prints_escaped`` walks a whole detail view and fails when a
field is a ``Markup`` object or when a template prints one unescaped.

Secrets never travel in a view. An item of class ``secret`` or ``unclassified`` has ``before`` and
``after`` set to ``None`` and shows only a short fingerprint, whatever the stored row holds. The
free text that comes from a vendor (object names, paths, rationales, order details) passes the log
scrubber of ``driftsniff.secrets.redact`` first, like in the change API.
"""

from dataclasses import dataclass
from datetime import date
from typing import Any, Final

SORTS: Final = ("newest", "oldest", "severity")
PAGE_SIZE: Final = 50
FINGERPRINT_SHOWN_CHARS: Final = 12

EXTERNAL_ANALYSIS_HEADING: Final = "External analysis, not verified by the product"
# Stored items from before rules carried an id have neither; the view says so instead of blank.
UNRATED_RULE_ID: Final = "unrated"
UNRATED_RATIONALE: Final = "No rule rationale was stored with this item."


@dataclass(frozen=True, slots=True)
class ChangeFilters:
    """What the change list is narrowed by (the filter bar and the search box).

    ``search`` matches the summary of a change and the object names of its items, ignoring
    case. ``severities`` are the highest severity of a change (any of them), ``status`` is
    ``open`` or ``acknowledged``, ``resource`` is a resource type of at least one item.
    ``created_from`` and ``created_to`` are UTC dates, both included. ``include_muted`` shows
    the changes whose every item is muted; by default they are hidden (a mute deletes nothing).
    """

    search: str = ""
    source_id: int | None = None
    severities: tuple[str, ...] = ()
    status: str | None = None
    resource: str | None = None
    created_from: date | None = None
    created_to: date | None = None
    sort: str = "newest"
    page: int = 1
    include_muted: bool = False


@dataclass(frozen=True, slots=True)
class ChangeRow:
    """One change in a list, and the head of a change detail."""

    id: int
    source_id: int
    source_name: str
    severity: str
    status: str
    summary: str
    item_count: int
    window_start: str
    window_end: str
    created_at: str
    rule_pack_version: str
    acknowledgement_count: int = 0
    note_count: int = 0
    enrichment_count: int = 0


@dataclass(frozen=True, slots=True)
class ChangePageView:
    """One page of the change list (50 changes), with what the pager needs."""

    rows: tuple[ChangeRow, ...]
    total: int
    page: int
    pages: int
    page_size: int
    # Changes the mutes hid from this list; 0 when ``include_muted`` is on or nothing is muted.
    muted_hidden: int = 0
    # True when so many changes matched that the mutes were applied to the newest part only.
    mute_scan_truncated: bool = False


@dataclass(frozen=True, slots=True)
class MoveView:
    """An order move in words: ``key`` moved from after ``from_after`` to before ``to_before``.

    ``None`` stands for an end of the list ("from the start", "to the end").
    """

    key: str | None
    from_after: str | None
    from_before: str | None
    to_after: str | None
    to_before: str | None
    summary: str | None


@dataclass(frozen=True, slots=True)
class ItemView:
    """One change item of a detail. ``rule_id`` and ``rationale`` are never empty."""

    id: int
    resource: str
    object_name: str | None
    change_kind: str
    path: str
    field_class: str
    severity: str
    rule_id: str
    rationale: str
    rationale_recorded: bool
    # Set only for a field that is shown; None for a secret or unclassified field.
    before: str | None
    after: str | None
    before_fingerprint: str | None
    after_fingerprint: str | None
    secret: bool
    muted: bool
    # Whether the interface may offer "mute this path" (never for a critical item).
    mutable: bool
    move: MoveView | None = None
    order_detail: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class ObjectGroup:
    """The items of one object, in the order they were stored."""

    resource: str
    object_id: int | None
    object_name: str | None
    items: tuple[ItemView, ...]


@dataclass(frozen=True, slots=True)
class AcknowledgementRow:
    id: int
    author: str
    comment: str
    created_at: str


@dataclass(frozen=True, slots=True)
class NoteRow:
    id: int
    author: str
    body: str
    created_at: str


@dataclass(frozen=True, slots=True)
class EnrichmentRow:
    """Text an external program appended. Shown under ``EXTERNAL_ANALYSIS_HEADING``."""

    id: int
    provider_label: str
    summary: str
    payload: Any | None
    created_at: str


@dataclass(frozen=True, slots=True)
class MuteRow:
    id: int
    resource: str
    path_pattern: str
    reason: str | None
    author: str
    created_at: str


@dataclass(frozen=True, slots=True)
class MuteResult:
    """The outcome of muting a path; ``created`` is False when the mute already existed."""

    mute: MuteRow
    created: bool


@dataclass(frozen=True, slots=True)
class ChangeDetailView:
    """One change with everything its detail page shows (acknowledgements and notes only grow)."""

    change: ChangeRow
    groups: tuple[ObjectGroup, ...]
    items_truncated: bool
    acknowledgements: tuple[AcknowledgementRow, ...]
    notes: tuple[NoteRow, ...]
    enrichments: tuple[EnrichmentRow, ...]
    muted_item_count: int = 0
