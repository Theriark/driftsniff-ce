"""What the history and the current configuration hand to the interface (P10-T7, backend slice).

Plain frozen dataclasses. The pages, the routes' HTML answers and the templates belong to the
frontend slice; this module fixes the data contract between the two.

The escaping contract is the one of ``driftsniff.changes.views``: every text field is **plain
text**, exactly the characters that were stored (after the log scrubber of
``driftsniff.secrets.redact``), never HTML. Nothing here is escaped in advance and nothing is
``markupsafe.Markup``; the templates print it through autoescape (a scan test forbids the
``safe`` filter), so markup in an object name or a field value comes out as text.

Secrets never travel in a view. A field of class ``secret`` or ``unclassified`` has
``value`` set to ``None`` and shows a short fingerprint (12 characters) only.
"""

from dataclasses import dataclass
from typing import Final

PAGE_SIZE: Final = 50
OBJECTS_PER_PAGE: Final = 50
FINGERPRINT_SHOWN_CHARS: Final = 12
SEARCH_MAX_CHARS: Final = 200
# A search reads at most this many objects of the chosen resource; ``search_truncated`` says so.
SEARCH_SCAN_LIMIT: Final = 5000
# The longest value a field shows; a longer one is cut and ``truncated`` is set.
VALUE_MAX_CHARS: Final = 2000


@dataclass(frozen=True, slots=True)
class SourceRef:
    """The source a page belongs to."""

    id: int
    name: str
    type: str
    enabled: bool


@dataclass(frozen=True, slots=True)
class SourceHistoryRow:
    """One source in the picker of the history and configuration pages."""

    id: int
    name: str
    type: str
    enabled: bool
    snapshot_count: int
    baseline_count: int
    latest_taken_at: str | None


@dataclass(frozen=True, slots=True)
class SnapshotRow:
    """One stored snapshot. ``is_baseline`` is the marker the history shows.

    A baseline is the first snapshot of a source and the first one after a normaliser version
    change: the diff engine starts from it and reports nothing across it. ``is_current`` marks the
    newest snapshot of the source, the one the configuration page shows.
    """

    id: int
    taken_at: str
    kind: str
    is_baseline: bool
    is_current: bool
    controller_version: str | None
    normaliser_version: int
    change_count: int
    manifest_bytes: int


@dataclass(frozen=True, slots=True)
class SnapshotPageView:
    """One page (50) of the snapshots of a source, newest first."""

    source: SourceRef
    rows: tuple[SnapshotRow, ...]
    total: int
    baseline_count: int
    page: int
    pages: int
    page_size: int


@dataclass(frozen=True, slots=True)
class SnapshotRef:
    """The snapshot the configuration shows."""

    id: int
    taken_at: str
    kind: str
    controller_version: str | None


@dataclass(frozen=True, slots=True)
class ResourceSummary:
    """One resource type of the current manifest.

    ``hidden_by_xo`` lists the fields Xen Orchestra itself never returns in clear (a change to
    them cannot be observed); it is empty for every other source type.
    """

    resource: str
    object_count: int
    ordered: bool
    hidden_by_xo: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FieldView:
    """One value of an object.

    ``path`` is the dotted field path with a 1-based ``[n]`` after every list member
    (``rules[2].action``). ``ordered`` is true inside a list whose order is meaningful.
    ``field_class`` is ``config``, ``secret`` or ``unclassified``; the last two never show their
    value, only ``fingerprint``. ``hidden_by_xo`` marks a field Xen Orchestra hides.
    """

    path: str
    value: str | None
    field_class: str
    secret: bool
    fingerprint: str | None
    ordered: bool
    hidden_by_xo: bool
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class ConfigObject:
    """One object of the current manifest, with its fields in stored order.

    ``position`` is the 1-based place of the object in an ordered resource (never page
    relative); it is ``None`` for a resource that has no order.
    """

    key: str
    name: str | None
    position: int | None
    fields: tuple[FieldView, ...]


@dataclass(frozen=True, slots=True)
class ConfigurationView:
    """The latest snapshot of a source, one resource at a time (50 objects a page).

    ``snapshot`` is ``None`` before the first snapshot (the page shows its empty state).
    ``selected_resource`` is the resource asked for, or the first one when none or an unknown
    one was asked for. ``total`` counts the objects of that resource that match ``search``.
    """

    source: SourceRef
    snapshot: SnapshotRef | None
    resources: tuple[ResourceSummary, ...]
    selected_resource: str | None
    search: str
    objects: tuple[ConfigObject, ...]
    total: int
    page: int
    pages: int
    page_size: int
    search_truncated: bool = False
