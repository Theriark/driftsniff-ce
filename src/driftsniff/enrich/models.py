"""Request and answer shapes of the enrichment API (P9-T5, docs/enrichment-api.md).

The answers show a change the way the interface does: the shown value of a ``config`` field, a
short fingerprint (12 characters) for a ``secret`` or unclassified field, and never both. The
enrichment request is checked here, field by field, and its error report names the field and the
kind of problem but never repeats what the caller sent.
"""

from typing import Annotated, Any, Final

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from driftsniff.db.tables import ENRICHMENT_SUMMARY_MAX_CHARS

PROVIDER_LABEL_MAX_CHARS: Final = 80
PAYLOAD_MAX_BYTES: Final = 32 * 1024
PAYLOAD_MAX_DEPTH: Final = 6
# The summary, the label and the payload together, as sent: the payload limit plus room for text.
REQUEST_MAX_BYTES: Final = 64 * 1024

_ALLOWED_CONTROLS: Final = frozenset("\n\r\t")

_Label = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=PROVIDER_LABEL_MAX_CHARS),
]
_Summary = Annotated[str, StringConstraints(min_length=1, max_length=ENRICHMENT_SUMMARY_MAX_CHARS)]


class SourceRef(BaseModel):
    """The source a change belongs to."""

    id: int
    name: str


class ChangeSummary(BaseModel):
    """One change event, without its items."""

    id: int
    source: SourceRef
    severity: str
    status: str
    summary: str
    item_count: int
    window_start: str
    window_end: str
    created_at: str
    rule_pack_version: str


class ChangeItemView(BaseModel):
    """One item of a change; ``before``/``after`` are set only for fields that are shown."""

    id: int
    resource: str
    object_name: str | None
    change_kind: str
    path: str
    field_class: str
    before: str | None
    after: str | None
    before_fingerprint: str | None
    after_fingerprint: str | None
    severity: str
    rule_id: str | None
    rationale: str | None
    order_detail: dict[str, Any] | None


class NoteView(BaseModel):
    """A note a person added to a change."""

    id: int
    author: str
    body: str
    created_at: str


class EnrichmentView(BaseModel):
    """An enrichment an external program appended; not verified by the product."""

    id: int
    provider_label: str
    summary: str
    payload: Any | None
    created_at: str


class ChangeDetail(ChangeSummary):
    """A change with its items, notes and enrichments."""

    items: list[ChangeItemView]
    items_truncated: bool
    notes: list[NoteView]
    enrichments: list[EnrichmentView]


class ChangePage(BaseModel):
    """One page of changes, newest first; ``next_cursor`` is None on the last page."""

    changes: list[ChangeSummary]
    next_cursor: str | None


class EnrichmentRequest(BaseModel):
    """The body of ``POST /api/v1/changes/{id}/enrichments``."""

    model_config = ConfigDict(extra="forbid")

    provider_label: _Label
    summary: _Summary
    payload: dict[str, Any] | None = None

    @field_validator("provider_label")
    @classmethod
    def _printable_label(cls, value: str) -> str:
        if not value.isprintable():
            raise ValueError("the label has characters that cannot be printed")
        return value

    @field_validator("summary")
    @classmethod
    def _plain_text(cls, value: str) -> str:
        for character in value:
            is_control = ord(character) < 32 or ord(character) == 127
            if is_control and character not in _ALLOWED_CONTROLS:
                raise ValueError("the summary has control characters")
        if not value.strip():
            raise ValueError("the summary is empty")
        return value


def payload_depth(value: object) -> int:
    """How many containers deep a JSON value goes (a scalar is 0, ``{"a": 1}`` is 1).

    Iterative, so a hostile document cannot exhaust the interpreter stack.
    """
    deepest = 0
    pending: list[tuple[object, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if isinstance(current, dict):
            children: list[object] = list(current.values())
        elif isinstance(current, list):
            children = list(current)
        else:
            continue
        depth += 1
        deepest = max(deepest, depth)
        pending.extend((child, depth) for child in children)
    return deepest
