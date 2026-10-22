"""The one message every channel sends (P9-T4, docs/notifications.md).

A message holds an event id, the source name, the highest severity, the event summary, the item
count and a link. Nothing else: the before and after values of a change, object names and paths
never leave the application, so a receiver learns that something changed and where to look, and
the details stay behind the sign-in. The tests plant canaries in every value of an event and look
for them in what is sent.

The text fields are cleaned (control characters become spaces, length is capped) because a source
name is typed by an admin and ends up in a mail subject and a JSON body.
"""

from dataclasses import dataclass
from typing import Final

MAX_SOURCE_CHARS: Final = 120
MAX_SUMMARY_CHARS: Final = 300
LINK_PATH: Final = "/changes/"


def clean_text(text: str, limit: int) -> str:
    """One line of printable text, at most ``limit`` characters."""
    flattened = "".join(char if char.isprintable() else " " for char in text)
    collapsed = " ".join(flattened.split())
    return collapsed[:limit]


def event_link(base_url: str, event_id: int) -> str:
    """The address of the change page, built from DRIFTSNIFF_BASE_URL."""
    return f"{base_url.rstrip('/')}{LINK_PATH}{event_id}"


@dataclass(frozen=True, slots=True)
class NotificationMessage:
    """The fields of a notification; ``test`` marks the sample the test button sends."""

    event_id: int
    source: str
    severity: str
    summary: str
    item_count: int
    link: str
    test: bool = False

    def as_dict(self) -> dict[str, object]:
        """The JSON object of the webhook body; the mail carries the same fields."""
        return {
            "event_id": self.event_id,
            "source": self.source,
            "severity": self.severity,
            "summary": self.summary,
            "item_count": self.item_count,
            "link": self.link,
            "test": self.test,
        }


def build_message(
    *,
    event_id: int,
    source: str,
    severity: str,
    summary: str,
    item_count: int,
    base_url: str,
    test: bool = False,
) -> NotificationMessage:
    """Make a message from the stored event fields."""
    return NotificationMessage(
        event_id=event_id,
        source=clean_text(source, MAX_SOURCE_CHARS),
        severity=severity,
        summary=clean_text(summary, MAX_SUMMARY_CHARS),
        item_count=item_count,
        link=event_link(base_url, event_id),
        test=test,
    )


def sample_message(base_url: str) -> NotificationMessage:
    """The message of the test button: clearly a test, with no event behind it."""
    return build_message(
        event_id=0,
        source="driftsniff test",
        severity="low",
        summary="This is a test message from driftsniff. No change was found.",
        item_count=0,
        base_url=base_url,
        test=True,
    )
