"""Which change items a mute may name.

``path_mutes`` is read by ``driftsniff.rules.engine.is_muted`` for the list views only: the rule
engine itself never reads the table, so classification and the stored severity do not depend on
a mute. A mute hides an item; the item stays stored with its real severity.
"""

from typing import Final

CRITICAL: Final = "critical"
SCHEMA_DRIFT_KIND: Final = "schema_drift"
WILDCARD_CHARACTER: Final = "*"


def mute_refusal(severity: str, change_kind: str, path: str) -> str | None:
    """Why an item cannot be muted, or None when it can.

    A critical item is never muted. A schema drift item names several paths in one text, and a
    path that holds ``*`` would be read as a wildcard, so neither can be turned into a mute that
    means what the person clicked.
    """
    if severity == CRITICAL:
        return "a critical item cannot be muted"
    if change_kind == SCHEMA_DRIFT_KIND:
        return "a schema drift item names several paths and cannot be muted"
    if WILDCARD_CHARACTER in path:
        return "a path with a wildcard character cannot be muted"
    return None
