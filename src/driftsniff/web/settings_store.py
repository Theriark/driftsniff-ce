"""The settings an admin may change, as rows of the ``settings`` table (docs/settings.md).

Two values are admin settings:

* ``retention_days``: the retention window of change events. The reader, the default and the bounds
  belong to ``driftsniff.sources.retention`` (30 to 365, default 365); this module only validates
  what an admin types and writes it.
* ``storage_warning_gb``: the size the storage card of the start page compares the database with.
  A whole number of gigabytes from 1 to 1000; a missing or invalid stored value gives 2.

Values are stored as text, like every row of the table. A value is only written after it passed
:func:`parse_whole_number`, so a bad entry changes nothing.
"""

from typing import Final

import sqlalchemy as sa
from sqlalchemy import Connection
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from driftsniff.db.tables import DEFAULT_WORKSPACE_ID, settings
from driftsniff.sources.retention import MAX_RETENTION_DAYS, MIN_RETENTION_DAYS

STORAGE_WARNING_SETTING: Final = "storage_warning_gb"
DEFAULT_STORAGE_WARNING_GB: Final = 2
MIN_STORAGE_WARNING_GB: Final = 1
MAX_STORAGE_WARNING_GB: Final = 1000
BYTES_PER_GB: Final = 1024 * 1024 * 1024
_MAX_DIGITS: Final = 6

FIELD_RETENTION: Final = "retention_days"
FIELD_STORAGE: Final = "storage_warning_gb"


class SettingInputError(ValueError):
    """An entered value breaks its rule. ``field`` names the form field; the text holds no value."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def parse_whole_number(raw: str | None, *, field: str, label: str, low: int, high: int) -> int:
    """A whole number from ``low`` to ``high``; SettingInputError otherwise (no sign, no space).

    ``label`` is the sentence of the rule, for example ``the retention window in days``. The
    message names the rule and never repeats what was typed.
    """
    rule = f"{label} must be a whole number from {low} to {high}"
    text = "" if raw is None else raw.strip()
    if not (text.isascii() and text.isdigit()) or len(text) > _MAX_DIGITS:
        raise SettingInputError(field, rule)
    number = int(text)
    if not low <= number <= high:
        raise SettingInputError(field, rule)
    return number


def parse_retention_days(raw: str | None) -> int:
    """The retention window an admin entered: 30 to 365 days."""
    return parse_whole_number(
        raw,
        field=FIELD_RETENTION,
        label="the retention window in days",
        low=MIN_RETENTION_DAYS,
        high=MAX_RETENTION_DAYS,
    )


def parse_storage_warning_gb(raw: str | None) -> int:
    """The storage warning size an admin entered: 1 to 1000 gigabytes."""
    return parse_whole_number(
        raw,
        field=FIELD_STORAGE,
        label="the storage warning size in gigabytes",
        low=MIN_STORAGE_WARNING_GB,
        high=MAX_STORAGE_WARNING_GB,
    )


def write_setting(connection: Connection, key: str, value: str) -> None:
    """Insert or replace one setting row of the default workspace."""
    statement = sqlite_insert(settings).values(
        workspace_id=DEFAULT_WORKSPACE_ID, key=key, value=value
    )
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=["workspace_id", "key"], set_={"value": statement.excluded.value}
        )
    )


def _stored(connection: Connection, key: str) -> str | None:
    raw = connection.execute(
        sa.select(settings.c.value).where(
            settings.c.workspace_id == DEFAULT_WORKSPACE_ID, settings.c.key == key
        )
    ).scalar_one_or_none()
    return None if raw is None else str(raw)


def storage_warning_gb(connection: Connection) -> int:
    """The storage warning size in gigabytes: the stored value when valid, else 2."""
    raw = _stored(connection, STORAGE_WARNING_SETTING)
    if raw is None:
        return DEFAULT_STORAGE_WARNING_GB
    try:
        return parse_storage_warning_gb(raw)
    except SettingInputError:
        return DEFAULT_STORAGE_WARNING_GB


def storage_warning_bytes(connection: Connection) -> int:
    """The storage warning size in bytes."""
    return storage_warning_gb(connection) * BYTES_PER_GB
