"""What the Home Assistant collector does to the objects before the pipeline sees them.

* ``get_config`` answers one object; it becomes a list of one with the fixed id ``core``.
* ``is_admin`` on a user is derived: true when its ``group_ids`` hold ``system-admin`` (the group
  that makes a user an administrator in Home Assistant). Rules cannot test a list member, so this
  is how becoming an administrator is seen.
* Automations and scripts are built by the client from ``get_states`` and the config commands:
  ``{"entity_id", "config"}`` and, for an automation, ``enabled`` (its state is ``on``). No other
  state value is ever kept.
* Objects are sorted by their key; the order of the answer is never trusted.

Everything else is raw: redaction, normalisation and keying belong to the pipeline.
"""

from typing import Any, Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.core.canonical import JsonValue

RESOURCE_USERS: Final = "homeassistant-users"
CORE_ID: Final = "core"
ADMIN_GROUP: Final = "system-admin"


def prepare_object(name: str, item: dict[str, Any]) -> dict[str, Any]:
    """One raw object of ``name`` with the steps above applied (a copy; ``item`` is not changed)."""
    prepared = dict(item)
    if name == RESOURCE_USERS:
        groups = prepared.get("group_ids")
        prepared["is_admin"] = isinstance(groups, list) and ADMIN_GROUP in groups
    return prepared


def prepare_objects(
    name: str, key_field: str, result: JsonValue, *, single: bool
) -> list[dict[str, JsonValue]]:
    """The result of one command as checked objects sorted by ``key_field``.

    Raises :class:`CollectorError` (``bad_payload``) for an answer of the wrong shape or an object
    without a usable key: that resource fails, the others are not affected.
    """
    if single:
        if not isinstance(result, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not an object")
        result = [{**result, key_field: CORE_ID}]
    if not isinstance(result, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
    objects: list[dict[str, JsonValue]] = []
    for item in result:
        key = item.get(key_field) if isinstance(item, dict) else None
        if not isinstance(item, dict) or not isinstance(key, str) or not key:
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable key")
        objects.append(prepare_object(name, item))
    objects.sort(key=lambda entry: str(entry[key_field]))
    return objects
