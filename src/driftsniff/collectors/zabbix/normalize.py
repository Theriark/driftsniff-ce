"""What the Zabbix collector does to raw objects before the pipeline sees them.

* Names that changed between versions but kept their shape get the newer name, so an upgrade of
  Zabbix is not reported as a change: ``groups`` of a host or a maintenance period becomes
  ``hostgroups`` (6.0 and 6.2 and later), ``rights`` of a user group becomes ``hostgroup_rights``.
* A macro of the type secret (``type`` ``"1"``) keeps its value, if a version ever returns it, in
  ``secret_value`` instead of ``value``. The type table classes ``secret_value`` as secret, so only
  its fingerprint is stored, while the value of a text or vault macro stays readable. Zabbix itself
  does not return the value of a secret macro (docs/vendor-notes/zabbix.md, statement 12).
* The authentication settings are one object without an id; the collector gives it the key
  ``authentication``.

Objects are sorted by their numeric id, so the order Zabbix returned never matters. Everything
else is raw: redaction, normalisation and keying belong to the pipeline.
"""

from collections.abc import Mapping
from typing import Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.zabbix.resources import (
    RESOURCE_AUTHENTICATION,
    RESOURCE_GLOBAL_MACROS,
    RESOURCE_HOSTS,
    RESOURCE_MAINTENANCE,
    RESOURCE_TEMPLATES,
    RESOURCE_USER_GROUPS,
    SINGLETON_KEY,
)
from driftsniff.core.canonical import JsonValue

SECRET_MACRO_TYPE: Final = "1"  # noqa: S105 - a macro type, not a password
SECRET_VALUE_FIELD: Final = "secret_value"  # noqa: S105 - a field name
_RENAMES: Final = {
    RESOURCE_HOSTS: ("groups", "hostgroups"),
    RESOURCE_MAINTENANCE: ("groups", "hostgroups"),
    RESOURCE_USER_GROUPS: ("rights", "hostgroup_rights"),
}


def hide_secret_macro(macro: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """The macro with the value of a secret macro moved to ``secret_value``."""
    if str(macro.get("type")) == SECRET_MACRO_TYPE and "value" in macro:
        macro = dict(macro)
        macro[SECRET_VALUE_FIELD] = macro.pop("value")
    return macro


def _macros(value: JsonValue) -> JsonValue:
    if not isinstance(value, list):
        return value
    return [hide_secret_macro(item) if isinstance(item, dict) else item for item in value]


def usable_id(value: object) -> bool:
    """A Zabbix id: a non-empty text (Zabbix sends ids as text) or a whole number."""
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, str) and value != "")


def id_order(value: JsonValue) -> tuple[int, int, str]:
    """Numeric ids in number order, anything else after them in text order."""
    text = str(value)
    return (0, int(text), "") if text.isdigit() else (1, 0, text)


def prepare_objects(name: str, key_field: str, raw: JsonValue) -> list[dict[str, JsonValue]]:
    """The raw ``result`` of one resource as checked, reshaped objects sorted by key.

    Raises :class:`CollectorError` (``bad_payload``) for a result that is not a list of objects
    (an object for the authentication settings) or for an object without a usable id.
    """
    if name == RESOURCE_AUTHENTICATION:
        if not isinstance(raw, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the authentication answer is not an object")
        raw = [{**raw, key_field: SINGLETON_KEY}]
    if not isinstance(raw, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
    rename = _RENAMES.get(name)
    objects: list[dict[str, JsonValue]] = []
    for item in raw:
        if not isinstance(item, Mapping) or not usable_id(item.get(key_field)):
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        prepared = dict(item)
        if rename is not None and rename[0] in prepared and rename[1] not in prepared:
            prepared[rename[1]] = prepared.pop(rename[0])
        if name in (RESOURCE_HOSTS, RESOURCE_TEMPLATES) and "macros" in prepared:
            prepared["macros"] = _macros(prepared["macros"])
        if name == RESOURCE_GLOBAL_MACROS:
            prepared = hide_secret_macro(prepared)
        objects.append(prepared)
    objects.sort(key=lambda item: id_order(item[key_field]))
    return objects
