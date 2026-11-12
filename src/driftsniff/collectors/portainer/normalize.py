"""What the Portainer collector does to raw objects before the pipeline sees them.

Portainer keeps several access lists as maps keyed by a numeric id (docs/vendor-notes/portainer.md,
statements 3, 4 and 9). A type table names fixed field paths, so a map key such as a user id would
make every member unclassified. The collector turns those maps into lists of objects that carry
the id as a field; the type table compares them as sets keyed by that field:

* ``UserAccessPolicies`` ``{"3": {"RoleId": 0}}`` becomes ``[{"UserId": 3, "RoleId": 0}]`` and
  ``TeamAccessPolicies`` the same with ``TeamId`` (environments, environment groups and the
  accesses of a registry);
* ``RegistryAccesses`` of a registry becomes a list with ``EnvironmentId``;
* ``Endpoints`` and ``EndpointGroups`` of a tag (``{"1": true}``) become the sorted ids that are
  true.

The settings are one object without an id; the collector gives it the key ``settings``. Objects are
sorted by key, so the order Portainer returned never matters. Everything else is raw: redaction,
normalisation and keying belong to the pipeline.
"""

from collections.abc import Mapping
from typing import Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.portainer.resources import (
    RESOURCE_ENVIRONMENT_GROUPS,
    RESOURCE_ENVIRONMENTS,
    RESOURCE_REGISTRIES,
    RESOURCE_SETTINGS,
    RESOURCE_TAGS,
)
from driftsniff.core.canonical import JsonValue

SETTINGS_KEY: Final = "settings"
_POLICY_KEYS: Final = (("UserAccessPolicies", "UserId"), ("TeamAccessPolicies", "TeamId"))
_TAG_MAPS: Final = ("Endpoints", "EndpointGroups")


def _id(text: str) -> JsonValue:
    """A map key as Portainer meant it: a number when it is one."""
    return int(text) if text.isdigit() else text


def _sort_key(value: JsonValue) -> tuple[int, str]:
    return (0, f"{value:020d}") if isinstance(value, int) else (1, str(value))


def _keyed_list(value: JsonValue, key_name: str) -> JsonValue:
    """``{"3": {...}}`` as ``[{key_name: 3, ...}]``; anything that is not a map stays as it is."""
    if not isinstance(value, Mapping):
        return value
    members: list[JsonValue] = []
    for key in sorted(value, key=lambda text: _sort_key(_id(text))):
        member = value[key]
        entry: dict[str, JsonValue] = {key_name: _id(key)}
        if isinstance(member, Mapping):
            entry.update({name: inner for name, inner in member.items() if name != key_name})
        members.append(entry)
    return members


def _policies(item: dict[str, JsonValue]) -> None:
    for field, key_name in _POLICY_KEYS:
        if field in item:
            item[field] = _keyed_list(item[field], key_name)


def _registry_accesses(item: dict[str, JsonValue]) -> None:
    accesses = _keyed_list(item.get("RegistryAccesses"), "EnvironmentId")
    if isinstance(accesses, list):
        for access in accesses:
            if isinstance(access, dict):
                _policies(access)
        item["RegistryAccesses"] = accesses


def _true_ids(value: JsonValue) -> JsonValue:
    if not isinstance(value, Mapping):
        return value
    ids = [_id(key) for key, flag in value.items() if flag is True]
    return sorted(ids, key=_sort_key)


def _usable_key(value: object) -> bool:
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, str) and value != "")


def prepare_objects(name: str, key_field: str, raw: JsonValue) -> list[dict[str, JsonValue]]:
    """The raw answer of one resource as checked, reshaped objects sorted by key.

    Raises :class:`CollectorError` (``bad_payload``) for an answer that is not a list of objects
    (an object for the settings) or for an object without a usable key: the whole resource fails,
    the others are not affected.
    """
    if name == RESOURCE_SETTINGS:
        if not isinstance(raw, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the settings answer is not an object")
        raw = [{**raw, key_field: SETTINGS_KEY}]
    if not isinstance(raw, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
    objects: list[dict[str, JsonValue]] = []
    for item in raw:
        if not isinstance(item, dict) or not _usable_key(item.get(key_field)):
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        prepared = dict(item)
        if name in (RESOURCE_ENVIRONMENTS, RESOURCE_ENVIRONMENT_GROUPS):
            _policies(prepared)
        elif name == RESOURCE_REGISTRIES:
            _registry_accesses(prepared)
        elif name == RESOURCE_TAGS:
            for field in _TAG_MAPS:
                if field in prepared:
                    prepared[field] = _true_ids(prepared[field])
        objects.append(prepared)
    objects.sort(key=lambda item: _sort_key(item[key_field]))
    return objects
