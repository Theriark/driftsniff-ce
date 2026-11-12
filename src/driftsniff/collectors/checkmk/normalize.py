"""What the Checkmk collector does to raw objects before the pipeline sees them.

Every Checkmk collection answers ``{"value": [domain object, ...], ...}`` and every domain object
is ``{"domainType", "id", "title", "links", "members", "extensions"}``
(docs/vendor-notes/checkmk.md, statement 4). The collector keeps ``id`` and ``title``, lifts the
members of ``extensions`` to the top of the object and drops ``domainType``, ``links`` and
``members`` (navigation, not configuration). So a host reads ``{"id", "title", "folder",
"attributes", ...}``.

Two attribute maps of hosts and folders have keys that are data, not field names, so a type table
could not name them. They are turned into lists keyed by a field and compared as sets:

* ``attributes.labels`` ``{"os": "linux"}`` becomes ``[{"key": "os", "value": "linux"}]``;
* every ``attributes.tag_<group>`` (built-in and own tag groups) is moved into
  ``attributes.tags`` as ``[{"group": "<group>", "value": ...}]``.

A notification rule keeps the plugin parameters whole (they can hold credentials and the type
table makes them secret); their ``plugin_name`` is copied next to them as
``notify_plugin.plugin_name`` so that a change of the method stays readable.

Objects are sorted by id, so the order Checkmk returned never matters. Everything else is raw:
redaction, normalisation and keying belong to the pipeline.
"""

import copy
from collections.abc import Mapping
from typing import Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.checkmk.resources import (
    RESOURCE_FOLDERS,
    RESOURCE_HOSTS,
    RESOURCE_NOTIFICATION_RULES,
)
from driftsniff.core.canonical import JsonValue

KEY_FIELD: Final = "id"
TAG_PREFIX: Final = "tag_"
_DROPPED: Final = ("domainType", "links", "members", "extensions")


def _attributes(attributes: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    reshaped: dict[str, JsonValue] = {}
    tags: dict[str, JsonValue] = {}
    for name, value in attributes.items():
        if name.startswith(TAG_PREFIX) and len(name) > len(TAG_PREFIX):
            tags[name[len(TAG_PREFIX) :]] = value
        elif name == "labels" and isinstance(value, Mapping):
            reshaped[name] = [{"key": key, "value": value[key]} for key in sorted(value)]
        else:
            reshaped[name] = value
    if tags:
        reshaped["tags"] = [{"group": group, "value": tags[group]} for group in sorted(tags)]
    return reshaped


def _plugin_name(item: dict[str, JsonValue]) -> None:
    config = item.get("rule_config")
    method = config.get("notification_method") if isinstance(config, dict) else None
    plugin = method.get("notify_plugin") if isinstance(method, dict) else None
    params = plugin.get("plugin_params") if isinstance(plugin, dict) else None
    if isinstance(plugin, dict) and isinstance(params, dict) and "plugin_name" in params:
        plugin["plugin_name"] = params["plugin_name"]


def _object(name: str, raw: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    extensions = raw.get("extensions")
    if extensions is not None and not isinstance(extensions, Mapping):
        raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable extensions")
    item: dict[str, JsonValue] = copy.deepcopy({k: v for k, v in raw.items() if k not in _DROPPED})
    for key, value in (extensions or {}).items():
        item.setdefault(
            key, copy.deepcopy(value)
        )  # id and title of the domain object win over an extension
    attributes = item.get("attributes")
    if name in (RESOURCE_HOSTS, RESOURCE_FOLDERS) and isinstance(attributes, Mapping):
        item["attributes"] = _attributes(attributes)
    if name == RESOURCE_NOTIFICATION_RULES:
        _plugin_name(item)
    return item


def prepare_objects(name: str, raw: JsonValue) -> list[dict[str, JsonValue]]:
    """The raw collection answer of one resource as checked, reshaped objects sorted by id.

    Raises :class:`CollectorError` (``bad_payload``) for an answer that is not a collection of
    objects or for an object without a usable id: the whole resource fails, the others are not
    affected. The input is not changed.
    """
    value = raw.get("value") if isinstance(raw, dict) else None
    if not isinstance(value, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a collection of objects")
    objects: list[dict[str, JsonValue]] = []
    for entry in value:
        if not isinstance(entry, dict) or not isinstance(entry.get(KEY_FIELD), str):
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        if entry[KEY_FIELD] == "":
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        objects.append(_object(name, entry))
    objects.sort(key=lambda item: str(item[KEY_FIELD]))
    return objects
