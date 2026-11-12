"""What the Redfish collector does to the answers before the pipeline sees them.

Pure functions, so they are tested without a BMC:

* :func:`link_of` reads a navigation link (``{"@odata.id": "/redfish/v1/..."}``) and refuses one
  that is not a plain Redfish path on the same service (:func:`safe_path`): the collector only
  follows links, so a link is untrusted input;
* :func:`clean` drops OData and Redfish annotations (``@odata.etag`` changes on every write,
  ``Members@odata.count``, ``...@Redfish.AllowableValues``) and the values that are only links;
* :func:`bios_objects` turns the ``Attributes`` of a Bios resource into one object per attribute;
* :func:`keyed` checks the key of every object and sorts by it, so the order the BMC used never
  matters;
* :func:`version_text` builds the controller version from the service root and the manager.

Everything else is raw: redaction, normalisation and keying belong to the pipeline.
"""

import re
from collections.abc import Mapping, Sequence
from typing import Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.redfish.resources import (
    FIELD_OBJECT_KEY,
    FIELD_SECRET_VALUE,
    FIELD_VALUE,
    MAX_LINK_CHARS,
    PASSWORD_MARKERS,
)
from driftsniff.core.canonical import JsonValue

MAX_VERSION_CHARS: Final = 160
_LINK_KEY: Final = "@odata.id"
_PATH_CHARS: Final = re.compile(r"/redfish/v1(?:/[A-Za-z0-9._~%!$&'()*+,;=:@-]*)*")
_SAFE_TEXT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}")


def safe_path(value: object) -> str | None:
    """``value`` when it is a Redfish path of this service, else None.

    A path starts with ``/redfish/v1``, has no query, fragment, host, backslash, space or ``..``
    segment, and is at most :data:`MAX_LINK_CHARS` long. A trailing slash is removed, so ``/a/`` and
    ``/a`` are the same resource.
    """
    if not isinstance(value, str) or len(value) > MAX_LINK_CHARS:
        return None
    if _PATH_CHARS.fullmatch(value) is None or ".." in value.split("/"):
        return None
    return value.rstrip("/") or None


def link_of(document: Mapping[str, JsonValue], *names: str) -> str | None:
    """The path of the link at ``names`` (``link_of(root, "Links", "Sessions")``), or None when the
    document has no such link. A link that is present but not a safe path is a bad payload."""
    current: JsonValue = dict(document)
    for name in names:
        if not isinstance(current, dict):
            return None
        current = current.get(name)
    if not isinstance(current, dict) or _LINK_KEY not in current:
        return None
    path = safe_path(current[_LINK_KEY])
    if path is None:
        raise CollectorError(ERROR_BAD_PAYLOAD, "a link of the answer is not a Redfish path")
    return path


def member_paths(document: Mapping[str, JsonValue], field: str = "Members") -> list[str]:
    """The paths of the links in the list ``field`` (the ``Members`` of a collection)."""
    members = document.get(field)
    if members is None:
        return []
    if not isinstance(members, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a Redfish collection")
    paths: list[str] = []
    for member in members:
        path = safe_path(member.get(_LINK_KEY)) if isinstance(member, dict) else None
        if path is None:
            raise CollectorError(ERROR_BAD_PAYLOAD, "a link of the answer is not a Redfish path")
        paths.append(path)
    return paths


def _is_link(value: JsonValue) -> bool:
    return isinstance(value, dict) and bool(value) and all("@" in key for key in value)


def _only_links(value: JsonValue) -> bool:
    if isinstance(value, list):
        return bool(value) and all(_is_link(member) for member in value)
    return _is_link(value)


def clean(value: JsonValue) -> JsonValue:
    """``value`` without annotation keys (any key holding ``@``) and without link-only values."""
    if isinstance(value, dict):
        return {
            key: clean(member)
            for key, member in value.items()
            if "@" not in key and not _only_links(member)
        }
    if isinstance(value, list):
        return [clean(member) for member in value if not _is_link(member)]
    return value


def text_id(document: Mapping[str, JsonValue], field: str = "Id") -> str:
    """The text id of a Redfish resource; a resource without one is a bad payload."""
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
    return value


def bios_objects(system_id: str, bios: Mapping[str, JsonValue]) -> list[dict[str, JsonValue]]:
    """One object per BIOS attribute: ``{ObjectKey, System, Attribute, value}``.

    An attribute whose name says password (``AdminPassword``, ``SysPwd``) keeps its value in
    ``secret_value`` instead, which the type table classes secret: the BMC should answer null for
    it, and if it does not, only a fingerprint is stored. A value that is not a scalar is skipped
    (the schema allows only text, numbers, booleans and null).
    """
    attributes = bios.get("Attributes")
    if not isinstance(attributes, dict):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the BIOS answer has no attributes")
    found: list[dict[str, JsonValue]] = []
    for name, value in attributes.items():
        if "@" in name or isinstance(value, dict | list):
            continue
        lowered = name.lower()
        field = (
            FIELD_SECRET_VALUE
            if any(marker in lowered for marker in PASSWORD_MARKERS)
            else FIELD_VALUE
        )
        found.append(
            {
                FIELD_OBJECT_KEY: f"{system_id}/{name}",
                "System": system_id,
                "Attribute": name,
                field: value,
            }
        )
    return found


def keyed(objects: Sequence[dict[str, JsonValue]], key_field: str) -> list[dict[str, JsonValue]]:
    """``objects`` sorted by ``key_field``; an object without a text key, or a key that appears
    twice, fails the whole resource (``bad_payload``)."""
    seen: set[str] = set()
    for item in objects:
        key = item.get(key_field)
        if not isinstance(key, str) or not key:
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable key")
        if key in seen:
            raise CollectorError(ERROR_BAD_PAYLOAD, "two objects of the answer have one key")
        seen.add(key)
    return sorted(objects, key=lambda item: str(item[key_field]))


def _safe(value: JsonValue) -> str | None:
    if isinstance(value, str) and _SAFE_TEXT.fullmatch(value.strip()):
        return value.strip()
    return None


def version_text(root: Mapping[str, JsonValue], firmware: JsonValue) -> str | None:
    """``Vendor Product firmware (Redfish x.y.z)`` from the parts that look like plain text.

    The BMC chooses these texts, so a part with other characters is left out rather than shown.
    """
    parts = [_safe(root.get("Vendor")), _safe(root.get("Product")), _safe(firmware)]
    text = " ".join(part for part in parts if part)
    redfish = _safe(root.get("RedfishVersion"))
    if redfish:
        text = f"{text} (Redfish {redfish})" if text else f"Redfish {redfish}"
    return text[:MAX_VERSION_CHARS] or None
