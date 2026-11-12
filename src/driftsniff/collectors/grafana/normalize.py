"""What the Grafana collector does to raw answers before the pipeline sees them.

* Lists are checked (a list of objects, each with a usable key) and sorted by key, so the order
  Grafana returned never matters.
* The notification policy tree is one object without an id; it gets the key ``policies``.
* A dashboard is read as ``{"dashboard": model, "meta": {...}}``. The collector keeps the model and
  lifts ``uid``, ``title`` and ``meta.folderUid`` to the top; the rest of ``meta`` describes the
  token's own rights and timestamps and is dropped.
* The permissions of a folder become one object per folder: its ``uid``, ``title`` and a list of
  entries keyed by ``subject`` (``user:<id>``, ``team:<id>`` or ``role:<role>``). Only the fields
  that say who holds which permission are kept, sorted by subject; ids and timestamps are dropped.

Everything else is raw: redaction, normalisation and keying belong to the pipeline.
"""

from collections.abc import Mapping
from typing import Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.grafana.resources import RESOURCE_NOTIFICATION_POLICIES
from driftsniff.core.canonical import JsonValue

POLICIES_KEY: Final = "policies"
PERMISSION_FIELDS: Final = ("permission", "userLogin", "team", "role", "inherited")


def _sort_key(value: JsonValue) -> tuple[int, str]:
    return (0, f"{value:020d}") if isinstance(value, int) else (1, str(value))


def _usable_key(value: object) -> bool:
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, str) and value != "")


def prepare_objects(name: str, key_field: str, raw: JsonValue) -> list[dict[str, JsonValue]]:
    """The raw answer of one resource as checked objects sorted by key.

    Raises :class:`CollectorError` (``bad_payload``) for an answer that is not a list of objects
    (an object for the notification policies) or for an object without a usable key.
    """
    if name == RESOURCE_NOTIFICATION_POLICIES:
        if not isinstance(raw, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the policy answer is not an object")
        raw = [{**raw, key_field: POLICIES_KEY}]
    if not isinstance(raw, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
    objects: list[dict[str, JsonValue]] = []
    for item in raw:
        if not isinstance(item, dict) or not _usable_key(item.get(key_field)):
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        objects.append(dict(item))
    objects.sort(key=lambda item: _sort_key(item[key_field]))
    return objects


def dashboard_object(answer: JsonValue) -> dict[str, JsonValue]:
    """``{"dashboard": model, "meta": {...}}`` as the stored dashboard object."""
    model = answer.get("dashboard") if isinstance(answer, dict) else None
    if not isinstance(answer, dict) or not isinstance(model, dict):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a dashboard")
    uid = model.get("uid")
    if not _usable_key(uid) or not isinstance(uid, str):
        raise CollectorError(ERROR_BAD_PAYLOAD, "a dashboard has no usable uid")
    meta = answer.get("meta")
    folder = meta.get("folderUid") if isinstance(meta, Mapping) else None
    return {"uid": uid, "title": model.get("title"), "folderUid": folder, "dashboard": model}


def _subject(entry: Mapping[str, JsonValue]) -> str | None:
    for field, kind in (("userId", "user"), ("teamId", "team")):
        value = entry.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return f"{kind}:{value}"
    role = entry.get("role")
    return f"role:{role}" if isinstance(role, str) and role else None


def folder_permissions(folder: Mapping[str, JsonValue], entries: JsonValue) -> dict[str, JsonValue]:
    """One folder and the entries of its permission list, keyed by subject."""
    if not isinstance(entries, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the permission answer is not a list")
    kept: list[JsonValue] = []
    for entry in entries:
        subject = _subject(entry) if isinstance(entry, dict) else None
        if subject is None or not isinstance(entry, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "a permission entry names nobody")
        member: dict[str, JsonValue] = {"subject": subject}
        member.update({name: entry[name] for name in PERMISSION_FIELDS if name in entry})
        kept.append(member)
    kept.sort(key=lambda member: str(member["subject"]) if isinstance(member, dict) else "")
    return {"uid": folder["uid"], "title": folder.get("title"), "permissions": kept}
