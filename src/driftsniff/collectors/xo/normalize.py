"""What the Xen Orchestra collector does to the objects before the pipeline sees them (P8-T2).

* Objects are sorted by id: the returned order of a collection is never trusted (notes, statement
  3), so the order the pipeline sees does not depend on it.
* The user and password part of the address of a backup repository is removed before storage
  (``url.credentials`` of the type table is a virtual path for it). The part that stays is scanned
  by the pipeline like every other value. The part that is removed is found with the same rule the
  scanner uses for ``scheme://user:password@host`` addresses.
* Templates that are built in are dropped (notes, decision 3). The marker field is unverified; an
  object without it is a template the administrator made and stays.

Everything else is raw: redaction, normalisation and keying belong to the pipeline.
"""

from collections.abc import Sequence
from typing import Any, Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.xo.resources import BUILT_IN_TEMPLATE_FIELD
from driftsniff.core.canonical import JsonValue
from driftsniff.secrets.scanner import url_credential_spans

RESOURCE_BACKUP_REPOSITORIES: Final = "backup-repositories"
RESOURCE_VM_TEMPLATES: Final = "vm-templates"
URL_FIELD: Final = "url"


def strip_url_credentials(text: str) -> str:
    """``text`` without the ``user:password@`` part of every address in it that has one."""
    result = text
    for start, end in reversed(list(url_credential_spans(text))):
        # ``end`` is the position of the at sign that closes the user and password part.
        result = result[:start] + result[end + 1 :]
    return result


def prepare_objects(name: str, raw: Sequence[JsonValue]) -> list[dict[str, JsonValue]]:
    """The raw objects of one collection, checked, cleaned and sorted by id.

    Raises :class:`CollectorError` (``bad_payload``) for a value that is not an object or that has
    no text id: the whole collection fails, the other collections are not affected.
    """
    objects: list[dict[str, JsonValue]] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        if name == RESOURCE_VM_TEMPLATES and item.get(BUILT_IN_TEMPLATE_FIELD) is True:
            continue
        if name == RESOURCE_BACKUP_REPOSITORIES:
            address = item.get(URL_FIELD)
            if isinstance(address, str):
                item[URL_FIELD] = strip_url_credentials(address)
        objects.append(item)
    objects.sort(key=_object_id)
    return objects


def _object_id(item: dict[str, Any]) -> str:
    return str(item["id"])
