"""What the Xen Orchestra collector does to the objects before the pipeline sees them (P8-T2).

* Objects are sorted by id: the returned order of a collection is never trusted (notes, statement
  3), so the order the pipeline sees does not depend on it.
* The user and password part of the address of a backup repository is removed before storage
  (``url.credentials`` of the type table is a virtual path for it). The part that stays is scanned
  by the pipeline like every other value. Everything before the last at sign goes, so the user-only
  form and a password that holds a slash are removed too (a hole in the first version, which used
  the scanner rule for ``scheme://user:password@host``).
* Templates that are built in are dropped (notes, decision 3). The marker field is unverified; an
  object without it is a template the administrator made and stays.

Everything else is raw: redaction, normalisation and keying belong to the pipeline.
"""

from collections.abc import Sequence
from typing import Any, Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.xo.resources import BUILT_IN_TEMPLATE_FIELD
from driftsniff.core.canonical import JsonValue

RESOURCE_BACKUP_REPOSITORIES: Final = "backup-repositories"
RESOURCE_VM_TEMPLATES: Final = "vm-templates"
URL_FIELD: Final = "url"
_AUTHORITY_END: Final = frozenset("/?#\"'<> \t\r\n")


def strip_url_credentials(text: str, *, whole_value: bool = False) -> str:
    """``text`` without the user and password part of every address in it that has one.

    The part before the last at sign of the authority goes, so ``user@host`` (no password) goes as
    well as ``user:password@host``. With ``whole_value`` the text is one address (the ``url`` field
    of a backup repository): the part goes up to the last at sign of the whole value, so a password
    that holds a slash, a question mark or a hash is removed completely. A path that holds an at
    sign loses its leading part in that mode; that is the price of never storing a password.
    """
    pieces: list[str] = []
    position = 0
    while (found := text.find("://", position)) != -1:
        start = found + 3
        if found == 0 or not text[found - 1].isalnum():
            pieces.append(text[position:start])
            position = start
            continue
        limit = len(text) if whole_value else _authority_end(text, start)
        at_sign = text.rfind("@", start, limit)
        pieces.append(text[position:start])
        position = start if at_sign == -1 else at_sign + 1
    pieces.append(text[position:])
    return "".join(pieces)


def _authority_end(text: str, start: int) -> int:
    """The position where the authority that starts at ``start`` ends."""
    end = start
    while end < len(text) and text[end] not in _AUTHORITY_END:
        end += 1
    return end


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
                item[URL_FIELD] = strip_url_credentials(address, whole_value=True)
        objects.append(item)
    objects.sort(key=_object_id)
    return objects


def _object_id(item: dict[str, Any]) -> str:
    return str(item["id"])
