"""What the Synology collector does to the answers before the pipeline sees them.

Pure functions, so they are tested without a server:

* :func:`split_credential` reads the one stored credential as ``user name:password``;
* :func:`objects_of` takes the objects out of the ``data`` of one answer;
* :func:`keyed` checks that every object has a text key and sorts by it, so the order the NAS
  returned is never trusted;
* :func:`share_object` and :func:`guest_access` build the share objects and the guest view from the
  share list and its permission rows.

Everything else is raw: redaction, normalisation and keying belong to the pipeline.
"""

from collections.abc import Mapping, Sequence
from typing import Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.synology.resources import GUEST_USER, SINGLETON_FIELD, SINGLETON_KEY
from driftsniff.core.canonical import JsonValue

MAX_USER_CHARS: Final = 256


def split_credential(secret: str) -> tuple[str, str]:
    """The user name and the password of a credential written ``user name:password``.

    The text is split at the first colon: DSM does not allow a colon in a user name, while a
    password may hold one. Raises ``ValueError`` with a fixed text (never the credential) when a
    part is missing or the user name has a control character.
    """
    user, colon, password = secret.partition(":")
    if not colon or not user or not password:
        raise ValueError("the credential must be written as user name:password")
    if len(user) > MAX_USER_CHARS or any(ord(char) < 0x20 or ord(char) == 0x7F for char in user):
        raise ValueError("the user name of the credential is not valid")
    return user, password


def objects_of(data: JsonValue, list_key: str | None) -> list[dict[str, JsonValue]]:
    """The objects in ``data``: the list under ``list_key``, ``data`` itself when it is ``""``,
    and for None the one settings object ``data`` is, keyed :data:`SINGLETON_KEY`."""
    if list_key is None:
        if not isinstance(data, dict):
            raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a settings object")
        return [{**data, SINGLETON_FIELD: SINGLETON_KEY}]
    found = data if list_key == "" else data.get(list_key) if isinstance(data, dict) else None
    if not isinstance(found, list) or not all(isinstance(item, dict) for item in found):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
    return list(found)


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


def share_object(
    share: Mapping[str, JsonValue], rows: Mapping[str, list[dict[str, JsonValue]]]
) -> dict[str, JsonValue]:
    """A share with its permission rows, one list per principal type (``permissions_local_user``
    and ``permissions_local_group``)."""
    built: dict[str, JsonValue] = dict(share)
    for principal_type, items in rows.items():
        built[f"permissions_{principal_type}"] = list(items)
    return built


def guest_access(
    share_name: str, user_rows: Sequence[Mapping[str, JsonValue]]
) -> dict[str, JsonValue] | None:
    """The guest view of one share: the ``guest`` row when it may read or write and is not denied,
    else None (guest has no access, and no object is listed)."""
    for row in user_rows:
        if row.get("name") != GUEST_USER:
            continue
        if row.get("is_deny") is True:
            return None
        if row.get("is_readonly") is True or row.get("is_writable") is True:
            return {
                "share": share_name,
                "is_readonly": row.get("is_readonly"),
                "is_writable": row.get("is_writable"),
            }
        return None
    return None
