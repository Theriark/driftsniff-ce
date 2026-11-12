"""What the Proxmox VE collector does to raw answers before the pipeline sees them.

* Every answer is ``{"data": ...}``; :func:`unwrap` takes the data out.
* An options answer (cluster options, firewall options) is one object without a key; it gets the
  key ``id`` = ``cluster``.
* A guest or node config has numbered keys (``net0``, ``scsi1``); a type table names fixed paths,
  so :func:`fold_slots` turns them into one list per kind, named as the API schema names them
  (``net[n]``), of ``{"slot": "net0", "value": "..."}`` members keyed by ``slot``.
* Comma separated member lists (the users of a group, the groups of a user, the privileges of a
  role) become sorted lists, compared as sets.
* ACL entries have no id; :func:`acl_entries` gives each the key ``path|type|ugid|roleid`` and
  splits off the entries of the Administrator role.
* API tokens come with their user (``/access/users?full=1``); :func:`tokens` lifts them out, keyed
  ``userid!tokenid``.
* Pool members carry live usage; only their ids are kept.

Objects are sorted by key. Everything else is raw: redaction and normalisation belong to the
pipeline.
"""

import re
from collections.abc import Iterable
from typing import Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.proxmox.resources import ADMIN_ROLE
from driftsniff.core.canonical import JsonValue

OPTIONS_KEY: Final = "cluster"
SLOT_FIELD: Final = "slot"
VALUE_FIELD: Final = "value"
# A name that is put into a request path: what Proxmox allows for node, group, ipset and realm ids.
_SEGMENT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SPLIT: Final = re.compile(r"[,;\s]+")


def bad(text: str) -> CollectorError:
    """A ``bad_payload`` error with a fixed text."""
    return CollectorError(ERROR_BAD_PAYLOAD, text)


def unwrap(parsed: JsonValue) -> JsonValue:
    """The ``data`` member of a Proxmox answer."""
    if not isinstance(parsed, dict) or "data" not in parsed:
        raise bad("the answer has no data member")
    return parsed["data"]


def path_segment(value: JsonValue) -> str:
    """A name from an answer that goes into a request path, checked so it cannot change the path."""
    if isinstance(value, str) and _SEGMENT.fullmatch(value):
        return value
    raise bad("a name in the answer cannot be used in a path")


def _usable_key(value: object) -> bool:
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, str) and value != "")


def _sort_key(value: JsonValue) -> tuple[int, str]:
    return (0, f"{value:020d}") if isinstance(value, int) else (1, str(value))


def object_list(raw: JsonValue) -> list[dict[str, JsonValue]]:
    """The answer as a list of objects (copies), or ``bad_payload``."""
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise bad("the answer is not a list of objects")
    return [dict(item) for item in raw if isinstance(item, dict)]


def keyed(objects: Iterable[dict[str, JsonValue]], key_field: str) -> list[dict[str, JsonValue]]:
    """``objects`` sorted by ``key_field``; an object without a usable key fails the resource."""
    result = list(objects)
    for item in result:
        if not _usable_key(item.get(key_field)):
            raise bad("an object of the answer has no usable id")
    keys = [item[key_field] for item in result]
    if len({str(key) for key in keys}) != len(keys):
        raise bad("two objects of the answer have the same id")
    result.sort(key=lambda item: _sort_key(item[key_field]))
    return result


def single(raw: JsonValue) -> list[dict[str, JsonValue]]:
    """An options object as one object with the key ``id`` = ``cluster``."""
    if not isinstance(raw, dict):
        raise bad("the answer is not an object")
    return [{**raw, "id": OPTIONS_KEY}]


def split_names(value: JsonValue) -> JsonValue:
    """``"b,a"`` as ``["a", "b"]``; a list is sorted; anything else stays as it is."""
    if isinstance(value, str):
        return sorted({part for part in _SPLIT.split(value) if part})
    if isinstance(value, list):
        return sorted({str(part) for part in value})
    return value


def fold_slots(config: dict[str, JsonValue], kinds: Iterable[str]) -> dict[str, JsonValue]:
    """``net0``, ``net1`` as ``net[n]``: a list of ``{slot, value}`` sorted by slot number."""
    patterns = {kind: re.compile(rf"{re.escape(kind)}(\d{{1,3}})") for kind in kinds}
    folded: dict[str, JsonValue] = {}
    slots: dict[str, list[tuple[int, str, JsonValue]]] = {}
    for key, value in config.items():
        for kind, pattern in patterns.items():
            match = pattern.fullmatch(key)
            if match:
                slots.setdefault(kind, []).append((int(match.group(1)), key, value))
                break
        else:
            folded[key] = value
    for kind, found in slots.items():
        found.sort()
        folded[f"{kind}[n]"] = [{SLOT_FIELD: key, VALUE_FIELD: value} for _, key, value in found]
    return folded


def acl_entries(
    raw: JsonValue,
) -> tuple[list[dict[str, JsonValue]], list[dict[str, JsonValue]]]:
    """The ACL as (other entries, Administrator entries), each keyed and sorted by ``id``."""
    others: list[dict[str, JsonValue]] = []
    admins: list[dict[str, JsonValue]] = []
    for entry in object_list(raw):
        parts = [entry.get(name) for name in ("path", "type", "ugid", "roleid")]
        if not all(isinstance(part, str) and part for part in parts):
            raise bad("an ACL entry of the answer is incomplete")
        entry["id"] = "|".join(str(part) for part in parts)
        (admins if entry["roleid"] == ADMIN_ROLE else others).append(entry)
    return keyed(others, "id"), keyed(admins, "id")


def users(raw: JsonValue) -> list[dict[str, JsonValue]]:
    """The users, without their tokens (a resource of their own), groups as a sorted list."""
    result = []
    for user in object_list(raw):
        user.pop("tokens", None)
        if "groups" in user:
            user["groups"] = split_names(user["groups"])
        result.append(user)
    return keyed(result, "userid")


def tokens(raw: JsonValue) -> list[dict[str, JsonValue]]:
    """The API tokens of every user, keyed ``userid!tokenid`` (metadata only: no secret exists)."""
    result: list[dict[str, JsonValue]] = []
    for user in object_list(raw):
        userid = user.get("userid")
        listed = user.get("tokens") or []
        if not isinstance(userid, str) or not isinstance(listed, list):
            raise bad("a user of the answer has no usable tokens")
        for token in object_list(listed):
            tokenid = token.get("tokenid")
            if not isinstance(tokenid, str) or not tokenid:
                raise bad("a token of the answer has no id")
            result.append({**token, "id": f"{userid}!{tokenid}", "userid": userid})
    return keyed(result, "id")


def pool_members(pool: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """A pool with its members reduced to their sorted ids (usage figures dropped)."""
    members = pool.get("members")
    if isinstance(members, list):
        ids = [member.get("id") for member in members if isinstance(member, dict)]
        pool["members"] = sorted(str(member_id) for member_id in ids if member_id is not None)
    return pool
