"""What the TrueNAS collector does to the objects before the pipeline sees them.

* A ``*.config`` method answers one object; it becomes a list of one.
* Private key material is removed before anything else sees it: the private key of a certificate
  and the SSH host private keys. The type table classes them ``ignore`` as well; dropping them here
  means they never reach the pipeline, not even as a fingerprint.
* ZFS properties of pools and datasets arrive as ``{"value", "rawvalue", "parsed", "source", ...}``
  objects. Only ``value`` (the text TrueNAS shows, such as ``LZ4`` or ``ON``) is kept, so a change
  reads ``LZ4 -> OFF`` and the type table names the property itself.
* Two derived fields, written in the type table and named in the rule packs:
  ``open_to_all`` on an NFS share is true when it names no network and no host (TrueNAS then exports
  it to everyone), and ``full_admin`` on a user is true when its ``roles`` hold ``FULL_ADMIN``
  (membership of ``builtin_administrators`` gives that role). Rules cannot test the name of a group,
  so this is how joining the administrators is seen on the user.
* The snapshot tasks embedded in a replication task are reduced to their ids: the tasks themselves
  are a resource of their own, and their run state would otherwise move the replication task.
* Objects are sorted by id; the order of the answer is never trusted.

Everything else is raw: redaction, normalisation and keying belong to the pipeline.
"""

from collections.abc import Mapping
from typing import Any, Final

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.core.canonical import JsonValue

RESOURCE_DATASETS: Final = "truenas-datasets"
RESOURCE_POOLS: Final = "truenas-pools"
RESOURCE_NFS: Final = "truenas-nfs-shares"
RESOURCE_USERS: Final = "truenas-users"
RESOURCE_REPLICATION: Final = "truenas-replication-tasks"

FULL_ADMIN_ROLE: Final = "FULL_ADMIN"

DROPPED_FIELDS: Final[Mapping[str, tuple[str, ...]]] = {
    "truenas-certificates": ("privatekey",),
    "truenas-ssh": (
        "privatekey",
        "host_key",
        "host_dsa_key",
        "host_ecdsa_key",
        "host_ed25519_key",
        "host_rsa_key",
    ),
}
_PROPERTY_RESOURCES: Final = frozenset({RESOURCE_DATASETS, RESOURCE_POOLS})


def _is_property(value: object) -> bool:
    return isinstance(value, Mapping) and "value" in value and "rawvalue" in value


def _usable_id(value: object) -> bool:
    if isinstance(value, bool):
        return False
    return (isinstance(value, str) and value != "") or isinstance(value, int)


def prepare_object(name: str, item: dict[str, Any]) -> dict[str, Any]:
    """One raw object of ``name`` with the steps above applied (a copy; ``item`` is not changed)."""
    prepared = dict(item)
    for key in DROPPED_FIELDS.get(name, ()):
        prepared.pop(key, None)
    if name in _PROPERTY_RESOURCES:
        for key, value in item.items():
            if _is_property(value):
                prepared[key] = value["value"]
    if name == RESOURCE_NFS:
        prepared["open_to_all"] = not prepared.get("networks") and not prepared.get("hosts")
    elif name == RESOURCE_USERS:
        roles = prepared.get("roles")
        prepared["full_admin"] = isinstance(roles, list) and FULL_ADMIN_ROLE in roles
    elif name == RESOURCE_REPLICATION:
        tasks = prepared.get("periodic_snapshot_tasks")
        if isinstance(tasks, list):
            prepared["periodic_snapshot_tasks"] = [
                task.get("id") if isinstance(task, Mapping) else task for task in tasks
            ]
    return prepared


def prepare_objects(name: str, result: JsonValue, *, single: bool) -> list[dict[str, JsonValue]]:
    """The result of one method call as checked, cleaned objects sorted by id.

    Raises :class:`CollectorError` (``bad_payload``) for an answer of the wrong shape or an object
    without a usable id: that resource fails, the others are not affected.
    """
    items = [result] if single else result
    if not isinstance(items, list):
        raise CollectorError(ERROR_BAD_PAYLOAD, "the answer is not a list of objects")
    objects: list[dict[str, JsonValue]] = []
    for item in items:
        if not isinstance(item, dict) or not _usable_id(item.get("id")):
            raise CollectorError(ERROR_BAD_PAYLOAD, "an object of the answer has no usable id")
        objects.append(prepare_object(name, item))
    objects.sort(key=lambda entry: str(entry["id"]))
    return objects
