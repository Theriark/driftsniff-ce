"""The TrueNAS resources the collector reads and the API method behind each one.

TrueNAS 25.04 and later expose a versioned JSON-RPC 2.0 API over one WebSocket; the REST API
(``/api/v2.0``) was deprecated in 25.04 and is removed in the next major release
(docs/vendor-notes/truenas.md). Each resource is one read-only method call. The method names come
from the published API reference for 25.10 (api.truenas.com, read 2026-11-12); no lab TrueNAS was
used, so they are checked against the documentation only.

``pool.dataset.query`` takes query options that keep the answer flat and leave out user
properties; those option names are from the same reference.

A resource that is not listed keeps its previous state in the run pipeline, so leaving one out can
never report an object as removed.
"""

from dataclasses import dataclass, field
from typing import Final

from driftsniff.core.canonical import JsonValue

API_PATH: Final = "/api/current"
LOGIN_METHOD: Final = "auth.login_ex"
LOGIN_MECHANISM: Final = "API_KEY_PLAIN"
VERSION_METHOD: Final = "system.version"


@dataclass(frozen=True, slots=True)
class TruenasResource:
    """One resource: its name in the type tables, the method that reads it and its parameters.

    ``single`` marks a ``*.config`` method that answers one object instead of a list.
    """

    name: str
    method: str
    params: list[JsonValue] = field(default_factory=list)
    single: bool = False


_DATASET_OPTIONS: Final[list[JsonValue]] = [
    [],
    # retrieve_children must stay on: TrueNAS 25.04.2.6 answered only the pool root datasets with
    # it off (lab DELTA, 2026-11-13). flat keeps every dataset a top-level object of its own.
    {"extra": {"flat": True, "retrieve_user_props": False}},
]

RESOURCES: Final = (
    TruenasResource("truenas-pools", "pool.query"),
    TruenasResource("truenas-datasets", "pool.dataset.query", _DATASET_OPTIONS),
    TruenasResource("truenas-smb-shares", "sharing.smb.query"),
    TruenasResource("truenas-nfs-shares", "sharing.nfs.query"),
    TruenasResource("truenas-iscsi-targets", "iscsi.target.query"),
    TruenasResource("truenas-iscsi-extents", "iscsi.extent.query"),
    TruenasResource("truenas-users", "user.query"),
    TruenasResource("truenas-groups", "group.query"),
    TruenasResource("truenas-ssh", "ssh.config", single=True),
    TruenasResource("truenas-services", "service.query"),
    TruenasResource("truenas-interfaces", "interface.query"),
    TruenasResource("truenas-network-config", "network.configuration.config", single=True),
    TruenasResource("truenas-snapshot-tasks", "pool.snapshottask.query"),
    TruenasResource("truenas-replication-tasks", "replication.query"),
    TruenasResource("truenas-cloud-sync-tasks", "cloudsync.query"),
    TruenasResource("truenas-cloud-credentials", "cloudsync.credentials.query"),
    TruenasResource("truenas-cron-jobs", "cronjob.query"),
    TruenasResource("truenas-certificates", "certificate.query"),
)

RESOURCE_BY_NAME: Final = {resource.name: resource for resource in RESOURCES}
