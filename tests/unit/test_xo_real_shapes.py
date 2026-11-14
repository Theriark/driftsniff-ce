"""The XO type table against field paths two real Xen Orchestra 5 servers returned (2026-11-13).

Every path below was unclassified before. Backup job settings are keyed by schedule id, so one
real id stands for all of them; host boot and agent timestamps are run state.
"""

import pytest

from driftsniff.core.normalize import FieldClass
from driftsniff.rules.loader import load_rules

SCHEDULE = "00000000-0000-4000-8000-000000000001"

REAL_PATHS = [
    *(
        (resource, "href", "ignore")
        for resource in (
            "acl-privileges acl-roles groups networks pbds pifs schedules servers srs users "
            "vbds vdis vifs vms"
        ).split()
    ),
    ("backup-jobs", f"settings.{SCHEDULE}.exportRetention", "config"),
    ("backup-jobs", f"settings.{SCHEDULE}.retentionPoolMetadata", "config"),
    ("backup-jobs", "settings..checkpointSnapshot", "config"),
    ("backup-jobs", "settings..nRetriesVmBackupFailures", "config"),
    ("backup-jobs", "vms.tags.__and.__or", "config"),
    ("backup-jobs", "vms.type", "config"),
    ("backup-jobs", "remotes.id", "config"),
    ("hosts", "certificates.fingerprint", "config"),
    ("hosts", "otherConfig.iscsi_iqn", "config"),
    ("hosts", "otherConfig.boot_time", "ignore"),
    ("hosts", "otherConfig.agent_start_time", "ignore"),
    ("hosts", "otherConfig.last_blob_sync_time", "ignore"),
    ("hosts", "otherConfig.rpm_patch_installation_time", "ignore"),
    ("networks", "other_config.ip_begin", "config"),
    ("networks", "other_config.is_host_internal_management_network", "config"),
    ("pools", "otherConfig.xo:migrationNetwork", "config"),
    ("pools", "otherConfig.auto_poweron", "config"),
    ("vms", "blockedOperations.destroy", "config"),
    ("vm-templates", "blockedOperations.destroy", "config"),
]


@pytest.mark.parametrize(("resource", "path", "expected"), REAL_PATHS)
def test_a_path_a_real_xo_server_returned_is_classified(
    resource: str, path: str, expected: str
) -> None:
    table = load_rules().type_tables[resource]
    assert table.field_class(path) is FieldClass(expected)
