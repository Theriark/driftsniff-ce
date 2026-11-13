"""The TrueNAS type tables against the field paths a real TrueNAS 25.04.2.6 returned.

The paths below are what the lab system DELTA answered on 2026-11-13 to a user with the Read-Only
Administrator privilege, after the collector's own preparation (list members share their list's
path). Every one of them must be classified; an unclassified field shows as a fingerprint only.
"""

import pytest

from driftsniff.collectors.truenas.resources import RESOURCE_BY_NAME
from driftsniff.core.normalize import FieldClass
from driftsniff.rules.loader import load_rules

REAL_PATHS_2504 = {
    "truenas-certificates": "CA_type_existing CA_type_intermediate CA_type_internal DN "
    "add_to_trusted_store can_be_revoked cert_type cert_type_CSR cert_type_existing "
    "cert_type_internal certificate chain chain_list city common country digest_algorithm email "
    "extensions.ExtendedKeyUsage extensions.SubjectAltName fingerprint from id internal issuer "
    "key_length key_type lifetime name organization revoked san serial state subject_name_hash "
    "type until",
    "truenas-datasets": "aclmode acltype atime casesensitivity checksum compression copies "
    "deduplication encrypted exec id mountpoint name origin pbkdf2iters pool readonly recordsize "
    "refreservation reservation snapdev snapdir special_small_block_size sync type xattr",
    "truenas-groups": "builtin gid group id id_type_both local name roles sid smb sudo_commands "
    "sudo_commands_nopasswd userns_idmap users",
    "truenas-interfaces": "aliases description fake id ipv4_dhcp ipv6_auto mtu name type",
    "truenas-network-config": "activity.activities activity.type domain domains hostname "
    "hostname_local hosts httpproxy id ipv4gateway ipv6gateway nameserver1 nameserver2 "
    "nameserver3 service_announcement.mdns service_announcement.netbios service_announcement.wsd",
    "truenas-pools": "autotrim dedup_table_quota guid id name path",
    "truenas-services": "enable id service",
    "truenas-smb-shares": "aapl_name_mangling abe acl afp audit.enable audit.ignore_list "
    "audit.watch_list auxsmbconf browsable comment durablehandle enabled fsrvp guestok home "
    "hostsallow hostsdeny id name path path_local path_suffix purpose recyclebin ro shadowcopy "
    "streams timemachine timemachine_quota vuid",
    "truenas-snapshot-tasks": "allow_empty dataset enabled exclude id lifetime_unit lifetime_value "
    "naming_schema recursive schedule.begin schedule.dom schedule.dow schedule.end schedule.hour "
    "schedule.minute schedule.month vmware_sync",
    "truenas-ssh": "bindiface compression host_ecdsa_key_pub host_ed25519_key_pub "
    "host_rsa_key_pub id kerberosauth options password_login_groups passwordauth "
    "sftp_log_facility sftp_log_level tcpfwd tcpport weak_ciphers",
    "truenas-users": "api_keys builtin email full_admin full_name group.bsdgrp_builtin "
    "group.bsdgrp_gid group.bsdgrp_group group.bsdgrp_smb group.bsdgrp_sudo_commands "
    "group.bsdgrp_sudo_commands_nopasswd group.bsdgrp_userns_idmap group.id groups home id "
    "id_type_both immutable local locked password_change_required password_disabled "
    "password_history roles shell sid smb smbhash ssh_password_enabled sudo_commands "
    "sudo_commands_nopasswd twofactor_auth_configured uid unixhash username userns_idmap",
}


@pytest.mark.parametrize("resource", sorted(REAL_PATHS_2504))
def test_every_field_of_a_real_2504_system_is_classified(resource: str) -> None:
    table = load_rules().type_tables[resource]
    unclassified = [
        path
        for path in REAL_PATHS_2504[resource].split()
        if table.field_class(path) is FieldClass.UNCLASSIFIED
    ]
    assert unclassified == []


def test_guest_access_on_a_2504_share_is_critical() -> None:
    candidates = load_rules().candidates("truenas-smb-shares", "guestok")
    assert [(c.rule.id, str(c.rule.severity)) for c in candidates] == [
        ("truenas.smb.guest_access_2504", "critical")
    ]


def test_the_dataset_query_reads_child_datasets() -> None:
    # With retrieve_children off, TrueNAS 25.04.2.6 answered the pool root datasets only.
    params = RESOURCE_BY_NAME["truenas-datasets"].params
    assert params[1] == {"extra": {"flat": True, "retrieve_user_props": False}}
