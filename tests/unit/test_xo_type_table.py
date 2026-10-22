"""The shipped Xen Orchestra type tables (P8-T1).

``rules/types/xo.yaml`` is loaded from the package, the way the application loads it. The field
names are unverified (the vendor reference was not read and no lab Xen Orchestra was used), so the
test pins what the plan decides: which fields are kept and which are ignored for each collection,
the collection modes, the secret and hidden fields, the floors and the collections that are never
requested. It does not claim that a vendor field name is right.
"""

from typing import Any

import pytest
from pydantic import ValidationError

from driftsniff.core.normalize import CollectionMode, FieldClass
from driftsniff.rules.loader import RuleIndex, load_rules
from driftsniff.rules.schema import ResourceTable, TypeSpec

CONFIG = FieldClass.CONFIG
IGNORE = FieldClass.IGNORE

VM_FIELDS = (
    "name_label name_description tags notes CPUs.max CPUs.number coresPerSocket cpuCap cpuMask "
    "cpuWeight memory.static memory.dynamic auto_poweron high_availability secureBoot "
    "virtualizationMode boot.firmware boot.order blockedOperations affinityHost startDelay "
    "nicType vga videoram viridian PV_args resourceSet suspendSr"
).split()

# The kept (config class) fields the plan lists for each collection.
KEPT: dict[str, list[str]] = {
    "vms": VM_FIELDS,
    "vm-templates": VM_FIELDS,
    "hosts": (
        "name_label name_description hostname enabled version build productBrand multipathing "
        "powerOnMode supplementalPacks certificates.notAfter license_expiry logging otherConfig"
    ).split(),
    "pools": (
        "name_label name_description HA_enabled haSrs default_SR crashDumpSr suspendSr "
        "migrationCompression platform_version otherConfig"
    ).split(),
    "networks": (
        "name_label name_description MTU bridge automatic defaultIsLocked isBonded nbd "
        "insecureNbd other_config"
    ).split(),
    "pifs": "device vlan mode ip netmask gateway dns".split(),
    "srs": (
        "name_label name_description SR_type content_type shared allocationStrategy "
        "inMaintenanceMode is_tools_sr"
    ).split(),
    "vifs": (
        "MAC MTU device lockingMode allowedIpv4Addresses allowedIpv6Addresses rateLimit "
        "txChecksumming"
    ).split(),
    "vbds": "bootable device is_cd_drive position read_only".split(),
    "vdis": "name_label VDI_type size cbt_enabled image_format".split(),
    "backup-jobs": "name type mode compression proxy remotes srs vms".split(),
    "schedules": "jobId cron enabled name timezone".split(),
    "backup-repositories": "name enabled url options".split(),
    "proxies": "name address version".split(),
    "servers": "label host username httpProxy allowUnauthorized readOnly enabled".split(),
    "users": "username email permission groups".split(),
    "groups": "name provider users aclRoleIds".split(),
}

# The ignore class fields (volatile, duplicates, back references, guest reported) of the plan, for
# the collections where the plan names them.
IGNORED: dict[str, list[str]] = {
    "vms": (
        "uuid type _xapiRef $pool $poolId $container power_state startTime agentStartTime "
        "installTime memory.usage memory.size current_operations addresses mainIpAddress "
        "os_version xenTools vulnerabilities docker snapshots VDIs parent"
    ).split(),
    "vm-templates": (
        "uuid type _xapiRef $pool $poolId memory.usage memory.size current_operations snapshots "
        "VDIs parent"
    ).split(),
    "hosts": (
        "uuid type _xapiRef $pool $poolId power_state startTime agentStartTime "
        "current_operations residentVms rebootRequired memory.usage"
    ).split(),
    "pools": "uuid type _xapiRef current_operations".split(),
    "networks": "uuid type _xapiRef $pool $poolId current_operations".split(),
    "pifs": "attached currently_attached uuid type _xapiRef $pool $poolId".split(),
    "pbds": "attached currently_attached uuid type _xapiRef $pool $poolId".split(),
    "srs": "size usage physical_usage current_operations VDIs uuid type _xapiRef".split(),
    "vifs": "attached currently_attached uuid type _xapiRef $pool $poolId".split(),
    "vbds": "attached currently_attached uuid type _xapiRef parent".split(),
    "vdis": "usage physical_usage current_operations snapshots parent uuid type _xapiRef".split(),
    "servers": "status error".split(),
    "users": ["last_uses"],
}

# The collections that the collector never requests (plan, P8-T1). None may have a type table.
EXCLUDED = (
    "tasks alarms messages backup-logs restore-logs backup-archives events vm-snapshots "
    "vdi-snapshots licenses sms pcis pgpus vm-controller xoa"
).split()

# The plan marks the security sensitive objects with the object floor high.
FLOORED = ("servers", "backup-repositories", "users", "groups", "acl-roles", "acl-privileges")

SETS = {
    "vms": ["tags"],
    "vm-templates": ["tags"],
    "hosts": ["supplementalPacks", "certificates"],
    "pools": ["haSrs"],
    "vifs": ["allowedIpv4Addresses", "allowedIpv6Addresses"],
    "backup-jobs": ["remotes", "srs", "vms"],
    "backup-job-settings": ["reportRecipients"],
    "users": ["groups"],
    "groups": ["users", "aclRoleIds"],
}


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


def table(index: RuleIndex, resource: str) -> ResourceTable:
    return index.type_tables[resource]


def xo_resources(index: RuleIndex) -> list[str]:
    return sorted(name for name in index.type_tables if not name.startswith("unifi-"))


def test_the_xo_resources_are_the_collections_of_the_plan(index: RuleIndex) -> None:
    assert xo_resources(index) == sorted(
        [
            "vms",
            "vm-templates",
            "hosts",
            "pools",
            "networks",
            "pifs",
            "pbds",
            "srs",
            "vifs",
            "vbds",
            "vdis",
            "backup-jobs",
            "backup-job-settings",
            "schedules",
            "backup-repositories",
            "proxies",
            "servers",
            "users",
            "groups",
            "acl-roles",
            "acl-privileges",
        ]
    )


@pytest.mark.parametrize("resource", EXCLUDED)
def test_an_excluded_collection_has_no_type_table(index: RuleIndex, resource: str) -> None:
    assert resource not in index.type_tables


@pytest.mark.parametrize("resource", sorted(KEPT))
def test_every_kept_field_of_the_plan_is_config_class(index: RuleIndex, resource: str) -> None:
    found = table(index, resource)
    for path in KEPT[resource]:
        assert found.field_class(path) is CONFIG, f"{resource}.{path}"


@pytest.mark.parametrize("resource", sorted(IGNORED))
def test_every_volatile_or_duplicate_field_of_the_plan_is_ignored(
    index: RuleIndex, resource: str
) -> None:
    found = table(index, resource)
    for path in IGNORED[resource]:
        assert found.field_class(path) is IGNORE, f"{resource}.{path}"


def test_size_and_usage_are_ignored_but_the_memory_limits_are_kept(index: RuleIndex) -> None:
    for resource in ("vms", "vm-templates"):
        found = table(index, resource)
        assert found.field_class("memory.static") is CONFIG
        assert found.field_class("memory.dynamic") is CONFIG
        assert found.field_class("memory.size") is IGNORE
        assert found.field_class("memory.usage") is IGNORE


def test_every_resource_has_a_key_and_the_key_has_a_class(index: RuleIndex) -> None:
    for resource in xo_resources(index):
        found = table(index, resource)
        assert found.object_key_field == "id", resource
        assert found.field_class("id") is CONFIG, resource


@pytest.mark.parametrize("resource", sorted(SETS))
def test_the_member_lists_are_compared_as_sets(index: RuleIndex, resource: str) -> None:
    for path in SETS[resource]:
        assert table(index, resource).collection_mode(path) is CollectionMode.SET, path


@pytest.mark.parametrize("resource", ["vms", "vm-templates"])
def test_the_boot_order_keeps_its_order(index: RuleIndex, resource: str) -> None:
    assert table(index, resource).collection_mode("boot.order") is CollectionMode.ORDERED_SCALAR


def test_the_xo_collections_are_plain_sets_of_objects(index: RuleIndex) -> None:
    for resource in xo_resources(index):
        assert table(index, resource).collection is CollectionMode.SET, resource


def test_the_credentials_are_secret_or_unclassified_never_config(index: RuleIndex) -> None:
    assert table(index, "pbds").field_class("device_config") is FieldClass.SECRET
    assert table(index, "users").field_class("authProviders") is FieldClass.SECRET
    for path in ("password", "token"):
        assert table(index, "servers").field_class(path) is FieldClass.UNCLASSIFIED
    assert table(index, "backup-repositories").field_class("url.credentials") is (
        FieldClass.UNCLASSIFIED
    )


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("servers", "password"),
        ("servers", "token"),
        ("backup-repositories", "url.credentials"),
    ],
)
def test_what_xo_hides_is_marked_hidden_by_xo(index: RuleIndex, resource: str, path: str) -> None:
    assert table(index, resource).is_hidden_by_xo(path) is True


def test_only_the_values_xo_hides_are_marked(index: RuleIndex) -> None:
    marked = {
        resource: sorted(found.hidden_by_xo)
        for resource, found in index.type_tables.items()
        if found.hidden_by_xo
    }
    assert marked == {
        "servers": ["password", "token"],
        "backup-repositories": ["url.credentials"],
    }
    assert table(index, "servers").is_hidden_by_xo("label") is False


@pytest.mark.parametrize("resource", FLOORED)
def test_security_sensitive_xo_objects_have_the_floor_high(index: RuleIndex, resource: str) -> None:
    found = table(index, resource)
    for kind in ("added", "removed", "modified", "moved"):
        assert found.floor_for(kind) == "high", f"{resource} {kind}"


def spec_data(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"resource": "servers", "fields": {"label": "config"}}
    data.update(changes)
    return data


def test_the_hidden_by_xo_marker_changes_no_field_class() -> None:
    marked = TypeSpec.model_validate(
        spec_data(hidden_by_xo=["password", "url.credentials"])
    ).to_table()
    assert marked.is_hidden_by_xo("password") is True
    assert marked.is_hidden_by_xo("label") is False
    assert marked.field_class("password") is FieldClass.UNCLASSIFIED
    assert TypeSpec.model_validate(spec_data()).to_table().hidden_by_xo == frozenset()


@pytest.mark.parametrize("hidden", [[""], ["a..b"], ["a.*"], ["password", "password"], "password"])
def test_a_bad_hidden_by_xo_list_is_refused(hidden: object) -> None:
    with pytest.raises(ValidationError):
        TypeSpec.model_validate(spec_data(hidden_by_xo=hidden))


def test_an_unlisted_field_is_unclassified(index: RuleIndex) -> None:
    assert table(index, "vms").field_class("someFieldTheTableDoesNotKnow") is (
        FieldClass.UNCLASSIFIED
    )
