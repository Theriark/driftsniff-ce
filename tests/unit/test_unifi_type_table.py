"""The shipped UniFi type tables (P7-T1).

``rules/types/unifi.yaml`` is loaded from the package, the way the application loads it. The test
pins what the plan decides: the collection mode of each resource and list, the secret fields and
the floors. That every path of UniFi Network 10.6.109 is classified is checked in
``tests/contract/test_unifi_real_shapes.py``.
"""

import pytest

from driftsniff.core.normalize import CollectionMode, FieldClass
from driftsniff.rules.loader import RuleIndex, load_rules
from driftsniff.rules.schema import ResourceTable

CONFIG = FieldClass.CONFIG
SECRET = FieldClass.SECRET
UNIFI_RESOURCES = (
    "unifi-sites",
    "unifi-site-settings",
    "unifi-networks",
    "unifi-wifi-broadcasts",
    "unifi-firewall-zones",
    "unifi-firewall-policies",
    "unifi-acl-rules",
    "unifi-dns-policies",
    "unifi-traffic-matching-lists",
    "unifi-wans",
    "unifi-vpn-site-to-site-tunnels",
    "unifi-vpn-servers",
    "unifi-radius-profiles",
    "unifi-device-tags",
    "unifi-devices",
)
ORDERED = ("unifi-firewall-policies", "unifi-acl-rules")
FLOORED = (
    "unifi-firewall-zones",
    "unifi-acl-rules",
    "unifi-vpn-site-to-site-tunnels",
    "unifi-vpn-servers",
    "unifi-radius-profiles",
)


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


def table(index: RuleIndex, resource: str) -> ResourceTable:
    return index.type_tables[resource]


def test_every_unifi_resource_is_defined_with_the_prefix(index: RuleIndex) -> None:
    unifi = sorted(name for name in index.type_tables if name.startswith("unifi-"))
    assert unifi == sorted(UNIFI_RESOURCES)


def test_the_unifi_tables_do_not_collide_with_the_xen_orchestra_names(index: RuleIndex) -> None:
    assert "networks" in index.type_tables
    assert "users" in index.type_tables
    assert "unifi-networks" in index.type_tables


@pytest.mark.parametrize("resource", ORDERED)
def test_policies_and_acl_rules_are_ordered_keyed_first_match(
    index: RuleIndex, resource: str
) -> None:
    found = table(index, resource)
    assert found.collection is CollectionMode.ORDERED_KEYED
    assert found.first_match is True
    assert found.object_key_field == "id"
    assert found.action_field is not None
    assert found.field_class(found.action_field) is CONFIG
    assert found.is_blocking("BLOCK")
    assert not found.is_blocking("ALLOW")


def test_firewall_policy_actions_are_read_from_a_flat_field(index: RuleIndex) -> None:
    found = table(index, "unifi-firewall-policies")
    assert found.action_field == "actionType"
    assert found.field_class("action.type") is FieldClass.IGNORE
    assert found.is_blocking("REJECT")


@pytest.mark.parametrize("resource", [name for name in UNIFI_RESOURCES if name not in ORDERED])
def test_other_resources_are_plain_sets(index: RuleIndex, resource: str) -> None:
    assert table(index, resource).collection is CollectionMode.SET


def test_every_declared_list_is_a_set(index: RuleIndex) -> None:
    # No list of the 10.6.109 API carries meaning by position; only whole collections are ordered.
    sets = [
        ("unifi-wifi-broadcasts", "broadcastingFrequenciesGHz"),
        ("unifi-firewall-zones", "networkIds"),
        ("unifi-firewall-policies", "connectionStateFilter"),
        ("unifi-firewall-policies", "source.trafficFilter.portFilter.items"),
        ("unifi-firewall-policies", "destination.trafficFilter.ipAddressFilter.items"),
        ("unifi-traffic-matching-lists", "items"),
        ("unifi-device-tags", "deviceIds"),
        ("unifi-devices", "features"),
    ]
    for resource, path in sets:
        assert table(index, resource).collection_mode(path) is CollectionMode.SET
    for resource in UNIFI_RESOURCES:
        modes = set(table(index, resource).collection_modes.values())
        assert modes <= {CollectionMode.SET}, resource


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("unifi-wifi-broadcasts", "securityConfiguration.passphrase"),
        ("unifi-radius-profiles", "sharedSecret"),
        ("unifi-vpn-site-to-site-tunnels", "preSharedKey"),
        ("unifi-vpn-servers", "preSharedKey"),
    ],
)
def test_credentials_are_secret_class(index: RuleIndex, resource: str, path: str) -> None:
    assert table(index, resource).field_class(path) is SECRET


def test_the_volatile_fields_of_devices_are_ignored(index: RuleIndex) -> None:
    devices = table(index, "unifi-devices")
    for path in ("state", "firmwareUpdatable"):
        assert devices.field_class(path) is FieldClass.IGNORE
    for path in ("name", "model", "firmwareVersion", "macAddress"):
        assert devices.field_class(path) is CONFIG


def test_an_unlisted_field_is_unclassified(index: RuleIndex) -> None:
    assert (
        table(index, "unifi-wifi-broadcasts").field_class("someFieldTheTableDoesNotKnow")
        is FieldClass.UNCLASSIFIED
    )


@pytest.mark.parametrize("resource", FLOORED)
def test_security_sensitive_objects_have_the_floor_high(index: RuleIndex, resource: str) -> None:
    found = table(index, resource)
    for kind in ("added", "modified", "moved"):
        assert found.floor_for(kind) == "high"


@pytest.mark.parametrize("resource", ["unifi-firewall-policies", "unifi-wifi-broadcasts"])
def test_policies_and_wifi_have_no_modified_floor_but_keep_the_others(
    index: RuleIndex, resource: str
) -> None:
    # Their packs rate a rename low or medium and every security field high by its own rule.
    found = table(index, resource)
    assert found.floor_for("modified") is None
    assert found.floor_for("added") == "high"
    assert found.floor_for("removed") in ("high", "critical")


def test_origin_and_configurable_are_config(index: RuleIndex) -> None:
    assert table(index, "unifi-firewall-policies").field_class("metadata.origin") is CONFIG
    assert table(index, "unifi-firewall-zones").field_class("metadata.configurable") is CONFIG


@pytest.mark.parametrize(
    "resource", ["unifi-firewall-zones", "unifi-firewall-policies", "unifi-acl-rules"]
)
def test_removing_a_zone_policy_or_acl_rule_is_critical(index: RuleIndex, resource: str) -> None:
    assert table(index, resource).floor_for("removed") == "critical"
