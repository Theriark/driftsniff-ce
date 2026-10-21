"""The shipped UniFi type tables (P7-T1).

``rules/types/unifi.yaml`` is loaded from the package, the way the application loads it. The field
names are unverified (dependency D5 is open), so the test pins what the plan decides, which is the
collection mode of each resource and list, the secret fields and the floors, and not the vendor
names themselves.
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
    "unifi-wifi-broadcasts",
    "unifi-firewall-zones",
    "unifi-firewall-policies",
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


def test_the_dns_server_lists_keep_their_order(index: RuleIndex) -> None:
    assert table(index, "unifi-networks").collection_mode("dhcpConfig.dnsServers") is (
        CollectionMode.ORDERED_SCALAR
    )
    assert table(index, "unifi-wans").collection_mode("dnsServers") is (
        CollectionMode.ORDERED_SCALAR
    )


def test_the_other_lists_are_sets(index: RuleIndex) -> None:
    sets = {
        "unifi-networks": "dhcpGuarding.trustedDhcpServerIpAddresses",
        "unifi-wifi-broadcasts": "broadcastingFrequenciesGHz",
        "unifi-firewall-zones": "networkIds",
        "unifi-firewall-policies": "connectionStateFilter",
        "unifi-traffic-matching-lists": "items",
        "unifi-device-tags": "deviceIds",
    }
    for resource, path in sets.items():
        assert table(index, resource).collection_mode(path) is CollectionMode.SET


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


def test_statistics_and_counters_of_devices_are_ignored(index: RuleIndex) -> None:
    devices = table(index, "unifi-devices")
    for path in ("uptimeSec", "lastHeartbeatAt", "statistics"):
        assert devices.field_class(path) is FieldClass.IGNORE
    for path in ("name", "model", "firmwareVersion", "state"):
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


@pytest.mark.parametrize(
    "resource", ["unifi-firewall-zones", "unifi-firewall-policies", "unifi-acl-rules"]
)
def test_removing_a_zone_policy_or_acl_rule_is_critical(index: RuleIndex, resource: str) -> None:
    assert table(index, resource).floor_for("removed") == "critical"
