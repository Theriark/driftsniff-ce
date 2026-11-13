"""The UniFi collector on objects in the shapes of a real UniFi Network 10.6.109 controller.

The reference band (``tests/fixtures/unifi/band-reference.json``) holds every resource in the field
paths and enum values that controller returned on 2026-11-13 (docs/vendor-notes/unifi.md),
including firewall policies made by the controller itself (``SYSTEM_DEFINED`` and ``DERIVED``),
which its ordering lists never name. The tests check that no field of those shapes is
unclassified, that such policies no longer make every run partial, and what a two-read drift on
real-shaped data is reported as.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.base import ResourceSpec
from driftsniff.collectors.unifi.client import UnifiClient
from driftsniff.collectors.unifi.normalize import ERROR_ORDERING_MISMATCH, prepare_object
from driftsniff.collectors.unifi.resources import RESOURCE_FIREWALL_POLICIES, RESOURCES
from driftsniff.core.normalize import FieldClass
from driftsniff.db.engine import Database
from driftsniff.rules.loader import load_rules

from .fake_unifi import CANARY_HEADER, Scenario, fake_unifi
from .unifi_bands import (
    Seeds,
    band_scenario,
    change_item_rows,
    collect,
    make_pipeline,
    open_database,
)

POLICIES = ResourceSpec(RESOURCE_FIREWALL_POLICIES)
# Pairs sorted; inside a pair: before list, controller-made policies by id, after list.
REAL_ORDER = ["pol-1", "pol-6", "pol-4", "pol-7", "pol-2", "pol-5", "pol-3"]


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    store = open_database(tmp_path)
    try:
        yield store
    finally:
        store.close()


def reference() -> Scenario:
    return band_scenario("reference", Seeds())


def leaf_paths(value: Any, path: str = "") -> Iterator[str]:
    """Every path the diff can report: scalar leaves, lists, and the fields of list members."""
    if isinstance(value, dict):
        for key, member in value.items():
            yield from leaf_paths(member, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        yield path
        for member in value:
            if isinstance(member, dict):
                yield from leaf_paths(member, path)
    else:
        yield path


def find(objects: list[dict[str, Any]], key: str) -> dict[str, Any]:
    return next(item for item in objects if item["id"] == key)


# -- the type tables ---------------------------------------------------------------------------


def test_no_field_of_the_real_shapes_is_unclassified() -> None:
    tables = load_rules().type_tables
    scenario = reference()
    unclassified: set[str] = set()
    walked = 0
    for resource in RESOURCES:
        if resource.site_path is None:
            objects = [{"id": "site-a", "name": "Site site-a", "internalReference": "default"}]
        else:
            objects = scenario.objects[resource.site_path.lstrip("/")]
        table = tables[resource.name]
        for item in objects:
            for path in leaf_paths(prepare_object(resource.name, item)):
                walked += 1
                if table.field_class(path) is FieldClass.UNCLASSIFIED:
                    unclassified.add(f"{resource.name}: {path}")
    assert walked > 300
    assert sorted(unclassified) == []


# -- the ordering of controller-made policies --------------------------------------------------


def test_controller_made_policies_are_placed_between_the_lists_and_the_read_is_clean() -> None:
    scenario = reference()
    with fake_unifi(scenario) as server:
        client = UnifiClient(server.url, CANARY_HEADER, allow_plain_http=True)
        try:
            client.probe()
            first = client.fetch(POLICIES)
            scenario.objects["firewall/policies"].reverse()
            second = client.fetch(POLICIES)
        finally:
            client.close()
    assert (first.ok, first.warning_class, first.warning_text) == (True, None, None)
    assert [item["id"] for item in first.objects] == REAL_ORDER
    assert [item["id"] for item in second.objects] == REAL_ORDER


def test_a_real_shaped_run_is_ok_not_partial(database: Database) -> None:
    with fake_unifi(reference()) as server:
        report = collect(make_pipeline(database), server)
    assert (report.status, report.error_class, report.error_summary) == ("ok", None, None)


def test_a_user_defined_policy_missing_from_its_list_still_makes_the_run_partial(
    database: Database,
) -> None:
    scenario = reference()
    scenario.firewall_order[("site-a", "zone-3", "zone-1")] = (["pol-2"], [])
    with fake_unifi(scenario) as server:
        report = collect(make_pipeline(database), server)
    assert (report.status, report.error_class) == ("partial", ERROR_ORDERING_MISMATCH)
    assert report.error_summary is not None
    assert "1 appended" in report.error_summary


# -- a two-read drift --------------------------------------------------------------------------


DRIFT = [
    ("unifi-devices", "modified", "firmwareVersion", "low", "unifi.devices.firmware_version"),
    ("unifi-dns-policies", "modified", "ipv4Address", "medium", "unifi.dns_policies.ipv4_address"),
    ("unifi-dns-policies", "removed", "", "medium", "unifi.dns_policies.any"),
    (
        "unifi-firewall-policies",
        "added",
        "destination.trafficFilter.portFilter.items",
        "high",
        "unifi.firewall_policies.destination_filter",
    ),
    (
        "unifi-firewall-policies",
        "modified",
        "actionType",
        "critical",
        "unifi.firewall_policies.action_to_allow",
    ),
    (
        "unifi-firewall-policies",
        "modified",
        "description",
        "low",
        "unifi.firewall_policies.description",
    ),
    ("unifi-firewall-policies", "modified", "enabled", "high", "unifi.firewall_policies.disabled"),
    (
        "unifi-firewall-policies",
        "modified",
        "loggingEnabled",
        "medium",
        "unifi.firewall_policies.logging_off",
    ),
    ("unifi-firewall-policies", "modified", "name", "low", "unifi.firewall_policies.name"),
    (
        "unifi-firewall-policies",
        "modified",
        "source.trafficFilter.ipAddressFilter.matchOpposite",
        "high",
        "unifi.firewall_policies.source_filter",
    ),
    # A list member that is removed takes the floor of a removed policy (the engine reads the kind
    # of the item, not whether it is a whole object): critical, not the rule's high.
    (
        "unifi-firewall-policies",
        "removed",
        "destination.trafficFilter.portFilter.items",
        "critical",
        "builtin.floor.removed",
    ),
    ("unifi-firewall-zones", "added", "networkIds", "high", "unifi.firewall_zones.network_ids"),
    ("unifi-networks", "modified", "vlanId", "high", "unifi.networks.vlan_id"),
    (
        "unifi-traffic-matching-lists",
        "added",
        "items",
        "high",
        "unifi.traffic_matching_lists.items",
    ),
    ("unifi-vpn-servers", "modified", "enabled", "high", "unifi.vpn_servers.enabled"),
    ("unifi-wifi-broadcasts", "modified", "enabled", "medium", "unifi.wifi.enabled"),
    (
        "unifi-wifi-broadcasts",
        "modified",
        "securityConfiguration.type",
        "high",
        "unifi.wifi.security_type",
    ),
]


def test_a_two_read_drift_on_real_shaped_data_gives_the_expected_changes(
    database: Database,
) -> None:
    pipeline = make_pipeline(database)
    scenario = reference()
    with fake_unifi(scenario) as server:
        first = collect(pipeline, server)
        assert (first.status, first.event_id) == ("ok", None)
        objects = scenario.objects
        policies = objects["firewall/policies"]
        find(policies, "pol-1")["enabled"] = False
        find(policies, "pol-1")["loggingEnabled"] = False
        find(policies, "pol-1")["destination"]["trafficFilter"]["portFilter"]["items"][0] = {
            "type": "PORT_NUMBER",
            "value": 8443,
        }
        find(policies, "pol-2")["action"]["type"] = "ALLOW"
        source = find(policies, "pol-2")["source"]["trafficFilter"]["ipAddressFilter"]
        source["matchOpposite"] = True
        find(policies, "pol-3")["name"] = "Printer by hardware address"
        find(policies, "pol-5")["description"] = "Reworded by an upgrade"
        find(objects["wifi/broadcasts"], "wifi-1")["securityConfiguration"]["type"] = (
            "WPA2_PERSONAL"
        )
        find(objects["wifi/broadcasts"], "wifi-2")["enabled"] = False
        find(objects["networks"], "net-2")["vlanId"] = 30
        find(objects["firewall/zones"], "zone-3")["networkIds"].append("net-1")
        find(objects["dns/policies"], "dns-1")["ipv4Address"] = "192.0.2.49"
        objects["dns/policies"] = [find(objects["dns/policies"], "dns-1")]
        find(objects["vpn/servers"], "vpn-2")["enabled"] = True
        find(objects["devices"], "dev-2")["firmwareVersion"] = "6.7.40"
        find(objects["devices"], "dev-1")["state"] = "OFFLINE"
        find(objects["devices"], "dev-1")["firmwareUpdatable"] = True
        find(objects["traffic-matching-lists"], "tml-2")["items"].append(
            {"type": "PORT_NUMBER", "value": 515}
        )
        second = collect(pipeline, server)
    assert (second.status, second.error_class) == ("ok", None)
    assert second.event_id is not None
    found = sorted(
        (row.resource, row.change_kind, row.path, row.severity, row.rule_id)
        for row in change_item_rows(database)
    )
    assert found == sorted(DRIFT)
    assert all(row.field_class == "config" for row in change_item_rows(database))
