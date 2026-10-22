"""The UniFi rows of the golden table against the shipped pack and type tables (P7-T4).

``test_golden_table.py`` runs all 23 rows against test-only tables. Here the rows whose resource is
a UniFi resource run again, against ``rules/types/unifi.yaml`` and ``rules/packs/unifi`` as the
application loads them: rows 3, 5, 16, 17, 21 and 22. Rows 7 and 9 name fields of the site settings
that the shipped table does not collect (the plan says to run them only if the field exists, and no
endpoint for site settings is known), so a test below pins that fact instead of running them. The
field names are unverified (dependency D5 is open, docs/vendor-notes/unifi.md).
"""

from functools import cache

import pytest

from driftsniff.core.diff import ChangeItem
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules

from .support import State, detect, state

CANARY_OLD = "CANARY-shipped-wifi-old"
CANARY_NEW = "CANARY-shipped-wifi-new"
POLICIES = "unifi-firewall-policies"


@cache
def shipped() -> RuleEngine:
    return RuleEngine(load_rules())


def items(
    resource: str, before: list[State], after: list[State], *, ordered: bool = False
) -> list[ChangeItem]:
    """The items between two collections, with each state normalised as the pipeline does."""
    table = shipped().index.type_tables[resource]
    old = [normalize_object(table, member) for member in before]
    new = [normalize_object(table, member) for member in after]
    return detect(resource, old, new, ordered=ordered, engine=shipped())


def only(found: list[ChangeItem]) -> ChangeItem:
    assert len(found) == 1, found
    return found[0]


def policies(*entries: tuple[str, str]) -> list[State]:
    return [state(id=key, name=f"policy {key}", actionType=action) for key, action in entries]


# -- the rows ----------------------------------------------------------------------------------


def test_row_3_a_renamed_network_is_low() -> None:
    item = only(
        items(
            "unifi-networks",
            [state(id="u1", name="Guest")],
            [state(id="u1", name="Guest access")],
        )
    )
    result = shipped().classify(item)
    assert (item.change_kind, item.path) == ("modified", "name")
    assert (result.severity, result.rule_id) == ("low", "unifi.networks.name")
    assert result.rationale.strip() != ""


def test_row_5_a_moved_radio_channel_is_no_change() -> None:
    before = state(id="d1", name="ap-1", interfaces={"radios": [{"band": "5GHz", "channel": 36}]})
    after = state(id="d1", name="ap-1", interfaces={"radios": [{"band": "5GHz", "channel": 40}]})
    assert items("unifi-devices", [before], [after]) == []


def test_row_5_control_a_real_device_change_is_reported() -> None:
    before = state(id="d1", name="ap-1", firmwareVersion="6.6.55")
    after = state(id="d1", name="ap-1", firmwareVersion="6.6.65")
    result = shipped().classify(only(items("unifi-devices", [before], [after])))
    assert (result.severity, result.rule_id) == ("medium", "unifi.devices.firmware_version")


def test_row_16_a_secured_wifi_that_becomes_open_is_critical() -> None:
    before = state(id="w1", name="staff", securityConfiguration={"type": "WPA2_PERSONAL"})
    after = state(id="w1", name="staff", securityConfiguration={"type": "OPEN"})
    item = only(items("unifi-wifi-broadcasts", [before], [after]))
    result = shipped().classify(item)
    assert (item.change_kind, item.path) == ("modified", "securityConfiguration.type")
    assert (result.severity, result.rule_id) == ("critical", "unifi.wifi.security_to_open")


def test_row_17_a_changed_passphrase_is_critical_and_shows_fingerprints_only() -> None:
    before = state(id="w1", name="staff", securityConfiguration={"passphrase": CANARY_OLD})
    after = state(id="w1", name="staff", securityConfiguration={"passphrase": CANARY_NEW})
    item = only(items("unifi-wifi-broadcasts", [before], [after]))
    result = shipped().classify(item)
    assert item.path == "securityConfiguration.passphrase"
    assert (item.before_value, item.after_value) == (None, None)
    assert item.before_fp is not None
    assert item.after_fp is not None
    assert item.before_fp != item.after_fp
    assert (result.severity, result.rule_id) == ("critical", "unifi.wifi.passphrase")
    for shown in (repr(item), repr(result), str(item.order_detail)):
        assert "CANARY" not in shown


def test_row_21_a_deleted_firewall_policy_is_critical() -> None:
    before = policies(("p1", "allow"), ("p2", "allow"))
    after = policies(("p1", "allow"))
    item = only(items(POLICIES, before, after, ordered=True))
    result = shipped().classify(item)
    assert (item.change_kind, item.object_key) == ("removed", "p2")
    assert (result.severity, result.rule_id) == ("critical", "builtin.floor.removed")


def test_row_22_a_policy_moved_above_a_block_policy_is_critical() -> None:
    before = policies(("p1", "allow"), ("p2", "block"), ("p3", "allow"))
    after = policies(("p1", "allow"), ("p3", "allow"), ("p2", "block"))
    item = only(items(POLICIES, before, after, ordered=True))
    result = shipped().classify(item)
    assert item.change_kind == "moved"
    assert (result.severity, result.rule_id) == ("critical", "builtin.move.blocking")


@pytest.mark.parametrize("verdict", ["block", "REJECT", "Block"])
def test_row_22_every_blocking_verdict_of_the_table_makes_the_move_critical(verdict: str) -> None:
    before = policies(("p1", "allow"), ("p2", verdict), ("p3", "allow"))
    after = policies(("p1", "allow"), ("p3", "allow"), ("p2", verdict))
    result = shipped().classify(only(items(POLICIES, before, after, ordered=True)))
    assert (result.severity, result.rule_id) == ("critical", "builtin.move.blocking")


# -- rows 7 and 9: the field does not exist ----------------------------------------------------


def test_rows_7_and_9_are_not_run_because_site_settings_have_no_such_fields() -> None:
    table = shipped().index.type_tables["unifi-site-settings"]
    assert table.field_class("guest_portal.title") is FieldClass.UNCLASSIFIED
    assert table.field_class("mgmt.led_enabled") is FieldClass.UNCLASSIFIED
    kept = {path for path, kind in table.field_classes.items() if kind is not FieldClass.IGNORE}
    assert kept == {"id"}


# -- the ordering fixtures with the shipped table ---------------------------------------------


def test_an_insert_at_the_top_of_the_firewall_list_is_one_added_item_and_high() -> None:
    before = policies(("p1", "allow"), ("p2", "allow"))
    after = policies(("p0", "allow"), ("p1", "allow"), ("p2", "allow"))
    item = only(items(POLICIES, before, after, ordered=True))
    result = shipped().classify(item)
    assert (item.change_kind, item.object_key, result.severity) == ("added", "p0", "high")


def test_a_swap_of_two_neighbours_is_one_move_and_at_least_high() -> None:
    before = policies(("p1", "allow"), ("p2", "allow"), ("p3", "allow"))
    after = policies(("p2", "allow"), ("p1", "allow"), ("p3", "allow"))
    item = only(items(POLICIES, before, after, ordered=True))
    result = shipped().classify(item)
    assert item.change_kind == "moved"
    assert result.severity == "high"


def test_the_same_policies_in_the_same_order_are_no_change() -> None:
    same = policies(("p1", "allow"), ("p2", "block"))
    assert items(POLICIES, same, same, ordered=True) == []


def test_a_moved_acl_rule_over_a_block_rule_is_critical() -> None:
    def rules(*order: str) -> list[State]:
        actions = {"a1": "ALLOW", "a2": "BLOCK", "a3": "ALLOW"}
        return [state(id=key, name=f"rule {key}", action=actions[key]) for key in order]

    before = rules("a1", "a2", "a3")
    after = rules("a1", "a3", "a2")
    item = only(items("unifi-acl-rules", before, after, ordered=True))
    result = shipped().classify(item)
    assert (result.severity, result.rule_id) == ("critical", "builtin.move.blocking")
