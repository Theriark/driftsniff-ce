"""The shipped UniFi pack (P7-T4).

``rules/packs/unifi/*.yaml`` and ``rules/types/unifi.yaml`` are loaded from the package, the way
the application loads them. Every rule has one input that it matches and one near miss that it
must not match; the inputs are in ``tests/fixtures/unifi/rule_cases.json``. Every name and value in
them is unverified against the vendor reference (dependency D5 is open) and synthetic.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass
from driftsniff.rules.engine import PathMute, RuleEngine, item_is_muted
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "unifi" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))
FINGERPRINT = "fp1:0a1b2c3d:" + "0" * 32
OTHER_FINGERPRINT = "fp1:0a1b2c3d:" + "1" * 32
SOURCES = {
    "packs/unifi/devices.yaml",
    "packs/unifi/firewall.yaml",
    "packs/unifi/network.yaml",
    "packs/unifi/vpn.yaml",
    "packs/unifi/wifi.yaml",
}


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def unifi_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {
        compiled.rule.id: compiled
        for compiled in index.rules
        if compiled.source.startswith("packs/unifi/")
    }


def text(value: JsonValue) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"), sort_keys=True)


def make(
    resource: str,
    kind: ChangeKind,
    path: str,
    before: JsonValue,
    after: JsonValue,
    *,
    secret: bool = False,
) -> ChangeItem:
    return ChangeItem(
        resource=resource,
        object_key="o1",
        object_name="object one",
        change_kind=kind,
        path=path,
        field_class=FieldClass.SECRET if secret else FieldClass.CONFIG,
        before_value=text(before),
        after_value=text(after),
        before_fp=FINGERPRINT if secret else None,
        after_fp=OTHER_FINGERPRINT if secret else None,
        window_start="2026-10-21T10:00:00Z",
        window_end="2026-10-21T10:05:00Z",
    )


def case_id(case: dict[str, Any]) -> str:
    return str(case["rule"])


# ---- the pack loads ---------------------------------------------------------------------------


def test_the_unifi_pack_loads_with_no_tie_and_holds_about_forty_rules(index: RuleIndex) -> None:
    rules = unifi_rules(index)
    assert 40 <= len(rules) <= 55
    assert re.fullmatch(r"[0-9a-f]{12}", index.pack_version)
    assert {compiled.source for compiled in rules.values()} == SOURCES


def test_every_unifi_rule_is_for_a_unifi_resource_with_a_type_table(index: RuleIndex) -> None:
    for compiled in unifi_rules(index).values():
        resource = compiled.rule.resource
        assert resource.startswith("unifi-"), compiled.rule.id
        assert resource in index.type_tables, compiled.rule.id
        assert compiled.rule.id.startswith("unifi."), compiled.rule.id


def test_every_unifi_rule_has_one_test_case_and_every_case_names_a_rule(index: RuleIndex) -> None:
    assert sorted(case_id(case) for case in CASES) == sorted(unifi_rules(index))


def test_every_unifi_rule_names_a_field_that_its_type_table_keeps(index: RuleIndex) -> None:
    for compiled in unifi_rules(index).values():
        rule = compiled.rule
        classes = index.type_tables[rule.resource].field_classes
        kept = [
            path
            for path, field_class in classes.items()
            if field_class is not FieldClass.IGNORE
            and path_matches(rule.segments, normalize_path(path))
        ]
        assert kept, f"{rule.id}: no kept field of {rule.resource} matches {rule.path}"


def test_every_unifi_rule_has_a_one_sentence_rationale(index: RuleIndex) -> None:
    for compiled in unifi_rules(index).values():
        rationale = compiled.rule.rationale
        assert rationale.endswith("."), compiled.rule.id
        assert rationale.count(". ") == 0, compiled.rule.id


def test_every_rule_of_a_floored_resource_is_at_least_as_high_as_its_floor(
    index: RuleIndex,
) -> None:
    # A rule below the floor would never be the reason of a result: the floor would be shown.
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for compiled in unifi_rules(index).values():
        rule = compiled.rule
        floor = index.type_tables[rule.resource].floor_for("modified")
        if floor is not None:
            assert order[rule.severity] >= order[floor], rule.id


def test_no_rule_reads_a_value_of_a_secret_field(index: RuleIndex) -> None:
    # A rule on a secret field can only ask whether it changed: the value is never shown.
    for compiled in unifi_rules(index).values():
        rule = compiled.rule
        classes = index.type_tables[rule.resource].field_classes
        secret = [
            path
            for path, field_class in classes.items()
            if field_class is FieldClass.SECRET
            and path_matches(rule.segments, normalize_path(path))
        ]
        if secret:
            assert rule.when is not None and rule.when.name == "changed", rule.id


# ---- one matching input and one near miss per rule --------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_a_rule_matches_its_input_and_gives_its_severity(
    case: dict[str, Any], index: RuleIndex, engine: RuleEngine
) -> None:
    rule = unifi_rules(index)[case["rule"]].rule
    item = make(
        rule.resource,
        case.get("kind", "modified"),
        case["path"],
        case["before"],
        case["after"],
        secret=case.get("secret", False),
    )
    result = engine.classify(item)
    assert result.matched_rule_id == rule.id
    assert result.rule_id == rule.id
    assert result.severity == case["severity"] == rule.severity
    assert result.rationale == rule.rationale
    assert result.floored is False


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_a_rule_does_not_match_its_near_miss(
    case: dict[str, Any], index: RuleIndex, engine: RuleEngine
) -> None:
    rule = unifi_rules(index)[case["rule"]].rule
    near = case["near"]
    item = make(
        rule.resource,
        case.get("kind", "modified"),
        near["path"],
        near["before"],
        near["after"],
    )
    result = engine.classify(item)
    assert result.matched_rule_id != rule.id
    assert result.rule_id != rule.id
    assert result.rationale != ""


# ---- behaviour that the plan names ------------------------------------------------------------


@pytest.mark.parametrize(
    "before", ["WPA_PERSONAL", "WPA2_PERSONAL", "WPA3_PERSONAL", "WPA2_WPA3_PERSONAL", "wpa2"]
)
@pytest.mark.parametrize("after", ["OPEN", "open", "NONE"])
def test_a_secured_wifi_that_becomes_open_is_critical(
    before: str, after: str, engine: RuleEngine
) -> None:
    item = make("unifi-wifi-broadcasts", "modified", "securityConfiguration.type", before, after)
    result = engine.classify(item)
    assert (result.severity, result.rule_id) == ("critical", "unifi.wifi.security_to_open")


def test_an_open_wifi_that_becomes_secured_is_high_not_critical(engine: RuleEngine) -> None:
    item = make("unifi-wifi-broadcasts", "modified", "securityConfiguration.type", "OPEN", "WPA3")
    result = engine.classify(item)
    assert (result.severity, result.rule_id) == ("high", "unifi.wifi.security_type")


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("unifi-wifi-broadcasts", "securityConfiguration.passphrase"),
        ("unifi-vpn-site-to-site-tunnels", "preSharedKey"),
        ("unifi-vpn-servers", "preSharedKey"),
        ("unifi-radius-profiles", "sharedSecret"),
    ],
)
def test_a_changed_credential_is_critical_and_its_item_has_no_value(
    resource: str, path: str, engine: RuleEngine
) -> None:
    item = engine.apply(make(resource, "modified", path, None, None, secret=True))
    assert item.severity == "critical"
    assert (item.before_value, item.after_value) == (None, None)
    assert item_is_muted(item, [PathMute(resource, "**"), PathMute(resource, path)]) is False


def test_adding_a_firewall_policy_is_high_by_its_floor(engine: RuleEngine) -> None:
    result = engine.classify(make("unifi-firewall-policies", "added", "", None, None))
    assert (result.severity, result.rule_id) == ("high", "builtin.floor.added")


def test_removing_a_firewall_zone_is_critical_by_its_floor(engine: RuleEngine) -> None:
    result = engine.classify(make("unifi-firewall-zones", "removed", "", None, None))
    assert (result.severity, result.rule_id) == ("critical", "builtin.floor.removed")


def test_a_policy_that_is_switched_on_is_not_the_disabled_rule(engine: RuleEngine) -> None:
    item = make("unifi-firewall-policies", "modified", "enabled", False, True)
    result = engine.classify(item)
    assert result.rule_id != "unifi.firewall_policies.disabled"
    assert result.severity == "high"


def test_a_renamed_network_is_low_and_can_be_muted(engine: RuleEngine) -> None:
    item = engine.apply(make("unifi-networks", "modified", "name", "Guest", "Guest access"))
    assert (item.severity, item.rule_id) == ("low", "unifi.networks.name")
    assert item_is_muted(item, [PathMute("unifi-networks", "name")]) is True


def test_a_field_without_a_rule_is_medium_and_unclassified(engine: RuleEngine) -> None:
    item = make("unifi-networks", "modified", "somethingNew", "a", "b")
    result = engine.classify(item)
    assert (result.severity, result.rule_id) == ("medium", "builtin.unclassified")
