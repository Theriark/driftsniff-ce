"""The shipped Redfish pack and type tables, loaded from the package as the application does.

Every rule has one input that it matches and one near miss that it must not match
(``tests/fixtures/redfish/rule_cases.json``; all names synthetic).
"""

import json
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.redfish.resources import RESOURCES
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "redfish" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def redfish_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {c.rule.id: c for c in index.rules if c.source.startswith("packs/redfish/")}


def text(value: JsonValue) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"), sort_keys=True)


def make(
    resource: str, kind: ChangeKind, path: str, before: JsonValue, after: JsonValue
) -> ChangeItem:
    return ChangeItem(
        resource=resource,
        object_key="1",
        object_name="object one",
        change_kind=kind,
        path=path,
        field_class=FieldClass.CONFIG,
        before_value=text(before),
        after_value=text(after),
        before_fp=None,
        after_fp=None,
        window_start="2026-11-12T10:00:00Z",
        window_end="2026-11-12T10:05:00Z",
    )


def test_every_resource_the_collector_reads_has_a_type_table(index: RuleIndex) -> None:
    assert set(RESOURCES) <= set(index.type_tables)
    assert all(name.startswith("redfish-") for name in RESOURCES)


def test_every_rule_has_one_case_and_names_a_kept_field(index: RuleIndex) -> None:
    rules = redfish_rules(index)
    assert sorted(case["rule"] for case in CASES) == sorted(rules)
    for compiled in rules.values():
        rule = compiled.rule
        classes = index.type_tables[rule.resource].field_classes
        assert any(
            field_class is not FieldClass.IGNORE
            and path_matches(rule.segments, normalize_path(path))
            for path, field_class in classes.items()
        ), rule.id
        assert rule.rationale.endswith(".") and ". " not in rule.rationale, rule.id


@pytest.mark.parametrize("case", CASES, ids=lambda case: str(case["rule"]))
def test_a_rule_matches_its_input_and_not_its_near_miss(
    case: dict[str, Any], index: RuleIndex, engine: RuleEngine
) -> None:
    rule = redfish_rules(index)[case["rule"]].rule
    item = make(
        rule.resource, case.get("kind", "modified"), case["path"], case["before"], case["after"]
    )
    result = engine.classify(item)
    assert (result.rule_id, result.severity) == (rule.id, case["severity"])
    assert result.floored is False
    near = case["near"]
    missed = engine.classify(
        make(rule.resource, "modified", near["path"], near["before"], near["after"])
    )
    assert missed.rule_id != rule.id


def test_a_new_account_is_critical_by_its_floor(engine: RuleEngine) -> None:
    result = engine.classify(make("redfish-accounts", "added", "", None, None))
    assert (result.severity, result.rule_id) == ("critical", "builtin.floor.added")


def test_a_removed_account_and_a_changed_policy_are_high(engine: RuleEngine) -> None:
    removed = engine.classify(make("redfish-accounts", "removed", "", None, None))
    policy = engine.classify(make("redfish-account-service", "modified", "Name", "a", "b"))
    assert (removed.severity, policy.severity) == ("high", "high")


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("redfish-accounts", "Password"),
        ("redfish-accounts", "SNMP.AuthenticationKey"),
        ("redfish-account-service", "LDAP.Authentication.Password"),
        ("redfish-account-service", "ActiveDirectory.Authentication.Password"),
        ("redfish-network-protocol", "SNMP.CommunityStrings.CommunityString"),
        ("redfish-event-subscriptions", "Context"),
        ("redfish-event-subscriptions", "HttpHeaders"),
        ("redfish-event-subscriptions", "SNMP.TrapCommunity"),
        ("redfish-bios", "secret_value"),
    ],
)
def test_credential_fields_are_secret(resource: str, path: str, index: RuleIndex) -> None:
    assert index.type_tables[resource].field_class(path) is FieldClass.SECRET


@pytest.mark.parametrize(
    ("resource", "quiet", "busy"),
    [
        (
            "redfish-systems",
            {"Id": "1", "Boot": {"BootOrder": ["Boot0001"]}},
            {
                "Id": "1",
                "Boot": {"BootOrder": ["Boot0001"], "RemainingAutomaticRetryAttempts": 2},
                "PowerState": "On",
                "Status": {"Health": "OK"},
                "LastResetTime": "2026-11-12T09:00:00Z",
                "IndicatorLED": "Off",
                "Oem": {"Vendor": {"PostCode": 7}},
            },
        ),
        (
            "redfish-managers",
            {"Id": "1"},
            {"Id": "1", "DateTime": "2026-11-12T09:00:00Z", "PowerState": "On", "Status": {}},
        ),
        (
            "redfish-manager-interfaces",
            {"ObjectKey": "1/1"},
            {"ObjectKey": "1/1", "LinkStatus": "LinkDown", "SpeedMbps": 100, "Status": {}},
        ),
        ("redfish-accounts", {"UserName": "a"}, {"UserName": "a", "Locked": True}),
        ("redfish-firmware", {"Id": "BMC"}, {"Id": "BMC", "Status": {"Health": "OK"}}),
    ],
)
def test_volatile_fields_do_not_reach_the_state(
    resource: str, quiet: dict[str, JsonValue], busy: dict[str, JsonValue], index: RuleIndex
) -> None:
    table = index.type_tables[resource]
    assert normalize_object(table, busy) == normalize_object(table, quiet)
