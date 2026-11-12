"""The shipped Checkmk pack and type tables, loaded from the package as the application does.

Every rule has one input that it matches and one near miss that it must not match
(``tests/fixtures/checkmk/rule_cases.json``; all names synthetic). A catch-all rule that is the only
rule of its resource has no near miss (``near`` is null).
"""

import json
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.checkmk.resources import RESOURCES
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "checkmk" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))
FINGERPRINT = "fp1:0a1b2c3d:" + "0" * 32
OTHER_FINGERPRINT = "fp1:0a1b2c3d:" + "1" * 32


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def checkmk_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {c.rule.id: c for c in index.rules if c.source.startswith("packs/checkmk/")}


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
        object_key="web-01",
        object_name="web-01",
        change_kind=kind,
        path=path,
        field_class=FieldClass.SECRET if secret else FieldClass.CONFIG,
        before_value=None if secret else text(before),
        after_value=None if secret else text(after),
        before_fp=FINGERPRINT if secret else None,
        after_fp=OTHER_FINGERPRINT if secret else None,
        window_start="2026-11-12T10:00:00Z",
        window_end="2026-11-12T10:05:00Z",
    )


def test_every_resource_the_collector_reads_has_a_type_table(index: RuleIndex) -> None:
    assert {resource.name for resource in RESOURCES} <= set(index.type_tables)


def test_every_rule_has_one_case_and_names_a_kept_field(index: RuleIndex) -> None:
    rules = checkmk_rules(index)
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
    rule = checkmk_rules(index)[case["rule"]].rule
    item = make(
        rule.resource,
        case.get("kind", "modified"),
        case["path"],
        case["before"],
        case["after"],
        secret=case.get("secret", False),
    )
    result = engine.classify(item)
    assert (result.rule_id, result.severity) == (rule.id, case["severity"])
    assert result.floored is False
    near = case["near"]
    if near is None:
        assert all(
            other.rule.resource != rule.resource
            for other in checkmk_rules(index).values()
            if other.rule.id != rule.id
        )
        return
    missed = engine.classify(
        make(rule.resource, "modified", near["path"], near["before"], near["after"])
    )
    assert missed.rule_id != rule.id


@pytest.mark.parametrize("resource", [resource.name for resource in RESOURCES])
def test_checkmk_tables_have_no_object_floors(resource: str, index: RuleIndex) -> None:
    # A floor would also grade a label or role removed from inside an object; "**" rules do it.
    table = index.type_tables[resource]
    assert [table.floor_for(k) for k in ("added", "removed", "modified", "moved")] == [None] * 4


def test_a_label_removed_from_a_host_stays_low(engine: RuleEngine) -> None:
    item = make("checkmk-hosts", "removed", "attributes.labels", {"key": "env", "value": "x"}, None)
    assert engine.classify(item).severity == "low"


def test_an_admin_role_removed_is_high_not_critical(engine: RuleEngine) -> None:
    result = engine.classify(make("checkmk-users", "removed", "roles", "admin", None))
    assert (result.severity, result.rule_id) == ("high", "checkmk.users.roles")


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("checkmk-hosts", "attributes.snmp_community"),
        ("checkmk-hosts", "attributes.management_snmp_community"),
        ("checkmk-hosts", "attributes.management_ipmi_credentials"),
        ("checkmk-folders", "attributes.snmp_community"),
        ("checkmk-folders", "attributes.management_snmp_community"),
        ("checkmk-folders", "attributes.management_ipmi_credentials"),
        ("checkmk-users", "password"),
        ("checkmk-users", "automation_secret"),
        ("checkmk-passwords", "password"),
        (
            "checkmk-notification-rules",
            "rule_config.notification_method.notify_plugin.plugin_params",
        ),
    ],
)
def test_credential_fields_are_secret(resource: str, path: str, index: RuleIndex) -> None:
    assert index.type_tables[resource].field_class(path) is FieldClass.SECRET


def test_volatile_fields_of_a_host_do_not_reach_the_state(index: RuleIndex) -> None:
    table = index.type_tables["checkmk-hosts"]
    quiet: dict[str, JsonValue] = {"id": "web-01", "attributes": {"ipaddress": "192.0.2.10"}}
    busy: dict[str, JsonValue] = {
        "id": "web-01",
        "title": "Web 1",
        "is_offline": False,
        "effective_attributes": None,
        "attributes": {
            "ipaddress": "192.0.2.10",
            "meta_data": {"created_at": 1.0, "updated_at": 2.0, "created_by": "cmkadmin"},
            "network_scan_result": {"start": 1},
            "inventory_failed": True,
            "waiting_for_discovery": True,
        },
    }
    assert normalize_object(table, busy) == normalize_object(table, quiet)
