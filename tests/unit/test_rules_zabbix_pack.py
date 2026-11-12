"""The shipped Zabbix pack and type tables, loaded from the package as the application does.

Every rule has one input that it matches and, unless it is the catch-all of its resource, one near
miss that it must not match (``tests/fixtures/zabbix/rule_cases.json``; all names synthetic).
"""

import json
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.zabbix.resources import RESOURCES
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "zabbix" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))
FINGERPRINT = "fp1:0a1b2c3d:" + "0" * 32
OTHER_FINGERPRINT = "fp1:0a1b2c3d:" + "1" * 32
FLOORED = ("zabbix-users", "zabbix-user-groups", "zabbix-user-roles", "zabbix-authentication")
CATCH_ALL = ("zabbix.authentication.any",)


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def zabbix_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {c.rule.id: c for c in index.rules if c.source.startswith("packs/zabbix/")}


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
        object_key="1",
        object_name="object one",
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
    names = {resource.name for resource in RESOURCES}
    assert names <= set(index.type_tables)
    assert all(name.startswith("zabbix-") for name in names)


def test_every_rule_has_one_case_and_names_a_kept_field(index: RuleIndex) -> None:
    rules = zabbix_rules(index)
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
    rule = zabbix_rules(index)[case["rule"]].rule
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
        assert rule.id in CATCH_ALL
        return
    missed = engine.classify(
        make(rule.resource, "modified", near["path"], near["before"], near["after"])
    )
    assert missed.rule_id != rule.id


@pytest.mark.parametrize("resource", FLOORED)
def test_access_resources_have_the_object_floor_high(resource: str, index: RuleIndex) -> None:
    table = index.type_tables[resource]
    assert [table.floor_for(k) for k in ("added", "removed", "modified", "moved")] == ["high"] * 4


def test_a_new_user_is_high_by_its_floor(engine: RuleEngine) -> None:
    result = engine.classify(make("zabbix-users", "added", "", None, None))
    assert (result.severity, result.rule_id) == ("high", "builtin.floor.added")


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("zabbix-hosts", "ipmi_password"),
        ("zabbix-hosts", "tls_psk"),
        ("zabbix-hosts", "tls_psk_identity"),
        ("zabbix-hosts", "macros.secret_value"),
        ("zabbix-hosts", "interfaces.details.community"),
        ("zabbix-hosts", "interfaces.details.authpassphrase"),
        ("zabbix-hosts", "interfaces.details.privpassphrase"),
        ("zabbix-templates", "macros.secret_value"),
        ("zabbix-media-types", "passwd"),
        ("zabbix-media-types", "parameters.value"),
        ("zabbix-media-types", "script"),
        ("zabbix-media-types", "client_secret"),
        ("zabbix-media-types", "access_token"),
        ("zabbix-media-types", "refresh_token"),
        ("zabbix-users", "passwd"),
        ("zabbix-global-macros", "secret_value"),
        ("zabbix-proxies", "tls_psk"),
        ("zabbix-proxies", "tls_psk_identity"),
        ("zabbix-authentication", "ldap_bind_password"),
    ],
)
def test_credential_fields_are_secret(resource: str, path: str, index: RuleIndex) -> None:
    assert index.type_tables[resource].field_class(path) is FieldClass.SECRET


def test_volatile_fields_of_a_trigger_do_not_reach_the_state(index: RuleIndex) -> None:
    table = index.type_tables["zabbix-triggers"]
    quiet: dict[str, JsonValue] = {"triggerid": "23101", "status": "0"}
    busy: dict[str, JsonValue] = {
        **quiet,
        "value": "1",
        "lastchange": "1762905600",
        "state": "1",
        "error": "Cannot evaluate",
    }
    assert normalize_object(table, busy) == normalize_object(table, quiet)


def test_volatile_fields_of_a_proxy_and_a_user_do_not_reach_the_state(index: RuleIndex) -> None:
    proxy = index.type_tables["zabbix-proxies"]
    assert normalize_object(
        proxy, {"proxyid": "1", "lastaccess": "1", "state": "2", "version": "70005"}
    ) == {"proxyid": "1"}
    user = index.type_tables["zabbix-users"]
    assert normalize_object(user, {"userid": "1", "attempt_clock": "9", "attempt_ip": "x"}) == {
        "userid": "1"
    }
