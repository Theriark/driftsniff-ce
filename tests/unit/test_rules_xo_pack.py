"""The shipped Xen Orchestra pack and type tables (P5-T3).

``rules/types/xo.yaml`` and ``rules/packs/xo/*.yaml`` are loaded from the package, the way the
application loads them. Every rule has one input that it matches and one near miss that it must not
match; the inputs are in ``tests/fixtures/xo/rule_cases.json`` and all names in them are synthetic.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import PathMute, RuleEngine, item_is_muted
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "xo" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))
FINGERPRINT = "fp1:0a1b2c3d:" + "0" * 32
OTHER_FINGERPRINT = "fp1:0a1b2c3d:" + "1" * 32
FLOORED = ("servers", "backup-repositories", "users", "groups", "acl-roles", "acl-privileges")


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def xo_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {
        compiled.rule.id: compiled
        for compiled in index.rules
        if compiled.source.startswith("packs/xo/")
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


def test_the_xo_pack_loads_with_no_tie_and_holds_about_forty_rules(index: RuleIndex) -> None:
    rules = xo_rules(index)
    assert 40 <= len(rules) <= 55
    assert re.fullmatch(r"[0-9a-f]{12}", index.pack_version)
    assert {compiled.source for compiled in rules.values()} == {
        "packs/xo/access.yaml",
        "packs/xo/backup.yaml",
        "packs/xo/compute.yaml",
        "packs/xo/network.yaml",
    }


def test_every_xo_rule_has_a_rule_for_a_resource_with_a_type_table(index: RuleIndex) -> None:
    for compiled in xo_rules(index).values():
        assert compiled.rule.resource in index.type_tables, compiled.rule.id


def test_every_xo_rule_has_one_test_case_and_every_case_names_a_rule(index: RuleIndex) -> None:
    rule_ids = sorted(xo_rules(index))
    case_ids = sorted(case_id(case) for case in CASES)
    assert case_ids == rule_ids


def test_every_xo_rule_names_a_field_that_its_type_table_keeps(index: RuleIndex) -> None:
    for compiled in xo_rules(index).values():
        rule = compiled.rule
        classes = index.type_tables[rule.resource].field_classes
        kept = [
            path
            for path, field_class in classes.items()
            if field_class is not FieldClass.IGNORE
            and path_matches(rule.segments, normalize_path(path))
        ]
        assert kept, f"{rule.id}: no kept field of {rule.resource} matches {rule.path}"


def test_every_xo_rule_has_a_one_sentence_rationale(index: RuleIndex) -> None:
    for compiled in xo_rules(index).values():
        rationale = compiled.rule.rationale
        assert rationale.endswith("."), compiled.rule.id
        assert rationale.count(". ") == 0, compiled.rule.id


# ---- one matching input and one near miss per rule --------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_a_rule_matches_its_input_and_gives_its_severity(
    case: dict[str, Any], index: RuleIndex, engine: RuleEngine
) -> None:
    rule = xo_rules(index)[case["rule"]].rule
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
    rule = xo_rules(index)[case["rule"]].rule
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


# ---- the type tables --------------------------------------------------------------------------


@pytest.mark.parametrize("resource", FLOORED)
def test_the_security_sensitive_objects_have_the_object_floor_high(
    resource: str, index: RuleIndex
) -> None:
    table = index.type_tables[resource]
    floors = [table.floor_for(kind) for kind in ("added", "removed", "modified", "moved")]
    assert floors == ["high", "high", "high", "high"]


def test_other_xo_objects_have_no_object_floor(index: RuleIndex) -> None:
    for resource, table in index.type_tables.items():
        if resource not in FLOORED and not resource.startswith("unifi-"):
            assert table.floors == {}, resource


def test_adding_an_xo_server_is_high_by_its_floor(engine: RuleEngine) -> None:
    result = engine.classify(make("servers", "added", "", None, None))
    assert (result.severity, result.rule_id) == ("high", "builtin.floor.added")
    assert result.floored is True


def test_a_floor_never_lowers_a_critical_rule(engine: RuleEngine) -> None:
    result = engine.classify(make("servers", "modified", "allowUnauthorized", False, True))
    assert (result.severity, result.rule_id) == ("critical", "xo.servers.allow_unauthorized")


@pytest.mark.parametrize("before", ["none", "user"])
def test_a_user_who_becomes_an_administrator_is_critical(before: str, engine: RuleEngine) -> None:
    result = engine.classify(make("users", "modified", "permission", before, "admin"))
    assert (result.severity, result.rule_id) == ("critical", "xo.users.permission_to_admin")


def test_a_user_who_stays_an_administrator_is_not_critical(engine: RuleEngine) -> None:
    result = engine.classify(make("users", "modified", "permission", "admin", "admin"))
    assert (result.severity, result.rule_id) == ("high", "xo.users.permission")


def test_the_backup_retention_rule_needs_a_drop_below_two(engine: RuleEngine) -> None:
    def classify(before: int, after: int) -> tuple[str, str]:
        item = make("backup-jobs", "modified", "settings.exportRetention", before, after)
        result = engine.classify(item)
        return result.severity, result.rule_id

    assert classify(30, 1) == ("high", "xo.backup_job_settings.export_retention_drop")
    assert classify(30, 2) == ("medium", "xo.backup_job_settings.export_retention")
    assert classify(1, 5) == ("medium", "xo.backup_job_settings.export_retention")


def test_a_field_without_a_rule_is_medium_and_unclassified(engine: RuleEngine) -> None:
    result = engine.classify(make("vms", "modified", "affinityHost", "a", "b"))
    assert (result.severity, result.rule_id) == ("medium", "builtin.unclassified")


def test_the_volatile_and_hidden_fields_of_a_vm_do_not_reach_the_state(index: RuleIndex) -> None:
    table = index.type_tables["vms"]
    quiet: dict[str, JsonValue] = {"id": "v1", "name_label": "web-1", "power_state": "Halted"}
    busy: dict[str, JsonValue] = {
        "id": "v1",
        "name_label": "web-1",
        "power_state": "Running",
        "memory": {"usage": 1048576, "size": 2097152, "static": [1, 2]},
        "docker": {"enabled": True},
        "snapshots": ["s1", "s2"],
        "startTime": 1760000000,
    }
    assert normalize_object(table, busy) == {
        "id": "v1",
        "name_label": "web-1",
        "memory": {"static": [1, 2]},
    }
    assert normalize_object(table, quiet) == {"id": "v1", "name_label": "web-1"}


def test_credential_fields_are_secret_or_unclassified_never_config(index: RuleIndex) -> None:
    assert index.type_tables["pbds"].field_class("device_config") is FieldClass.SECRET
    assert index.type_tables["users"].field_class("authProviders") is FieldClass.SECRET
    assert index.type_tables["servers"].field_class("password") is FieldClass.UNCLASSIFIED
    assert index.type_tables["users"].field_class("pw_hash") is FieldClass.UNCLASSIFIED


# ---- mutes with the shipped pack --------------------------------------------------------------


def test_a_mute_hides_a_low_xo_item_that_keeps_its_severity(engine: RuleEngine) -> None:
    item = engine.apply(make("networks", "modified", "name_label", "net-a", "net-b"))
    assert item.severity == "low"
    assert item_is_muted(item, [PathMute("networks", "name_label")]) is True
    assert item_is_muted(item, [PathMute("vms", "name_label")]) is False


def test_a_mute_hides_a_high_xo_item_that_keeps_its_severity(engine: RuleEngine) -> None:
    changed = make("backup-repositories", "modified", "url", "nfs://a.test/s", "nfs://b.test/s")
    item = engine.apply(changed)
    assert (item.severity, item.rule_id) == ("high", "xo.backup_repositories.url")
    assert item_is_muted(item, [PathMute("backup-repositories", "url")]) is True


@pytest.mark.parametrize(
    ("resource", "path", "before", "after"),
    [
        ("users", "permission", "none", "admin"),
        ("servers", "allowUnauthorized", False, True),
        ("groups", "aclRoleIds", None, "role-a"),
    ],
)
def test_a_mute_never_hides_a_critical_xo_item(
    resource: str, path: str, before: JsonValue, after: JsonValue, engine: RuleEngine
) -> None:
    kind: ChangeKind = "added" if before is None else "modified"
    item = engine.apply(make(resource, kind, path, before, after))
    assert item.severity == "critical"
    everything = [PathMute(resource, "**"), PathMute(resource, path)]
    assert item_is_muted(item, everything) is False
