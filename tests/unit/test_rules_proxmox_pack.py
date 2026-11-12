"""The shipped Proxmox VE pack and type tables, loaded from the package as the application does.

Every rule has one input that it matches and one near miss that it must not match
(``tests/fixtures/proxmox/rule_cases.json``; all names synthetic).
"""

import json
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.proxmox.resources import RESOURCES
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "proxmox" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))
FINGERPRINT = "fp1:0a1b2c3d:" + "0" * 32
OTHER_FINGERPRINT = "fp1:0a1b2c3d:" + "1" * 32


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def proxmox_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {c.rule.id: c for c in index.rules if c.source.startswith("packs/proxmox/")}


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
    assert {resource.name for resource in RESOURCES} <= set(index.type_tables)
    assert all(resource.name.startswith("proxmox-") for resource in RESOURCES)


def test_every_rule_has_one_case_and_names_a_kept_field(index: RuleIndex) -> None:
    rules = proxmox_rules(index)
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
    rule = proxmox_rules(index)[case["rule"]].rule
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
    missed = engine.classify(
        make(
            rule.resource, near.get("kind", "modified"), near["path"], near["before"], near["after"]
        )
    )
    assert missed.rule_id != rule.id


@pytest.mark.parametrize(
    ("resource", "kind", "severity"),
    [
        ("proxmox-users", "added", "high"),
        ("proxmox-tokens", "added", "high"),
        ("proxmox-acl", "added", "high"),
        ("proxmox-admin-acl", "added", "critical"),
        ("proxmox-admin-acl", "removed", "high"),
        ("proxmox-backup-jobs", "removed", "high"),
        ("proxmox-firewall-rules", "added", "high"),
        ("proxmox-realms", "added", "high"),
    ],
)
def test_object_floors(resource: str, kind: ChangeKind, severity: str, engine: RuleEngine) -> None:
    result = engine.classify(make(resource, kind, "", None, None))
    assert result.severity == severity


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("proxmox-vms", "cipassword"),
        ("proxmox-containers", "env"),
        ("proxmox-storage", "password"),
        ("proxmox-storage", "encryption-key"),
        ("proxmox-storage", "keyring"),
        ("proxmox-realms", "password"),
        ("proxmox-realms", "client-key"),
        ("proxmox-users", "keys"),
        ("proxmox-cluster-options", "http_proxy"),
    ],
)
def test_credential_fields_are_secret(resource: str, path: str, index: RuleIndex) -> None:
    assert index.type_tables[resource].field_class(path) is FieldClass.SECRET


def test_volatile_fields_do_not_reach_the_state(index: RuleIndex) -> None:
    vms = index.type_tables["proxmox-vms"]
    quiet: dict[str, JsonValue] = {"vmid": 100, "name": "web-01"}
    busy: dict[str, JsonValue] = {
        **quiet,
        "digest": "d1",
        "lock": "backup",
        "meta": "creation-qemu=9.0.2,ctime=1",
        "vmgenid": "x",
        "parent": "snap1",
        "snaptime": 1,
    }
    assert normalize_object(vms, busy) == normalize_object(vms, quiet)
    jobs = index.type_tables["proxmox-backup-jobs"]
    assert normalize_object(jobs, {"id": "b", "next-run": 1}) == {"id": "b"}
    users = index.type_tables["proxmox-users"]
    assert normalize_object(users, {"userid": "a@pve", "tfa-locked-until": 9, "tokens": []}) == {
        "userid": "a@pve"
    }
