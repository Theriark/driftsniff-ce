"""The shipped Synology DSM pack and type tables.

``rules/types/synology.yaml`` and ``rules/packs/synology/*.yaml`` are loaded from the package. Every
rule has one input it matches (``tests/fixtures/synology/rule_cases.json``, synthetic values) and,
unless it is a catch-all ``**`` rule, one near miss it must not match.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "synology" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))
NEAR_CASES = [case for case in CASES if case["near"] is not None]


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {c.rule.id: c for c in index.rules if c.source.startswith("packs/synology/")}


def text(value: JsonValue) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"), sort_keys=True)


def make(resource: str, kind: ChangeKind, path: str, before: JsonValue, after: JsonValue) -> Any:
    return ChangeItem(
        resource=resource,
        object_key="o1",
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


def test_every_rule_has_one_case_and_a_resource_with_a_type_table(index: RuleIndex) -> None:
    found = rules(index)
    assert sorted(case["rule"] for case in CASES) == sorted(found)
    for compiled in found.values():
        assert compiled.rule.resource in index.type_tables
        assert compiled.rule.rationale.endswith(".")


def test_every_field_rule_names_a_kept_field(index: RuleIndex) -> None:
    for compiled in rules(index).values():
        rule = compiled.rule
        if rule.path == "**":
            continue
        classes = index.type_tables[rule.resource].field_classes
        assert any(
            field_class is not FieldClass.IGNORE
            and path_matches(rule.segments, normalize_path(path))
            for path, field_class in classes.items()
        ), rule.id


@pytest.mark.parametrize("case", CASES, ids=lambda case: str(case["rule"]))
def test_a_rule_matches_its_input(
    case: dict[str, Any], index: RuleIndex, engine: RuleEngine
) -> None:
    rule = rules(index)[case["rule"]].rule
    kind = case.get("kind", "modified")
    result = engine.classify(make(rule.resource, kind, case["path"], case["before"], case["after"]))
    assert result.matched_rule_id == rule.id
    assert result.severity == case["severity"]


@pytest.mark.parametrize("case", NEAR_CASES, ids=lambda case: str(case["rule"]))
def test_a_rule_does_not_match_its_near_miss(
    case: dict[str, Any], index: RuleIndex, engine: RuleEngine
) -> None:
    rule = rules(index)[case["rule"]].rule
    near = case["near"]
    result = engine.classify(
        make(rule.resource, "modified", near["path"], near["before"], near["after"])
    )
    assert result.matched_rule_id != rule.id


@pytest.mark.parametrize(
    ("resource", "kind", "severity"),
    [
        ("synology-users", "added", "high"),
        ("synology-users", "removed", "high"),
        ("synology-groups", "added", "high"),
        ("synology-shares", "removed", "high"),
        ("synology-administrators", "added", "critical"),
        ("synology-administrators", "removed", "high"),
        ("synology-guest-share-access", "added", "critical"),
        ("synology-packages", "added", "medium"),
    ],
)
def test_whole_objects_get_their_floor(
    resource: str, kind: ChangeKind, severity: str, engine: RuleEngine
) -> None:
    assert engine.classify(make(resource, kind, "", None, None)).severity == severity


def test_a_description_of_a_user_stays_low(engine: RuleEngine) -> None:
    result = engine.classify(make("synology-users", "modified", "description", "a", "b"))
    assert (result.severity, result.floored) == ("low", False)
