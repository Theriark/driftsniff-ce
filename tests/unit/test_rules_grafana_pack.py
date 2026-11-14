"""The shipped Grafana pack and type tables, loaded from the package as the application does.

Every rule has one input that it matches and one near miss that it must not match
(``tests/fixtures/grafana/rule_cases.json``; all names synthetic).
"""

import json
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.grafana.resources import RESOURCES
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "grafana" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))
FINGERPRINT = "fp1:0a1b2c3d:" + "0" * 32
OTHER_FINGERPRINT = "fp1:0a1b2c3d:" + "1" * 32
FLOORED_HIGH = (
    "grafana-contact-points",
    "grafana-notification-policies",
    "grafana-org-users",
    "grafana-service-accounts",
)


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def grafana_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {c.rule.id: c for c in index.rules if c.source.startswith("packs/grafana/")}


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


def test_every_rule_has_one_case_and_names_a_kept_field(index: RuleIndex) -> None:
    rules = grafana_rules(index)
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
    rule = grafana_rules(index)[case["rule"]].rule
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
        make(rule.resource, "modified", near["path"], near["before"], near["after"])
    )
    assert missed.rule_id != rule.id


@pytest.mark.parametrize("resource", FLOORED_HIGH)
def test_access_and_alert_routing_have_the_object_floor_high(
    resource: str, index: RuleIndex
) -> None:
    table = index.type_tables[resource]
    assert [table.floor_for(k) for k in ("added", "removed", "modified", "moved")] == ["high"] * 4


def test_folder_permissions_floor_only_added_and_removed(index: RuleIndex) -> None:
    table = index.type_tables["grafana-folder-permissions"]
    floors = [table.floor_for(k) for k in ("added", "removed", "modified", "moved")]
    assert floors == ["high", "high", None, None]


@pytest.mark.parametrize(
    ("path", "before", "after", "severity"),
    [
        # A real Grafana 13.3.0 rename (2026-11-13) rated high here before; access did not change.
        ("title", "Operations", "Operations (driftsniff test)", "low"),
        ("permissions.permission", 1, 4, "high"),
        ("permissions.role", "Viewer", "Editor", "high"),
    ],
)
def test_a_folder_permission_change_is_rated_by_what_changed(
    path: str, before: JsonValue, after: JsonValue, severity: str, engine: RuleEngine
) -> None:
    result = engine.classify(make("grafana-folder-permissions", "modified", path, before, after))
    assert result.severity == severity


@pytest.mark.parametrize(
    ("resource", "severity"),
    [
        ("grafana-alert-rules", "high"),
        ("grafana-datasources", "high"),
        ("grafana-folders", "high"),
        ("grafana-dashboards", "medium"),
    ],
)
def test_a_removed_object_is_raised_by_its_floor(
    resource: str, severity: str, engine: RuleEngine
) -> None:
    result = engine.classify(make(resource, "removed", "", None, None))
    assert result.severity == severity
    assert result.rule_id == "builtin.floor.removed"


def test_a_changed_contact_point_secret_is_high(engine: RuleEngine) -> None:
    item = make("grafana-contact-points", "modified", "settings", None, None, secret=True)
    assert engine.classify(item).severity == "high"


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("grafana-datasources", "password"),
        ("grafana-datasources", "basicAuthPassword"),
        ("grafana-datasources", "secureJsonData"),
        ("grafana-contact-points", "settings"),
    ],
)
def test_credential_fields_are_secret(resource: str, path: str, index: RuleIndex) -> None:
    assert index.type_tables[resource].field_class(path) is FieldClass.SECRET


@pytest.mark.parametrize(
    ("resource", "quiet", "busy"),
    [
        (
            "grafana-org-users",
            {"userId": 3, "login": "dana", "role": "Viewer"},
            {"lastSeenAt": "2026-11-12T09:00:00Z", "lastSeenAtAge": "1m", "avatarUrl": "/a"},
        ),
        (
            "grafana-dashboards",
            {"uid": "d", "dashboard": {"panels": []}},
            {"dashboard": {"panels": [], "version": 9, "id": 4, "iteration": 17}},
        ),
        ("grafana-alert-rules", {"uid": "r", "title": "t"}, {"id": 3, "updated": "2026-11-12"}),
        ("grafana-datasources", {"uid": "s", "url": "u"}, {"version": 8, "id": 2}),
        ("grafana-folders", {"uid": "f", "title": "t"}, {"isStarred": True, "url": "/f"}),
    ],
)
def test_volatile_fields_do_not_reach_the_state(
    resource: str, quiet: dict[str, JsonValue], busy: dict[str, JsonValue], index: RuleIndex
) -> None:
    table = index.type_tables[resource]
    merged: dict[str, JsonValue] = {**quiet, **busy}
    if "dashboard" in quiet:
        merged["dashboard"] = busy["dashboard"]
    assert normalize_object(table, merged) == normalize_object(table, quiet)
