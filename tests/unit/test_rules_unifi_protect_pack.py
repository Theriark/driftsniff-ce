"""The shipped UniFi Protect pack, type tables and wiring, loaded as the application does.

Every rule has one input that it matches and one near miss that it must not match
(``tests/fixtures/unifi_protect/rule_cases.json``; all names synthetic). A catch-all rule (``**``)
has no near miss: on its resource every path is its own.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.unifi_protect.client import ProtectClient, prepare_objects
from driftsniff.collectors.unifi_protect.resources import RESOURCES
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches
from driftsniff.sources.factory import ResourceFilter, build_collector
from driftsniff.web.dashboard import RESOURCE_LABELS
from driftsniff.web.source_pages import CREDENTIAL_LABELS, resources_of

CASES_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "unifi_protect" / "rule_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))
ADDRESS = "https://protect.example.invalid"
CANARY = b"CANARY-upk-0"


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def protect_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {c.rule.id: c for c in index.rules if c.source.startswith("packs/unifi_protect/")}


def text(value: JsonValue) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"), sort_keys=True)


def make(
    resource: str, kind: ChangeKind, path: str, before: JsonValue, after: JsonValue
) -> ChangeItem:
    return ChangeItem(
        resource=resource,
        object_key="camera-0001",
        object_name="Front door",
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


def test_every_resource_has_a_type_table_and_a_label(index: RuleIndex) -> None:
    for resource in RESOURCES:
        assert resource.name.startswith("protect-")
        assert resource.name in index.type_tables
        assert RESOURCE_LABELS[resource.name]


def test_every_rule_has_one_case_and_names_a_kept_field(index: RuleIndex) -> None:
    rules = protect_rules(index)
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
    rule = protect_rules(index)[case["rule"]].rule
    item = make(
        rule.resource, case.get("kind", "modified"), case["path"], case["before"], case["after"]
    )
    result = engine.classify(item)
    assert (result.rule_id, result.severity) == (rule.id, case["severity"])
    assert result.floored is False
    near = case["near"]
    if near is None:
        assert rule.path == "**"
        return
    missed = engine.classify(
        make(rule.resource, "modified", near["path"], near["before"], near["after"])
    )
    assert missed.rule_id != rule.id


@pytest.mark.parametrize("resource", ["protect-cameras", "protect-sensors"])
def test_a_removed_camera_or_sensor_is_high_by_its_floor(resource: str, engine: RuleEngine) -> None:
    result = engine.classify(make(resource, "removed", "", None, None))
    assert (result.severity, result.rule_id) == ("high", "builtin.floor.removed")


def test_the_removal_floor_also_covers_a_removed_list_member(engine: RuleEngine) -> None:
    item = make("protect-sensors", "removed", "armProfileIds", "arm-profile-0001", None)
    result = engine.classify(item)
    assert (result.severity, result.rule_id) == ("high", "builtin.floor.removed")


def test_no_protect_field_is_secret(index: RuleIndex) -> None:
    for resource in RESOURCES:
        classes = index.type_tables[resource.name].field_classes.values()
        assert FieldClass.SECRET not in classes, resource.name


@pytest.mark.parametrize(
    ("resource", "kept", "busy"),
    [
        (
            "protect-cameras",
            {"id": "camera-0001", "name": "Front door", "isMicEnabled": False},
            {
                "state": "DISCONNECTED",
                "lcdMessage": {"type": "DO_NOT_DISTURB", "resetAt": None, "text": ""},
                "activePatrolSlot": 2,
                "featureFlags": {"hasMic": True},
                "hasPackageCamera": True,
            },
        ),
        (
            "protect-sensors",
            {"id": "sensor-0001", "alarmSettings": {"isEnabled": True}},
            {
                "state": "CONNECTED",
                "batteryStatus": {"percentage": 10, "isLow": True},
                "stats": {"temperature": {"value": 30, "status": "high"}},
                "isOpened": True,
                "openStatusChangedAt": 1,
                "isMotionDetected": True,
                "motionDetectedAt": 1,
                "alarmTriggeredAt": 1,
                "leakDetectedAt": 1,
                "externalLeakDetectedAt": 1,
                "tamperingDetectedAt": 1,
                "wirelessConnectionState": {"bridge": "bridge-0001"},
                "featureFlags": {"motion": {"channelCount": 1}},
            },
        ),
        (
            "protect-lights",
            {"id": "light-0001", "lightModeSettings": {"mode": "motion"}},
            {
                "state": "CONNECTED",
                "isDark": True,
                "isLightOn": True,
                "isLightForceEnabled": True,
                "lastMotion": 1,
                "isPirMotionDetected": True,
            },
        ),
        ("protect-nvr", {"id": "nvr-0001"}, {"armMode": {"status": "armed", "armedAt": 1}}),
        ("protect-viewers", {"id": "viewer-0001"}, {"state": "CONNECTED", "streamLimit": 4}),
        ("protect-chimes", {"id": "chime-0001"}, {"state": "CONNECTING"}),
    ],
)
def test_volatile_fields_do_not_reach_the_state(
    resource: str, kept: dict[str, JsonValue], busy: dict[str, JsonValue], index: RuleIndex
) -> None:
    table = index.type_tables[resource]
    assert normalize_object(table, {**kept, **busy}) == normalize_object(table, kept)


def test_prepare_wraps_the_nvr_and_sorts_lists_by_id() -> None:
    assert prepare_objects("protect-nvr", {"id": "nvr-0001"}) == [{"id": "nvr-0001"}]
    listed = prepare_objects("protect-cameras", [{"id": "camera-0002"}, {"id": "camera-0001"}])
    assert [item["id"] for item in listed] == ["camera-0001", "camera-0002"]


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("protect-cameras", {"id": "camera-0001"}),
        ("protect-cameras", [{"id": None}]),
        ("protect-nvr", "nvr"),
    ],
)
def test_prepare_refuses_another_shape(name: str, raw: JsonValue) -> None:
    with pytest.raises(CollectorError) as caught:
        prepare_objects(name, raw)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


def test_a_protect_source_gets_the_protect_collector() -> None:
    collector = build_collector("unifi_protect", ADDRESS, CANARY, {})
    try:
        assert isinstance(collector, ProtectClient)
        assert [spec.name for spec in collector.resources()] == [r.name for r in RESOURCES]
    finally:
        collector.close()


def test_a_resource_turned_off_is_not_listed() -> None:
    collector = build_collector(
        "unifi_protect", ADDRESS, CANARY, {"resources_off": ["protect-sensors"]}
    )
    try:
        assert isinstance(collector, ResourceFilter)
        assert "protect-sensors" not in [spec.name for spec in collector.resources()]
    finally:
        collector.close()


def test_the_source_pages_know_the_protect_type() -> None:
    assert CREDENTIAL_LABELS["unifi_protect"] == "API key"
    assert resources_of("unifi_protect", {}) == tuple(r.name for r in RESOURCES)
