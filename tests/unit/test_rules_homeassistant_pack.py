"""The shipped Home Assistant pack and type tables, the collector's object preparation and its
wiring into the factory and the source pages.

Every rule has one input that it matches and, unless it is a ``**`` rule (which matches every
path), one near miss that it must not match. All names are synthetic.
"""

import json
from typing import Any

import pytest

from driftsniff.collectors.base import CollectorError
from driftsniff.collectors.homeassistant.client import HomeAssistantClient
from driftsniff.collectors.homeassistant.normalize import prepare_objects
from driftsniff.collectors.homeassistant.resources import RESOURCES
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import CompiledRule, RuleIndex, load_rules
from driftsniff.rules.schema import normalize_path, path_matches
from driftsniff.sources.factory import build_collector
from driftsniff.web.dashboard import RESOURCE_LABELS, SOURCE_TYPE_LABELS
from driftsniff.web.source_pages import CREDENTIAL_LABELS, resources_of

FINGERPRINT = "fp1:0a1b2c3d:" + "0" * 32
OTHER_FINGERPRINT = "fp1:0a1b2c3d:" + "1" * 32
SECRET_FIELDS = ("latitude", "longitude", "config.actions", "config.triggers", "config.sequence")

# (rule id, path, before, after, severity, near miss (path, before, after) or None, kind, secret)
CASES: list[tuple[str, str, Any, Any, str, Any, str, bool]] = [
    (
        "homeassistant.users.made_admin",
        "is_admin",
        False,
        True,
        "critical",
        ("is_admin", True, False),
        "modified",
        False,
    ),
    (
        "homeassistant.users.admin_removed",
        "is_admin",
        True,
        False,
        "medium",
        ("is_admin", False, True),
        "modified",
        False,
    ),
    (
        "homeassistant.users.made_owner",
        "is_owner",
        False,
        True,
        "critical",
        ("is_owner", True, False),
        "modified",
        False,
    ),
    (
        "homeassistant.users.activated",
        "is_active",
        False,
        True,
        "high",
        ("is_active", True, False),
        "modified",
        False,
    ),
    (
        "homeassistant.users.deactivated",
        "is_active",
        True,
        False,
        "low",
        ("is_active", False, True),
        "modified",
        False,
    ),
    (
        "homeassistant.users.remote_login",
        "local_only",
        True,
        False,
        "high",
        ("local_only", False, True),
        "modified",
        False,
    ),
    (
        "homeassistant.users.local_only",
        "local_only",
        False,
        True,
        "low",
        ("local_only", True, False),
        "modified",
        False,
    ),
    (
        "homeassistant.users.groups",
        "group_ids",
        None,
        "system-read-only",
        "high",
        ("name", "a", "b"),
        "added",
        False,
    ),
    (
        "homeassistant.users.credentials",
        "credentials",
        None,
        {"type": "command_line"},
        "high",
        ("name", "a", "b"),
        "added",
        False,
    ),
    (
        "homeassistant.users.username",
        "username",
        "guest",
        "tablet",
        "medium",
        ("name", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.users.system_generated",
        "system_generated",
        False,
        True,
        "medium",
        ("name", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.users.added_or_removed",
        "",
        None,
        None,
        "critical",
        ("name", "a", "b"),
        "added",
        False,
    ),
    (
        "homeassistant.users.name",
        "name",
        "Guest",
        "Tablet",
        "low",
        ("username", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.core.external_url",
        "external_url",
        "https://a.example.invalid",
        "https://b.example.invalid",
        "high",
        ("internal_url", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.core.internal_url",
        "internal_url",
        "http://192.0.2.10:8123",
        "http://192.0.2.11:8123",
        "medium",
        ("external_url", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.core.allowlist_dirs",
        "allowlist_external_dirs",
        None,
        "/share",
        "high",
        ("time_zone", "a", "b"),
        "added",
        False,
    ),
    (
        "homeassistant.core.allowlist_urls",
        "allowlist_external_urls",
        None,
        "https://c.example.invalid",
        "medium",
        ("time_zone", "a", "b"),
        "added",
        False,
    ),
    (
        "homeassistant.core.latitude",
        "latitude",
        None,
        None,
        "medium",
        ("time_zone", "a", "b"),
        "modified",
        True,
    ),
    (
        "homeassistant.core.longitude",
        "longitude",
        None,
        None,
        "medium",
        ("time_zone", "a", "b"),
        "modified",
        True,
    ),
    (
        "homeassistant.core.general",
        "time_zone",
        "Europe/Lisbon",
        "Europe/Madrid",
        "low",
        ("external_url", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.automations.disabled",
        "enabled",
        True,
        False,
        "medium",
        ("enabled", False, True),
        "modified",
        False,
    ),
    (
        "homeassistant.automations.enabled",
        "enabled",
        False,
        True,
        "low",
        ("enabled", True, False),
        "modified",
        False,
    ),
    (
        "homeassistant.automations.alias",
        "config.alias",
        "Porch",
        "Porch light",
        "low",
        ("config.mode", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.automations.description",
        "config.description",
        "",
        "Turns the porch on",
        "low",
        ("config.mode", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.automations.config",
        "config.actions",
        None,
        None,
        "medium",
        ("config.alias", "a", "b"),
        "modified",
        True,
    ),
    (
        "homeassistant.scripts.alias",
        "config.alias",
        "Water",
        "Water garden",
        "low",
        ("config.mode", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.scripts.description",
        "config.description",
        "",
        "Fifteen minutes",
        "low",
        ("config.mode", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.scripts.config",
        "config.sequence",
        None,
        None,
        "medium",
        ("config.alias", "a", "b"),
        "modified",
        True,
    ),
    (
        "homeassistant.integrations.added_or_removed",
        "",
        None,
        None,
        "medium",
        ("title", "a", "b"),
        "removed",
        False,
    ),
    (
        "homeassistant.integrations.disabled",
        "disabled_by",
        None,
        "user",
        "medium",
        ("title", "a", "b"),
        "added",
        False,
    ),
    (
        "homeassistant.integrations.title",
        "title",
        "Broker",
        "Main broker",
        "low",
        ("disabled_by", None, "user"),
        "modified",
        False,
    ),
    (
        "homeassistant.integrations.polling",
        "pref_disable_polling",
        False,
        True,
        "low",
        ("title", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.integrations.new_entities",
        "pref_disable_new_entities",
        False,
        True,
        "low",
        ("title", "a", "b"),
        "modified",
        False,
    ),
    (
        "homeassistant.entities.disabled_by_user",
        "disabled_by",
        None,
        "user",
        "medium",
        ("disabled_by", None, "integration"),
        "added",
        False,
    ),
    (
        "homeassistant.entities.alexa",
        "options.cloud.alexa.should_expose",
        False,
        True,
        "medium",
        ("options.cloud.alexa.should_expose", True, False),
        "modified",
        False,
    ),
    (
        "homeassistant.entities.google",
        "options.cloud.google_assistant.should_expose",
        False,
        True,
        "medium",
        ("options.cloud.google_assistant.should_expose", True, False),
        "modified",
        False,
    ),
    (
        "homeassistant.entities.google_2fa",
        "options.cloud.google_assistant.disable_2fa",
        False,
        True,
        "high",
        ("options.cloud.google_assistant.disable_2fa", True, False),
        "modified",
        False,
    ),
    (
        "homeassistant.entities.general",
        "name",
        "Door",
        "Garage door",
        "low",
        ("disabled_by", None, "user"),
        "modified",
        False,
    ),
    ("homeassistant.areas.general", "name", "Garage", "Workshop", "low", None, "modified", False),
    (
        "homeassistant.dashboards.require_admin",
        "require_admin",
        True,
        False,
        "medium",
        ("require_admin", False, True),
        "modified",
        False,
    ),
    (
        "homeassistant.dashboards.general",
        "title",
        "Lab",
        "Lab overview",
        "low",
        ("require_admin", True, False),
        "modified",
        False,
    ),
]


@pytest.fixture(scope="module")
def index() -> RuleIndex:
    return load_rules()


@pytest.fixture(scope="module")
def engine(index: RuleIndex) -> RuleEngine:
    return RuleEngine(index)


def pack_rules(index: RuleIndex) -> dict[str, CompiledRule]:
    return {c.rule.id: c for c in index.rules if c.source.startswith("packs/homeassistant/")}


def text(value: JsonValue) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"), sort_keys=True)


def make(
    resource: str, kind: Any, path: str, before: Any, after: Any, *, secret: bool = False
) -> ChangeItem:
    change_kind: ChangeKind = kind
    return ChangeItem(
        resource=resource,
        object_key="1",
        object_name="object one",
        change_kind=change_kind,
        path=path,
        field_class=FieldClass.SECRET if secret else FieldClass.CONFIG,
        before_value=None if secret else text(before),
        after_value=None if secret else text(after),
        before_fp=FINGERPRINT if secret else None,
        after_fp=OTHER_FINGERPRINT if secret else None,
        window_start="2026-11-12T10:00:00Z",
        window_end="2026-11-12T10:05:00Z",
    )


def test_every_rule_has_one_case_and_names_a_kept_field(index: RuleIndex) -> None:
    rules = pack_rules(index)
    assert sorted(case[0] for case in CASES) == sorted(rules)
    for compiled in rules.values():
        rule = compiled.rule
        classes = index.type_tables[rule.resource].field_classes
        assert any(
            field_class is not FieldClass.IGNORE
            and path_matches(rule.segments, normalize_path(path))
            for path, field_class in classes.items()
        ), rule.id
        assert rule.rationale.endswith(".") and ". " not in rule.rationale, rule.id


@pytest.mark.parametrize("case", CASES, ids=lambda case: str(case[0]))
def test_a_rule_matches_its_input_and_not_its_near_miss(
    case: tuple[str, str, Any, Any, str, Any, str, bool], index: RuleIndex, engine: RuleEngine
) -> None:
    rule_id, path, before, after, severity, near, kind, secret = case
    rule = pack_rules(index)[rule_id].rule
    result = engine.classify(make(rule.resource, kind, path, before, after, secret=secret))
    assert (result.rule_id, result.severity) == (rule_id, severity)
    assert result.floored is False
    if near is not None:
        missed = engine.classify(make(rule.resource, "modified", *near))
        assert missed.rule_id != rule_id


def test_every_resource_has_a_type_table_a_label_and_no_floor(index: RuleIndex) -> None:
    for resource in RESOURCES:
        table = index.type_tables[resource.name]
        assert resource.name in RESOURCE_LABELS, resource.name
        assert table.object_key_field == resource.key_field
        assert not table.floors, resource.name
    assert resources_of("homeassistant", {}) == tuple(resource.name for resource in RESOURCES)
    assert "homeassistant" in SOURCE_TYPE_LABELS and "homeassistant" in CREDENTIAL_LABELS


@pytest.mark.parametrize("path", SECRET_FIELDS)
def test_location_and_automation_bodies_are_secret(path: str, index: RuleIndex) -> None:
    resource = {
        "config.actions": "homeassistant-automations",
        "config.triggers": "homeassistant-automations",
        "config.sequence": "homeassistant-scripts",
    }.get(path, "homeassistant-core-config")
    assert index.type_tables[resource].field_class(path) is FieldClass.SECRET


def test_volatile_fields_do_not_reach_the_state(index: RuleIndex) -> None:
    core = index.type_tables["homeassistant-core-config"]
    quiet: dict[str, JsonValue] = {"id": "core", "time_zone": "Europe/Lisbon"}
    busy = quiet | {"state": "RUNNING", "version": "2026.11.0", "components": ["api"]}
    assert normalize_object(core, busy) == normalize_object(core, quiet)
    entry = index.type_tables["homeassistant-integrations"]
    quiet = {"entry_id": "e1", "domain": "met"}
    busy = quiet | {"state": "setup_retry", "reason": "x", "modified_at": 1.0}
    assert normalize_object(entry, busy) == normalize_object(entry, quiet)


def test_core_config_gets_the_fixed_id_and_users_get_is_admin() -> None:
    assert prepare_objects(
        "homeassistant-core-config", "id", {"time_zone": "UTC"}, single=True
    ) == [{"time_zone": "UTC", "id": "core"}]
    users: list[Any] = [
        {"id": "b", "group_ids": ["system-users"]},
        {"id": "a", "group_ids": ["system-users", "system-admin"]},
    ]
    prepared = prepare_objects("homeassistant-users", "id", users, single=False)
    assert [(user["id"], user["is_admin"]) for user in prepared] == [("a", True), ("b", False)]
    assert "is_admin" not in users[0]  # the raw object is not changed


@pytest.mark.parametrize(
    ("result", "single"), [([{"id": ""}], False), ([{"name": "x"}], False), ({}, False), ([], True)]
)
def test_an_answer_of_the_wrong_shape_fails_the_resource(result: Any, single: bool) -> None:
    with pytest.raises(CollectorError):
        prepare_objects("homeassistant-areas", "id", result, single=single)


def test_the_factory_builds_the_home_assistant_collector() -> None:
    collector = build_collector(
        "homeassistant", "https://home.example.invalid", b"CANARY-homeassistant-00", {}
    )
    try:
        assert isinstance(collector, HomeAssistantClient)
    finally:
        collector.close()
