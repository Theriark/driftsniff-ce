"""The classification engine: rules, floors, the default, moves and mutes.

Every type table and pack here is synthetic and is written in the shipped file format to a
temporary folder, then loaded with ``load_rules``. No vendor field name is used.
"""

import json
from dataclasses import replace
from typing import Any

import pytest
from pydantic import ValidationError

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import (
    SCHEMA_DRIFT_RATIONALE,
    SCHEMA_DRIFT_RULE_ID,
    ChangeItem,
    ChangeKind,
)
from driftsniff.core.normalize import FieldClass
from driftsniff.rules import engine as engine_module
from driftsniff.rules.engine import (
    MOVE_BLOCKING_RULE_ID,
    MOVE_RULE_ID,
    UNCLASSIFIED_RATIONALE,
    UNCLASSIFIED_RULE_ID,
    PathMute,
    RuleEngine,
    highest,
    is_muted,
    item_is_muted,
    severity_rank,
)
from driftsniff.rules.loader import load_rules
from driftsniff.rules.schema import ResourceTable, Severity, TypeSpec

TYPES = """\
version: 1
types:
  - resource: fw_rules
    collection: ordered-keyed
    key_field: id
    name_field: name
    action_field: action
    first_match: true
    floors: {added: high, removed: critical, modified: high, moved: high}
    fields:
      id: config
      name: config
      action: config
      enabled: config
      comment: config
      token: secret
  - resource: gateways
    key_field: id
    name_field: name
    action_field: action
    fields:
      id: config
      name: config
      rules: config
      rules.id: config
      rules.action: config
      tags: config
    lists:
      rules: {mode: ordered-keyed, key_field: id, first_match: true}
      tags: set
  - resource: reject_rules
    collection: ordered-keyed
    key_field: id
    action_field: verdict
    blocking_actions: [REJECT, Blackhole]
    first_match: true
    fields: {id: config, verdict: config}
  - resource: roles
    key_field: id
    floor: high
    fields: {id: config, permission: config, label: config}
  - resource: wifi_networks
    floor: high
    fields: {name: config, security: config}
  - resource: servers
    fields: {name: config, tls_verify: config, retention: config}
  - resource: notes
    key_field: id
    fields: {id: config, text: config}
  - resource: devices
    fields: {label: config}
"""

PACK = """\
version: 1
rules:
  - id: fw.disabled
    resource: fw_rules
    path: enabled
    when: {name: boolean_flips_to, value: false}
    severity: critical
    rationale: A firewall rule was switched off.
  - id: fw.comment
    resource: fw_rules
    path: comment
    severity: low
    rationale: A comment on a firewall rule changed.
  - id: fw.token
    resource: fw_rules
    path: token
    when: changed
    severity: high
    rationale: The secret of a firewall rule changed.
  - id: roles.admin
    resource: roles
    path: permission
    when: {name: enum_transition, from: [none], to: [admin]}
    severity: critical
    rationale: A role went from no permission to administrator.
  - id: roles.label
    resource: roles
    path: label
    severity: low
    rationale: A role label changed.
  - id: wifi.downgrade
    resource: wifi_networks
    path: security
    when: {name: enum_transition, from: [wpa2, wpa3], to: [open]}
    severity: critical
    rationale: A secured network became open.
  - id: servers.tls
    resource: servers
    path: tls_verify
    when: {name: boolean_flips_to, value: false}
    severity: critical
    rationale: Certificate checks were switched off.
  - id: servers.any
    resource: servers
    path: "**"
    severity: medium
    rationale: A server setting changed.
  - id: servers.name
    resource: servers
    path: name
    severity: low
    rationale: A server was renamed.
  - id: servers.retention
    resource: servers
    path: retention
    severity: high
    rationale: The retention changed.
  - id: servers.retention_drop
    resource: servers
    path: retention
    when: {name: decreases_below, n: 2}
    severity: critical
    rationale: The retention fell below two.
  - id: notes.any
    resource: notes
    path: "**"
    severity: low
    rationale: A note changed.
"""


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory) -> RuleEngine:
    root = tmp_path_factory.mktemp("rules")
    (root / "types").mkdir()
    (root / "packs" / "xo").mkdir(parents=True)
    (root / "types" / "synthetic.yaml").write_text(TYPES, encoding="utf-8")
    (root / "packs" / "xo" / "synthetic.yaml").write_text(PACK, encoding="utf-8")
    return RuleEngine(load_rules(root))


def text(value: JsonValue) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def make(
    resource: str,
    kind: ChangeKind = "modified",
    path: str = "",
    before: JsonValue = None,
    after: JsonValue = None,
    *,
    before_fp: str | None = None,
    after_fp: str | None = None,
    detail: dict[str, JsonValue] | None = None,
    field_class: FieldClass = FieldClass.CONFIG,
) -> ChangeItem:
    return ChangeItem(
        resource=resource,
        object_key="o1",
        object_name="object one",
        change_kind=kind,
        path=path,
        field_class=field_class,
        before_value=None if before is None else text(before),
        after_value=None if after is None else text(after),
        before_fp=before_fp,
        after_fp=after_fp,
        window_start="2026-10-21T10:00:00Z",
        window_end="2026-10-21T10:05:00Z",
        order_detail=detail,
    )


def moved(
    resource: str,
    path: str,
    moved_actions: list[str] | None = None,
    jumped_actions: list[str] | None = None,
) -> ChangeItem:
    detail: dict[str, JsonValue] = {"key": "r1", "summary": "r1 moved"}
    if moved_actions is not None:
        detail["moved_actions"] = [*moved_actions]
    if jumped_actions is not None:
        detail["jumped_actions"] = [*jumped_actions]
    return make(resource, "moved", path, detail=detail)


# ---- the acceptance checks -------------------------------------------------------------------


def test_removing_a_firewall_rule_is_critical(engine: RuleEngine) -> None:
    result = engine.classify(make("fw_rules", "removed"))
    assert result.severity == "critical"
    assert result.rule_id == "builtin.floor.removed"
    assert result.floored is True
    assert result.matched_rule_id == UNCLASSIFIED_RULE_ID
    assert result.rationale != ""


def test_removing_a_note_is_low(engine: RuleEngine) -> None:
    result = engine.classify(make("notes", "removed"))
    assert (result.severity, result.rule_id) == ("low", "notes.any")
    assert result.rationale == "A note changed."
    assert result.floored is False


def test_a_critical_item_cannot_be_muted(engine: RuleEngine) -> None:
    mutes = [PathMute("fw_rules", "**"), PathMute("notes", "**")]
    removed_rule = engine.apply(make("fw_rules", "removed"))
    removed_note = engine.apply(make("notes", "removed"))
    assert removed_rule.severity == "critical"
    assert item_is_muted(removed_rule, mutes) is False
    assert removed_note.severity == "low"
    assert item_is_muted(removed_note, mutes) is True


# ---- the rules -----------------------------------------------------------------------------


def test_the_most_specific_rule_wins(engine: RuleEngine) -> None:
    def classify(path: str, before: JsonValue, after: JsonValue) -> tuple[str, str]:
        result = engine.classify(make("servers", "modified", path, before, after))
        return result.severity, result.rule_id

    assert classify("retention", 5, 1) == ("critical", "servers.retention_drop")
    assert classify("retention", 5, 4) == ("high", "servers.retention")
    assert classify("name", "a", "b") == ("low", "servers.name")
    assert classify("other", "a", "b") == ("medium", "servers.any")
    assert classify("retention", 1, 0) == ("critical", "servers.retention_drop")


def test_tls_verification_switched_off_is_critical(engine: RuleEngine) -> None:
    off = engine.classify(make("servers", "modified", "tls_verify", True, False))
    assert (off.severity, off.rule_id) == ("critical", "servers.tls")
    on = engine.classify(make("servers", "modified", "tls_verify", False, True))
    assert (on.severity, on.rule_id) == ("medium", "servers.any")


def test_a_permission_from_none_to_admin_is_critical(engine: RuleEngine) -> None:
    up = engine.classify(make("roles", "modified", "permission", "none", "admin"))
    assert (up.severity, up.rule_id, up.floored) == ("critical", "roles.admin", False)
    down = engine.classify(make("roles", "modified", "permission", "admin", "none"))
    assert (down.severity, down.rule_id, down.floored) == ("high", "builtin.floor.modified", True)
    assert down.matched_rule_id == UNCLASSIFIED_RULE_ID


def test_a_wifi_security_downgrade_to_open_is_critical(engine: RuleEngine) -> None:
    for before in ("wpa2", "wpa3"):
        result = engine.classify(make("wifi_networks", "modified", "security", before, "open"))
        assert (result.severity, result.rule_id) == ("critical", "wifi.downgrade")
    upgrade = engine.classify(make("wifi_networks", "modified", "security", "open", "wpa3"))
    assert (upgrade.severity, upgrade.rule_id) == ("high", "builtin.floor.modified")


def test_switching_a_firewall_rule_off_is_critical_and_on_is_the_floor(engine: RuleEngine) -> None:
    off = engine.classify(make("fw_rules", "modified", "enabled", True, False))
    assert (off.severity, off.rule_id, off.floored) == ("critical", "fw.disabled", False)
    on = engine.classify(make("fw_rules", "modified", "enabled", False, True))
    assert (on.severity, on.rule_id, on.floored) == ("high", "builtin.floor.modified", True)


def test_a_secret_is_read_through_its_fingerprint(engine: RuleEngine) -> None:
    changed = make(
        "fw_rules",
        "modified",
        "token",
        before_fp="fp1:0a1b2c3d:" + "a" * 32,
        after_fp="fp1:0a1b2c3d:" + "b" * 32,
        field_class=FieldClass.SECRET,
    )
    result = engine.classify(changed)
    assert (result.severity, result.rule_id) == ("high", "fw.token")
    same = make(
        "fw_rules",
        "modified",
        "token",
        before_fp="fp1:0a1b2c3d:" + "a" * 32,
        after_fp="fp1:0a1b2c3d:" + "a" * 32,
        field_class=FieldClass.SECRET,
    )
    assert engine.classify(same).rule_id == "builtin.floor.modified"


def test_a_path_in_camel_case_reaches_a_snake_case_rule(engine: RuleEngine) -> None:
    result = engine.classify(make("servers", "modified", "tlsVerify", True, False))
    assert result.rule_id == "servers.tls"


def test_a_value_that_is_not_json_is_read_as_text() -> None:
    assert engine_module._value("not json {", None) == "not json {"
    assert engine_module._value("[" * 100_000, None) == "[" * 100_000
    assert engine_module._value('{"a":1}', None) == {"a": 1}
    assert engine_module._value(None, "fp1:x") == "fp1:x"
    assert engine_module._value(None, None) is None


# ---- no rule: the default ------------------------------------------------------------------


def test_an_item_no_rule_applies_to_is_medium_and_unclassified(engine: RuleEngine) -> None:
    result = engine.classify(make("devices", "modified", "label", "a", "b"))
    assert result.severity == "medium"
    assert result.rule_id == "builtin.unclassified"
    assert result.rationale == "unclassified field, not reviewed"
    assert (result.rule_id, result.rationale) == (UNCLASSIFIED_RULE_ID, UNCLASSIFIED_RATIONALE)
    assert result.floored is False


def test_a_resource_without_a_type_table_is_unclassified(engine: RuleEngine) -> None:
    result = engine.classify(make("unknown_things", "added"))
    assert (result.severity, result.rule_id) == ("medium", UNCLASSIFIED_RULE_ID)


def test_an_unclassified_field_of_a_resource_with_rules_is_unclassified(engine: RuleEngine) -> None:
    result = engine.classify(make("roles", "modified", "other", 1, 2))
    assert result.matched_rule_id == UNCLASSIFIED_RULE_ID
    assert result.severity == "high"


def test_a_rule_whose_predicate_does_not_hold_is_skipped(engine: RuleEngine) -> None:
    result = engine.classify(make("roles", "modified", "permission", "none", "user"))
    assert result.matched_rule_id == UNCLASSIFIED_RULE_ID


# ---- floors --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("resource", "kind", "expected"),
    [
        ("roles", "added", "high"),
        ("roles", "removed", "high"),
        ("roles", "modified", "high"),
        ("roles", "moved", "high"),
        ("wifi_networks", "added", "high"),
        ("fw_rules", "added", "high"),
        ("fw_rules", "removed", "critical"),
        ("fw_rules", "modified", "high"),
        ("fw_rules", "moved", "high"),
        ("devices", "added", "medium"),
        ("devices", "removed", "medium"),
    ],
)
def test_an_object_floor_applies_to_each_kind_of_change(
    engine: RuleEngine, resource: str, kind: ChangeKind, expected: str
) -> None:
    assert engine.classify(make(resource, kind)).severity == expected


def test_the_final_severity_is_the_maximum_of_the_rule_and_the_floor(engine: RuleEngine) -> None:
    low_rule = engine.classify(make("roles", "modified", "label", "a", "b"))
    assert (low_rule.severity, low_rule.rule_id, low_rule.floored) == (
        "high",
        "builtin.floor.modified",
        True,
    )
    assert low_rule.matched_rule_id == "roles.label"
    high_rule = engine.classify(make("roles", "modified", "permission", "none", "admin"))
    assert (high_rule.severity, high_rule.rule_id, high_rule.floored) == (
        "critical",
        "roles.admin",
        False,
    )


def test_a_rule_as_high_as_the_floor_is_the_result(engine: RuleEngine) -> None:
    result = engine.classify(
        make(
            "fw_rules",
            "modified",
            "token",
            before_fp="fp1:0a1b2c3d:" + "a" * 32,
            after_fp="fp1:0a1b2c3d:" + "b" * 32,
        )
    )
    assert (result.severity, result.rule_id, result.floored) == ("high", "fw.token", False)


def test_a_floor_below_the_default_does_not_lower_it(engine: RuleEngine) -> None:
    result = engine.classify(make("devices", "modified", "label", "a", "b"))
    assert result.severity == "medium"


def test_the_floor_text_names_the_resource_and_the_kind(engine: RuleEngine) -> None:
    result = engine.classify(make("roles", "removed"))
    assert "roles" in result.rationale
    assert "removed" in result.rationale
    assert "high" in result.rationale


def test_schema_drift_keeps_the_classification_of_the_diff(engine: RuleEngine) -> None:
    drift = make("roles", "schema_drift", "a, b")
    result = engine.classify(drift)
    assert (result.severity, result.rule_id) == ("low", SCHEMA_DRIFT_RULE_ID)
    assert result.rationale == SCHEMA_DRIFT_RATIONALE
    classified = replace(
        drift, severity="low", rule_id=SCHEMA_DRIFT_RULE_ID, rationale="From the diff."
    )
    assert engine.classify(classified).rationale == "From the diff."


# ---- moves in a list where the first match wins ---------------------------------------------


def test_a_move_in_a_first_match_list_is_at_least_high(engine: RuleEngine) -> None:
    result = engine.classify(moved("gateways", "rules", ["allow"], ["allow", "log"]))
    assert result.severity == "high"
    assert result.rule_id == MOVE_RULE_ID
    assert result.floored is True
    assert result.matched_rule_id == UNCLASSIFIED_RULE_ID
    assert "gateways" in result.rationale


@pytest.mark.parametrize(
    ("moved_actions", "jumped_actions"),
    [
        (["deny"], ["allow"]),
        (["drop"], []),
        (["allow"], ["deny"]),
        (["allow"], ["allow", "drop"]),
        (["DENY"], []),
        ([" Drop "], []),
    ],
)
def test_a_move_across_or_of_a_deny_or_drop_is_critical(
    engine: RuleEngine, moved_actions: list[str], jumped_actions: list[str]
) -> None:
    result = engine.classify(moved("gateways", "rules", moved_actions, jumped_actions))
    assert (result.severity, result.rule_id) == ("critical", MOVE_BLOCKING_RULE_ID)
    assert result.floored is True


def test_the_resource_level_order_is_read_the_same_way(engine: RuleEngine) -> None:
    safe = engine.classify(moved("fw_rules", "", ["allow"], ["allow"]))
    assert (safe.severity, safe.rule_id) == ("high", "builtin.floor.moved")
    blocked = engine.classify(moved("fw_rules", "", ["allow"], ["deny"]))
    assert (blocked.severity, blocked.rule_id) == ("critical", MOVE_BLOCKING_RULE_ID)


def test_the_blocking_actions_of_a_table_replace_deny_and_drop(engine: RuleEngine) -> None:
    custom = engine.classify(moved("reject_rules", "", ["allow"], ["reject"]))
    assert (custom.severity, custom.rule_id) == ("critical", MOVE_BLOCKING_RULE_ID)
    also = engine.classify(moved("reject_rules", "", ["BLACKHOLE"], []))
    assert also.severity == "critical"
    default_words = engine.classify(moved("reject_rules", "", ["deny"], ["drop"]))
    assert (default_words.severity, default_words.rule_id) == ("high", MOVE_RULE_ID)


def test_a_move_without_actions_in_the_detail_is_high(engine: RuleEngine) -> None:
    result = engine.classify(moved("gateways", "rules"))
    assert (result.severity, result.rule_id) == ("high", MOVE_RULE_ID)


def test_a_move_in_a_list_that_is_not_first_match_has_no_move_floor(engine: RuleEngine) -> None:
    result = engine.classify(moved("gateways", "tags", ["deny"], ["deny"]))
    assert result.severity == "medium"
    assert (result.rule_id, result.floored) == (UNCLASSIFIED_RULE_ID, False)


def test_a_move_in_a_resource_that_is_not_first_match_has_no_move_floor(engine: RuleEngine) -> None:
    result = engine.classify(moved("gateways", "", ["deny"], ["deny"]))
    assert (result.severity, result.rule_id) == ("medium", UNCLASSIFIED_RULE_ID)


def test_a_large_reorder_of_a_first_match_list_is_high(engine: RuleEngine) -> None:
    detail: dict[str, JsonValue] = {"note": "order changed", "old_count": 9000, "new_count": 9000}
    item = make("gateways", "order_changed", "rules", detail=detail)
    result = engine.classify(item)
    assert (result.severity, result.rule_id) == ("high", MOVE_RULE_ID)
    other = engine.classify(make("gateways", "order_changed", "tags", detail=detail))
    assert other.severity == "medium"


def test_a_malformed_order_detail_is_ignored(engine: RuleEngine) -> None:
    bad: dict[str, JsonValue] = {"moved_actions": "deny", "jumped_actions": [1, None, {"a": 1}]}
    item = make("gateways", "moved", "rules", detail=bad)
    assert engine.classify(item).severity == "high"
    assert engine.classify(make("gateways", "moved", "rules")).severity == "high"


# ---- the same input always gives the same output --------------------------------------------

SAMPLE: list[ChangeItem] = [
    make("fw_rules", "removed"),
    make("fw_rules", "modified", "enabled", True, False),
    make("roles", "modified", "label", "a", "b"),
    make("servers", "modified", "retention", 5, 1),
    make("servers", "modified", "other", "a", "b"),
    make("notes", "added"),
    make("devices", "modified", "label", "a", "b"),
    moved("gateways", "rules", ["allow"], ["deny"]),
    moved("fw_rules", "", ["allow"], ["allow"]),
    make("gateways", "order_changed", "rules"),
    make("roles", "schema_drift", "a"),
    make("unknown_things", "removed"),
]


def test_the_same_input_gives_the_same_output_over_100_repeats(engine: RuleEngine) -> None:
    first = [engine.classify(item) for item in SAMPLE]
    for _ in range(100):
        assert [engine.classify(item) for item in SAMPLE] == first
        assert [engine.classify(item) for item in reversed(SAMPLE)] == list(reversed(first))


def test_every_result_has_a_rule_id_and_a_rationale(engine: RuleEngine) -> None:
    for item in SAMPLE:
        result = engine.classify(item)
        assert result.rule_id.strip() != ""
        assert result.rationale.strip() != ""
        assert result.matched_rule_id.strip() != ""
        assert result.severity in ("low", "medium", "high", "critical")


def test_apply_fills_the_three_fields_and_changes_nothing_else(engine: RuleEngine) -> None:
    item = make("fw_rules", "removed")
    applied = engine.apply(item)
    result = engine.classify(item)
    assert (applied.severity, applied.rule_id, applied.rationale) == (
        result.severity,
        result.rule_id,
        result.rationale,
    )
    assert (item.severity, item.rule_id, item.rationale) == (None, None, None)
    expected = replace(
        item, severity=result.severity, rule_id=result.rule_id, rationale=result.rationale
    )
    assert applied == expected


def test_the_engine_reports_the_pack_version_of_its_index(engine: RuleEngine) -> None:
    assert len(engine.pack_version) == 12


def test_severities_are_ranked_and_compared() -> None:
    order: list[Severity] = ["low", "medium", "high", "critical"]
    assert [severity_rank(severity) for severity in order] == [0, 1, 2, 3]
    assert highest("low", "high") == "high"
    assert highest("critical", "medium") == "critical"
    assert highest("medium", "medium") == "medium"


# ---- mutes ----------------------------------------------------------------------------------


def test_a_mute_hides_an_item_that_is_not_critical() -> None:
    mutes = [PathMute("servers", "name")]
    assert is_muted("low", "servers", "name", mutes) is True
    assert is_muted("medium", "servers", "name", mutes) is True
    assert is_muted("high", "servers", "name", mutes) is True


def test_a_mute_never_hides_a_critical_item() -> None:
    everything = [PathMute("servers", "**"), PathMute("servers", "name"), PathMute("servers", "*")]
    assert is_muted("critical", "servers", "name", everything) is False
    assert is_muted("critical", "servers", "", everything) is False


def test_an_item_without_a_severity_is_never_muted() -> None:
    assert is_muted(None, "servers", "name", [PathMute("servers", "**")]) is False


def test_a_mute_applies_to_its_own_resource_and_path_only() -> None:
    mutes = [PathMute("servers", "name")]
    assert is_muted("low", "roles", "name", mutes) is False
    assert is_muted("low", "servers", "label", mutes) is False
    assert is_muted("low", "servers", "name.deep", mutes) is False
    assert is_muted("low", "servers", "name", []) is False


def test_a_mute_pattern_can_use_wildcards() -> None:
    assert is_muted("low", "servers", "a.b", [PathMute("servers", "a.*")]) is True
    assert is_muted("low", "servers", "a.b.c", [PathMute("servers", "a.*")]) is False
    assert is_muted("low", "servers", "a.b.c", [PathMute("servers", "a.**")]) is True
    assert is_muted("low", "servers", "anything.at.all", [PathMute("servers", "**")]) is True


def test_a_mute_pattern_and_a_path_are_compared_in_snake_case() -> None:
    assert is_muted("low", "servers", "tlsVerify", [PathMute("servers", "tls_verify")]) is True
    assert is_muted("low", "servers", "tls_verify", [PathMute("servers", " tlsVerify ")]) is True


def test_an_empty_pattern_matches_only_the_empty_path() -> None:
    mutes = [PathMute("servers", "")]
    assert is_muted("low", "servers", "", mutes) is True
    assert is_muted("low", "servers", "name", mutes) is False


def test_any_one_of_several_mutes_is_enough() -> None:
    mutes = [PathMute("servers", "a"), PathMute("notes", "b"), PathMute("servers", "c")]
    assert is_muted("low", "servers", "c", mutes) is True
    assert is_muted("low", "notes", "c", mutes) is False


# ---- the type table keys the engine reads ---------------------------------------------------


def type_data(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "resource": "fw_rules",
        "collection": "ordered-keyed",
        "key_field": "id",
        "action_field": "action",
        "first_match": True,
        "fields": {"id": "config", "action": "config", "rules.action": "config"},
        "lists": {"rules": {"mode": "ordered-keyed", "key_field": "id", "first_match": True}},
    }
    data.update(changes)
    return data


def problems(error: pytest.ExceptionInfo[ValidationError]) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
        for item in error.value.errors(include_url=False)
    )


def test_the_table_knows_its_first_match_lists_and_blocking_actions() -> None:
    table = TypeSpec.model_validate(type_data()).to_table()
    assert isinstance(table, ResourceTable)
    assert table.action_field == "action"
    assert table.first_match is True
    assert table.first_match_lists == frozenset({"rules"})
    assert table.is_first_match("") is True
    assert table.is_first_match("rules") is True
    assert table.is_first_match("tags") is False
    assert table.blocking_actions == frozenset({"deny", "drop"})
    assert table.is_blocking("DENY") and table.is_blocking(" drop ")
    assert not table.is_blocking("allow")


def test_the_defaults_know_no_action_and_no_first_match() -> None:
    table = TypeSpec.model_validate({"resource": "x", "fields": {"a": "config"}}).to_table()
    assert table.action_field is None
    assert table.first_match is False
    assert table.first_match_lists == frozenset()
    assert table.blocking_actions == frozenset()
    assert table.is_first_match("") is False
    assert table.is_blocking("deny") is False


def test_blocking_actions_are_trimmed_and_case_folded() -> None:
    table = TypeSpec.model_validate(type_data(blocking_actions=[" Reject ", "REJECT", "Sink"]))
    assert table.to_table().blocking_actions == frozenset({"reject", "sink"})


@pytest.mark.parametrize("value", [[], [""], ["deny", "  "]])
def test_blocking_actions_need_text(value: list[str]) -> None:
    with pytest.raises(ValidationError) as error:
        TypeSpec.model_validate(type_data(blocking_actions=value))
    assert "one or more non-empty texts" in problems(error)


def test_blocking_actions_need_an_action_field() -> None:
    with pytest.raises(ValidationError) as error:
        TypeSpec.model_validate(type_data(action_field=None, blocking_actions=["deny"]))
    assert "blocking_actions needs an action_field" in problems(error)


def test_first_match_needs_an_ordered_keyed_collection_and_list() -> None:
    with pytest.raises(ValidationError) as error:
        TypeSpec.model_validate(type_data(collection="set", key_field=None))
    assert "first_match needs a collection of the mode ordered-keyed" in problems(error)
    with pytest.raises(ValidationError) as error:
        TypeSpec.model_validate(type_data(lists={"tags": {"mode": "set", "first_match": True}}))
    assert "first_match needs a list of the mode ordered-keyed" in problems(error)


def test_the_action_field_of_a_first_match_order_must_be_config() -> None:
    for fields in (
        {"id": "config", "rules.action": "config"},
        {"id": "config", "action": "secret", "rules.action": "config"},
        {"id": "config", "action": "ignore", "rules.action": "config"},
    ):
        with pytest.raises(ValidationError) as error:
            TypeSpec.model_validate(type_data(fields=fields))
        assert "the action field 'action' must have the class config" in problems(error)


def test_the_action_field_of_a_first_match_list_must_be_config() -> None:
    with pytest.raises(ValidationError) as error:
        TypeSpec.model_validate(type_data(fields={"id": "config", "action": "config"}))
    assert "the action field 'rules.action' must have the class config" in problems(error)


def test_a_first_match_order_without_an_action_field_is_allowed() -> None:
    table = TypeSpec.model_validate(type_data(action_field=None, fields={"id": "config"}))
    assert table.to_table().action_field is None
