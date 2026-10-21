"""Rule and type-table schema: validation, paths, specificity and the TypeTable interface."""

from typing import Any, get_args

import pytest
from pydantic import ValidationError

from driftsniff.core import diff
from driftsniff.core.normalize import (
    CollectionMode,
    FieldClass,
    StaticTypeTable,
    TypeTable,
    normalize_object,
)
from driftsniff.rules import schema
from driftsniff.rules.schema import (
    PackFile,
    ResourceTable,
    Rule,
    TypeFile,
    TypeSpec,
    WhenSpec,
    normalize_path,
    path_matches,
    paths_overlap,
    snake_case,
)


def rule_data(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "test.rule",
        "resource": "vms",
        "path": "name_label",
        "severity": "low",
        "rationale": "A synthetic reason.",
    }
    data.update(changes)
    return data


def type_data(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"resource": "vms", "fields": {"name_label": "config"}}
    data.update(changes)
    return data


def problems(error: pytest.ExceptionInfo[ValidationError]) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
        for item in error.value.errors(include_url=False)
    )


# --- paths -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("segment", "expected"),
    [
        ("secureBoot", "secure_boot"),
        ("secure_boot", "secure_boot"),
        ("SecureBoot", "secure_boot"),
        ("HTTPProxy", "http_proxy"),
        ("HA_enabled", "ha_enabled"),
        ("PV_args", "pv_args"),
        ("allowedIpv4Addresses", "allowed_ipv4_addresses"),
        ("other-config", "other_config"),
        ("_xapiRef", "xapi_ref"),
        ("name", "name"),
        ("0", "0"),
        ("$$", ""),
    ],
)
def test_segments_become_lower_case_snake_case(segment: str, expected: str) -> None:
    assert snake_case(segment) == expected


def test_the_path_of_an_item_is_normalised_segment_by_segment() -> None:
    assert normalize_path("") == ()
    assert normalize_path("name") == ("name",)
    assert normalize_path("settings.exportRetention") == ("settings", "export_retention")
    assert normalize_path("dns.servers.0") == ("dns", "servers", "0")


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        (["name"], ["name"]),
        (["settings", "*"], ["settings", "retention"]),
        (["*", "retention"], ["settings", "retention"]),
        (["*"], ["anything"]),
        (["settings", "**"], ["settings", "a", "b", "c"]),
        (["settings", "**"], ["settings", "a"]),
        (["settings", "**"], ["settings"]),
        (["**"], ["a", "b"]),
        (["**"], []),
    ],
)
def test_a_pattern_matches_the_paths_it_describes(pattern: list[str], path: list[str]) -> None:
    assert path_matches(pattern, path)


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        (["name"], ["other"]),
        (["name"], ["name", "more"]),
        (["name", "more"], ["name"]),
        (["settings", "*"], ["settings"]),
        (["settings", "*"], ["settings", "a", "b"]),
        (["settings", "*"], ["other", "a"]),
        (["*"], []),
        (["settings", "**"], ["other", "a"]),
        (["name"], []),
    ],
)
def test_a_pattern_does_not_match_other_paths(pattern: list[str], path: list[str]) -> None:
    assert not path_matches(pattern, path)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (["a"], ["a"]),
        (["a", "*"], ["*", "b"]),
        (["a", "**"], ["a"]),
        (["a", "**"], ["a", "b", "c"]),
        (["*"], ["**"]),
        (["**"], ["**"]),
        (["**"], []),
        ([], []),
        (["*", "b"], ["a", "*"]),
    ],
)
def test_two_patterns_overlap_when_one_path_matches_both(
    first: list[str], second: list[str]
) -> None:
    assert paths_overlap(first, second)
    assert paths_overlap(second, first)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (["a"], ["b"]),
        (["a", "b"], ["a"]),
        (["a", "b"], ["a", "c"]),
        (["a", "*"], ["b", "*"]),
        (["*"], ["*", "*"]),
        (["a"], []),
    ],
)
def test_two_patterns_do_not_overlap_when_no_path_matches_both(
    first: list[str], second: list[str]
) -> None:
    assert not paths_overlap(first, second)
    assert not paths_overlap(second, first)


# --- rules -------------------------------------------------------------------------------


def test_the_severities_are_those_of_the_diff() -> None:
    assert get_args(schema.Severity) == get_args(diff.Severity.__value__)


def test_a_valid_rule_is_read_and_its_path_is_normalised() -> None:
    rule = Rule.model_validate(rule_data(path="secureBoot", rationale="  Boot protection.  "))
    assert rule.id == "test.rule"
    assert rule.resource == "vms"
    assert rule.path == "secure_boot"
    assert rule.segments == ("secure_boot",)
    assert rule.severity == "low"
    assert rule.when is None
    assert rule.rationale == "Boot protection."


@pytest.mark.parametrize(
    ("path", "when", "expected"),
    [
        ("name", None, 2),
        ("secureBoot", None, 2),
        ("settings.exportRetention", None, 4),
        ("settings.*", None, 2),
        ("*.exportRetention", None, 2),
        ("*", None, 0),
        ("**", None, 0),
        ("settings.**", None, 2),
        ("name", "changed", 3),
        ("settings.exportRetention", {"name": "decreases_below", "n": 2}, 5),
        ("**", "becomes_empty", 1),
    ],
)
def test_specificity_counts_literal_segments_twice_and_a_predicate_once(
    path: str, when: object, expected: int
) -> None:
    assert Rule.model_validate(rule_data(path=path, when=when)).specificity == expected


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_every_severity_is_accepted(severity: str) -> None:
    assert Rule.model_validate(rule_data(severity=severity)).severity == severity


def test_a_rule_without_a_required_field_is_refused() -> None:
    for name in ("id", "resource", "path", "severity", "rationale"):
        data = rule_data()
        del data[name]
        with pytest.raises(ValidationError) as error:
            Rule.model_validate(data)
        assert f"{name}: Field required" in problems(error)


@pytest.mark.parametrize("severity", ["urgent", "CRITICAL", "", "info", None, 3])
def test_an_unknown_severity_is_refused(severity: object) -> None:
    with pytest.raises(ValidationError) as error:
        Rule.model_validate(rule_data(severity=severity))
    assert "severity" in problems(error)


@pytest.mark.parametrize("name", ["", "Upper", "has space", "-lead", ".lead", "a/b"])
def test_an_id_or_a_resource_must_be_a_lower_case_name(name: str) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(rule_data(id=name))
    with pytest.raises(ValidationError):
        Rule.model_validate(rule_data(resource=name))


@pytest.mark.parametrize("path", ["", "  ", "a..b", ".a", "a.", "**.a", "a.**.b", "$$", "a.$$.b"])
def test_a_malformed_path_is_refused(path: str) -> None:
    with pytest.raises(ValidationError) as error:
        Rule.model_validate(rule_data(path=path))
    assert "path" in problems(error)


@pytest.mark.parametrize("rationale", ["", "   ", "\n"])
def test_a_rule_needs_a_rationale(rationale: str) -> None:
    with pytest.raises(ValidationError) as error:
        Rule.model_validate(rule_data(rationale=rationale))
    assert "rationale" in problems(error)


def test_an_unknown_key_is_refused() -> None:
    with pytest.raises(ValidationError) as error:
        Rule.model_validate(rule_data(colour="red"))
    assert "colour: Extra inputs are not permitted" in problems(error)


def test_a_predicate_is_a_name_or_a_name_with_arguments() -> None:
    plain = Rule.model_validate(rule_data(when="becomes_empty"))
    assert plain.when == WhenSpec(name="becomes_empty", args={})
    with_args = Rule.model_validate(
        rule_data(when={"name": "enum_transition", "from": ["a"], "to": ["b"]})
    )
    assert with_args.when is not None
    assert with_args.when.name == "enum_transition"
    assert with_args.when.args == {"from": ["a"], "to": ["b"]}
    given = Rule.model_validate(rule_data(when=WhenSpec(name="changed", args={})))
    assert given.when == WhenSpec(name="changed", args={})
    assert Rule.model_validate(rule_data(when=None)).when is None


@pytest.mark.parametrize(
    ("when", "fragment"),
    [
        ("nope", "unknown predicate 'nope'"),
        ({"name": "nope"}, "unknown predicate 'nope'"),
        ({"name": "decreases_below"}, "needs the argument(s) n"),
        ({"name": "decreases_below", "n": "two"}, "n must be a finite number"),
        ({"name": "changed", "extra": 1}, "does not take extra"),
        ({"n": 2}, "needs a name"),
        (5, "predicate name"),
        (["changed"], "predicate name"),
    ],
)
def test_a_bad_predicate_is_refused(when: object, fragment: str) -> None:
    with pytest.raises(ValidationError) as error:
        Rule.model_validate(rule_data(when=when))
    text = problems(error)
    assert text.startswith("when: ")
    assert fragment in text


def test_a_rule_cannot_be_changed() -> None:
    rule = Rule.model_validate(rule_data())
    with pytest.raises(ValidationError):
        rule.severity = "high"


# --- type tables -------------------------------------------------------------------------


def test_a_type_table_is_read_and_becomes_a_resource_table() -> None:
    spec = TypeSpec.model_validate(
        type_data(
            collection="ordered-keyed",
            key_field="id",
            name_field="name_label",
            floors={"added": "high", "removed": "critical"},
            fields={"name_label": "config", "secureBoot": "config", "memory.usage": "ignore"},
            lists={"tags": {"mode": "set", "key_field": "name"}, "dns.servers": "ordered-scalar"},
        )
    )
    table = spec.to_table()
    assert isinstance(table, ResourceTable)
    assert isinstance(table, StaticTypeTable)
    assert table.resource == "vms"
    assert table.collection is CollectionMode.ORDERED_KEYED
    assert table.object_key_field == "id"
    assert table.name_field == "name_label"
    assert table.field_class("secureBoot") is FieldClass.CONFIG
    assert table.field_class("memory.usage") is FieldClass.IGNORE
    assert table.field_class("undeclared") is FieldClass.UNCLASSIFIED
    assert table.collection_mode("tags") is CollectionMode.SET
    assert table.item_key_field("tags") == "name"
    assert table.collection_mode("dns.servers") is CollectionMode.ORDERED_SCALAR
    assert table.item_key_field("dns.servers") is None
    assert table.collection_mode("undeclared") is CollectionMode.ORDERED_SCALAR
    assert table.floor_for("added") == "high"
    assert table.floor_for("removed") == "critical"
    assert table.floor_for("modified") is None


def test_a_resource_table_can_be_used_as_a_type_table() -> None:
    spec = TypeSpec.model_validate(
        type_data(
            key_field="id",
            fields={"name_label": "config", "memory.usage": "ignore", "tags": "config"},
            lists={"tags": {"mode": "set", "key_field": "name"}},
        )
    )
    table: TypeTable = spec.to_table()
    raw = {
        "id": "vm-1",
        "name_label": "web",
        "memory": {"usage": 123},
        "tags": [{"name": "b"}, {"name": "a"}],
        "notes": None,
    }
    assert normalize_object(table, raw) == {
        "id": "vm-1",
        "name_label": "web",
        "memory": {},
        "tags": [{"name": "a"}, {"name": "b"}],
    }


def test_the_defaults_of_a_type_table() -> None:
    table = TypeSpec.model_validate(type_data()).to_table()
    assert table.collection is CollectionMode.SET
    assert table.object_key_field is None
    assert table.name_field is None
    assert table.floors == {}
    assert table.floor_for("added") is None


def test_the_floor_shorthand_covers_the_four_kinds_of_change() -> None:
    table = TypeSpec.model_validate(type_data(floor="high")).to_table()
    assert table.floors == {"added": "high", "removed": "high", "modified": "high", "moved": "high"}


def test_a_type_table_cannot_have_a_floor_and_floors() -> None:
    with pytest.raises(ValidationError) as error:
        TypeSpec.model_validate(type_data(floor="high", floors={"added": "low"}))
    assert "use floor or floors, not both" in problems(error)


def test_an_ordered_keyed_collection_needs_a_key_field() -> None:
    with pytest.raises(ValidationError) as error:
        TypeSpec.model_validate(type_data(collection="ordered-keyed"))
    assert "needs a key_field" in problems(error)
    TypeSpec.model_validate(type_data(collection="ordered-keyed", key_field="id"))


@pytest.mark.parametrize(
    "changes",
    [
        {"resource": "Has Space"},
        {"collection": "bag"},
        {"floor": "urgent"},
        {"floors": {"deleted": "high"}},
        {"floors": {"added": "urgent"}},
        {"fields": {"name_label": "public"}},
        {"fields": {"a..b": "config"}},
        {"fields": {"": "config"}},
        {"fields": {"a.*": "config"}},
        {"fields": "name_label"},
        {"lists": {"tags": "bag"}},
        {"lists": {"tags": {"mode": "set", "key_field": ""}}},
        {"lists": {"tags": {"key_field": "name"}}},
        {"lists": {"a.": "set"}},
        {"key_field": ""},
        {"name_field": ""},
        {"colour": "red"},
    ],
)
def test_a_bad_type_table_is_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TypeSpec.model_validate(type_data(**changes))


def test_a_type_table_needs_its_resource_and_fields() -> None:
    for name in ("resource", "fields"):
        data = type_data()
        del data[name]
        with pytest.raises(ValidationError) as error:
            TypeSpec.model_validate(data)
        assert f"{name}: Field required" in problems(error)


# --- files -------------------------------------------------------------------------------


def test_the_files_have_a_version_and_a_list() -> None:
    pack = PackFile.model_validate({"version": 1, "rules": [rule_data()]})
    assert [rule.id for rule in pack.rules] == ["test.rule"]
    types = TypeFile.model_validate({"version": 1, "types": [type_data()]})
    assert [spec.resource for spec in types.types] == ["vms"]
    assert PackFile.model_validate({"version": 1, "rules": []}).rules == []


@pytest.mark.parametrize("version", [0, 2, "1.0", None])
def test_a_file_of_another_version_is_refused(version: object) -> None:
    with pytest.raises(ValidationError):
        PackFile.model_validate({"version": version, "rules": []})
    with pytest.raises(ValidationError):
        TypeFile.model_validate({"version": version, "types": []})


def test_a_file_without_its_list_or_with_other_keys_is_refused() -> None:
    with pytest.raises(ValidationError) as error:
        PackFile.model_validate({"version": 1})
    assert "rules: Field required" in problems(error)
    with pytest.raises(ValidationError) as error:
        TypeFile.model_validate({"version": 1})
    assert "types: Field required" in problems(error)
    with pytest.raises(ValidationError) as error:
        PackFile.model_validate({"version": 1, "rules": [], "other": 1})
    assert "other: Extra inputs are not permitted" in problems(error)
