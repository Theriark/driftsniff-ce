"""The rule loader: validation with file and line, the index, ties and the pack version.

All packs and type tables here are synthetic and written to a temporary folder.
"""

from hashlib import sha256
from pathlib import Path

import pytest

from driftsniff.core.normalize import CollectionMode
from driftsniff.rules import loader
from driftsniff.rules.loader import (
    RuleIndex,
    RuleLoadError,
    RuleTieError,
    compute_pack_version,
    load_rules,
)
from driftsniff.rules.predicates import Predicate
from driftsniff.rules.schema import ResourceTable

TYPES = """\
version: 1
types:
  - resource: vms
    collection: set
    key_field: id
    name_field: name_label
    floor: high
    fields:
      name_label: config
      secureBoot: config
      settings.exportRetention: config
      memory.usage: ignore
    lists:
      tags:
        mode: set
        key_field: name
  - resource: hosts
    collection: ordered-keyed
    key_field: id
    fields:
      name_label: config
"""


def entry(
    rule_id: str,
    path: str,
    severity: str = "low",
    when: str | None = None,
    resource: str = "vms",
) -> str:
    lines = [
        f"  - id: {rule_id}\n",
        f"    resource: {resource}\n",
        f'    path: "{path}"\n',
    ]
    if when is not None:
        lines.append(f"    when: {when}\n")
    lines.append(f"    severity: {severity}\n")
    lines.append("    rationale: A synthetic reason.\n")
    return "".join(lines)


def pack(*entries: str) -> str:
    return "version: 1\nrules:\n" + "".join(entries)


def write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    raise AssertionError(f"{needle!r} is not in the text")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    write(tmp_path, "types/test.yaml", TYPES)
    return tmp_path


def load_error(root: Path) -> RuleLoadError:
    with pytest.raises(RuleLoadError) as error:
        load_rules(root)
    return error.value


# --- loading and the index ---------------------------------------------------------------


def test_packs_and_types_are_loaded_and_indexed(root: Path) -> None:
    text = pack(entry("xo.name", "name_label"), entry("xo.boot", "secureBoot", "high"))
    write(root, "packs/xo/a.yaml", text)
    write(root, "packs/unifi/b.yaml", pack(entry("unifi.host", "name_label", resource="hosts")))
    index = load_rules(root)
    assert isinstance(index, RuleIndex)
    ids = sorted(compiled.rule.id for compiled in index.rules)
    assert ids == ["unifi.host", "xo.boot", "xo.name"]
    assert sorted(index.by_resource) == ["hosts", "vms"]
    assert sorted(index.type_tables) == ["hosts", "vms"]
    vms = index.type_tables["vms"]
    assert isinstance(vms, ResourceTable)
    assert vms.name_field == "name_label"
    assert vms.floor_for("moved") == "high"
    assert index.type_tables["hosts"].collection is CollectionMode.ORDERED_KEYED
    boot = next(compiled for compiled in index.rules if compiled.rule.id == "xo.boot")
    assert boot.rule.severity == "high"
    assert boot.rule.path == "secure_boot"
    assert boot.specificity == 2
    assert boot.predicate is None
    assert boot.source == "packs/xo/a.yaml"
    assert boot.line == line_of(text, "id: xo.boot")


def test_a_root_without_files_gives_an_empty_index(tmp_path: Path) -> None:
    index = load_rules(tmp_path)
    assert index.rules == ()
    assert index.by_resource == {}
    assert index.type_tables == {}
    assert index.candidates("vms", "name_label") == ()


def test_the_default_root_loads() -> None:
    index = load_rules()
    assert len(index.pack_version) == 12
    assert index.pack_version == compute_pack_version()


def test_only_yaml_files_of_the_known_folders_are_read(root: Path) -> None:
    write(root, "packs/xo/a.yaml", pack(entry("xo.name", "name_label")))
    write(root, "packs/xo/notes.txt", "not yaml: [")
    write(root, "packs/xo/b.yml", "not yaml: [")
    write(root, "packs/other/c.yaml", "not yaml: [")
    write(root, "elsewhere/d.yaml", "not yaml: [")
    (root / "packs" / "xo" / "folder.yaml").mkdir()
    index = load_rules(root)
    assert [compiled.rule.id for compiled in index.rules] == ["xo.name"]


# --- specificity and candidates ----------------------------------------------------------


def test_candidates_are_listed_most_specific_first(root: Path) -> None:
    write(
        root,
        "packs/xo/a.yaml",
        pack(
            entry("any", "**", "low"),
            entry("under_settings", "settings.*", "medium"),
            entry("retention", "settings.exportRetention", "high"),
            entry(
                "retention_drop",
                "settings.exportRetention",
                "critical",
                when="{name: decreases_below, n: 2}",
            ),
        ),
    )
    index = load_rules(root)

    def ids(resource: str, path: str) -> list[str]:
        return [compiled.rule.id for compiled in index.candidates(resource, path)]

    assert ids("vms", "settings.exportRetention") == [
        "retention_drop",
        "retention",
        "under_settings",
        "any",
    ]
    assert ids("vms", "settings.export_retention") == ids("vms", "settings.exportRetention")
    assert ids("vms", "settings.other") == ["under_settings", "any"]
    assert ids("vms", "name_label") == ["any"]
    assert ids("vms", "") == ["any"]
    assert ids("hosts", "settings.exportRetention") == []
    assert ids("unknown", "name_label") == []
    specificity = {compiled.rule.id: compiled.specificity for compiled in index.rules}
    assert specificity == {"any": 0, "under_settings": 2, "retention": 4, "retention_drop": 5}
    drop = next(c for c in index.rules if c.rule.id == "retention_drop")
    assert drop.predicate is not None
    assert drop.predicate(5, 1)
    assert not drop.predicate(5, 3)


def test_a_path_in_camel_case_matches_the_snake_case_rule(root: Path) -> None:
    write(root, "packs/xo/a.yaml", pack(entry("boot", "secure_boot", "high")))
    index = load_rules(root)
    assert [c.rule.id for c in index.candidates("vms", "secureBoot")] == ["boot"]
    assert [c.rule.id for c in index.candidates("vms", "secure_boot")] == ["boot"]
    assert index.candidates("vms", "secureBoot.extra") == ()


def test_rules_that_cannot_apply_to_the_same_field_do_not_tie(root: Path) -> None:
    write(
        root,
        "packs/xo/a.yaml",
        pack(
            entry("a", "settings.alpha"),
            entry("b", "settings.beta"),
            entry("c", "other.*"),
            entry("d", "settings.*.deep"),
            entry("e", "settings.alpha", resource="hosts"),
        ),
    )
    assert len(load_rules(root).rules) == 5


# --- ties --------------------------------------------------------------------------------


def test_two_wildcard_rules_of_equal_specificity_on_one_field_are_a_tie(root: Path) -> None:
    text = pack(entry("first", "settings.*"), entry("second", "*.exportRetention"))
    write(root, "packs/xo/a.yaml", text)
    error = load_error(root)
    assert isinstance(error, RuleTieError)
    assert (error.first_id, error.second_id) == ("first", "second")
    assert error.file == root / "packs" / "xo" / "a.yaml"
    assert error.line == line_of(text, "id: second")
    assert "ties with rule 'first'" in str(error)
    assert f"packs/xo/a.yaml:{line_of(text, 'id: first')}" in str(error)


def test_two_rules_on_the_same_path_are_a_tie(root: Path) -> None:
    text = pack(entry("one", "name_label"), entry("two", "name_label", "high"))
    write(root, "packs/xo/a.yaml", text)
    assert isinstance(load_error(root), RuleTieError)


def test_two_rules_with_predicates_that_may_both_hold_are_a_tie(root: Path) -> None:
    write(
        root,
        "packs/xo/a.yaml",
        pack(
            entry("one", "name_label", when="changed"),
            entry("two", "name_label", when="becomes_empty"),
        ),
    )
    assert isinstance(load_error(root), RuleTieError)


def test_a_tie_between_two_files_is_found(root: Path) -> None:
    write(root, "packs/unifi/a.yaml", pack(entry("one", "name_label")))
    write(root, "packs/xo/a.yaml", pack(entry("two", "name_label")))
    error = load_error(root)
    assert isinstance(error, RuleTieError)
    assert error.file == root / "packs" / "xo" / "a.yaml"


def test_a_tie_is_a_load_error(root: Path) -> None:
    write(root, "packs/xo/a.yaml", pack(entry("one", "**"), entry("two", "*")))
    assert isinstance(load_error(root), RuleLoadError)


def test_rules_whose_predicates_exclude_each_other_do_not_tie(root: Path) -> None:
    write(
        root,
        "packs/xo/a.yaml",
        pack(
            entry("to_off", "secureBoot", "high", when="{name: boolean_flips_to, value: false}"),
            entry("to_on", "secureBoot", "low", when="{name: boolean_flips_to, value: true}"),
            entry(
                "down",
                "settings.exportRetention",
                when="{name: enum_transition, from: [a], to: [b]}",
            ),
            entry(
                "up",
                "settings.exportRetention",
                when="{name: enum_transition, from: [b], to: [b]}",
            ),
        ),
    )
    assert len(load_rules(root).rules) == 4


def test_equal_predicates_that_do_not_exclude_each_other_are_a_tie(root: Path) -> None:
    flip = "{name: boolean_flips_to, value: true}"
    write(
        root,
        "packs/xo/a.yaml",
        pack(entry("one", "secureBoot", when=flip), entry("two", "secureBoot", when=flip)),
    )
    assert isinstance(load_error(root), RuleTieError)


# --- YAML booleans: only true and false (YAML 1.2), never on, off, yes, no, y or n -------

WORDS = ["on", "off", "yes", "no", "y", "n", "On", "OFF", "Yes", "NO", "Y", "N"]


def only_predicate(root: Path, when: str) -> Predicate:
    write(root, "packs/xo/a.yaml", pack(entry("a", "secureBoot", when=when)))
    predicate = load_rules(root).rules[0].predicate
    assert predicate is not None
    return predicate


@pytest.mark.parametrize("word", WORDS)
def test_a_yaml_11_boolean_word_in_enum_transition_lists_stays_text(root: Path, word: str) -> None:
    predicate = only_predicate(root, f"{{name: enum_transition, from: [{word}], to: [x]}}")
    assert predicate.args == {"from": [word], "to": ["x"]}
    assert predicate(word, "x") is True
    assert predicate(True, "x") is False
    predicate = only_predicate(root, f"{{name: enum_transition, from: [x], to: [{word}]}}")
    assert predicate.args == {"from": ["x"], "to": [word]}
    assert predicate("x", word) is True
    assert predicate("x", False) is False


@pytest.mark.parametrize("word", WORDS)
def test_a_yaml_11_boolean_word_as_a_predicate_value_stays_text(root: Path, word: str) -> None:
    predicate = only_predicate(root, f"{{name: any_to_value, value: {word}}}")
    assert predicate.args == {"value": word}
    assert predicate("x", word) is True
    assert predicate("x", True) is False
    assert predicate("x", False) is False


@pytest.mark.parametrize("word", ["yes", "no", "on", "off"])
def test_a_yaml_11_boolean_word_is_not_a_boolean_argument(root: Path, word: str) -> None:
    text = pack(entry("a", "secureBoot", when=f"{{name: boolean_flips_to, value: {word}}}"))
    write(root, "packs/xo/a.yaml", text)
    error = load_error(root)
    assert error.line == line_of(text, "when:")
    assert "must be true or false" in error.message


@pytest.mark.parametrize(
    ("text", "value"),
    [("true", True), ("True", True), ("TRUE", True), ("false", False), ("FALSE", False)],
)
def test_true_and_false_still_load_as_booleans(root: Path, text: str, value: bool) -> None:
    flips = only_predicate(root, f"{{name: boolean_flips_to, value: {text}}}")
    assert flips.args == {"value": value}
    assert flips(not value, value) is True
    target = only_predicate(root, f"{{name: any_to_value, value: {text}}}")
    assert target.args == {"value": value}
    assert target("x", value) is True
    members = only_predicate(root, f"{{name: enum_transition, from: [{text}], to: [x]}}")
    assert members.args == {"from": [value], "to": ["x"]}


@pytest.mark.parametrize("quote", ["'", '"'])
def test_a_quoted_word_stays_text(root: Path, quote: str) -> None:
    word = f"{quote}on{quote}"
    predicate = only_predicate(root, f"{{name: enum_transition, from: [{word}], to: [x]}}")
    assert predicate.args == {"from": ["on"], "to": ["x"]}
    predicate = only_predicate(root, f"{{name: any_to_value, value: {quote}true{quote}}}")
    assert predicate.args == {"value": "true"}


@pytest.mark.parametrize("word", ["on", "off", "yes", "no", "y", "n"])
def test_yaml_boolean_words_as_rule_ids_load_as_text(root: Path, word: str) -> None:
    write(root, "packs/xo/a.yaml", pack(entry(word, "secureBoot"), entry("other", "name_label")))
    index = load_rules(root)
    assert sorted(compiled.rule.id for compiled in index.rules) == sorted([word, "other"])
    assert all(isinstance(compiled.rule.id, str) for compiled in index.rules)


@pytest.mark.parametrize("word", ["on", "off", "yes", "no", "y", "n"])
def test_yaml_boolean_words_as_field_names_of_a_type_table_load_as_text(
    root: Path, word: str
) -> None:
    types = (
        "version: 1\ntypes:\n"
        f"  - resource: gadgets\n    key_field: {word}\n    name_field: {word}\n"
        f"    fields:\n      {word}: config\n      other: ignore\n"
    )
    write(root, "types/gadgets.yaml", types)
    table = load_rules(root).type_tables["gadgets"]
    assert table.object_key_field == word
    assert table.name_field == word
    assert table.field_class(word) == "config"
    assert table.field_class("other") == "ignore"


# --- errors name the file and the line ---------------------------------------------------


def test_a_missing_field_names_the_file_and_the_rule(root: Path) -> None:
    text = (
        "version: 1\nrules:\n"
        "  - id: no.rationale\n"
        "    resource: vms\n"
        "    path: name_label\n"
        "    severity: low\n"
    )
    path = write(root, "packs/xo/bad.yaml", text)
    error = load_error(root)
    assert error.file == path
    assert error.line == line_of(text, "id: no.rationale")
    assert "rules.0.rationale: Field required" in error.message
    assert str(error) == f"{path}:{error.line}: {error.message}"


def test_an_unknown_severity_names_its_line(root: Path) -> None:
    text = pack(entry("ok", "name_label"), entry("bad", "secureBoot", severity="urgent"))
    path = write(root, "packs/xo/bad.yaml", text)
    error = load_error(root)
    assert error.file == path
    assert error.line == line_of(text, "severity: urgent")
    assert "rules.1.severity" in error.message


def test_a_bad_predicate_names_its_line(root: Path) -> None:
    text = pack(entry("bad", "name_label", when="no_such_predicate"))
    path = write(root, "packs/xo/bad.yaml", text)
    error = load_error(root)
    assert error.file == path
    assert error.line == line_of(text, "when: no_such_predicate")
    assert "unknown predicate 'no_such_predicate'" in error.message


def test_bad_predicate_arguments_are_refused(root: Path) -> None:
    text = pack(entry("bad", "name_label", when="{name: decreases_below}"))
    write(root, "packs/xo/bad.yaml", text)
    assert "needs the argument(s) n" in load_error(root).message


def test_an_unknown_key_names_its_line(root: Path) -> None:
    text = pack(entry("bad", "name_label")) + "    colour: red\n"
    write(root, "packs/xo/bad.yaml", text)
    error = load_error(root)
    assert error.line == line_of(text, "colour: red")
    assert "Extra inputs are not permitted" in error.message


def test_more_than_one_problem_is_counted(root: Path) -> None:
    text = (
        "version: 1\nrules:\n"
        "  - id: Bad Id\n"
        "    resource: vms\n"
        "    path: name_label\n"
        "    severity: urgent\n"
    )
    write(root, "packs/xo/bad.yaml", text)
    error = load_error(root)
    assert "more)" in error.message


def test_a_file_of_another_version_is_refused(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "version: 2\nrules: []\n")
    error = load_error(root)
    assert error.line == 1
    assert "version" in error.message


def test_a_file_without_its_list_is_refused(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "version: 1\n")
    error = load_error(root)
    assert error.line == 1
    assert "rules: Field required" in error.message


def test_a_file_that_is_not_a_mapping_is_refused(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "- one\n- two\n")
    error = load_error(root)
    assert error.line == 1
    assert "dictionary" in error.message or "object" in error.message


def test_a_scalar_file_is_refused_without_a_line(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "just text\n")
    error = load_error(root)
    assert error.line is None


def test_a_bad_type_table_names_its_line(root: Path) -> None:
    text = TYPES.replace("secureBoot: config", "secureBoot: public")
    path = write(root, "types/test.yaml", text)
    error = load_error(root)
    assert error.file == path
    assert error.line == line_of(text, "secureBoot: public")
    assert "types.0.fields.secureBoot" in error.message


def test_a_bad_key_of_a_type_table_names_its_line(root: Path) -> None:
    text = TYPES + "    floors:\n      deleted: high\n"
    write(root, "types/test.yaml", text)
    error = load_error(root)
    assert error.line == line_of(text, "deleted: high")


def test_invalid_yaml_names_its_line(root: Path) -> None:
    text = "version: 1\nrules: [\n"
    path = write(root, "packs/xo/bad.yaml", text)
    error = load_error(root)
    assert error.file == path
    assert error.line is not None
    assert "not valid YAML" in error.message


def test_a_control_character_is_refused(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "version: 1\nrules: \x07\n")
    error = load_error(root)
    assert error.line is None
    assert error.message == "not valid YAML"


def test_an_empty_file_is_refused(root: Path) -> None:
    path = write(root, "packs/xo/bad.yaml", "")
    error = load_error(root)
    assert error.file == path
    assert error.line is None
    assert str(error) == f"{path}: the file is empty"


def test_a_file_that_is_not_utf8_is_refused(root: Path) -> None:
    path = root / "packs" / "xo" / "bad.yaml"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"version: 1\nrules: \xff\xfe\n")
    assert load_error(root).message == "the file is not valid UTF-8"


def test_a_duplicate_key_names_its_line(root: Path) -> None:
    text = "version: 1\nversion: 1\nrules: []\n"
    write(root, "packs/xo/bad.yaml", text)
    error = load_error(root)
    assert error.line == 2
    assert "appears twice" in error.message


def test_two_documents_in_one_file_are_refused(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "version: 1\nrules: []\n---\nversion: 1\nrules: []\n")
    assert "not valid YAML" in load_error(root).message


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("1: a\n", "a key must be text"),
        ("? [a]\n: b\n", "a key must be text"),
        ("when: 2020-01-01\n", "a value of type date is not allowed"),
    ],
)
def test_keys_and_values_of_the_wrong_kind_are_refused(
    root: Path, text: str, fragment: str
) -> None:
    write(root, "packs/xo/bad.yaml", text)
    error = load_error(root)
    assert error.line == 1
    assert fragment in error.message


def test_an_arbitrary_tag_is_refused(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "version: !!python/object:os.system x\n")
    assert "not valid YAML" in load_error(root).message


def test_a_deeply_nested_file_is_refused(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "version: 1\nrules: " + "[" * 40 + "]" * 40 + "\n")
    assert "nested too deeply" in load_error(root).message


def test_a_file_with_too_many_nodes_is_refused(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAX_NODES", 5)
    write(root, "packs/xo/bad.yaml", pack(entry("one", "name_label")))
    assert "too large" in load_error(root).message


def test_a_recursion_error_is_a_load_error(root: Path) -> None:
    write(root, "packs/xo/bad.yaml", "version: 1\nrules: " + "[" * 5000 + "]" * 5000 + "\n")
    assert "nested too deeply" in load_error(root).message


def test_a_file_over_the_size_limit_is_refused(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAX_FILE_BYTES", 10)
    write(root, "packs/xo/bad.yaml", pack(entry("one", "name_label")))
    error = load_error(root)
    assert error.line is None
    assert "larger than 10 bytes" in error.message


def test_a_file_that_cannot_be_read_is_refused(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(self: Path) -> bytes:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_bytes", refuse)
    error = load_error(root)
    assert error.line is None
    assert "cannot read the file: Permission denied" in error.message


def test_a_duplicate_rule_id_is_refused(root: Path) -> None:
    text = pack(entry("same", "name_label"), entry("same", "secureBoot"))
    write(root, "packs/xo/a.yaml", text)
    error = load_error(root)
    assert error.line == line_of(text, "id: same") + 5
    assert "'same' is already used at packs/xo/a.yaml:3" in error.message


def test_a_duplicate_rule_id_across_files_is_refused(root: Path) -> None:
    write(root, "packs/unifi/a.yaml", pack(entry("same", "name_label")))
    write(root, "packs/xo/a.yaml", pack(entry("same", "secureBoot")))
    error = load_error(root)
    assert error.file == root / "packs" / "xo" / "a.yaml"
    assert "packs/unifi/a.yaml" in error.message


def test_a_rule_for_a_resource_without_a_type_table_is_refused(root: Path) -> None:
    text = pack(entry("ok", "name_label"), entry("lost", "name_label", resource="routers"))
    write(root, "packs/xo/a.yaml", text)
    error = load_error(root)
    assert error.line == line_of(text, "id: lost")
    assert "'routers', which has no type table" in error.message


def test_a_resource_defined_twice_is_refused(root: Path) -> None:
    text = "version: 1\ntypes:\n  - resource: vms\n    fields: {a: config}\n"
    write(root, "types/more.yaml", text)
    error = load_error(root)
    assert error.file == root / "types" / "test.yaml"
    assert "'vms' is already defined at types/more.yaml:3" in error.message


def test_a_load_error_without_a_line_has_only_the_file(tmp_path: Path) -> None:
    error = RuleLoadError(tmp_path / "x.yaml", None, "broken")
    assert str(error) == f"{tmp_path / 'x.yaml'}: broken"
    assert (error.file, error.line, error.message) == (tmp_path / "x.yaml", None, "broken")


# --- the rule pack version ---------------------------------------------------------------


def expected_version(root: Path, relatives: list[str]) -> str:
    digest = sha256()
    for relative in sorted(relatives):
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update((root / relative).read_bytes() + b"\0")
    return digest.hexdigest()[:12]


def test_the_version_is_the_first_12_hex_characters_of_the_sha256_over_the_sorted_files(
    root: Path,
) -> None:
    write(root, "packs/xo/b.yaml", pack(entry("b", "secureBoot")))
    write(root, "packs/xo/a.yaml", pack(entry("a", "name_label")))
    write(root, "packs/unifi/c.yaml", pack(entry("c", "name_label", resource="hosts")))
    files = ["packs/xo/b.yaml", "packs/xo/a.yaml", "packs/unifi/c.yaml", "types/test.yaml"]
    version = load_rules(root).pack_version
    assert version == expected_version(root, files)
    assert version == compute_pack_version(root)
    assert len(version) == 12
    assert version == version.lower()
    assert all(character in "0123456789abcdef" for character in version)


def test_the_version_is_stable(root: Path) -> None:
    write(root, "packs/xo/a.yaml", pack(entry("a", "name_label")))
    first = load_rules(root).pack_version
    assert load_rules(root).pack_version == first
    assert compute_pack_version(root) == first


def test_the_version_depends_on_the_content_and_not_on_the_folder(
    root: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    write(root, "packs/xo/a.yaml", pack(entry("a", "name_label")))
    other = tmp_path_factory.mktemp("copy")
    write(other, "types/test.yaml", TYPES)
    write(other, "packs/xo/a.yaml", pack(entry("a", "name_label")))
    assert load_rules(other).pack_version == load_rules(root).pack_version


def test_the_version_changes_when_a_file_changes(root: Path) -> None:
    path = write(root, "packs/xo/a.yaml", pack(entry("a", "name_label", "low")))
    before = load_rules(root).pack_version
    path.write_text(pack(entry("a", "name_label", "high")), encoding="utf-8")
    after = load_rules(root).pack_version
    assert after != before
    path.write_text(pack(entry("a", "name_label", "low")), encoding="utf-8")
    assert load_rules(root).pack_version == before


def test_the_version_does_not_depend_on_the_line_endings(root: Path) -> None:
    text = pack(entry("a", "name_label"))
    path = write(root, "packs/xo/a.yaml", text)
    types = root / "types" / "test.yaml"
    lf = load_rules(root).pack_version
    path.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    types.write_bytes(TYPES.replace("\n", "\r\n").encode("utf-8"))
    assert compute_pack_version(root) == lf
    assert load_rules(root).pack_version == lf
    path.write_bytes(text.replace("\n", "\r").encode("utf-8"))
    assert compute_pack_version(root) == lf
    path.write_bytes(text.replace("low", "high").replace("\n", "\r\n").encode("utf-8"))
    assert compute_pack_version(root) != lf


def test_the_version_of_a_yml_file_is_not_part_of_it(root: Path) -> None:
    before = load_rules(root).pack_version
    write(root, "packs/xo/a.yml", pack(entry("a", "name_label")))
    assert load_rules(root).pack_version == before


def test_the_version_changes_when_a_type_table_changes(root: Path) -> None:
    before = load_rules(root).pack_version
    write(root, "types/test.yaml", TYPES.replace("floor: high", "floor: critical"))
    assert load_rules(root).pack_version != before


def test_the_version_changes_when_a_file_is_added_removed_or_renamed(root: Path) -> None:
    base = load_rules(root).pack_version
    added = write(root, "packs/xo/a.yaml", pack(entry("a", "name_label")))
    with_file = load_rules(root).pack_version
    assert with_file != base
    renamed = added.rename(root / "packs" / "xo" / "z.yaml")
    assert load_rules(root).pack_version != with_file
    renamed.unlink()
    assert load_rules(root).pack_version == base


def test_the_version_of_no_files_is_the_hash_of_nothing(tmp_path: Path) -> None:
    assert compute_pack_version(tmp_path) == sha256(b"").hexdigest()[:12]
    assert load_rules(tmp_path).pack_version == "e3b0c44298fc"
