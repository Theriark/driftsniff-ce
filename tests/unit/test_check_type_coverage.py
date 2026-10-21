"""Tests for scripts/check_type_coverage.py: every field a type table names has a class (P5-T4)."""

import textwrap
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from check_type_coverage import check_root, main, uncovered
from driftsniff.core.normalize import CollectionMode, FieldClass, StaticTypeTable

CONFIG = FieldClass.CONFIG
GOLDEN_ROOT = Path(__file__).resolve().parents[1] / "golden"


def table(
    classes: Mapping[str, FieldClass] | None = None,
    lists: Mapping[str, CollectionMode] | None = None,
    member_keys: Mapping[str, str] | None = None,
    key_field: str | None = "id",
    name_field: str | None = "name",
    action_field: str | None = None,
) -> StaticTypeTable:
    """A table keyed by id and named by name; by default only those two fields have a class."""
    return StaticTypeTable(
        object_key_field=key_field,
        name_field=name_field,
        field_classes={"id": CONFIG, "name": CONFIG} if classes is None else classes,
        collection_modes={} if lists is None else lists,
        item_key_fields={} if member_keys is None else member_keys,
        action_field=action_field,
    )


def test_a_table_whose_named_fields_all_have_a_class_passes() -> None:
    complete = table(
        classes={"id": CONFIG, "name": CONFIG, "action": CONFIG, "tags": CONFIG},
        lists={"tags": CollectionMode.SET},
        action_field="action",
    )
    assert uncovered({"things": complete}) == []


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"classes": {"name": CONFIG}}, "things: key_field 'id' has no class"),
        ({"classes": {"id": CONFIG}}, "things: name_field 'name' has no class"),
        ({"action_field": "action"}, "things: action_field 'action' has no class"),
        ({"lists": {"tags": CollectionMode.SET}}, "things: list 'tags' has no class"),
        (
            {
                "classes": {"id": CONFIG, "name": CONFIG, "rules": CONFIG},
                "lists": {"rules": CollectionMode.ORDERED_KEYED},
                "member_keys": {"rules": "rid"},
            },
            "things: member key 'rules.rid' of a list has no class",
        ),
        ({"classes": {}}, "things: no field has a class"),
    ],
    ids=["key", "name", "action", "list", "member-key", "empty"],
)
def test_a_field_without_a_class_is_reported(changes: dict[str, Any], expected: str) -> None:
    assert expected in uncovered({"things": table(**changes)})


def test_a_list_is_covered_by_a_classified_field_below_it() -> None:
    covered = table(
        classes={"id": CONFIG, "name": CONFIG, "certs.notAfter": CONFIG},
        lists={"certs": CollectionMode.SET},
    )
    assert uncovered({"hosts": covered}) == []


def test_a_field_that_only_shares_a_prefix_does_not_cover_a_list() -> None:
    tables = {
        "hosts": table(
            classes={"id": CONFIG, "name": CONFIG, "certsExtra": CONFIG},
            lists={"certs": CollectionMode.SET},
        )
    }
    assert uncovered(tables) == ["hosts: list 'certs' has no class"]


def test_the_problems_come_out_in_a_stable_order() -> None:
    broken = table(classes={})
    tables = {"zeta": broken, "alpha": broken}
    assert [problem.split(":")[0] for problem in uncovered(tables)] == ["alpha", "zeta"]


def test_the_shipped_type_tables_pass() -> None:
    count, problems = check_root(None)
    assert problems == []
    assert count > 0
    assert main([]) == 0


def test_the_test_only_golden_type_tables_pass() -> None:
    count, problems = check_root(GOLDEN_ROOT)
    assert problems == []
    assert count > 0


def test_main_fails_on_a_table_that_names_a_field_without_a_class(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "types").mkdir()
    broken = """
        version: 1
        types:
          - resource: things
            key_field: id
            name_field: label
            fields: {id: config}
    """
    (tmp_path / "types" / "broken.yaml").write_text(textwrap.dedent(broken), encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    assert "things: name_field 'label' has no class" in capsys.readouterr().err


def test_main_fails_on_a_root_without_type_tables(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(tmp_path)]) == 1
    assert "no type tables found" in capsys.readouterr().err


def test_main_reports_a_type_file_that_does_not_load(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "types").mkdir()
    bad = """
        version: 2
        types: []
    """
    (tmp_path / "types" / "bad.yaml").write_text(textwrap.dedent(bad), encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    assert "cannot load the rules" in capsys.readouterr().err
