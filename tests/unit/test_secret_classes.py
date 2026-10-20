"""Field classes: names, parsing and what each class means for storage and display."""

import pytest

from driftsniff.db.tables import FIELD_CLASSES
from driftsniff.secrets.classes import (
    FIELD_CLASS_NAMES,
    FieldClass,
    is_fingerprinted,
    is_shown_as_fingerprint,
    parse_field_class,
)


def test_the_four_classes_match_the_database_check_constraint() -> None:
    assert sorted(FIELD_CLASS_NAMES) == sorted(FIELD_CLASSES)
    assert len(FIELD_CLASS_NAMES) == 4


@pytest.mark.parametrize("member", list(FieldClass))
def test_every_class_parses_from_its_name(member: FieldClass) -> None:
    assert parse_field_class(member.value) is member


@pytest.mark.parametrize("name", ["", "Secret", "password", "config "])
def test_an_unknown_class_name_is_refused_and_lists_the_choices(name: str) -> None:
    with pytest.raises(ValueError, match="unknown field class") as raised:
        parse_field_class(name)
    for known in FIELD_CLASS_NAMES:
        assert known in str(raised.value)


def test_only_the_secret_class_is_stored_as_a_fingerprint() -> None:
    assert [member for member in FieldClass if is_fingerprinted(member)] == [FieldClass.SECRET]


def test_secret_and_unclassified_changes_are_shown_as_fingerprints() -> None:
    shown = {member for member in FieldClass if is_shown_as_fingerprint(member)}
    assert shown == {FieldClass.SECRET, FieldClass.UNCLASSIFIED}
