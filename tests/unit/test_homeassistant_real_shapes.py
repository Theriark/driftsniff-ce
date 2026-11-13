"""Home Assistant against what a real Home Assistant 2026.10.4 returned (2026-11-13).

The entity paths below were unclassified on that system. The id fields listed in
``rules/overrides.yaml`` hold ULIDs, MAC addresses and long entity ids that the high-entropy rule
took for secrets; the overrides silence that rule there and nothing else.
"""

import pytest

from driftsniff.core.normalize import FieldClass
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.scanner import ScanRule, load_overrides

REAL_ENTITY_PATHS = [
    "categories.automation",
    "has_entity_name",
    "options.battery_notes.entity_id",
    "options.collection.hash",
    "options.sensor.display_precision",
    "options.sensor.private.suggested_unit_of_measurement",
    "options.sensor.suggested_display_precision",
    "options.sensor.unit_of_measurement",
]

ID_PATHS = [
    ("homeassistant-entities", "unique_id"),
    ("homeassistant-entities", "entity_id"),
    ("homeassistant-entities", "config_entry_id"),
    ("homeassistant-entities", "config_subentry_id"),
    ("homeassistant-entities", "categories.automation"),
    ("homeassistant-entities", "options.battery_notes.entity_id"),
    ("homeassistant-integrations", "entry_id"),
]


def test_every_entity_field_a_real_system_added_is_classified() -> None:
    table = load_rules().type_tables["homeassistant-entities"]
    unclassified = [
        path for path in REAL_ENTITY_PATHS if table.field_class(path) is FieldClass.UNCLASSIFIED
    ]
    assert unclassified == []


@pytest.mark.parametrize(("resource", "path"), ID_PATHS)
def test_ids_are_exempt_from_the_entropy_rule_only(resource: str, path: str) -> None:
    overrides = load_overrides()
    assert overrides.suppresses(resource, path, ScanRule.HIGH_ENTROPY)
    assert not overrides.suppresses(resource, path, ScanRule.JWT)
    assert not overrides.suppresses(resource, path, ScanRule.PREFIXED_CREDENTIAL)
