"""Subtree classes in type tables: a class for every undeclared path below a path."""

import pytest
from pydantic import ValidationError

from driftsniff.core.normalize import FieldClass, StaticTypeTable
from driftsniff.rules.loader import load_rules
from driftsniff.rules.schema import TypeSpec

TABLE = StaticTypeTable(
    field_classes={
        "panels.token": FieldClass.SECRET,
        "panels.cache": FieldClass.IGNORE,
        "name": FieldClass.CONFIG,
    },
    subtree_classes={"panels": FieldClass.CONFIG, "panels.private": FieldClass.IGNORE},
)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("panels", FieldClass.CONFIG),
        ("panels.options.legend.mode", FieldClass.CONFIG),
        ("panels.token", FieldClass.SECRET),
        ("panels.cache", FieldClass.IGNORE),
        ("panels.private.state", FieldClass.IGNORE),
        ("name", FieldClass.CONFIG),
        ("panelsx.y", FieldClass.UNCLASSIFIED),
        ("other.panels.x", FieldClass.UNCLASSIFIED),
    ],
)
def test_the_nearest_subtree_classes_an_undeclared_path(path: str, expected: FieldClass) -> None:
    assert TABLE.field_class(path) is expected


def test_a_table_without_subtrees_is_unchanged() -> None:
    assert StaticTypeTable().field_class("a.b") is FieldClass.UNCLASSIFIED


def test_a_subtree_path_is_checked_like_a_field_path() -> None:
    with pytest.raises(ValidationError):
        TypeSpec.model_validate(
            {"resource": "x-things", "fields": {"id": "config"}, "subtrees": {"a.*": "config"}}
        )


@pytest.mark.parametrize(
    ("resource", "path", "expected"),
    [
        # Paths a real Grafana 13.3.0 returned inside dashboard panels (2026-11-13).
        ("grafana-dashboards", "dashboard.panels.fieldConfig.defaults.color.mode", "config"),
        ("grafana-dashboards", "dashboard.panels.transformations.options.indexByName", "config"),
        ("grafana-dashboards", "dashboard.panels.gridPos.h", "config"),
        ("grafana-dashboards", "dashboard.uid", "ignore"),
        ("grafana-alert-rules", "labels.notification_owner", "config"),
        ("grafana-datasources", "secureJsonData", "secret"),
        ("checkmk-notification-rules", "rule_config.conditions.match_host_labels.value", "config"),
        (
            "checkmk-notification-rules",
            "rule_config.notification_method.notify_plugin.plugin_params",
            "secret",
        ),
        ("homeassistant-entities", "options.sensor.suggested_display_precision", "ignore"),
        ("homeassistant-entities", "options.light.some_integration_option", "config"),
    ],
)
def test_shipped_subtrees(resource: str, path: str, expected: str) -> None:
    assert load_rules().type_tables[resource].field_class(path).value == expected
