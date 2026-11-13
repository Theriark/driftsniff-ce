"""The Checkmk type table against fields a real Checkmk 2.5.0p14 Community site returned.

These are the paths the lab site answered on 2026-11-13 that the table did not name before (list
members share their list's path). Every one must be classified.
"""

import pytest

from driftsniff.core.normalize import FieldClass
from driftsniff.rules.loader import load_rules

REAL_PATHS_25 = {
    "checkmk-notification-rules": [
        "rule_config.contact_selection.restrict_by_custom_macros.state",
        "rule_config.conditions.event_console_alerts.state",
        "rule_config.conditions.match_exclude_service_groups.state",
        "rule_config.conditions.match_exclude_service_groups_regex.state",
        "rule_config.conditions.match_host_event_type.state",
        "rule_config.conditions.match_host_labels.state",
        "rule_config.conditions.match_host_tags.state",
        "rule_config.conditions.match_notification_comment.state",
        "rule_config.conditions.match_plugin_output.state",
        "rule_config.conditions.match_plugin_output.value",
        "rule_config.conditions.match_service_event_type.state",
        "rule_config.conditions.match_service_groups_regex.state",
        "rule_config.conditions.match_service_labels.state",
        "rule_config.conditions.match_service_levels.state",
        "rule_config.conditions.restrict_to_notification_numbers.state",
        "rule_config.conditions.throttle_periodic_notifications.state",
        "rule_config.conditions.match_host_event_type.value.acknowledgement_of_problem",
        "rule_config.conditions.match_host_event_type.value.alert_handler_execution_failed",
        "rule_config.conditions.match_host_event_type.value.alert_handler_execution_successful",
        "rule_config.conditions.match_host_event_type.value.any_down",
        "rule_config.conditions.match_host_event_type.value.any_unreachable",
        "rule_config.conditions.match_host_event_type.value.any_up",
        "rule_config.conditions.match_host_event_type.value.down_unreachable",
        "rule_config.conditions.match_host_event_type.value.down_up",
        "rule_config.conditions.match_host_event_type.value.start_or_end_of_flapping_state",
        "rule_config.conditions.match_host_event_type.value.start_or_end_of_scheduled_downtime",
        "rule_config.conditions.match_host_event_type.value.unreachable_down",
        "rule_config.conditions.match_host_event_type.value.unreachable_up",
        "rule_config.conditions.match_host_event_type.value.up_down",
        "rule_config.conditions.match_host_event_type.value.up_unreachable",
        "rule_config.conditions.match_service_event_type.value.acknowledgement_of_problem",
        "rule_config.conditions.match_service_event_type.value.alert_handler_execution_failed",
        "rule_config.conditions.match_service_event_type.value.alert_handler_execution_successful",
        "rule_config.conditions.match_service_event_type.value.any_crit",
        "rule_config.conditions.match_service_event_type.value.any_ok",
        "rule_config.conditions.match_service_event_type.value.any_unknown",
        "rule_config.conditions.match_service_event_type.value.any_warn",
        "rule_config.conditions.match_service_event_type.value.crit_ok",
        "rule_config.conditions.match_service_event_type.value.crit_unknown",
        "rule_config.conditions.match_service_event_type.value.crit_warn",
        "rule_config.conditions.match_service_event_type.value.ok_crit",
        "rule_config.conditions.match_service_event_type.value.ok_ok",
        "rule_config.conditions.match_service_event_type.value.ok_unknown",
        "rule_config.conditions.match_service_event_type.value.ok_warn",
        "rule_config.conditions.match_service_event_type.value.start_or_end_of_flapping_state",
        "rule_config.conditions.match_service_event_type.value.start_or_end_of_scheduled_downtime",
        "rule_config.conditions.match_service_event_type.value.unknown_crit",
        "rule_config.conditions.match_service_event_type.value.unknown_ok",
        "rule_config.conditions.match_service_event_type.value.unknown_warn",
        "rule_config.conditions.match_service_event_type.value.warn_crit",
        "rule_config.conditions.match_service_event_type.value.warn_ok",
        "rule_config.conditions.match_service_event_type.value.warn_unknown",
    ],
    "checkmk-users": [
        "start_url",
    ],
}


@pytest.mark.parametrize("resource", sorted(REAL_PATHS_25))
def test_every_field_a_real_2_5_site_added_is_classified(resource: str) -> None:
    table = load_rules().type_tables[resource]
    unclassified = [
        path
        for path in REAL_PATHS_25[resource]
        if table.field_class(path) is FieldClass.UNCLASSIFIED
    ]
    assert unclassified == []
