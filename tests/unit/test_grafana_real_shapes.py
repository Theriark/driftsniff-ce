"""The Grafana type table against fields a real Grafana 13.3.0 returned (2026-11-13).

These are the paths with a fixed name that the table did not hold. Dashboard panel internals,
alert labels and plugin specific data source settings vary per panel, rule or plugin and are not
listed here.
"""

import pytest

from driftsniff.core.normalize import FieldClass
from driftsniff.rules.loader import load_rules

REAL_PATHS_13 = {
    "grafana-datasources": [
        "jsonData.allowDangerousHTTPMethods",
        "jsonData.allowedHosts",
        "jsonData.auth_method",
        "jsonData.backend",
        "jsonData.customHealthCheckEnabled",
        "jsonData.customHealthCheckUrl",
        "jsonData.edition",
        "jsonData.httpHeaderName1",
        "jsonData.httpMethod",
        "jsonData.timeInterval",
        "jsonData.timeoutInSeconds",
        "jsonData.url",
        "jsonData.username",
    ],
    "grafana-folders": [
        "isDeleted",
    ],
    "grafana-alert-rules": [
        "keep_firing_for",
        "annotations.summary",
        "annotations.description",
        "annotations.runbook_url",
        "data.relativeTimeRange.from",
        "data.relativeTimeRange.to",
        "data.model.refId",
        "data.model.type",
        "data.model.datasource.type",
        "data.model.datasource.uid",
        "data.model.expr",
        "data.model.expression",
        "data.model.instant",
        "data.model.range",
        "data.model.intervalMs",
        "data.model.maxDataPoints",
    ],
    "grafana-dashboards": [
        "dashboard.description",
        "dashboard.editable",
        "dashboard.graphTooltip",
        "dashboard.refresh",
        "dashboard.time.from",
        "dashboard.time.to",
        "dashboard.timepicker.refresh_intervals",
        "dashboard.timepicker.time_options",
    ],
    "grafana-org-users": [
        "uid",
        "isExternallySynced",
        "isProvisioned",
        "created",
    ],
}


@pytest.mark.parametrize("resource", sorted(REAL_PATHS_13))
def test_every_fixed_field_a_real_13_3_server_added_is_classified(resource: str) -> None:
    table = load_rules().type_tables[resource]
    unclassified = [
        path
        for path in REAL_PATHS_13[resource]
        if table.field_class(path) is FieldClass.UNCLASSIFIED
    ]
    assert unclassified == []
