"""The Prometheus resources the collector reads and where it reads them.

Paths and answer shapes come from the Prometheus HTTP API documentation and the configuration
reference, read on 2026-11-12 (docs/vendor-notes/prometheus.md). No lab Prometheus was used.
Every answer is the API envelope ``{"status": "success", "data": ...}``. Three GETs feed eight
resources: the running configuration (YAML text in ``data.yaml``) gives four, the flags one and the
rule list three. Targets and their live state are never read.
"""

from dataclasses import dataclass
from typing import Final

VERSION_PATH: Final = "/api/v1/status/buildinfo"
CONFIG_PATH: Final = "/api/v1/status/config"
FLAGS_PATH: Final = "/api/v1/status/flags"
# Prometheus ignores a parameter it does not know, so an older server sends the alerts anyway;
# the type tables ignore them.
RULES_PATH: Final = "/api/v1/rules?exclude_alerts=true"

RESOURCE_GLOBAL: Final = "prometheus-global"
RESOURCE_SCRAPE_JOBS: Final = "prometheus-scrape-jobs"
RESOURCE_ALERTING: Final = "prometheus-alerting"
RESOURCE_REMOTE_WRITE: Final = "prometheus-remote-write"
RESOURCE_FLAGS: Final = "prometheus-flags"
RESOURCE_RULE_GROUPS: Final = "prometheus-rule-groups"
RESOURCE_ALERTING_RULES: Final = "prometheus-alerting-rules"
RESOURCE_RECORDING_RULES: Final = "prometheus-recording-rules"


@dataclass(frozen=True, slots=True)
class PrometheusResource:
    """One resource: its name in the type tables and the API path its objects come from."""

    name: str
    path: str


RESOURCES: Final = (
    PrometheusResource(RESOURCE_GLOBAL, CONFIG_PATH),
    PrometheusResource(RESOURCE_SCRAPE_JOBS, CONFIG_PATH),
    PrometheusResource(RESOURCE_ALERTING, CONFIG_PATH),
    PrometheusResource(RESOURCE_REMOTE_WRITE, CONFIG_PATH),
    PrometheusResource(RESOURCE_FLAGS, FLAGS_PATH),
    PrometheusResource(RESOURCE_RULE_GROUPS, RULES_PATH),
    PrometheusResource(RESOURCE_ALERTING_RULES, RULES_PATH),
    PrometheusResource(RESOURCE_RECORDING_RULES, RULES_PATH),
)

RESOURCE_PATHS: Final = {resource.name: resource for resource in RESOURCES}
