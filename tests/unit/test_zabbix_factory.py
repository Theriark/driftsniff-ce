"""The collector factory builds the Zabbix collector for a zabbix source."""

from driftsniff.collectors.zabbix.client import ZabbixClient
from driftsniff.collectors.zabbix.resources import RESOURCES
from driftsniff.sources.factory import ResourceFilter, build_collector
from driftsniff.web.dashboard import RESOURCE_LABELS
from driftsniff.web.source_pages import CREDENTIAL_LABELS, resources_of

ADDRESS = "https://zabbix.example.invalid/zabbix"
CANARY = b"CANARY-zabbix-02"


def test_a_zabbix_source_gets_the_zabbix_collector() -> None:
    collector = build_collector("zabbix", ADDRESS, CANARY, {})
    try:
        assert isinstance(collector, ZabbixClient)
        assert [spec.name for spec in collector.resources()] == [r.name for r in RESOURCES]
    finally:
        collector.close()


def test_a_resource_turned_off_is_not_listed() -> None:
    collector = build_collector("zabbix", ADDRESS, CANARY, {"resources_off": ["zabbix-triggers"]})
    try:
        assert isinstance(collector, ResourceFilter)
        assert "zabbix-triggers" not in [spec.name for spec in collector.resources()]
    finally:
        collector.close()


def test_the_source_pages_know_the_zabbix_type() -> None:
    assert CREDENTIAL_LABELS["zabbix"] == "API token"
    assert resources_of("zabbix", {}) == tuple(r.name for r in RESOURCES)
    assert all(r.name in RESOURCE_LABELS for r in RESOURCES)
