"""The collector factory builds the Portainer collector for a portainer source."""

from driftsniff.collectors.portainer.client import PortainerClient
from driftsniff.collectors.portainer.resources import RESOURCES
from driftsniff.sources.factory import ResourceFilter, build_collector
from driftsniff.web.source_pages import CREDENTIAL_LABELS, resources_of

ADDRESS = "https://portainer.example.invalid:9443"
CANARY = b"ptr_CANARYfactoryToken01"


def test_a_portainer_source_gets_the_portainer_collector() -> None:
    collector = build_collector("portainer", ADDRESS, CANARY, {})
    try:
        assert isinstance(collector, PortainerClient)
        assert [spec.name for spec in collector.resources()] == [r.name for r in RESOURCES]
    finally:
        collector.close()


def test_a_resource_turned_off_is_not_listed() -> None:
    collector = build_collector(
        "portainer", ADDRESS, CANARY, {"resources_off": ["portainer-stacks"]}
    )
    try:
        assert isinstance(collector, ResourceFilter)
        assert "portainer-stacks" not in [spec.name for spec in collector.resources()]
    finally:
        collector.close()


def test_the_source_pages_know_the_portainer_type() -> None:
    assert CREDENTIAL_LABELS["portainer"] == "Access token"
    assert resources_of("portainer", {}) == tuple(r.name for r in RESOURCES)
