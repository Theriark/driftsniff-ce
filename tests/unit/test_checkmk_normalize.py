"""How the Checkmk collector reshapes domain objects before the pipeline sees them."""

import copy
from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.checkmk.normalize import prepare_objects


def collection(*objects: Any) -> Any:
    return {"id": "host", "domainType": "host_config", "links": [], "value": list(objects)}


def domain(ident: str, title: str, extensions: Any) -> dict[str, Any]:
    return {
        "links": [{"rel": "self"}],
        "domainType": "host_config",
        "id": ident,
        "title": title,
        "members": {},
        "extensions": extensions,
    }


def test_extensions_are_lifted_and_navigation_is_dropped() -> None:
    raw = collection(domain("web-01", "Web 1", {"folder": "/", "attributes": {}, "id": "x"}))
    (host,) = prepare_objects("checkmk-hosts", raw)
    assert host == {"id": "web-01", "title": "Web 1", "folder": "/", "attributes": {}}


def test_labels_and_tags_of_hosts_and_folders_become_keyed_lists() -> None:
    attributes = {
        "ipaddress": "192.0.2.10",
        "labels": {"os": "linux", "env": "prod"},
        "tag_criticality": "prod",
        "tag_agent": "cmk-agent",
        "tag_": "kept as it is",
    }
    for name in ("checkmk-hosts", "checkmk-folders"):
        (item,) = prepare_objects(name, collection(domain("a", "a", {"attributes": attributes})))
        assert item["attributes"] == {
            "ipaddress": "192.0.2.10",
            "labels": [{"key": "env", "value": "prod"}, {"key": "os", "value": "linux"}],
            "tags": [
                {"group": "agent", "value": "cmk-agent"},
                {"group": "criticality", "value": "prod"},
            ],
            "tag_": "kept as it is",
        }


def test_other_resources_keep_their_attributes() -> None:
    raw = collection(domain("ops", "Ops", {"attributes": {"tag_x": "y"}}))
    (item,) = prepare_objects("checkmk-contact-groups", raw)
    assert item["attributes"] == {"tag_x": "y"}


def test_the_plugin_name_of_a_notification_rule_is_copied_out_of_its_parameters() -> None:
    params = {"plugin_name": "slack", "webhook_url": "secret"}
    rule = {"rule_config": {"notification_method": {"notify_plugin": {"plugin_params": params}}}}
    items: Any = prepare_objects("checkmk-notification-rules", collection(domain("r1", "R", rule)))
    plugin = items[0]["rule_config"]["notification_method"]["notify_plugin"]
    assert plugin == {"plugin_name": "slack", "plugin_params": params}


def test_objects_are_sorted_by_id_and_the_input_is_not_changed() -> None:
    rule = {
        "rule_config": {
            "notification_method": {"notify_plugin": {"plugin_params": {"plugin_name": "mail"}}}
        }
    }
    raw = collection(
        domain("b", "b", {"attributes": {"labels": {"x": "1"}}}),
        domain("a", "a", rule),
    )
    before = copy.deepcopy(raw)
    assert [item["id"] for item in prepare_objects("checkmk-hosts", raw)] == ["a", "b"]
    prepare_objects("checkmk-notification-rules", raw)
    assert raw == before


@pytest.mark.parametrize(
    "raw",
    [
        [],
        {"value": {}},
        {"value": ["x"]},
        {"value": [{"title": "no id"}]},
        {"value": [{"id": ""}]},
        {"value": [{"id": 3}]},
        {"value": [{"id": "a", "extensions": []}]},
    ],
)
def test_an_answer_of_the_wrong_shape_fails_the_resource(raw: Any) -> None:
    with pytest.raises(CollectorError) as caught:
        prepare_objects("checkmk-hosts", raw)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD
