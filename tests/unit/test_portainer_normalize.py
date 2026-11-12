"""The reshaping the Portainer collector does before the pipeline sees the objects."""

from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.portainer.normalize import SETTINGS_KEY, prepare_objects


def test_access_maps_become_lists_keyed_by_id_in_number_order() -> None:
    raw: Any = [
        {
            "Id": 1,
            "UserAccessPolicies": {"10": {"RoleId": 0}, "9": {"RoleId": 1}},
            "TeamAccessPolicies": {},
        }
    ]
    (item,) = prepare_objects("portainer-environments", "Id", raw)
    assert item["UserAccessPolicies"] == [{"UserId": 9, "RoleId": 1}, {"UserId": 10, "RoleId": 0}]
    assert item["TeamAccessPolicies"] == []


def test_registry_accesses_are_reshaped_with_their_policies() -> None:
    raw: Any = [{"Id": 1, "RegistryAccesses": {"2": {"TeamAccessPolicies": {"1": {"RoleId": 0}}}}}]
    (item,) = prepare_objects("portainer-registries", "Id", raw)
    assert item["RegistryAccesses"] == [
        {"EnvironmentId": 2, "TeamAccessPolicies": [{"TeamId": 1, "RoleId": 0}]}
    ]


def test_tag_maps_keep_only_the_ids_that_are_true() -> None:
    raw: Any = [{"ID": 1, "Endpoints": {"3": True, "1": True, "2": False}, "EndpointGroups": None}]
    (item,) = prepare_objects("portainer-tags", "ID", raw)
    assert item["Endpoints"] == [1, 3]
    assert item["EndpointGroups"] is None


def test_the_settings_object_gets_its_fixed_key() -> None:
    (item,) = prepare_objects("portainer-settings", "Id", {"AuthenticationMethod": 1})
    assert item == {"AuthenticationMethod": 1, "Id": SETTINGS_KEY}


def test_objects_are_sorted_by_key_and_the_input_is_not_changed() -> None:
    raw: Any = [{"Id": 10, "UserAccessPolicies": {"1": {}}}, {"Id": 2}]
    result = prepare_objects("portainer-environments", "Id", raw)
    assert [item["Id"] for item in result] == [2, 10]
    assert raw[0]["UserAccessPolicies"] == {"1": {}}


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("portainer-users", {"Id": 1}),
        ("portainer-users", [{"Id": True}]),
        ("portainer-users", [{"Id": ""}]),
        ("portainer-users", ["text"]),
        ("portainer-settings", []),
    ],
)
def test_an_answer_of_the_wrong_shape_fails_the_resource(name: str, raw: object) -> None:
    with pytest.raises(CollectorError) as caught:
        prepare_objects(name, "Id", raw)  # type: ignore[arg-type]
    assert caught.value.error_class == ERROR_BAD_PAYLOAD
