"""The pure helpers of the Redfish collector: links, cleaning, BIOS objects, keys and version."""

from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.redfish.normalize import (
    bios_objects,
    clean,
    keyed,
    link_of,
    member_paths,
    safe_path,
    version_text,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/redfish/v1/Systems/System.Embedded.1", "/redfish/v1/Systems/System.Embedded.1"),
        ("/redfish/v1/Systems/1/", "/redfish/v1/Systems/1"),
        ("/redfish/v1/", "/redfish/v1"),
        ("https://bmc.example.invalid/redfish/v1/Systems", None),
        ("//elsewhere.invalid/redfish/v1", None),
        ("/redfish/v1/../../etc/passwd", None),
        ("/redfish/v1/Systems?$expand=*", None),
        ("/redfish/v1/Systems#x", None),
        ("/redfish/v1/a b", None),
        ("/redfish/v1/a\\b", None),
        ("/other/v1", None),
        ("/redfish/v1/" + "a" * 600, None),
        (7, None),
    ],
)
def test_only_plain_paths_of_the_service_are_followed(value: Any, expected: str | None) -> None:
    assert safe_path(value) == expected


def test_a_link_is_read_and_a_foreign_link_is_a_bad_payload() -> None:
    root: Any = {"Links": {"Sessions": {"@odata.id": "/redfish/v1/SessionService/Sessions"}}}
    assert link_of(root, "Links", "Sessions") == "/redfish/v1/SessionService/Sessions"
    assert link_of(root, "Systems") is None
    with pytest.raises(CollectorError) as caught:
        link_of({"Systems": {"@odata.id": "http://evil.invalid/"}}, "Systems")
    assert caught.value.error_class == ERROR_BAD_PAYLOAD
    with pytest.raises(CollectorError):
        member_paths({"Members": [{"@odata.id": "/redfish/v1/x"}, {"Name": "no link"}]})
    assert member_paths({}) == []


def test_clean_drops_annotations_and_links_and_keeps_values() -> None:
    raw: Any = {
        "@odata.id": "/redfish/v1/Systems/1",
        "@odata.etag": 'W/"1"',
        "Id": "1",
        "Bios": {"@odata.id": "/redfish/v1/Systems/1/Bios"},
        "PCIeDevices": [{"@odata.id": "/a"}, {"@odata.id": "/b"}],
        "PCIeDevices@odata.count": 2,
        "Boot": {
            "BootOrder": ["Boot0001"],
            "BootSourceOverrideTarget": "None",
            "BootSourceOverrideTarget@Redfish.AllowableValues": ["None", "Pxe"],
        },
        "Empty": {},
        "Mixed": [{"@odata.id": "/a"}, {"Name": "x", "@odata.id": "/b"}],
    }
    assert clean(raw) == {
        "Id": "1",
        "Boot": {"BootOrder": ["Boot0001"], "BootSourceOverrideTarget": "None"},
        "Empty": {},
        "Mixed": [{"Name": "x"}],
    }


def test_bios_attributes_become_objects_and_passwords_a_secret_field() -> None:
    bios: Any = {
        "Attributes": {
            "ProcVirtualization": "Enabled",
            "SysPwd": None,
            "AdminPassword": "x",
            "Nested": {"a": 1},
            "Attr@Redfish.AllowableValues": ["a"],
        }
    }
    objects: dict[Any, Any] = {item["Attribute"]: item for item in bios_objects("1", bios)}
    assert sorted(objects) == ["AdminPassword", "ProcVirtualization", "SysPwd"]
    assert objects["ProcVirtualization"]["value"] == "Enabled"
    assert objects["AdminPassword"] == {
        "ObjectKey": "1/AdminPassword",
        "System": "1",
        "Attribute": "AdminPassword",
        "secret_value": "x",
    }
    assert "value" not in objects["SysPwd"]
    with pytest.raises(CollectorError):
        bios_objects("1", {"Id": "Bios"})


def test_keyed_sorts_and_refuses_missing_or_duplicate_keys() -> None:
    assert [item["Id"] for item in keyed([{"Id": "b"}, {"Id": "a"}], "Id")] == ["a", "b"]
    cases: list[Any] = [[{"Id": ""}], [{"Id": 1}], [{"Id": "a"}, {"Id": "a"}]]
    for objects in cases:
        with pytest.raises(CollectorError):
            keyed(objects, "Id")


def test_the_version_keeps_only_plain_text() -> None:
    root: Any = {"Vendor": "Dell", "Product": "Integrated Dell Remote Access Controller"}
    root["RedfishVersion"] = "1.17.0"
    assert (
        version_text(root, "7.00.00.171")
        == "Dell Integrated Dell Remote Access Controller 7.00.00.171 (Redfish 1.17.0)"
    )
    assert version_text({"RedfishVersion": "1.6.0", "Vendor": "<b>x</b>"}, None) == "Redfish 1.6.0"
    assert version_text({}, None) is None
