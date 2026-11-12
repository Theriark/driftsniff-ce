"""The pure helpers of the Synology collector: credential, answers, keys and the guest view."""

from typing import Any

import pytest

from driftsniff.collectors.base import CollectorError
from driftsniff.collectors.synology.normalize import (
    guest_access,
    keyed,
    objects_of,
    share_object,
    split_credential,
)


def test_the_credential_splits_at_the_first_colon() -> None:
    assert split_credential("reader:pa:ss") == ("reader", "pa:ss")


@pytest.mark.parametrize("bad", ["reader", "reader:", ":secret", "re\nader:secret"])
def test_a_credential_without_both_parts_is_refused_without_its_text(bad: str) -> None:
    with pytest.raises(ValueError) as caught:
        split_credential(bad)
    assert "secret" not in str(caught.value)


def test_a_settings_answer_is_one_object_with_the_settings_key() -> None:
    assert objects_of({"enable_ssh": True}, None) == [
        {"enable_ssh": True, "object_key": "settings"}
    ]


def test_a_list_answer_is_read_under_its_key_or_as_the_data_itself() -> None:
    assert objects_of({"users": [{"name": "a"}], "total": 1}, "users") == [{"name": "a"}]
    assert objects_of([{"ifname": "eth0"}], "") == [{"ifname": "eth0"}]


@pytest.mark.parametrize(
    ("data", "list_key"), [([], None), ({"users": {}}, "users"), ({"users": [1]}, "users")]
)
def test_an_answer_of_the_wrong_shape_is_a_bad_payload(data: object, list_key: str | None) -> None:
    with pytest.raises(CollectorError) as caught:
        objects_of(data, list_key)  # type: ignore[arg-type]
    assert caught.value.error_class == "bad_payload"


def test_objects_are_sorted_by_key_and_a_missing_or_repeated_key_fails() -> None:
    assert keyed([{"name": "b"}, {"name": "a"}], "name") == [{"name": "a"}, {"name": "b"}]
    for objects in ([{"name": ""}], [{"name": "a"}, {"name": "a"}], [{"id": 1}]):
        with pytest.raises(CollectorError):
            keyed(objects, "name")  # type: ignore[arg-type]


def test_a_share_carries_one_permission_list_per_principal_type() -> None:
    built = share_object({"name": "media"}, {"local_user": [{"name": "bob"}], "local_group": []})
    assert built == {
        "name": "media",
        "permissions_local_user": [{"name": "bob"}],
        "permissions_local_group": [],
    }


def row(**flags: bool) -> dict[str, Any]:
    base = {"name": "guest", "is_readonly": False, "is_writable": False, "is_deny": False}
    return {**base, **flags}


def test_guest_access_is_listed_only_when_guest_may_read_or_write() -> None:
    assert guest_access("public", [row()]) is None
    assert guest_access("public", [row(is_readonly=True, is_deny=True)]) is None
    assert guest_access("public", [{**row(is_readonly=True), "name": "bob"}]) is None
    assert guest_access("public", [row(is_writable=True)]) == {
        "share": "public",
        "is_readonly": False,
        "is_writable": True,
    }
