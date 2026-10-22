"""The small pieces of the Xen Orchestra collector (P8-T2): paths, field list, clean up, expiry.

No server is needed here; ``tests/contract/test_xo_client.py`` runs the client against a fake one.
"""

from datetime import UTC, date, datetime, timedelta
from urllib.parse import parse_qs

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.resolve import ERROR_BLOCKED_ADDRESS, check_address
from driftsniff.collectors.xo.client import entered_expiry, expiry_is_near
from driftsniff.collectors.xo.normalize import prepare_objects, strip_url_credentials
from driftsniff.collectors.xo.resources import (
    COLLECTIONS,
    EXCLUDED_COLLECTIONS,
    collection_path,
    collection_query,
    field_list,
)
from driftsniff.core.canonical import JsonValue
from driftsniff.rules.loader import load_rules
from driftsniff.rules.schema import TypeSpec

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
TABLES = load_rules().type_tables


def test_the_collections_and_the_excluded_ones_do_not_overlap() -> None:
    assert not set(COLLECTIONS) & set(EXCLUDED_COLLECTIONS)
    assert len(set(COLLECTIONS)) == len(COLLECTIONS)
    assert len(EXCLUDED_COLLECTIONS) == 15


@pytest.mark.parametrize("name", COLLECTIONS)
def test_a_collection_has_a_path_and_a_type_table(name: str) -> None:
    assert collection_path(name) == f"/{name}"
    assert name in TABLES


@pytest.mark.parametrize("name", [*EXCLUDED_COLLECTIONS, "", "unknown", "../vms", "vms/1"])
def test_an_excluded_or_unknown_collection_has_no_path(name: str) -> None:
    with pytest.raises(ValueError, match="not read"):
        collection_path(name)


def test_the_field_list_has_the_first_segment_of_every_kept_field_sorted() -> None:
    table = TypeSpec.model_validate(
        {
            "resource": "vms",
            "key_field": "id",
            "fields": {
                "id": "config",
                "name_label": "config",
                "memory.static": "config",
                "memory.usage": "ignore",
                "uuid": "ignore",
                "authProviders": "secret",
            },
        }
    ).to_table()
    assert field_list("vms", table) == "authProviders,id,memory,name_label"


def test_the_field_list_always_has_the_key_and_a_collection_may_add_a_field() -> None:
    table = TypeSpec.model_validate(
        {"resource": "vm-templates", "fields": {"name_label": "config", "uuid": "ignore"}}
    ).to_table()
    assert field_list("vms", table) == "id,name_label"
    assert field_list("vm-templates", table) == "id,isDefaultTemplate,name_label"


def test_the_shipped_field_lists_name_no_ignore_class_only_field() -> None:
    for name in COLLECTIONS:
        requested = set(field_list(name, TABLES[name]).split(","))
        assert "id" in requested, name
        assert not requested & {"uuid", "_xapiRef", "power_state", "snapshots", "VDIs"}, name


def test_the_query_asks_for_the_fields_and_ndjson_only() -> None:
    assert parse_qs(collection_query("id,name_label")) == {
        "fields": ["id,name_label"],
        "ndjson": ["true"],
    }


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("smb://svc:secret@backup-a.example.test/share", "smb://backup-a.example.test/share"),
        ("nfs://backup-b.example.test/share", "nfs://backup-b.example.test/share"),
        ("https://u:p@host.example.test:8443/x?y=z", "https://host.example.test:8443/x?y=z"),
        ("a@b.example.test", "a@b.example.test"),
        ("", ""),
    ],
)
def test_the_user_and_password_part_of_an_address_is_removed(text: str, expected: str) -> None:
    assert strip_url_credentials(text) == expected


def test_every_address_in_a_text_is_cleaned() -> None:
    text = "from smb://a:b@one.example.test/x to smb://c:d@two.example.test/y"
    expected = "from smb://one.example.test/x to smb://two.example.test/y"
    assert strip_url_credentials(text) == expected


def test_the_objects_are_sorted_by_id() -> None:
    raw = [{"id": "b"}, {"id": "a"}, {"id": "c"}]
    assert [item["id"] for item in prepare_objects("vms", raw)] == ["a", "b", "c"]


def test_only_templates_drop_the_built_in_ones() -> None:
    raw = [{"id": "a", "isDefaultTemplate": True}, {"id": "b", "isDefaultTemplate": False}]
    assert [item["id"] for item in prepare_objects("vm-templates", raw)] == ["b"]
    assert [item["id"] for item in prepare_objects("vms", raw)] == ["a", "b"]


def test_only_repositories_have_their_address_cleaned() -> None:
    raw = [{"id": "a", "url": "smb://u:p@h.example.test/s"}]
    assert prepare_objects("backup-repositories", raw)[0]["url"] == "smb://h.example.test/s"
    other = [{"id": "a", "url": "smb://u:p@h.example.test/s"}]
    assert prepare_objects("proxies", other)[0]["url"] == "smb://u:p@h.example.test/s"


@pytest.mark.parametrize("bad", [[1], ["text"], [None], [{"name": "no id"}], [{"id": 3}]])
def test_a_value_that_is_not_an_object_with_a_text_id_is_a_bad_payload(
    bad: list[JsonValue],
) -> None:
    with pytest.raises(CollectorError) as caught:
        prepare_objects("vms", bad)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


def test_an_entered_date_means_the_end_of_that_day_in_utc() -> None:
    assert entered_expiry(None) is None
    assert entered_expiry(date(2026, 11, 1)) == datetime(2026, 11, 1, 23, 59, 59, tzinfo=UTC)
    assert entered_expiry(datetime(2026, 11, 1, 8, 0)) == datetime(2026, 11, 1, 8, 0, tzinfo=UTC)
    stamped = datetime(2026, 11, 1, 8, 0, tzinfo=UTC)
    assert entered_expiry(stamped) is stamped


@pytest.mark.parametrize(
    ("delta", "near"),
    [
        (timedelta(days=-1), True),
        (timedelta(0), True),
        (timedelta(days=14), True),
        (timedelta(days=14, seconds=1), False),
        (timedelta(days=365), False),
    ],
)
def test_an_expiry_within_14_days_or_past_is_near(delta: timedelta, near: bool) -> None:
    assert expiry_is_near(NOW + delta, NOW) is near


def test_no_known_expiry_is_never_near() -> None:
    assert expiry_is_near(None, NOW) is False


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "100.100.100.200",
        "fe80::1",
        "fe80::1%eth0",
    ],
)
def test_a_blocked_address_is_refused(address: str) -> None:
    with pytest.raises(CollectorError) as caught:
        check_address("https://xo.example.test", lambda host: [address])
    assert caught.value.error_class == ERROR_BLOCKED_ADDRESS


def test_an_unusable_address_is_refused_and_an_ordinary_one_passes() -> None:
    with pytest.raises(CollectorError) as caught:
        check_address("https://xo.example.test", lambda host: ["not-an-address"])
    assert caught.value.error_class == ERROR_BLOCKED_ADDRESS
    check_address("https://xo.example.test", lambda host: ["192.0.2.10", "2001:db8::10"])
