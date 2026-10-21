"""The push collector (collectors/push.py): body parsing and the declared-field allow-list."""

import json

import pytest

from driftsniff.collectors.base import ResourceSpec
from driftsniff.collectors.push import (
    MAX_PUSH_BODY_BYTES,
    PUSH_HEADER,
    PushBodyError,
    PushCollector,
    parse_push_body,
)
from driftsniff.core.canonical import JsonValue

CANARY_NOTE = "CANARY-push-undeclared-note-0001"
FIELDS = {"networks": ["_id", "name", "vlan"], "hosts": ["id"]}


def test_the_limits_are_the_ones_of_the_plan() -> None:
    assert MAX_PUSH_BODY_BYTES == 10 * 1024 * 1024
    assert PUSH_HEADER == "X-Driftsniff-Push-Key"


def test_a_good_body_parses_to_resource_names_and_object_lists() -> None:
    body = json.dumps({"networks": [{"_id": "n1", "vlan": 10}], "hosts": []}).encode()
    assert parse_push_body(body) == {"networks": [{"_id": "n1", "vlan": 10}], "hosts": []}
    assert parse_push_body(b"{}") == {}


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"\xff\xfe",
        b"[]",
        b'"text"',
        b'{"networks": {"_id": "n1"}}',
        b'{"networks": ["n1"]}',
        b'{"networks": [[1]]}',
        b'{"networks": [], "networks": []}',
        b'{"networks": [{"a": 1, "a": 2}]}',
        b'{"networks": [{"vlan": NaN}]}',
        b'{"networks": [{"vlan": Infinity}]}',
        b'{"networks": [{"vlan": -Infinity}]}',
        b"[" * 100000,
    ],
)
def test_a_body_that_is_not_resource_lists_is_refused(body: bytes) -> None:
    with pytest.raises(PushBodyError):
        parse_push_body(body)


def test_a_parse_error_never_repeats_the_body() -> None:
    body = json.dumps({"networks": {"note": CANARY_NOTE}}).encode()
    with pytest.raises(PushBodyError) as error:
        parse_push_body(body)
    assert CANARY_NOTE not in str(error.value)


def objects() -> dict[str, list[dict[str, JsonValue]]]:
    return {
        "networks": [
            {"_id": "n1", "name": "Lab", "vlan": 10, "notes": CANARY_NOTE},
            {"_id": "n2", "name": "Guest", "uptime": 5},
        ],
        "hosts": [{"id": 1, "ip": "10.0.0.5"}],
        "extra": [{"id": 9}],
    }


def test_only_declared_fields_of_declared_resources_are_handed_on() -> None:
    collector = PushCollector(objects(), FIELDS, body_bytes=321)
    assert collector.probe() is None
    assert [spec.name for spec in collector.resources()] == ["hosts", "networks"]
    hosts = collector.fetch(ResourceSpec("hosts"))
    networks = collector.fetch(ResourceSpec("networks"))
    assert hosts.ok
    assert networks.ok
    assert list(hosts.objects) == [{"id": 1}]
    assert list(networks.objects) == [
        {"_id": "n1", "name": "Lab", "vlan": 10},
        {"_id": "n2", "name": "Guest"},
    ]
    assert CANARY_NOTE not in repr(networks.objects)


def test_an_undeclared_resource_is_ignored_and_counted() -> None:
    collector = PushCollector(objects(), FIELDS)
    assert collector.ignored_resources == 1
    assert "extra" not in [spec.name for spec in collector.resources()]


def test_a_declared_resource_missing_from_the_body_is_not_listed() -> None:
    collector = PushCollector({"hosts": [{"id": 1}]}, FIELDS)
    assert [spec.name for spec in collector.resources()] == ["hosts"]
    assert collector.ignored_resources == 0


def test_the_body_size_is_reported_once() -> None:
    collector = PushCollector(objects(), FIELDS, body_bytes=321)
    first = collector.fetch(ResourceSpec("hosts"))
    second = collector.fetch(ResourceSpec("networks"))
    assert (first.bytes_fetched, second.bytes_fetched) == (321, 0)


def test_the_source_data_is_not_changed() -> None:
    document = objects()
    collector = PushCollector(document, FIELDS)
    collector.fetch(ResourceSpec("networks"))
    assert document == objects()
