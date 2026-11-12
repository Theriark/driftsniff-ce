"""What the Prometheus collector makes of the configuration, flags and rule answers."""

from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.prometheus.normalize import (
    config_objects,
    flag_field,
    flags_object,
    hide_url_password,
    parse_yaml,
    rules_objects,
)


def test_yaml_scalars_that_are_not_json_stay_as_written() -> None:
    assert parse_yaml("a: 2026-11-12\nb: 1m\nc: true\n") == {
        "a": "2026-11-12",
        "b": "1m",
        "c": True,
    }
    assert parse_yaml("") == {}


def test_a_document_that_is_too_deep_is_refused() -> None:
    with pytest.raises(CollectorError) as caught:
        parse_yaml("[" * 100 + "]" * 100)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://u:pw@h.example.invalid/x", "https://u:<secret>@h.example.invalid/x"),
        ("https://:pw@h.example.invalid", "https://:<secret>@h.example.invalid"),
        ("https://h.example.invalid/x", "https://h.example.invalid/x"),
        ("https://u@h.example.invalid", "https://u@h.example.invalid"),
    ],
)
def test_a_password_in_a_url_is_hidden(url: str, expected: str) -> None:
    assert hide_url_password(url) == expected


def test_an_empty_configuration_still_gives_the_two_single_objects() -> None:
    found = config_objects({})
    assert found["prometheus-global"] == [{"id": "global", "global": {}}]
    assert found["prometheus-alerting"] == [{"id": "alerting"}]
    assert found["prometheus-scrape-jobs"] == found["prometheus-remote-write"] == []


def test_remote_write_targets_are_keyed_by_name_else_by_url() -> None:
    doc: Any = {
        "remote_write": [
            {"url": "https://b.example.invalid"},
            {"url": "https://a.example.invalid", "name": "z"},
        ]
    }
    targets = config_objects(doc)["prometheus-remote-write"]
    assert [target["id"] for target in targets] == ["https://b.example.invalid", "z"]


def test_flag_names_lose_their_dots_and_dashes() -> None:
    assert flag_field("web.enable-admin-api") == "web_enable_admin_api"
    assert flags_object({"log.level": "info"}) == [{"id": "flags", "log_level": "info"}]


def test_rules_are_split_by_type_and_repeated_names_are_numbered() -> None:
    rule: Any = {"name": "r", "query": "x", "type": "recording", "labels": {"b": "2", "a": "1"}}
    data: Any = {"groups": [{"name": "g", "file": "f.yml", "interval": 60, "rules": [rule, rule]}]}
    found = rules_objects(data)
    assert found["prometheus-rule-groups"] == [
        {"name": "g", "file": "f.yml", "interval": 60, "id": "f.yml / g"}
    ]
    assert [item["id"] for item in found["prometheus-recording-rules"]] == [
        "f.yml / g / r",
        "f.yml / g / r #2",
    ]
    assert found["prometheus-recording-rules"][0]["labels"] == [
        {"name": "a", "value": "1"},
        {"name": "b", "value": "2"},
    ]
    assert found["prometheus-alerting-rules"] == []


def test_a_rule_of_an_unknown_type_is_a_bad_payload() -> None:
    data: Any = {"groups": [{"name": "g", "file": "f", "rules": [{"name": "r", "type": "x"}]}]}
    with pytest.raises(CollectorError):
        rules_objects(data)
