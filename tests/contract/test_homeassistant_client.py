"""Contract tests of the Home Assistant client against the fake WebSocket API.

The fake (``fake_homeassistant.py``) speaks the wire protocol with its own framing, so these tests
check the sign in, the command handling and what reaches the pipeline. Every name it serves comes
from the Home Assistant core source and docs only (docs/vendor-notes/homeassistant.md).
"""

import json
import logging
from typing import Any

import pytest

from driftsniff.collectors.base import (
    ERROR_CONNECTION,
    ERROR_TIMEOUT,
    CollectorError,
    ResourceSpec,
)
from driftsniff.collectors.homeassistant.client import (
    ERROR_COMMAND,
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    HomeAssistantClient,
)
from driftsniff.collectors.homeassistant.resources import RESOURCES

from .fake_homeassistant import (
    CANARY_TOKEN,
    HA_VERSION,
    FakeHomeAssistant,
    Scenario,
    error,
    fake_homeassistant,
)


def make_client(server: FakeHomeAssistant, token: str = CANARY_TOKEN, **options: Any) -> Any:
    return HomeAssistantClient(server.url, token, allow_plain_http=True, **options)


def read_all(client: HomeAssistantClient) -> dict[str, Any]:
    client.probe()
    return {spec.name: client.fetch(spec) for spec in client.resources()}


def read_fake(scenario: Scenario | None = None) -> tuple[dict[str, Any], FakeHomeAssistant]:
    with fake_homeassistant(scenario) as server:
        client = make_client(server)
        try:
            return read_all(client), server
        finally:
            client.close()


def keyed(results: dict[str, Any], name: str, key: str) -> dict[Any, dict[str, Any]]:
    return {item[key]: item for item in results[name].objects}


def test_a_probe_signs_in_and_reports_the_version() -> None:
    with fake_homeassistant() as server:
        client = make_client(server)
        try:
            assert client.probe() == HA_VERSION
        finally:
            client.close()
        assert server.auth_messages == [{"type": "auth", "access_token": CANARY_TOKEN}]
        assert server.commands_sent() == []


def test_the_token_travels_only_inside_the_auth_message() -> None:
    _, server = read_fake()
    for headers in server.upgrades:
        assert CANARY_TOKEN not in json.dumps(headers)
    assert server.calls and all(
        CANARY_TOKEN not in json.dumps(call.fields) for call in server.calls
    )


def test_a_wrong_token_is_unauthorized() -> None:
    with fake_homeassistant() as server:
        client = make_client(server, "CANARY-wrng-0")
        with pytest.raises(CollectorError) as caught:
            client.probe()
        client.close()
    assert (caught.value.error_class, caught.value.status) == (ERROR_UNAUTHORIZED, "401")
    assert "CANARY" not in str(caught.value)


@pytest.mark.parametrize(
    ("status", "error_class"),
    [(404, ERROR_NO_API), (401, ERROR_UNAUTHORIZED), (403, ERROR_FORBIDDEN)],
)
def test_a_refused_upgrade_stops_the_probe(status: int, error_class: str) -> None:
    with fake_homeassistant(Scenario(upgrade_status=status)) as server:
        client = make_client(server)
        with pytest.raises(CollectorError) as caught:
            client.probe()
        client.close()
    assert caught.value.error_class == error_class


def test_fetching_before_the_probe_is_refused() -> None:
    with fake_homeassistant() as server:
        client = make_client(server)
        with pytest.raises(CollectorError) as caught:
            client.fetch(ResourceSpec("homeassistant-users"))
        client.close()
    assert caught.value.error_class == ERROR_NOT_PROBED


@pytest.mark.parametrize("token", ["", "with space", "tab\there"])
def test_a_token_of_the_wrong_shape_is_refused_without_echoing_it(token: str) -> None:
    with pytest.raises(ValueError) as caught:
        HomeAssistantClient("https://home.example.invalid", token)
    assert str(caught.value) == "the access token is blank or has spaces or unusual characters"


def test_plain_http_is_refused_without_the_option() -> None:
    with pytest.raises(ValueError):
        HomeAssistantClient("http://home.example.invalid", CANARY_TOKEN)


def test_a_full_run_reads_every_resource_and_the_states_once() -> None:
    results, server = read_fake()
    sent = server.commands_sent()
    assert list(results) == [resource.name for resource in RESOURCES]
    assert all(result.ok for result in results.values())
    assert sent.count("get_states") == 1
    assert sent.count("automation/config") == 2 and sent.count("script/config") == 1
    for resource in RESOURCES:
        if resource.domain is None:
            assert sent.count(resource.command) == 1, resource.command


def test_every_resource_has_the_expected_objects() -> None:
    results, _ = read_fake()
    core = results["homeassistant-core-config"].objects
    assert len(core) == 1 and core[0]["id"] == "core"
    assert core[0]["external_url"] == "https://home.example.invalid"
    integrations = keyed(results, "homeassistant-integrations", "entry_id")
    assert [item["domain"] for item in integrations.values()] == ["met", "mqtt"]
    users = keyed(results, "homeassistant-users", "username")
    assert (users["owner"]["is_admin"], users["guest"]["is_admin"]) == (True, False)
    automations = keyed(results, "homeassistant-automations", "entity_id")
    assert sorted(automations) == [
        "automation.close_garage_at_night",
        "automation.porch_light_at_sunset",
    ]
    porch = automations["automation.porch_light_at_sunset"]
    assert porch["enabled"] is True and porch["config"]["alias"] == "Porch light at sunset"
    scripts = keyed(results, "homeassistant-scripts", "entity_id")
    assert (
        list(scripts) == ["script.water_garden"] and "enabled" not in scripts["script.water_garden"]
    )
    assert sorted(keyed(results, "homeassistant-areas", "area_id")) == ["garage", "living_room"]
    assert len(results["homeassistant-entities"].objects) == 3
    assert sorted(keyed(results, "homeassistant-dashboards", "url_path")) == ["lab-overview", "map"]


def test_no_state_value_reaches_the_pipeline() -> None:
    results, _ = read_fake()
    text = json.dumps([list(result.objects) for result in results.values()], ensure_ascii=False)
    assert "11.4" not in text and "last_triggered" not in text and "closed" not in text


def test_events_and_fragmented_answers_are_handled() -> None:
    results, _ = read_fake(Scenario(event_before=True, fragment=True))
    assert all(result.ok for result in results.values())


def test_a_token_that_is_no_administrator_gets_403_on_the_admin_resources() -> None:
    results, _ = read_fake(Scenario(admin=False))
    for name in ("homeassistant-users", "homeassistant-automations", "homeassistant-scripts"):
        assert (results[name].error_class, results[name].status) == (ERROR_FORBIDDEN, "403"), name
    assert results["homeassistant-entities"].ok and results["homeassistant-core-config"].ok


def test_an_unknown_command_is_coverage_404_and_other_errors_are_command_errors() -> None:
    scenario = Scenario(errors={"config/area_registry/list": error("home_assistant_error", "x")})
    del scenario.commands["lovelace/dashboards/list"]
    results, _ = read_fake(scenario)
    dashboards = results["homeassistant-dashboards"]
    assert (dashboards.error_class, dashboards.status) == (ERROR_NOT_AVAILABLE, "404")
    assert results["homeassistant-areas"].error_class == ERROR_COMMAND
    assert not results["homeassistant-areas"].retryable
    assert results["homeassistant-entities"].ok


def test_a_resource_without_a_type_table_is_not_read() -> None:
    with fake_homeassistant() as server:
        client = make_client(server)
        try:
            client.probe()
            result = client.fetch(ResourceSpec("homeassistant-unknown"))
        finally:
            client.close()
    assert result.error_class == ERROR_UNKNOWN_RESOURCE


def test_a_slow_command_times_out_and_the_next_call_reconnects() -> None:
    with fake_homeassistant(Scenario(delay={"get_config": 1.5})) as server:
        client = make_client(server, request_timeout=0.5)
        try:
            client.probe()
            slow = client.fetch(ResourceSpec("homeassistant-core-config"))
            after = client.fetch(ResourceSpec("homeassistant-integrations"))
        finally:
            client.close()
        logins = len(server.auth_messages)
    assert slow.error_class == ERROR_TIMEOUT and slow.retryable
    assert after.ok
    assert logins == 2


def test_a_closed_connection_fails_that_resource_and_the_next_one_reconnects() -> None:
    results, _ = read_fake(Scenario(close_on={"config/auth/list"}))
    assert results["homeassistant-users"].error_class == ERROR_CONNECTION
    assert results["homeassistant-automations"].ok


def test_the_credential_never_appears_in_logs_errors_or_results(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    scenario = Scenario(admin=False, delay={"get_config": 1.0})
    texts: list[str] = []
    with fake_homeassistant(scenario) as server:
        client = make_client(server, request_timeout=0.3)
        try:
            for result in read_all(client).values():
                texts.append(json.dumps([result.error_text, list(result.objects)]))
        finally:
            client.close()
        bad = make_client(server, "CANARY-not-the-token-00")
        with pytest.raises(CollectorError) as caught:
            bad.probe()
        bad.close()
        texts.append(str(caught.value))
    joined = "\n".join([*texts, caplog.text])
    assert CANARY_TOKEN not in joined
    assert "CANARY-not-the-token-00" not in joined
