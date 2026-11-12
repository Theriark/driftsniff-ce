"""Contract tests of the TrueNAS client against the fake JSON-RPC WebSocket API.

The fake (``fake_truenas.py``) speaks the wire protocol with its own framing, so these tests check
the client's WebSocket code, its JSON-RPC handling and what reaches the pipeline. Every name it
serves comes from the API reference only (docs/vendor-notes/truenas.md).
"""

import json
import logging
from typing import Any

import pytest

from driftsniff.collectors.base import (
    ERROR_BAD_PAYLOAD,
    ERROR_CONNECTION,
    ERROR_TIMEOUT,
    CollectorError,
    ResourceSpec,
)
from driftsniff.collectors.truenas.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_RPC,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    TruenasClient,
)
from driftsniff.collectors.truenas.resources import RESOURCES

from .fake_truenas import (
    CANARY_CREDENTIAL,
    CANARY_KEY,
    CANARY_USER,
    ERROR_ACCESS_DENIED,
    FakeTruenas,
    Scenario,
    fake_truenas,
)


def make_client(server: FakeTruenas, credential: str = CANARY_CREDENTIAL, **options: Any) -> Any:
    return TruenasClient(server.url, credential, allow_plain_http=True, **options)


def read_all(client: TruenasClient) -> dict[str, Any]:
    client.probe()
    return {spec.name: client.fetch(spec) for spec in client.resources()}


def objects_of(results: dict[str, Any], name: str) -> dict[Any, dict[str, Any]]:
    return {item["id"]: item for item in results[name].objects}


def test_a_probe_signs_in_and_reports_the_version() -> None:
    with fake_truenas() as server:
        client = make_client(server)
        try:
            assert client.probe() == "25.10.1"
        finally:
            client.close()
        assert server.methods_called() == ["auth.login_ex", "system.version"]
        login = server.calls[0].params[0]
        assert login["mechanism"] == "API_KEY_PLAIN"
        assert (login["username"], login["api_key"]) == (CANARY_USER, CANARY_KEY)


def test_the_api_key_travels_only_inside_the_sign_in_call() -> None:
    with fake_truenas() as server:
        client = make_client(server)
        try:
            read_all(client)
        finally:
            client.close()
        for headers in server.upgrades:
            assert CANARY_KEY not in json.dumps(headers)
        later = [call for call in server.calls if call.method != "auth.login_ex"]
        assert later and all(CANARY_KEY not in json.dumps(call.params) for call in later)
        assert all(call.authenticated for call in later)


def test_a_wrong_api_key_is_unauthorized() -> None:
    with fake_truenas() as server:
        client = make_client(server, f"{CANARY_USER}:7-wrong")
        with pytest.raises(CollectorError) as caught:
            client.probe()
        client.close()
    assert caught.value.error_class == ERROR_UNAUTHORIZED
    assert caught.value.status == "401"


def test_an_expired_key_is_unauthorized() -> None:
    with fake_truenas(Scenario(login_response="EXPIRED")) as server:
        client = make_client(server)
        with pytest.raises(CollectorError) as caught:
            client.probe()
        client.close()
    assert caught.value.error_class == ERROR_UNAUTHORIZED


@pytest.mark.parametrize(
    ("status", "error_class"), [(404, ERROR_NO_API), (401, ERROR_UNAUTHORIZED)]
)
def test_a_refused_upgrade_stops_the_probe(status: int, error_class: str) -> None:
    with fake_truenas(Scenario(upgrade_status=status)) as server:
        client = make_client(server)
        with pytest.raises(CollectorError) as caught:
            client.probe()
        client.close()
    assert caught.value.error_class == error_class


def test_a_wrong_accept_value_breaks_the_protocol() -> None:
    with fake_truenas(Scenario(bad_accept=True)) as server:
        client = make_client(server)
        with pytest.raises(CollectorError) as caught:
            client.probe()
        client.close()
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


def test_fetching_before_the_probe_is_refused() -> None:
    with fake_truenas() as server:
        client = make_client(server)
        with pytest.raises(CollectorError) as caught:
            client.fetch(ResourceSpec("truenas-pools"))
        client.close()
    assert caught.value.error_class == ERROR_NOT_PROBED


@pytest.mark.parametrize("credential", ["no-colon", ":key", "user:", "user:key with space"])
def test_a_credential_of_the_wrong_shape_is_refused_without_echoing_it(credential: str) -> None:
    with pytest.raises(ValueError) as caught:
        TruenasClient("https://nas.example", credential)
    assert str(caught.value) in (
        "enter the credential as username:API key",
        "the credential has spaces or characters TrueNAS does not use",
    )


def test_plain_http_is_refused_without_the_option() -> None:
    with pytest.raises(ValueError):
        TruenasClient("http://nas.example", CANARY_CREDENTIAL)


def test_a_full_run_calls_each_method_once() -> None:
    with fake_truenas() as server:
        client = make_client(server)
        try:
            results = read_all(client)
        finally:
            client.close()
        called = server.methods_called()
    assert all(result.ok for result in results.values())
    assert list(results) == [resource.name for resource in RESOURCES]
    for resource in RESOURCES:
        assert called.count(resource.method) == 1, resource.method


def test_a_resource_without_a_type_table_is_not_read() -> None:
    with fake_truenas() as server:
        client = make_client(server)
        try:
            client.probe()
            result = client.fetch(ResourceSpec("truenas-unknown"))
        finally:
            client.close()
    assert result.error_class == ERROR_UNKNOWN_RESOURCE


def test_private_keys_never_reach_the_pipeline() -> None:
    with fake_truenas() as server:
        client = make_client(server)
        try:
            results = read_all(client)
        finally:
            client.close()
    text = json.dumps([list(result.objects) for result in results.values()])
    assert "SYNTHETIC-PRIVATE-KEY" not in text
    assert "privatekey" not in objects_of(results, "truenas-certificates")[1]
    ssh = objects_of(results, "truenas-ssh")[1]
    assert not [key for key in ssh if key.startswith("host_") and not key.endswith("pub")]


def test_properties_are_flattened_and_derived_fields_are_added() -> None:
    with fake_truenas() as server:
        client = make_client(server)
        try:
            results = read_all(client)
        finally:
            client.close()
    media = objects_of(results, "truenas-datasets")["tank/media"]
    assert (media["compression"], media["readonly"], media["quota"]) == ("LZ4", "OFF", "1T")
    assert objects_of(results, "truenas-pools")[1]["autotrim"] == "OFF"
    assert objects_of(results, "truenas-nfs-shares")[1]["open_to_all"] is False
    users = objects_of(results, "truenas-users")
    assert (users[1]["full_admin"], users[71]["full_admin"]) == (True, False)
    assert objects_of(results, "truenas-replication-tasks")[1]["periodic_snapshot_tasks"] == [1]


def test_events_pings_and_fragmented_answers_are_handled() -> None:
    scenario = Scenario(event_before=True, ping_before=True, fragment=True)
    with fake_truenas(scenario) as server:
        client = make_client(server)
        try:
            results = read_all(client)
        finally:
            client.close()
    assert all(result.ok for result in results.values())
    assert len(results["truenas-datasets"].objects) == 3


def test_an_unknown_method_is_coverage_404() -> None:
    scenario = Scenario()
    del scenario.methods["iscsi.target.query"]
    with fake_truenas(scenario) as server:
        client = make_client(server)
        try:
            results = read_all(client)
        finally:
            client.close()
    failed = results["truenas-iscsi-targets"]
    assert (failed.error_class, failed.status) == (ERROR_NOT_AVAILABLE, "404")
    assert results["truenas-iscsi-extents"].ok


def test_a_denied_method_is_coverage_403_and_other_errors_are_rpc_errors() -> None:
    other = {"code": -32001, "message": "Method call error", "data": {"errname": "EINVAL"}}
    scenario = Scenario(errors={"user.query": ERROR_ACCESS_DENIED, "group.query": other})
    with fake_truenas(scenario) as server:
        client = make_client(server)
        try:
            results = read_all(client)
        finally:
            client.close()
    assert (results["truenas-users"].error_class, results["truenas-users"].status) == (
        ERROR_FORBIDDEN,
        "403",
    )
    assert results["truenas-groups"].error_class == ERROR_RPC
    assert not results["truenas-groups"].retryable
    assert results["truenas-ssh"].ok


def test_a_slow_method_times_out_and_the_next_call_reconnects() -> None:
    with fake_truenas(Scenario(delay={"pool.query": 1.5})) as server:
        client = make_client(server, request_timeout=0.5)
        try:
            client.probe()
            slow = client.fetch(ResourceSpec("truenas-pools"))
            after = client.fetch(ResourceSpec("truenas-datasets"))
        finally:
            client.close()
        logins = server.methods_called().count("auth.login_ex")
    assert slow.error_class == ERROR_TIMEOUT and slow.retryable
    assert after.ok
    assert logins == 2


def test_a_closed_connection_fails_that_resource_and_the_next_one_reconnects() -> None:
    with fake_truenas(Scenario(close_on={"sharing.smb.query"})) as server:
        client = make_client(server)
        try:
            results = read_all(client)
        finally:
            client.close()
    assert results["truenas-smb-shares"].error_class == ERROR_CONNECTION
    assert results["truenas-nfs-shares"].ok


def test_the_credential_never_appears_in_logs_errors_or_results(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    scenario = Scenario(errors={"user.query": ERROR_ACCESS_DENIED}, delay={"pool.query": 1.0})
    texts: list[str] = []
    with fake_truenas(scenario) as server:
        client = make_client(server, request_timeout=0.3)
        try:
            for spec in [*read_all(client).values()]:
                texts.append(json.dumps([spec.error_text, list(spec.objects)]))
        finally:
            client.close()
        bad = make_client(server, f"{CANARY_USER}:7-not-the-key")
        with pytest.raises(CollectorError) as caught:
            bad.probe()
        bad.close()
        texts.append(str(caught.value))
    joined = "\n".join([*texts, caplog.text])
    assert CANARY_KEY not in joined
    assert "7-not-the-key" not in joined
