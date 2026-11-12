"""The Synology DSM client against a fake NAS on localhost, and two runs through the pipeline.

Covered: discovery and sign in, the password and the sid only in the form body, a wrong password
(one attempt, no retry), a 2-step account, a session that expires between calls and one that is
lost twice, an API the NAS does not list (never requested) and one the account may not read, sign
out at the end, and two reads with changes in between that give the expected severities.

Every name the fake serves is unverified against a real DSM (docs/vendor-notes/synology.md).
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_HTTP, CollectorError, ResourceSpec
from driftsniff.collectors.synology.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_SESSION,
    ERROR_TWO_FACTOR,
    ERROR_UNAUTHORIZED,
    SynologyClient,
)
from driftsniff.collectors.synology.resources import RESOURCES
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.sources.factory import build_collector

from .fake_synology import (
    CANARY_CREDENTIAL,
    CANARY_PASSWORD,
    CANARY_USER,
    FakeSynology,
    Scenario,
    fake_synology,
)
from .unifi_bands import SOURCE_ID, change_item_rows, coverage_rows, make_pipeline


@contextmanager
def connected(
    scenario: Scenario | None = None, credential: str = CANARY_CREDENTIAL
) -> Iterator[tuple[FakeSynology, SynologyClient]]:
    with fake_synology(scenario) as server:
        client = SynologyClient(server.url, credential, allow_plain_http=True)
        try:
            yield server, client
        finally:
            client.close()


def logins(server: FakeSynology) -> int:
    return sum(1 for r in server.calls("SYNO.API.Auth") if r.params.get("method") == "login")


# -- discovery, sign in and where the secrets travel -------------------------------------------


def test_a_probe_discovers_the_apis_and_signs_in() -> None:
    with connected() as (server, client):
        assert client.probe() is None
        assert [(r.path, r.params["api"]) for r in server.requests] == [
            ("/webapi/query.cgi", "SYNO.API.Info"),
            ("/webapi/entry.cgi", "SYNO.API.Auth"),
        ]
        login = server.requests[1].form
        assert login["account"] == CANARY_USER
        assert login["version"] == "6"
        assert login["format"] == "sid"


def test_the_password_and_the_sid_only_travel_in_the_form_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    with connected() as (server, client):
        client.probe()
        for spec in client.resources():
            assert client.fetch(spec).ok, spec.name
        client.close()
        sids = {r.form["_sid"] for r in server.requests if "_sid" in r.form}
        assert len(sids) == 1
        sid = next(iter(sids))
        for request in server.requests:
            assert request.method == "POST"
            assert request.query == ""
            assert CANARY_PASSWORD not in request.path
            if request.form.get("method") != "login":
                assert CANARY_PASSWORD not in request.form.values()
        assert CANARY_PASSWORD not in caplog.text
        assert sid not in caplog.text
        assert server.live_sessions == 0


def test_close_signs_out() -> None:
    with connected() as (server, client):
        client.probe()
        assert server.live_sessions == 1
        client.close()
        assert server.live_sessions == 0
        assert server.requests[-1].form["method"] == "logout"


# -- refusals ----------------------------------------------------------------------------------


def test_a_wrong_password_is_unauthorized_and_tried_once() -> None:
    with connected(credential=f"{CANARY_USER}:CANARY-wrong") as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_UNAUTHORIZED
        assert caught.value.status == "401"
        assert not caught.value.retryable
        assert "CANARY-wrong" not in str(caught.value)
        assert logins(server) == 1
        with pytest.raises(CollectorError) as unprobed:
            client.fetch(ResourceSpec("synology-users"))
        assert unprobed.value.error_class == ERROR_NOT_PROBED


def test_a_two_step_account_cannot_be_used() -> None:
    scenario = Scenario(two_factor={CANARY_USER})
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_TWO_FACTOR


def test_an_address_that_is_not_dsm_is_no_api() -> None:
    scenario = Scenario(http_status=404)
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_a_server_error_on_the_probe_may_be_retried() -> None:
    scenario = Scenario(http_status=503)
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_HTTP
    assert caught.value.retryable


def test_a_credential_without_a_password_is_refused_before_any_request() -> None:
    with pytest.raises(ValueError, match="user name:password"):
        SynologyClient("https://nas.example", CANARY_USER)


# -- sessions ----------------------------------------------------------------------------------


def test_an_expired_session_signs_in_again_once() -> None:
    with connected() as (server, client):
        client.probe()
        server.expire()
        result = client.fetch(ResourceSpec("synology-users"))
        assert result.ok
        assert logins(server) == 2
        assert [item["name"] for item in result.objects] == sorted(
            user["name"] for user in server.scenario.config["users"]
        )


def test_a_session_lost_twice_fails_the_resource_only() -> None:
    scenario = Scenario(session_calls=0)
    with connected(scenario) as (server, client):
        client.probe()
        result = client.fetch(ResourceSpec("synology-terminal"))
        assert not result.ok
        assert result.error_class == ERROR_SESSION
        assert logins(server) == 2


# -- coverage ----------------------------------------------------------------------------------


def test_an_api_the_nas_does_not_list_is_not_available_and_never_requested() -> None:
    scenario = Scenario(missing={"SYNO.Core.QuickConnect"})
    with connected(scenario) as (server, client):
        client.probe()
        result = client.fetch(ResourceSpec("synology-quickconnect"))
        assert (result.ok, result.error_class, result.status) == (False, ERROR_NOT_AVAILABLE, "404")
        assert server.calls("SYNO.Core.QuickConnect") == []


def test_an_api_the_account_may_not_read_is_forbidden() -> None:
    scenario = Scenario(forbidden={"SYNO.Core.User"})
    with connected(scenario) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("synology-users"))
        assert (result.ok, result.error_class, result.status) == (False, ERROR_FORBIDDEN, "403")


def test_every_resource_reads_and_is_keyed() -> None:
    with connected() as (_, client):
        client.probe()
        assert [spec.name for spec in client.resources()] == [r.name for r in RESOURCES]
        read = {spec.name: client.fetch(spec) for spec in client.resources()}
    assert all(result.ok for result in read.values())
    names = {name: [dict(item) for item in result.objects] for name, result in read.items()}
    assert [item["name"] for item in names["synology-administrators"]] == ["admin", CANARY_USER]
    assert names["synology-guest-share-access"] == []
    groups = {item["name"]: item["members"] for item in names["synology-groups"]}
    assert groups["administrators"] == ["admin", CANARY_USER]
    assert [item["object_key"] for item in names["synology-file-services"]] == [
        "afp",
        "nfs",
        "smb",
    ]
    backup: Any = names["synology-shares"][0]
    assert backup["name"] == "backup"
    assert {row["name"] for row in backup["permissions_local_group"]} == {
        "administrators",
        "users",
    }


def test_the_factory_builds_the_synology_client() -> None:
    collector = build_collector(
        "synology",
        "https://nas.example",
        CANARY_CREDENTIAL.split(":", 1)[1].encode(),
        {"username": CANARY_CREDENTIAL.split(":", 1)[0]},
    )
    try:
        assert isinstance(collector, SynologyClient)
    finally:
        collector.close()


# -- two runs through the pipeline -------------------------------------------------------------


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    store = Database(database_path(tmp_path))
    upgrade_to_head(store)
    with store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (1, 'lab-nas', 'synology')"
        )
    try:
        yield store
    finally:
        store.close()


def severities(database: Database) -> dict[tuple[str, str, str], str]:
    """(resource, path, change kind) to severity, of every stored change item."""
    found: dict[tuple[str, str, str], str] = {}
    for row in change_item_rows(database):
        found[(str(row.resource), str(row.path), str(row.change_kind))] = str(row.severity)
    return found


def run(database: Database, server: FakeSynology) -> Any:
    client = SynologyClient(server.url, CANARY_CREDENTIAL, allow_plain_http=True)
    return make_pipeline(database).run(SOURCE_ID, client)


def test_two_reads_with_changes_give_the_expected_severities(database: Database) -> None:
    with fake_synology() as server:
        first = run(database, server)
        assert first.status == "ok", first
        coverage = coverage_rows(database)
        assert sorted(coverage) == sorted(resource.name for resource in RESOURCES)
        assert {row.last_status for row in coverage.values()} == {"200"}
        baseline = len(change_item_rows(database))

        server.set_setting("terminal", "enable_telnet", True)
        server.set_setting("terminal", "enable_ssh", True)
        server.set_setting("firewall", "enable_firewall", False)
        server.set_setting("quickconnect", "enabled", True)
        server.add_member("administrators", "bob")
        server.grant_guest("public", write=False)
        server.install_package("Docker", "Container Manager", "24.0.2-1535")
        server.mutate(lambda config: config["shares"][1].__setitem__("desc", "films"))
        # Volatile values move as well: they must not raise a change.
        server.mutate(lambda config: config["users"][1].__setitem__("password_last_change", 1))
        server.mutate(lambda config: config["interfaces"][0].__setitem__("status", "down"))
        server.mutate(lambda config: config["packages"][0].__setitem__("timestamp", 1))

        second = run(database, server)
        assert second.status == "ok", second
        assert server.live_sessions == 0

    rows = change_item_rows(database)[baseline:]
    got = {(str(r.resource), str(r.path), str(r.change_kind)): str(r.severity) for r in rows}
    assert got == {
        ("synology-terminal", "enable_telnet", "modified"): "critical",
        ("synology-terminal", "enable_ssh", "modified"): "high",
        ("synology-firewall", "enable_firewall", "modified"): "critical",
        ("synology-quickconnect", "enabled", "modified"): "high",
        ("synology-administrators", "", "added"): "critical",
        ("synology-groups", "members", "added"): "high",
        ("synology-guest-share-access", "", "added"): "critical",
        ("synology-shares", "permissions_local_user", "modified"): "high",
        ("synology-packages", "", "added"): "medium",
        ("synology-shares", "desc", "modified"): "low",
    }


def test_a_read_that_changes_nothing_stores_no_change(database: Database) -> None:
    with fake_synology() as server:
        run(database, server)
        before = len(change_item_rows(database))
        run(database, server)
    assert len(change_item_rows(database)) == before
