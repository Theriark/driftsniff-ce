"""Resource collection, the ordering merge and the UniFi pack through the real collector (P7-T4).

The fake controller serves firewall policies, ACL rules and their ordering documents (all names
unverified, docs/vendor-notes/unifi.md). The first group reads through :class:`UnifiClient` alone;
the last group runs the whole pipeline on a migrated database, so a moved firewall policy is
followed from the ordering document to a stored change item.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import ResourceSpec
from driftsniff.collectors.unifi.client import (
    ERROR_BAD_PAYLOAD,
    ERROR_FORBIDDEN,
    ERROR_NOT_AVAILABLE,
    UnifiClient,
)
from driftsniff.collectors.unifi.normalize import ERROR_ORDERING_MISMATCH, MAX_ZONE_PAIRS
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_unifi import CANARY_HEADER, FakeUnifi, Scenario, fake_unifi

POLICIES = ResourceSpec("unifi-firewall-policies")
ACL_RULES = ResourceSpec("unifi-acl-rules")
ORDERING = "/firewall/policies/ordering"
ACL_ORDERING = "/acl-rules/ordering"
SOURCE_ID = 1


def policy(
    key: str, source: str = "z1", destination: str = "z2", verdict: str = "BLOCK"
) -> dict[str, Any]:
    return {
        "id": key,
        "name": f"Policy {key}",
        "enabled": True,
        "action": {"type": verdict},
        "source": {"zoneId": source},
        "destination": {"zoneId": destination},
    }


def acl_rule(key: str, verdict: str = "ALLOW") -> dict[str, Any]:
    return {"id": key, "name": f"Rule {key}", "enabled": True, "action": verdict}


def ids(objects: Any) -> list[str]:
    return [item["id"] for item in objects]


@contextmanager
def connected(scenario: Scenario) -> Iterator[tuple[FakeUnifi, UnifiClient]]:
    with fake_unifi(scenario) as server:
        client = UnifiClient(server.url, CANARY_HEADER, allow_plain_http=True)
        try:
            client.probe()
            yield server, client
        finally:
            client.close()


# -- firewall policies -------------------------------------------------------------------------


def test_policies_come_back_in_position_order_pair_by_pair() -> None:
    scenario = Scenario(
        objects={
            "firewall/policies": [
                policy("a1", "z1", "z2"),
                policy("a2", "z1", "z2"),
                policy("c1", "z0", "z3"),
            ],
        },
        firewall_order={
            ("site-a", "z0", "z3"): (["c1"], []),
            ("site-a", "z1", "z2"): (["a2"], ["a1"]),
        },
    )
    with connected(scenario) as (server, client):
        result = client.fetch(POLICIES)
        queries = [parse_qs(request.query) for request in server.requests_for(ORDERING)]
    assert result.ok
    assert ids(result.objects) == ["c1", "a2", "a1"]
    assert (result.warning_class, result.warning_text) == (None, None)
    assert [item["actionType"] for item in result.objects] == ["BLOCK", "BLOCK", "BLOCK"]
    assert [item["action"] for item in result.objects] == [{"type": "BLOCK"}] * 3
    sources = [query["sourceFirewallZoneId"] for query in queries]
    destinations = [query["destinationFirewallZoneId"] for query in queries]
    assert (sources, destinations) == ([["z0"], ["z1"]], [["z3"], ["z2"]])


def test_the_policies_before_the_system_defined_ones_come_first() -> None:
    scenario = Scenario(
        objects={"firewall/policies": [policy("p1"), policy("p2"), policy("p3")]},
        firewall_order={("site-a", "z1", "z2"): (["p3", "p1"], ["p2"])},
    )
    with connected(scenario) as (_, client):
        result = client.fetch(POLICIES)
    assert ids(result.objects) == ["p3", "p1", "p2"]


def test_a_policy_the_ordering_does_not_name_is_appended_and_the_result_warns() -> None:
    scenario = Scenario(
        objects={"firewall/policies": [policy("p1"), policy("p2"), policy("p3")]},
        firewall_order={("site-a", "z1", "z2"): (["p2", "ghost"], [])},
    )
    with connected(scenario) as (_, client):
        result = client.fetch(POLICIES)
    assert result.ok
    assert ids(result.objects) == ["p2", "p1", "p3"]
    assert result.warning_class == ERROR_ORDERING_MISMATCH
    assert result.warning_text is not None
    assert "2 appended" in result.warning_text
    assert "1 ids dropped" in result.warning_text
    assert "p1" not in result.warning_text
    assert "ghost" not in result.warning_text


def test_a_policy_without_zones_is_appended_and_has_no_ordering_request() -> None:
    nameless = {"id": "p9", "name": "No zones", "action": {"type": "ALLOW"}}
    scenario = Scenario(
        objects={"firewall/policies": [nameless, policy("p1")]},
        firewall_order={("site-a", "z1", "z2"): (["p1"], [])},
    )
    with connected(scenario) as (server, client):
        result = client.fetch(POLICIES)
        requests = server.requests_for(ORDERING)
    assert ids(result.objects) == ["p1", "p9"]
    assert result.warning_class == ERROR_ORDERING_MISMATCH
    assert len(requests) == 1
    assert "actionType" in result.objects[0]


def test_no_policies_need_no_ordering_request() -> None:
    with connected(Scenario()) as (server, client):
        result = client.fetch(POLICIES)
        acl = client.fetch(ACL_RULES)
        requests = server.requests_for(ORDERING) + server.requests_for(ACL_ORDERING)
    assert (result.ok, list(result.objects), result.warning_class) == (True, [], None)
    assert (acl.ok, list(acl.objects)) == (True, [])
    assert requests == []


def test_every_site_has_its_own_ordering() -> None:
    scenario = Scenario(
        sites=["site-a", "site-b"],
        site_objects={
            ("site-a", "firewall/policies"): [policy("a1"), policy("a2")],
            ("site-b", "firewall/policies"): [policy("b1"), policy("b2")],
        },
        firewall_order={
            ("site-a", "z1", "z2"): (["a2", "a1"], []),
            ("site-b", "z1", "z2"): (["b1"], ["b2"]),
        },
    )
    with connected(scenario) as (_, client):
        result = client.fetch(POLICIES)
    assert result.warning_class is None
    assert ids(result.objects) == ["a2", "a1", "b1", "b2"]


def test_too_many_zone_pairs_fail_the_resource_before_any_ordering_request() -> None:
    many = [policy(f"p{index:04d}", f"z{index:04d}", "zz") for index in range(MAX_ZONE_PAIRS + 1)]
    with connected(Scenario(objects={"firewall/policies": many})) as (server, client):
        result = client.fetch(POLICIES)
        requests = server.requests_for(ORDERING)
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)
    assert requests == []


@pytest.mark.parametrize(
    ("status", "error_class"), [(404, ERROR_NOT_AVAILABLE), (403, ERROR_FORBIDDEN)]
)
def test_an_ordering_that_cannot_be_read_fails_the_resource_with_its_status(
    status: int, error_class: str
) -> None:
    scenario = Scenario(
        objects={"firewall/policies": [policy("p1")]},
        status={"firewall/policies/ordering": status},
    )
    with connected(scenario) as (_, client):
        result = client.fetch(POLICIES)
    assert (result.ok, result.error_class, result.status) == (False, error_class, str(status))
    assert list(result.objects) == []


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b'{"orderedFirewallPolicyIds": 5}',
        b'{"orderedFirewallPolicyIds": {"beforeSystemDefined": [1]}}',
        b"[]",
    ],
)
def test_an_ordering_answer_of_the_wrong_shape_is_a_bad_payload(body: bytes) -> None:
    scenario = Scenario(
        objects={"firewall/policies": [policy("p1")]},
        raw={"firewall/policies/ordering": body},
    )
    with connected(scenario) as (_, client):
        result = client.fetch(POLICIES)
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


def test_the_key_never_travels_in_an_ordering_request_but_the_header() -> None:
    scenario = Scenario(
        objects={"firewall/policies": [policy("p1")], "acl-rules": [acl_rule("r1")]},
        firewall_order={("site-a", "z1", "z2"): (["p1"], [])},
        acl_order={"site-a": ["r1"]},
    )
    with connected(scenario) as (server, client):
        client.fetch(POLICIES)
        client.fetch(ACL_RULES)
        ordering = server.requests_for(ORDERING) + server.requests_for(ACL_ORDERING)
    assert len(ordering) == 2
    for request in ordering:
        assert request.header == CANARY_HEADER
        assert CANARY_HEADER not in request.path
        assert CANARY_HEADER not in request.query


# -- ACL rules ---------------------------------------------------------------------------------


def test_acl_rules_come_back_in_the_order_of_their_list() -> None:
    scenario = Scenario(
        objects={"acl-rules": [acl_rule("r1"), acl_rule("r2", "BLOCK"), acl_rule("r3")]},
        acl_order={"site-a": ["r3", "r1", "r2"]},
    )
    with connected(scenario) as (_, client):
        result = client.fetch(ACL_RULES)
    assert result.ok
    assert ids(result.objects) == ["r3", "r1", "r2"]
    assert result.warning_class is None
    assert all("actionType" not in item for item in result.objects)


def test_an_acl_rule_the_list_does_not_name_is_appended_and_the_result_warns() -> None:
    scenario = Scenario(
        objects={"acl-rules": [acl_rule("r1"), acl_rule("r2")]},
        acl_order={"site-a": ["r2", "ghost"]},
    )
    with connected(scenario) as (_, client):
        result = client.fetch(ACL_RULES)
    assert ids(result.objects) == ["r2", "r1"]
    assert result.warning_class == ERROR_ORDERING_MISMATCH


def test_an_acl_ordering_that_cannot_be_read_fails_the_resource() -> None:
    scenario = Scenario(
        objects={"acl-rules": [acl_rule("r1")]},
        status={"acl-rules/ordering": 404},
    )
    with connected(scenario) as (_, client):
        result = client.fetch(ACL_RULES)
    assert (result.ok, result.error_class, result.status) == (False, ERROR_NOT_AVAILABLE, "404")


def test_an_acl_ordering_answer_of_the_wrong_shape_is_a_bad_payload() -> None:
    scenario = Scenario(
        objects={"acl-rules": [acl_rule("r1")]},
        raw={"acl-rules/ordering": b'{"data": []}'},
    )
    with connected(scenario) as (_, client):
        result = client.fetch(ACL_RULES)
    assert (result.ok, result.error_class) == (False, ERROR_BAD_PAYLOAD)


# -- the whole pipeline ------------------------------------------------------------------------


class Clock:
    """UTC timestamps one second apart."""

    def __init__(self) -> None:
        self.second = 0

    def __call__(self) -> str:
        self.second += 1
        moment = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC) + timedelta(seconds=self.second)
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    store = Database(database_path(tmp_path))
    try:
        upgrade_to_head(store)
        with store.write() as connection:
            connection.exec_driver_sql(
                "INSERT INTO sources (id, name, type) VALUES (1, 'lab-controller', 'unifi')"
            )
        yield store
    finally:
        store.close()


@pytest.fixture
def pipeline(database: Database) -> RunPipeline:
    return RunPipeline(
        database,
        RuleEngine(load_rules()),
        Fingerprinter(bytes(range(32)), "0a1b2c3d"),
        clock=Clock(),
    )


def pipeline_scenario() -> Scenario:
    return Scenario(
        objects={
            "firewall/zones": [
                {"id": "z1", "name": "Internal", "networkIds": ["n1"]},
                {"id": "z2", "name": "External", "networkIds": ["n2"]},
            ],
            "firewall/policies": [
                policy("p1", verdict="ALLOW"),
                policy("p2", verdict="BLOCK"),
                policy("p3", verdict="ALLOW"),
            ],
        },
        firewall_order={("site-a", "z1", "z2"): (["p1", "p2", "p3"], [])},
    )


def collect(pipeline: RunPipeline, server: FakeUnifi) -> RunReport:
    return pipeline.run(SOURCE_ID, UnifiClient(server.url, CANARY_HEADER, allow_plain_http=True))


def item_rows(database: Database) -> list[sa.Row[tuple[object, ...]]]:
    with database.read() as connection:
        return list(connection.execute(sa.select(tables.change_items)))


def test_a_moved_firewall_policy_is_one_critical_move_end_to_end(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_unifi(pipeline_scenario()) as server:
        first = collect(pipeline, server)
        assert (first.status, first.event_id) == ("ok", None)
        # One site, two zones, three policies.
        assert first.object_count == 6
        assert item_rows(database) == []
        server.scenario.firewall_order[("site-a", "z1", "z2")] = (["p1", "p3", "p2"], [])
        second = collect(pipeline, server)
    assert second.status == "ok"
    assert second.event_id is not None
    (item,) = item_rows(database)
    assert (item.resource, item.change_kind, item.path) == (
        "unifi-firewall-policies",
        "moved",
        "",
    )
    assert (item.severity, item.rule_id) == ("critical", "builtin.move.blocking")


def test_an_unchanged_ordering_reports_nothing(database: Database, pipeline: RunPipeline) -> None:
    with fake_unifi(pipeline_scenario()) as server:
        collect(pipeline, server)
        second = collect(pipeline, server)
    assert (second.status, second.event_id, second.stored_new_snapshot) == ("ok", None, False)
    assert item_rows(database) == []


def test_a_policy_that_drops_out_of_the_ordering_makes_the_run_partial_and_is_not_removed(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_unifi(pipeline_scenario()) as server:
        collect(pipeline, server)
        server.scenario.firewall_order[("site-a", "z1", "z2")] = (["p1", "p2"], [])
        report = collect(pipeline, server)
    assert report.status == "partial"
    assert report.error_class == ERROR_ORDERING_MISMATCH
    assert report.error_summary is not None
    assert report.error_summary.startswith("repaired: unifi-firewall-policies (ordering_mismatch:")
    assert "1 appended" in report.error_summary
    # p3 is still there, at the end of the list, where it already was: nothing changed.
    assert report.object_count == 6
    assert item_rows(database) == []
    with database.read() as connection:
        row = connection.execute(
            sa.select(tables.resource_coverage).where(
                tables.resource_coverage.c.resource == "unifi-firewall-policies"
            )
        ).one()
    assert (row.last_status, row.object_count, row.stale_since) == ("200", 3, None)


def test_a_policy_missing_from_the_controller_is_a_critical_removal(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_unifi(pipeline_scenario()) as server:
        collect(pipeline, server)
        server.scenario.objects["firewall/policies"] = [policy("p1"), policy("p3")]
        server.scenario.firewall_order[("site-a", "z1", "z2")] = (["p1", "p3"], [])
        report = collect(pipeline, server)
    assert report.status == "ok"
    (item,) = item_rows(database)
    assert (item.change_kind, item.severity, item.rule_id) == (
        "removed",
        "critical",
        "builtin.floor.removed",
    )


def test_an_ordering_that_cannot_be_read_keeps_the_previous_policies(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_unifi(pipeline_scenario()) as server:
        collect(pipeline, server)
        server.scenario.status["firewall/policies/ordering"] = 403
        report = collect(pipeline, server)
    assert report.status == "partial"
    assert report.error_class == ERROR_FORBIDDEN
    assert item_rows(database) == []
    with database.read() as connection:
        row = connection.execute(
            sa.select(tables.resource_coverage).where(
                tables.resource_coverage.c.resource == "unifi-firewall-policies"
            )
        ).one()
    assert (row.last_status, row.object_count) == ("403", 3)
    assert row.stale_since is not None
