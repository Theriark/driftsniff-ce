"""Coverage rows for every failure case of the UniFi client, through the whole pipeline (P7-T5).

``test_unifi_client.py`` checks what the client returns for each case; this file runs the same
cases through :class:`RunPipeline` on a migrated database and checks what a person sees in the
coverage panel: the status of the resource, the objects it still holds, when it went stale, and that
nothing is reported as removed. The reference band of ``tests/fixtures/unifi`` is the healthy
controller. Every name the fake serves is unverified (dependency D5).
"""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import ERROR_BAD_JSON, ERROR_CONNECTION, ERROR_TIMEOUT
from driftsniff.collectors.unifi.client import (
    ERROR_BAD_PAYLOAD,
    ERROR_FORBIDDEN,
    ERROR_NOT_AVAILABLE,
    ERROR_PAGING_LOOP,
    ERROR_UNAUTHORIZED,
    ERROR_UNSUPPORTED_VERSION,
    UnifiClient,
)
from driftsniff.collectors.unifi.resources import RESOURCES
from driftsniff.db import tables
from driftsniff.db.engine import Database
from driftsniff.sources.runs import RunPipeline

from .fake_unifi import CANARY_HEADER, Scenario, fake_unifi
from .unifi_bands import (
    SOURCE_ID,
    Seeds,
    band_scenario,
    change_item_rows,
    collect,
    coverage_rows,
    make_pipeline,
    open_database,
)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    store = open_database(tmp_path)
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def pipeline(database: Database) -> RunPipeline:
    return make_pipeline(database)


def healthy() -> Scenario:
    return band_scenario("reference", Seeds())


def many(prefix: str, count: int) -> list[dict[str, Any]]:
    return [{"id": f"{prefix}-{index:04d}", "name": f"{prefix} {index}"} for index in range(count)]


# -- a resource that cannot be read ------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "route", "resource", "error_class"),
    [
        (403, "radius/profiles", "unifi-radius-profiles", ERROR_FORBIDDEN),
        (404, "vpn/servers", "unifi-vpn-servers", ERROR_NOT_AVAILABLE),
    ],
)
def test_a_refused_resource_keeps_its_objects_and_goes_stale_and_the_others_stay_fresh(
    database: Database,
    pipeline: RunPipeline,
    status: int,
    route: str,
    resource: str,
    error_class: str,
) -> None:
    with fake_unifi(healthy()) as server:
        first = collect(pipeline, server)
        before = coverage_rows(database)[resource]
        server.scenario.status[route] = status
        second = collect(pipeline, server)
    rows = coverage_rows(database)
    row = rows[resource]
    assert (first.status, second.status, second.error_class) == ("ok", "partial", error_class)
    assert (row.last_status, row.object_count) == (str(status), 2)
    assert row.last_ok_at == before.last_ok_at
    assert row.stale_since == before.last_ok_at
    others = [other for name, other in rows.items() if name != resource]
    assert len(others) == len(RESOURCES) - 1
    assert all((other.last_status, other.stale_since) == ("200", None) for other in others)
    assert change_item_rows(database) == []


def truncate(scenario: Scenario) -> None:
    scenario.truncate.add("networks")


def invalid_json(scenario: Scenario) -> None:
    scenario.raw["wifi/broadcasts"] = b"{not json"


def not_a_page(scenario: Scenario) -> None:
    scenario.raw["firewall/zones"] = b'{"data": 5}'


def slow(scenario: Scenario) -> None:
    scenario.delay["devices"] = 1.0


def repeated_page(scenario: Scenario) -> None:
    scenario.objects["vpn/servers"] = many("vpn", 250)
    scenario.ignore_offset.add("vpn/servers")


@pytest.mark.parametrize(
    ("break_it", "options", "resource", "error_classes"),
    [
        pytest.param(
            truncate,
            {},
            "unifi-networks",
            {ERROR_CONNECTION, ERROR_BAD_JSON},
            id="truncated body",
        ),
        pytest.param(
            invalid_json, {}, "unifi-wifi-broadcasts", {ERROR_BAD_JSON}, id="invalid json"
        ),
        pytest.param(not_a_page, {}, "unifi-firewall-zones", {ERROR_BAD_PAYLOAD}, id="not a page"),
        pytest.param(
            slow, {"request_timeout": 0.2}, "unifi-devices", {ERROR_TIMEOUT}, id="slow answer"
        ),
        pytest.param(
            repeated_page, {}, "unifi-vpn-servers", {ERROR_PAGING_LOOP}, id="repeated page"
        ),
    ],
)
def test_a_resource_that_fails_to_read_is_an_error_row_with_its_objects_kept(
    database: Database,
    pipeline: RunPipeline,
    break_it: Callable[[Scenario], None],
    options: dict[str, Any],
    resource: str,
    error_classes: set[str],
) -> None:
    with fake_unifi(healthy()) as server:
        first = collect(pipeline, server)
        before = coverage_rows(database)[resource]
        break_it(server.scenario)
        second = collect(pipeline, server, **options)
    rows = coverage_rows(database)
    row = rows[resource]
    assert first.status == "ok"
    assert second.status == "partial"
    assert second.error_class in error_classes
    assert row.last_status == "error"
    assert (row.object_count, row.last_ok_at, row.stale_since) == (
        before.object_count,
        before.last_ok_at,
        before.last_ok_at,
    )
    assert before.object_count > 0
    others = [other for name, other in rows.items() if name != resource]
    assert all((other.last_status, other.stale_since) == ("200", None) for other in others)
    # A resource that could not be read is never reported as removed.
    assert change_item_rows(database) == []


def test_stale_since_stays_at_the_first_failure_and_clears_when_the_resource_reads_again(
    database: Database, pipeline: RunPipeline
) -> None:
    resource = "unifi-radius-profiles"
    with fake_unifi(healthy()) as server:
        collect(pipeline, server)
        ok_at = coverage_rows(database)[resource].last_ok_at
        server.scenario.status["radius/profiles"] = 403
        collect(pipeline, server)
        collect(pipeline, server)
        stale = coverage_rows(database)[resource]
        del server.scenario.status["radius/profiles"]
        recovered = collect(pipeline, server)
    row = coverage_rows(database)[resource]
    assert (stale.last_status, stale.stale_since, stale.last_ok_at) == ("403", ok_at, ok_at)
    assert recovered.status == "ok"
    assert (row.last_status, row.stale_since, row.object_count) == ("200", None, 2)
    assert row.last_ok_at is not None
    assert ok_at is not None
    assert row.last_ok_at > ok_at


# -- paging boundaries -------------------------------------------------------------------------


@pytest.mark.parametrize("count", [0, 200, 201, 400])
def test_the_object_count_of_a_row_follows_the_paging_boundaries(
    database: Database, pipeline: RunPipeline, count: int
) -> None:
    scenario = healthy()
    scenario.objects["networks"] = many("net", count)
    with fake_unifi(scenario) as server:
        report = collect(pipeline, server)
    row = coverage_rows(database)["unifi-networks"]
    assert report.status == "ok"
    assert (row.last_status, row.object_count, row.stale_since) == ("200", count, None)


# -- no collection at all ----------------------------------------------------------------------


def test_a_version_below_the_floor_runs_no_collection_and_writes_no_coverage(
    database: Database, pipeline: RunPipeline
) -> None:
    scenario = healthy()
    scenario.version = "10.1.83"
    with fake_unifi(scenario) as server:
        report = collect(pipeline, server)
        paths = [request.path for request in server.requests]
    assert (report.status, report.error_class) == ("failed", ERROR_UNSUPPORTED_VERSION)
    assert paths == ["/integration/v1/info"]
    assert coverage_rows(database) == {}
    with database.read() as connection:
        snapshots = connection.execute(sa.select(sa.func.count()).select_from(tables.snapshots))
        assert snapshots.scalar_one() == 0


def test_a_refused_key_runs_no_collection_and_writes_no_coverage(
    database: Database, pipeline: RunPipeline
) -> None:
    scenario = healthy()
    scenario.expected_header = "the key the controller expects"
    with fake_unifi(scenario) as server:
        report = collect(pipeline, server)
        paths = [request.path for request in server.requests]
    assert (report.status, report.error_class) == ("failed", ERROR_UNAUTHORIZED)
    assert paths == ["/integration/v1/info"]
    assert coverage_rows(database) == {}


# -- the console proxy path --------------------------------------------------------------------


def test_the_proxy_base_path_is_found_and_every_resource_is_covered(
    database: Database, pipeline: RunPipeline
) -> None:
    scenario = healthy()
    scenario.base_path = "/proxy/network/integration"
    scenario.html_elsewhere = True
    with fake_unifi(scenario) as server:
        client = UnifiClient(server.url, CANARY_HEADER, allow_plain_http=True)
        report = pipeline.run(SOURCE_ID, client)
    rows = coverage_rows(database)
    assert report.status == "ok"
    assert client.base_path == "/proxy/network/integration"
    assert sorted(rows) == sorted(item.name for item in RESOURCES)
    assert {row.last_status for row in rows.values()} == {"200"}
