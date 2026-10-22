"""Volatility and coverage of the Xen Orchestra collector through the whole pipeline (P8-T4).

The fake server serves the pool of ``tests/fixtures/xo/pool.json`` in three phases of a simulated
backup run (``base``, ``during`` and ``after``; see ``tests/contract/xo_pool.py``). The real client
and the real run pipeline collect each phase into a migrated database, and the tests check what a
person would see:

* the backup run, which creates and deletes snapshots and changes snapshot lists, disk lists,
  parents, power state and memory numbers, produces **no** change item, while a real configuration
  change made at the same moment is still reported;
* the coverage panel lists every collection in admin mode, and in a read-only fixture the
  collections an admin only can read (users, groups, servers and remotes) show 403 with their
  objects kept and never reported as removed.

Every name the fake serves is unverified (docs/vendor-notes/xo.md). The fake returns every field of
an object whatever the request asks for, which is the worst case for the normaliser.
"""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD
from driftsniff.collectors.xo.client import ERROR_FORBIDDEN, ERROR_NOT_AVAILABLE
from driftsniff.collectors.xo.resources import COLLECTIONS, EXCLUDED_COLLECTIONS
from driftsniff.db import tables
from driftsniff.db.engine import Database
from driftsniff.sources.runs import RunPipeline

from .fake_xo import PREFIX, TOKENS, FakeXo, fake_xo
from .unifi_bands import change_item_rows, coverage_rows
from .xo_pool import (
    Phase,
    benign_seeds,
    collect,
    kept_counts,
    make_pipeline,
    open_database,
    pool_scenario,
)

# The collections a read-only role cannot read (plan P8-T4; unverified, test X2 is open): the
# plan's "remotes" are the backup repositories.
ADMIN_ONLY = ("users", "groups", "servers", "backup-repositories")

# Collections whose volatile fields are still different after the run (a new parent, a new memory
# number), and those that the run leaves as they were once it is over.
LEFT_BEHIND = ("vms", "hosts", "srs", "vdis", "vbds", "users")
RETURNED = ("vifs", "pifs", "pbds", "servers")


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


def event_count(database: Database) -> int:
    with database.read() as connection:
        rows = connection.execute(sa.select(sa.func.count()).select_from(tables.change_events))
        return int(rows.scalar_one())


def requested_names(server: FakeXo) -> set[str]:
    """The collections (and the two fixed routes) the server was asked for."""
    names: set[str] = set()
    for request in server.requests:
        assert request.path.startswith(PREFIX), request.path
        names.add(request.path.removeprefix(PREFIX).strip("/"))
    return names


# -- the simulated backup run ------------------------------------------------------------------


def test_the_simulated_backup_run_changes_the_pool_but_not_its_configuration() -> None:
    """The fixture would prove nothing if the phases looked the same to the collector."""
    seeds = benign_seeds()
    base = pool_scenario(seeds, "base").objects
    during = pool_scenario(seeds, "during").objects
    after = pool_scenario(seeds, "after").objects
    for changed in (*LEFT_BEHIND, *RETURNED):
        assert during[changed] != base[changed], changed
        assert after[changed] != during[changed], changed
    for changed in LEFT_BEHIND:
        assert after[changed] != base[changed], changed
    for returned in RETURNED:
        assert after[returned] == base[returned], returned
    assert [item["id"] for item in during["vm-snapshots"]] == ["snap-web-1", "snap-db-1"]
    assert [item["id"] for item in during["vdi-snapshots"]] == ["vdi-snap-web-1", "vdi-snap-db-1"]
    assert [item["id"] for item in during["tasks"]] == ["task-backup-1"]
    assert base["vm-snapshots"] == after["vm-snapshots"] == []
    assert base["vms"][0]["snapshots"] == []
    assert during["vms"][0]["snapshots"] == ["snap-web-1"]
    assert base["vms"][0]["name_label"] == during["vms"][0]["name_label"] == "web-1"


def test_a_simulated_backup_run_produces_zero_change_items(
    database: Database, pipeline: RunPipeline
) -> None:
    seeds = benign_seeds()
    phases: list[Phase] = ["base", "during", "after", "base", "during", "after"]
    with fake_xo(pool_scenario(seeds, "base")) as server:
        reports = []
        for phase in phases:
            server.scenario.objects = pool_scenario(seeds, phase).objects
            reports.append(collect(pipeline, server))
        names = requested_names(server)
    assert [report.status for report in reports] == ["ok"] * len(phases)
    assert [report.event_id for report in reports] == [None] * len(phases)
    assert len({report.object_count for report in reports}) == 1
    assert reports[0].object_count == sum(kept_counts().values())
    assert change_item_rows(database) == []
    assert event_count(database) == 0
    # Neither a snapshot, a task nor a log is ever requested, though the fake serves them.
    assert names <= {"", TOKENS, *COLLECTIONS}
    assert names.isdisjoint(EXCLUDED_COLLECTIONS)


def rename_a_vm(objects: dict[str, list[dict[str, Any]]]) -> None:
    objects["vms"][0]["name_label"] = "web-1-renamed"


def promote_a_user(objects: dict[str, list[dict[str, Any]]]) -> None:
    objects["users"][1]["permission"] = "admin"


def shorten_retention(objects: dict[str, list[dict[str, Any]]]) -> None:
    objects["backup-jobs"][0]["settings"]["exportRetention"] = 1


@pytest.mark.parametrize(
    ("change", "resource", "path"),
    [
        pytest.param(rename_a_vm, "vms", "name_label", id="vm renamed"),
        pytest.param(promote_a_user, "users", "permission", id="user promoted"),
        pytest.param(
            shorten_retention, "backup-jobs", "settings.exportRetention", id="retention shortened"
        ),
    ],
)
def test_a_real_change_made_during_a_backup_run_is_the_only_change_reported(
    database: Database,
    pipeline: RunPipeline,
    change: Callable[[dict[str, list[dict[str, Any]]]], None],
    resource: str,
    path: str,
) -> None:
    seeds = benign_seeds()
    with fake_xo(pool_scenario(seeds, "base")) as server:
        collect(pipeline, server)
        during = pool_scenario(seeds, "during")
        change(during.objects)
        server.scenario.objects = during.objects
        report = collect(pipeline, server)
    items = change_item_rows(database)
    assert report.status == "ok"
    assert report.event_id is not None
    assert [(item.resource, item.path) for item in items] == [(resource, path)]


# -- the coverage panel ------------------------------------------------------------------------


def test_admin_mode_covers_every_collection(database: Database, pipeline: RunPipeline) -> None:
    with fake_xo(pool_scenario(benign_seeds())) as server:
        report = collect(pipeline, server)
    rows = coverage_rows(database)
    expected = kept_counts()
    assert report.status == "ok"
    assert sorted(rows) == sorted(COLLECTIONS)
    assert {name: row.object_count for name, row in rows.items()} == expected
    for row in rows.values():
        assert (row.last_status, row.stale_since) == ("200", None)
        assert row.last_ok_at is not None


def read_only(server: FakeXo) -> None:
    for name in ADMIN_ONLY:
        server.scenario.status[name] = 403


def test_the_read_only_fixture_shows_403_on_the_admin_only_collections(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_xo(pool_scenario(benign_seeds())) as server:
        read_only(server)
        report = collect(pipeline, server)
    rows = coverage_rows(database)
    expected = kept_counts()
    assert (report.status, report.error_class) == ("partial", ERROR_FORBIDDEN)
    assert sorted(rows) == sorted(COLLECTIONS)
    for name in ADMIN_ONLY:
        row = rows[name]
        assert (row.last_status, row.object_count, row.last_ok_at) == ("403", 0, None)
        assert row.stale_since is not None
    reachable = {name: row for name, row in rows.items() if name not in ADMIN_ONLY}
    assert len(reachable) == len(COLLECTIONS) - len(ADMIN_ONLY)
    for name, row in reachable.items():
        assert row.last_status == "200"
        assert (row.object_count, row.stale_since) == (expected[name], None)
    assert change_item_rows(database) == []


def test_a_credential_that_loses_its_admin_rights_goes_stale_and_removes_nothing(
    database: Database, pipeline: RunPipeline
) -> None:
    with fake_xo(pool_scenario(benign_seeds())) as server:
        first = collect(pipeline, server)
        before = coverage_rows(database)
        read_only(server)
        second = collect(pipeline, server)
        third = collect(pipeline, server)
        stale = coverage_rows(database)
        server.scenario.status.clear()
        recovered = collect(pipeline, server)
    after = coverage_rows(database)
    expected = kept_counts()
    assert (first.status, second.status, third.status, recovered.status) == (
        "ok",
        "partial",
        "partial",
        "ok",
    )
    for name in ADMIN_ONLY:
        assert (stale[name].last_status, stale[name].object_count) == ("403", expected[name])
        assert stale[name].last_ok_at == before[name].last_ok_at
        assert stale[name].stale_since == before[name].last_ok_at
        assert (after[name].last_status, after[name].stale_since) == ("200", None)
        assert after[name].last_ok_at is not None
        assert before[name].last_ok_at is not None
        assert after[name].last_ok_at > before[name].last_ok_at
    # A collection that could not be read is never reported as removed, nor as added again.
    assert change_item_rows(database) == []
    assert event_count(database) == 0


def not_available(server: FakeXo) -> None:
    server.scenario.status["acl-privileges"] = 404


def bad_line(server: FakeXo) -> None:
    server.scenario.raw["proxies"] = b'{"id": "proxy-a"}\nthis line is not json\n'


@pytest.mark.parametrize(
    ("break_it", "resource", "status", "error_class"),
    [
        pytest.param(not_available, "acl-privileges", "404", ERROR_NOT_AVAILABLE, id="404"),
        pytest.param(bad_line, "proxies", "error", ERROR_BAD_PAYLOAD, id="bad line"),
    ],
)
def test_one_unreadable_collection_goes_stale_alone(
    database: Database,
    pipeline: RunPipeline,
    break_it: Callable[[FakeXo], None],
    resource: str,
    status: str,
    error_class: str,
) -> None:
    with fake_xo(pool_scenario(benign_seeds())) as server:
        first = collect(pipeline, server)
        before = coverage_rows(database)[resource]
        break_it(server)
        second = collect(pipeline, server)
    rows = coverage_rows(database)
    row = rows[resource]
    assert first.status == "ok"
    assert (second.status, second.error_class) == ("partial", error_class)
    assert (row.last_status, row.object_count) == (status, before.object_count)
    assert before.object_count > 0
    assert (row.last_ok_at, row.stale_since) == (before.last_ok_at, before.last_ok_at)
    others = [other for name, other in rows.items() if name != resource]
    assert len(others) == len(COLLECTIONS) - 1
    assert all((other.last_status, other.stale_since) == ("200", None) for other in others)
    assert change_item_rows(database) == []
