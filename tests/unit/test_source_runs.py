"""The run pipeline (sources/runs.py), driven by fake collectors on a migrated database.

No real controller is contacted: a fake collector hands over raw objects, or a failure, and the
tests read back what the pipeline stored. The clock, the sleeps and the monotonic time are fakes,
so retries and the time limit take no real time.
"""

import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
    ERROR_BODY_TOO_LARGE,
    ERROR_CONNECTION,
    ERROR_HTTP,
    ERROR_REDIRECT,
    ERROR_TIMEOUT,
    MAX_ERROR_TEXT_CHARS,
    Collector,
    CollectorError,
    FetchResult,
    ResourceSpec,
)
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem
from driftsniff.core.normalize import CollectionMode, FieldClass
from driftsniff.core.runs import start_run
from driftsniff.core.snapshots import latest_snapshot, resolve_current_state
from driftsniff.core.states import decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import RuleIndex
from driftsniff.rules.schema import ResourceTable
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import (
    ERROR_ALREADY_RUNNING,
    ERROR_BAD_OBJECT,
    ERROR_DISABLED,
    ERROR_DUPLICATE_KEY,
    ERROR_DUPLICATE_RESOURCE,
    ERROR_INTERRUPTED,
    ERROR_NO_RESOURCES,
    ERROR_RUN_TIMEOUT,
    ERROR_UNKNOWN_RESOURCE,
    RUN_LIMIT_SECONDS,
    RunPipeline,
    RunReport,
    error_summary,
)
from driftsniff.sources.service import SourceNotFoundError

SOURCE_ID = 1
START = datetime(2026, 10, 21, 9, 0, 0, tzinfo=UTC)
FINGERPRINTER = Fingerprinter(bytes(range(32)), "0a1b2c3d")
CANARY_FIRST = "CANARY-passphrase-0001-first"
CANARY_SECOND = "CANARY-passphrase-0002-second"
# A three-part dotted value in the shape the scrubber must remove, built from base64url-style
# pieces at import time so the file holds no credential-shaped literal.
JWT_MARK = "ey" + "J"
JWT = ".".join(JWT_MARK + part for part in ("hbGciOi", "zdWIiOi", "YWJj"))
QUERY_SECRET = "zz" + "9" * 6
QUERY_URL = "see https://host.example/path?" + "tok" + "en=" + QUERY_SECRET

C = FieldClass.CONFIG
NETWORKS = ResourceTable(
    resource="networks",
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": C,
        "name": C,
        "vlan": C,
        "comment": C,
        "passphrase": FieldClass.SECRET,
        "uptime": FieldClass.IGNORE,
    },
    floors={"removed": "critical"},
)
HOSTS = ResourceTable(
    resource="hosts",
    object_key_field="id",
    name_field="hostname",
    field_classes={"id": C, "hostname": C, "ip": C},
)
POLICIES = ResourceTable(
    resource="policies",
    object_key_field="id",
    name_field="name",
    collection=CollectionMode.ORDERED_KEYED,
    field_classes={"id": C, "name": C, "action": C},
    action_field="action",
    first_match=True,
    blocking_actions=frozenset({"deny"}),
)
INDEX = RuleIndex(
    pack_version="pack-t1",
    rules=(),
    by_resource={},
    type_tables={"networks": NETWORKS, "hosts": HOSTS, "policies": POLICIES},
)


def networks(
    *,
    vlan: int = 20,
    secret: str = CANARY_FIRST,
    uptime: int = 5,
    lab: bool = True,
) -> list[dict[str, JsonValue]]:
    found: list[dict[str, JsonValue]] = []
    if lab:
        found.append(
            {"_id": "n1", "name": "Lab", "vlan": 10, "passphrase": secret, "uptime": uptime}
        )
    found.append({"_id": "n2", "name": "Guest", "vlan": vlan})
    return found


def hosts() -> list[dict[str, JsonValue]]:
    return [
        {"id": 1, "hostname": "nas", "ip": "10.0.0.5"},
        {"id": 2, "hostname": "printer", "ip": "10.0.0.6"},
    ]


def policies(order: Sequence[str] = ("p1", "p2", "p3")) -> list[dict[str, JsonValue]]:
    actions = {"p1": "allow", "p2": "deny", "p3": "allow"}
    return [{"id": key, "name": f"Policy {key}", "action": actions[key]} for key in order]


class FakeCollector(Collector):
    """Hands over what it was given; scripted failures come first, per resource."""

    def __init__(
        self, data: Mapping[str, Sequence[Any]], *, version: str | None = "10.0.1"
    ) -> None:
        self.data = dict(data)
        self.version = version
        self.listed: list[str] | None = None
        self.probe_errors: list[Exception] = []
        self.resources_error: Exception | None = None
        self.close_error: Exception | None = None
        self.script: dict[str, list[FetchResult | Exception]] = {}
        self.on_fetch: Callable[[ResourceSpec], None] | None = None
        self.on_probe: Callable[[], None] | None = None
        self.probes = 0
        self.calls: list[str] = []
        self.closed = 0

    def probe(self) -> str | None:
        self.probes += 1
        if self.on_probe is not None:
            self.on_probe()
        if self.probe_errors:
            raise self.probe_errors.pop(0)
        return self.version

    def resources(self) -> Sequence[ResourceSpec]:
        if self.resources_error is not None:
            raise self.resources_error
        names = list(self.data) if self.listed is None else self.listed
        return [ResourceSpec(name) for name in names]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        self.calls.append(spec.name)
        if self.on_fetch is not None:
            self.on_fetch(spec)
        queue = self.script.get(spec.name)
        if queue:
            step = queue.pop(0)
            if isinstance(step, Exception):
                raise step
            return step
        return FetchResult.success(self.data[spec.name], bytes_fetched=100)

    def close(self) -> None:
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


class Clock:
    """UTC timestamps one second apart, one for every call."""

    def __init__(self) -> None:
        self.second = 0

    def __call__(self) -> str:
        value = START + timedelta(seconds=self.second)
        self.second += 1
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class Timer:
    """A monotonic time that only moves when a test or a sleep moves it."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def jump_to(self, now: float) -> None:
        self.now = now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Rig:
    database: Database
    pipeline: RunPipeline
    timer: Timer
    notified: list[int] = field(default_factory=list)

    def run(self, collector: Collector) -> RunReport:
        return self.pipeline.run(SOURCE_ID, collector)


def make_rig(
    database: Database,
    *,
    engine: RuleEngine | None = None,
    notifier: Callable[[int], None] | None = None,
) -> Rig:
    timer = Timer()
    notified: list[int] = []
    pipeline = RunPipeline(
        database,
        RuleEngine(INDEX) if engine is None else engine,
        FINGERPRINTER,
        notifier=notified.append if notifier is None else notifier,
        clock=Clock(),
        sleep=timer.sleep,
        monotonic=timer.monotonic,
    )
    return Rig(database, pipeline, timer, notified)


@pytest.fixture
def rig(store: Database) -> Rig:
    return make_rig(store)


def table_rows(database: Database, table: sa.Table) -> list[sa.Row[tuple[object, ...]]]:
    with database.read() as connection:
        return list(connection.execute(sa.select(table).order_by(*table.primary_key.columns)))


def count(database: Database, table: sa.Table) -> int:
    with database.read() as connection:
        return connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()


def run_rows(database: Database) -> list[sa.Row[tuple[object, ...]]]:
    return table_rows(database, tables.runs)


def source_row(database: Database) -> sa.Row[tuple[object, ...]]:
    return table_rows(database, tables.sources)[0]


def coverage(database: Database) -> dict[str, sa.Row[tuple[object, ...]]]:
    return {str(row.resource): row for row in table_rows(database, tables.resource_coverage)}


def items_by_kind(database: Database) -> dict[str, sa.Row[tuple[object, ...]]]:
    return {str(row.change_kind): row for row in table_rows(database, tables.change_items)}


def refused(status: str = "403") -> FetchResult:
    return FetchResult.failure(ERROR_HTTP, "forbidden", status=status)


def test_the_run_limit_is_five_minutes() -> None:
    assert RUN_LIMIT_SECONDS == 300.0


def test_the_first_run_stores_a_baseline_and_no_event(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks(), "hosts": hosts()})
    report = rig.run(collector)
    assert report.status == "ok"
    assert report.stored_new_snapshot is True
    assert report.event_id is None
    assert report.object_count == 4
    assert (report.error_class, report.error_summary) == (None, None)
    snapshot = table_rows(rig.database, tables.snapshots)
    assert [row.kind for row in snapshot] == ["baseline"]
    assert count(rig.database, tables.change_events) == 0
    assert count(rig.database, tables.object_states) == 4
    object_rows = table_rows(rig.database, tables.objects)
    assert sorted((row.resource, row.object_key) for row in object_rows) == [
        ("hosts", "1"),
        ("hosts", "2"),
        ("networks", "n1"),
        ("networks", "n2"),
    ]
    names = {(row.resource, row.object_key): row.display_name for row in object_rows}
    assert names[("networks", "n1")] == "Lab"
    assert names[("hosts", "2")] == "printer"
    (run,) = run_rows(rig.database)
    assert run.id == report.run_id
    assert run.status == "ok"
    assert run.finished_at is not None
    assert (run.object_count, run.bytes_fetched) == (4, 200)
    assert bool(run.stored_new_snapshot) is True
    assert run.new_state_bytes > 0
    assert run.manifest_bytes > 0
    source = source_row(rig.database)
    assert source.last_success_at == run.finished_at == source.last_checked_at
    assert source.controller_version == "10.0.1"
    assert collector.closed == 1
    for row in coverage(rig.database).values():
        assert (row.last_status, row.last_ok_at, row.stale_since) == ("200", run.finished_at, None)
        assert row.object_count == 2


def test_a_change_stores_one_event_with_classified_items(rig: Rig) -> None:
    rig.run(FakeCollector({"networks": networks(), "hosts": hosts()}))
    second = rig.run(FakeCollector({"networks": networks(vlan=30, lab=False), "hosts": hosts()}))
    assert second.status == "ok"
    assert second.stored_new_snapshot is True
    assert second.event_id is not None
    assert second.object_count == 3
    first_run, second_run = run_rows(rig.database)
    first_snapshot, second_snapshot = table_rows(rig.database, tables.snapshots)
    assert second_snapshot.kind == "normal"
    (event,) = table_rows(rig.database, tables.change_events)
    assert event.id == second.event_id
    assert event.snapshot_id == second_snapshot.id
    assert event.previous_snapshot_id == first_snapshot.id
    assert event.max_severity == "critical"
    assert event.item_count == 2
    assert event.rule_pack_version == "pack-t1"
    assert event.status == "open"
    assert event.summary == "2 changes in 1 resource type, highest severity critical"
    assert event.window_start == first_run.finished_at
    assert event.window_end == second_run.finished_at == event.created_at
    items = items_by_kind(rig.database)
    assert set(items) == {"removed", "modified"}
    removed, modified = items["removed"], items["modified"]
    objects = {row.object_key: row for row in table_rows(rig.database, tables.objects)}
    assert objects["n1"].removed_at == second_run.finished_at
    assert removed.object_id == objects["n1"].id
    assert (removed.resource, removed.path, removed.object_name_at_time) == ("networks", "", "Lab")
    assert (removed.severity, removed.rule_id) == ("critical", "builtin.floor.removed")
    assert modified.object_id == objects["n2"].id
    assert (modified.path, modified.field_class) == ("vlan", "config")
    assert (modified.before_value, modified.after_value) == ("20", "30")
    assert (modified.severity, modified.rule_id) == ("medium", "builtin.unclassified")
    assert modified.object_name_at_time == "Guest"
    assert modified.rationale


def test_a_secret_is_stored_and_shown_as_a_fingerprint_only(rig: Rig) -> None:
    rig.run(FakeCollector({"networks": networks(secret=CANARY_FIRST)}))
    report = rig.run(FakeCollector({"networks": networks(secret=CANARY_SECOND)}))
    assert report.event_id is not None
    (item,) = table_rows(rig.database, tables.change_items)
    assert (item.path, item.field_class, item.change_kind) == ("passphrase", "secret", "modified")
    assert item.before_value is None
    assert item.after_value is None
    assert str(item.before_fp).startswith("fp1:0a1b2c3d:")
    assert str(item.after_fp).startswith("fp1:0a1b2c3d:")
    assert item.before_fp != item.after_fp
    for state in table_rows(rig.database, tables.object_states):
        assert b"CANARY" not in decompress_bytes(state.body_zstd, 1_000_000)
    for table in (tables.runs, tables.change_events, tables.change_items, tables.objects):
        assert "CANARY" not in repr(table_rows(rig.database, table))


def test_an_ignored_field_alone_never_makes_a_snapshot(rig: Rig) -> None:
    rig.run(FakeCollector({"networks": networks(uptime=1)}))
    second = rig.run(FakeCollector({"networks": networks(uptime=99)}))
    assert second.status == "ok"
    assert second.stored_new_snapshot is False
    assert second.event_id is None
    assert count(rig.database, tables.snapshots) == 1
    assert count(rig.database, tables.change_events) == 0


def test_a_run_without_change_stores_nothing_new(rig: Rig) -> None:
    rig.run(FakeCollector({"networks": networks(), "hosts": hosts()}))
    states = count(rig.database, tables.object_states)
    second = rig.run(FakeCollector({"networks": networks(), "hosts": hosts()}))
    assert (second.status, second.stored_new_snapshot, second.event_id) == ("ok", False, None)
    assert count(rig.database, tables.snapshots) == 1
    assert count(rig.database, tables.object_states) == states
    first_run, second_run = run_rows(rig.database)
    assert bool(second_run.stored_new_snapshot) is False
    assert (second_run.new_state_bytes, second_run.manifest_bytes) == (0, 0)
    source = source_row(rig.database)
    assert source.last_checked_at == second_run.finished_at
    assert source.last_success_at == second_run.finished_at != first_run.finished_at


def test_the_notifier_hears_of_an_event_after_the_commit(store: Database) -> None:
    heard: list[tuple[int, int]] = []

    def notify(event_id: int) -> None:
        # The event is already committed: a separate read connection sees it.
        heard.append((event_id, count(store, tables.change_events)))

    rig = make_rig(store, notifier=notify)
    rig.run(FakeCollector({"networks": networks()}))
    assert heard == []
    report = rig.run(FakeCollector({"networks": networks(vlan=30)}))
    assert heard == [(report.event_id, 1)]


def test_a_failing_notifier_does_not_change_the_result(store: Database) -> None:
    def explode(event_id: int) -> None:
        raise RuntimeError("CANARY-notify-0009")

    rig = make_rig(store, notifier=explode)
    rig.run(FakeCollector({"networks": networks()}))
    report = rig.run(FakeCollector({"networks": networks(vlan=30)}))
    assert report.status == "ok"
    assert report.event_id is not None
    assert count(store, tables.change_events) == 1
    assert [row.status for row in run_rows(store)] == ["ok", "ok"]


def test_a_run_started_while_the_source_is_running_is_skipped(rig: Rig) -> None:
    inner: list[RunReport] = []
    second = FakeCollector({"networks": networks()})
    first = FakeCollector({"networks": networks()})
    first.on_fetch = lambda spec: inner.append(rig.run(second))
    outer = rig.run(first)
    assert outer.status == "ok"
    (skipped,) = inner
    assert skipped.status == "skipped"
    assert skipped.error_class == ERROR_ALREADY_RUNNING
    assert skipped.stored_new_snapshot is False
    assert second.calls == []
    assert second.probes == 0
    assert second.closed == 1
    skipped_row, ok_row = sorted(run_rows(rig.database), key=lambda row: row.status != "skipped")
    assert skipped_row.id == skipped.run_id
    assert skipped_row.status == "skipped"
    assert skipped_row.error_class == ERROR_ALREADY_RUNNING
    assert skipped_row.finished_at is not None
    assert ok_row.status == "ok"
    assert count(rig.database, tables.snapshots) == 1
    # The lock is released when the run ends.
    assert rig.run(FakeCollector({"networks": networks()})).status == "ok"


def test_a_run_started_from_another_thread_is_skipped(rig: Rig) -> None:
    entered = threading.Event()
    release = threading.Event()
    results: list[RunReport] = []

    def block(spec: ResourceSpec) -> None:
        entered.set()
        release.wait(10)

    first = FakeCollector({"networks": networks()})
    first.on_fetch = block
    thread = threading.Thread(target=lambda: results.append(rig.run(first)))
    thread.start()
    try:
        assert entered.wait(10)
        second = FakeCollector({"networks": networks()})
        skipped = rig.run(second)
    finally:
        release.set()
        thread.join(10)
    assert skipped.status == "skipped"
    assert skipped.error_class == ERROR_ALREADY_RUNNING
    assert second.calls == []
    assert [report.status for report in results] == ["ok"]
    assert sorted(row.status for row in run_rows(rig.database)) == ["ok", "skipped"]


def test_a_disabled_source_is_skipped(rig: Rig) -> None:
    with rig.database.write() as connection:
        connection.execute(sa.update(tables.sources).values(enabled=False))
    collector = FakeCollector({"networks": networks()})
    report = rig.run(collector)
    assert report.status == "skipped"
    assert report.error_class == ERROR_DISABLED
    assert (collector.probes, collector.calls, collector.closed) == (0, [], 1)
    (run,) = run_rows(rig.database)
    assert (run.status, run.error_class) == ("skipped", ERROR_DISABLED)
    assert run.finished_at is not None
    assert count(rig.database, tables.snapshots) == 0


def test_an_unknown_source_is_an_error_and_the_collector_is_still_closed(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    with pytest.raises(SourceNotFoundError):
        rig.pipeline.run(99, collector)
    assert collector.closed == 1
    assert count(rig.database, tables.runs) == 0


def test_a_run_left_open_by_a_dead_process_is_closed_as_interrupted(rig: Rig) -> None:
    with rig.database.write() as connection:
        start_run(connection, SOURCE_ID, "2026-10-20T08:00:00Z")
    report = rig.run(FakeCollector({"networks": networks()}))
    assert report.status == "ok"
    old, new = run_rows(rig.database)
    assert (old.status, old.error_class) == ("failed", ERROR_INTERRUPTED)
    assert old.finished_at is not None
    assert old.error_summary
    assert (new.id, new.status) == (report.run_id, "ok")


def test_a_probe_that_fails_ends_the_run_and_stores_nothing(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    refusal = CollectorError(ERROR_HTTP, "the controller refused the key", status="401")
    collector.probe_errors = [refusal]
    report = rig.run(collector)
    assert report.status == "failed"
    assert report.error_class == ERROR_HTTP
    assert report.error_summary == "the controller refused the key"
    assert collector.calls == []
    assert collector.closed == 1
    assert rig.timer.sleeps == []
    (run,) = run_rows(rig.database)
    assert (run.status, run.error_class) == ("failed", ERROR_HTTP)
    assert run.finished_at is not None
    for table in (tables.snapshots, tables.object_states, tables.objects, tables.resource_coverage):
        assert count(rig.database, table) == 0
    assert source_row(rig.database).last_success_at is None


def test_a_probe_that_times_out_is_tried_again(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.probe_errors = [CollectorError(ERROR_TIMEOUT, "no answer")]
    report = rig.run(collector)
    assert report.status == "ok"
    assert collector.probes == 2
    assert rig.timer.sleeps == [1.0]


def test_a_probe_is_tried_four_times_at_most(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.probe_errors = [CollectorError(ERROR_TIMEOUT, "no answer") for _ in range(5)]
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("failed", ERROR_TIMEOUT)
    assert collector.probes == 4
    assert rig.timer.sleeps == [1.0, 2.0, 4.0]


def test_a_probe_that_is_refused_is_not_tried_again(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.probe_errors = [CollectorError(ERROR_HTTP, "forbidden", status="403")]
    assert rig.run(collector).status == "failed"
    assert collector.probes == 1
    assert rig.timer.sleeps == []


def test_a_server_error_is_retried_after_one_two_and_four_seconds(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    bad = FetchResult.failure(ERROR_HTTP, "bad gateway", status="502", bytes_fetched=7)
    collector.script["networks"] = [bad, bad, bad]
    report = rig.run(collector)
    assert report.status == "ok"
    assert collector.calls == ["networks"] * 4
    assert rig.timer.sleeps == [1.0, 2.0, 4.0]
    (run,) = run_rows(rig.database)
    assert run.bytes_fetched == 3 * 7 + 100


def test_a_resource_that_keeps_failing_is_given_up_after_four_reads(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    bad = FetchResult.failure(ERROR_HTTP, "bad gateway", status="502", bytes_fetched=7)
    collector.script["networks"] = [bad, bad, bad, bad, bad]
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("failed", ERROR_HTTP)
    assert report.error_summary == "bad gateway"
    assert collector.calls == ["networks"] * 4
    assert rig.timer.sleeps == [1.0, 2.0, 4.0]
    (run,) = run_rows(rig.database)
    assert (run.status, run.bytes_fetched) == ("failed", 28)
    assert coverage(rig.database)["networks"].last_status == "502"
    assert count(rig.database, tables.snapshots) == 0


def test_a_timeout_is_retried(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.script["networks"] = [FetchResult.failure(ERROR_TIMEOUT, "no answer")]
    assert rig.run(collector).status == "ok"
    assert collector.calls == ["networks"] * 2
    assert rig.timer.sleeps == [1.0]


@pytest.mark.parametrize(
    ("error_class", "status"),
    [
        (ERROR_HTTP, "403"),
        (ERROR_HTTP, "404"),
        (ERROR_CONNECTION, "error"),
        (ERROR_BAD_JSON, "error"),
        (ERROR_REDIRECT, "302"),
        (ERROR_BODY_TOO_LARGE, "error"),
    ],
)
def test_anything_but_a_timeout_or_a_server_error_is_not_retried(
    rig: Rig, error_class: str, status: str
) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.script["networks"] = [FetchResult.failure(error_class, "no good", status=status)]
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("failed", error_class)
    assert collector.calls == ["networks"]
    assert rig.timer.sleeps == []
    assert coverage(rig.database)["networks"].last_status == status


def test_a_failed_resource_keeps_its_previous_state_and_the_run_is_partial(rig: Rig) -> None:
    rig.run(FakeCollector({"networks": networks(), "hosts": hosts()}))
    first_run = run_rows(rig.database)[0]
    collector = FakeCollector({"networks": networks(vlan=30), "hosts": hosts()})
    collector.script["hosts"] = [refused()]
    report = rig.run(collector)
    assert report.status == "partial"
    assert report.error_class == ERROR_HTTP
    assert report.error_summary == "failed: hosts (403)"
    assert report.object_count == 4
    assert report.event_id is not None
    second_run = run_rows(rig.database)[1]
    assert (second_run.status, second_run.error_class) == ("partial", ERROR_HTTP)
    assert second_run.error_summary == "failed: hosts (403)"
    # A partial run is a check but not a success.
    source = source_row(rig.database)
    assert source.last_checked_at == second_run.finished_at
    assert source.last_success_at == first_run.finished_at
    current = latest_snapshot_state(rig.database)
    assert set(current["hosts"]) == {"1", "2"}
    assert current["networks"]["n2"]["vlan"] == 30
    objects = table_rows(rig.database, tables.objects)
    assert all(row.removed_at is None for row in objects if row.resource == "hosts")
    (item,) = table_rows(rig.database, tables.change_items)
    assert (item.resource, item.path, item.change_kind) == ("networks", "vlan", "modified")
    hosts_row = coverage(rig.database)["hosts"]
    assert hosts_row.last_status == "403"
    assert hosts_row.last_ok_at == first_run.finished_at
    assert hosts_row.stale_since == first_run.finished_at
    assert hosts_row.object_count == 2
    assert coverage(rig.database)["networks"].last_status == "200"
    # The next good read clears the mark.
    third = rig.run(FakeCollector({"networks": networks(vlan=30), "hosts": hosts()}))
    assert third.status == "ok"
    cleared = coverage(rig.database)["hosts"]
    assert (cleared.last_status, cleared.stale_since) == ("200", None)
    assert cleared.last_ok_at == run_rows(rig.database)[2].finished_at


def latest_snapshot_state(database: Database) -> dict[str, dict[str, dict[str, JsonValue]]]:
    with database.read() as connection:
        state = resolve_current_state(connection, SOURCE_ID)
    assert state is not None
    return state


def test_a_resource_that_was_never_read_is_stale_from_its_first_failure(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks(), "hosts": hosts()})
    collector.script["hosts"] = [refused("404")]
    report = rig.run(collector)
    assert report.status == "partial"
    (run,) = run_rows(rig.database)
    row = coverage(rig.database)["hosts"]
    assert (row.last_status, row.last_ok_at, row.object_count) == ("404", None, 0)
    assert row.stale_since == run.finished_at
    assert set(latest_snapshot_state(rig.database)) == {"networks"}
    second = rig.run(FakeCollector({"networks": networks(), "hosts": hosts()}))
    assert second.status == "ok"
    assert second.event_id is not None
    assert sorted(row.change_kind for row in table_rows(rig.database, tables.change_items)) == [
        "added",
        "added",
    ]


def test_a_resource_the_collector_stops_listing_is_carried_over(rig: Rig) -> None:
    rig.run(FakeCollector({"networks": networks(), "hosts": hosts()}))
    second = rig.run(FakeCollector({"networks": networks()}))
    assert second.status == "ok"
    assert second.stored_new_snapshot is False
    assert second.object_count == 4
    assert all(row.removed_at is None for row in table_rows(rig.database, tables.objects))


def test_an_ordered_resource_keeps_its_order_and_reports_a_move(rig: Rig) -> None:
    rig.run(FakeCollector({"policies": policies()}))
    report = rig.run(FakeCollector({"policies": policies(("p3", "p1", "p2"))}))
    assert report.event_id is not None
    (event,) = table_rows(rig.database, tables.change_events)
    assert event.max_severity in ("high", "critical")
    kinds = {row.change_kind for row in table_rows(rig.database, tables.change_items)}
    assert kinds == {"moved"}
    with rig.database.read() as connection:
        newest = latest_snapshot(connection, SOURCE_ID)
    assert newest is not None
    assert list(newest.manifest.positions["policies"]) == ["p3", "p1", "p2"]


def test_the_order_of_a_carried_resource_is_carried_with_it(rig: Rig) -> None:
    rig.run(FakeCollector({"policies": policies(("p3", "p1", "p2")), "hosts": hosts()}))
    collector = FakeCollector({"policies": policies(), "hosts": hosts()})
    collector.script["policies"] = [refused()]
    report = rig.run(collector)
    assert report.status == "partial"
    # The manifest is the one of the first run, positions included: nothing new is stored.
    assert report.stored_new_snapshot is False
    assert count(rig.database, tables.snapshots) == 1


def test_a_time_limit_stops_the_resources_that_are_not_reached(store: Database) -> None:
    rig = make_rig(store)
    collector = FakeCollector({"networks": networks(), "hosts": hosts()})
    collector.on_fetch = lambda spec: rig.timer.advance(RUN_LIMIT_SECONDS + 1.0)
    report = rig.run(collector)
    assert report.status == "partial"
    assert report.error_class == ERROR_RUN_TIMEOUT
    assert report.error_summary == "failed: hosts (error)"
    assert collector.calls == ["networks"]
    assert coverage(store)["hosts"].last_status == "error"
    assert coverage(store)["networks"].last_status == "200"


def test_a_retry_that_would_end_after_the_time_limit_is_not_started(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.script["networks"] = [FetchResult.failure(ERROR_TIMEOUT, "no answer")]
    collector.on_fetch = lambda spec: rig.timer.jump_to(RUN_LIMIT_SECONDS - 0.5)
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("failed", ERROR_TIMEOUT)
    assert collector.calls == ["networks"]
    assert rig.timer.sleeps == []


def test_a_probe_retry_that_would_end_after_the_time_limit_is_not_started(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.probe_errors = [CollectorError(ERROR_TIMEOUT, "no answer")]
    collector.on_probe = lambda: rig.timer.jump_to(RUN_LIMIT_SECONDS - 0.5)
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("failed", ERROR_TIMEOUT)
    assert rig.timer.sleeps == []


def test_a_resource_without_a_type_table_fails_alone(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks(), "ghosts": [{"_id": "g1"}]})
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("partial", ERROR_UNKNOWN_RESOURCE)
    assert collector.calls == ["networks"]
    assert coverage(rig.database)["ghosts"].last_status == "error"
    assert count(rig.database, tables.snapshots) == 1


def test_a_run_where_nothing_could_be_read_is_failed(rig: Rig) -> None:
    collector = FakeCollector({"ghosts": [{"_id": "g1"}]})
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("failed", ERROR_UNKNOWN_RESOURCE)
    assert count(rig.database, tables.snapshots) == 0


@pytest.mark.parametrize(
    ("objects", "error_class"),
    [
        ([{"name": "no key"}], ERROR_BAD_OBJECT),
        ([{"_id": None, "name": "null key"}], ERROR_BAD_OBJECT),
        ([{"_id": True, "name": "bool key"}], ERROR_BAD_OBJECT),
        ([{"_id": "", "name": "empty key"}], ERROR_BAD_OBJECT),
        ([{"_id": ["a"], "name": "list key"}], ERROR_BAD_OBJECT),
        (["not an object"], ERROR_BAD_OBJECT),
        ([{"_id": "a"}, {"_id": "b"}, {"_id": "a"}], ERROR_DUPLICATE_KEY),
    ],
)
def test_an_object_without_a_usable_key_fails_its_resource(
    rig: Rig, objects: list[Any], error_class: str
) -> None:
    report = rig.run(FakeCollector({"networks": objects, "hosts": hosts()}))
    assert (report.status, report.error_class) == ("partial", error_class)
    assert report.error_summary == "failed: networks (error)"
    assert coverage(rig.database)["networks"].last_status == "error"
    assert set(latest_snapshot_state(rig.database)) == {"hosts"}


def test_an_integer_key_is_the_key_as_text(rig: Rig) -> None:
    rig.run(FakeCollector({"hosts": hosts()}))
    assert sorted(set(latest_snapshot_state(rig.database)["hosts"])) == ["1", "2"]


def test_a_resource_with_no_objects_is_a_good_read(rig: Rig) -> None:
    report = rig.run(FakeCollector({"networks": [], "hosts": hosts()}))
    assert report.status == "ok"
    assert coverage(rig.database)["networks"].object_count == 0


def test_a_collector_that_lists_nothing_fails_the_run(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.listed = []
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("failed", ERROR_NO_RESOURCES)
    assert count(rig.database, tables.snapshots) == 0


def test_a_collector_that_lists_a_resource_twice_fails_the_run(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.listed = ["networks", "networks"]
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("failed", ERROR_DUPLICATE_RESOURCE)
    assert collector.calls == []


def test_an_unexpected_error_is_recorded_by_its_class_name_only(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks(), "hosts": hosts()})
    collector.script["networks"] = [RuntimeError("CANARY-boom-0007 {payload}")]
    report = rig.run(collector)
    assert (report.status, report.error_class) == ("partial", "RuntimeError")
    assert report.error_summary == "failed: networks (error)"
    assert "CANARY" not in repr(table_rows(rig.database, tables.runs))


@pytest.mark.parametrize("where", ["probe", "resources"])
def test_an_unexpected_error_before_the_read_fails_the_run_with_the_class_name(
    rig: Rig, where: str
) -> None:
    collector = FakeCollector({"networks": networks()})
    if where == "probe":
        collector.probe_errors = [ValueError("CANARY-probe-0010")]
    else:
        collector.resources_error = KeyError("CANARY-resources-0011")
    report = rig.run(collector)
    expected = "ValueError" if where == "probe" else "KeyError"
    assert (report.status, report.error_class, report.error_summary) == (
        "failed",
        expected,
        expected,
    )
    assert collector.closed == 1
    assert "CANARY" not in repr(table_rows(rig.database, tables.runs))


def test_a_collector_that_fails_to_close_does_not_change_the_result(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    collector.close_error = RuntimeError("CANARY-close-0012")
    report = rig.run(collector)
    assert report.status == "ok"
    assert collector.closed == 1


def test_a_failure_while_storing_leaves_nothing_of_the_run(store: Database) -> None:
    class Exploding(RuleEngine):
        def apply(self, item: ChangeItem) -> ChangeItem:
            raise RuntimeError("CANARY-apply-0008")

    rig = make_rig(store, engine=Exploding(INDEX))
    first = rig.run(FakeCollector({"networks": networks(), "hosts": hosts()}))
    assert first.status == "ok"
    before = {
        table.name: table_rows(store, table)
        for table in (
            tables.snapshots,
            tables.object_states,
            tables.objects,
            tables.resource_coverage,
            tables.sources,
        )
    }
    collector = FakeCollector({"networks": networks(vlan=30), "hosts": hosts()})
    report = rig.run(collector)
    assert (report.status, report.error_class, report.error_summary) == (
        "failed",
        "RuntimeError",
        "RuntimeError",
    )
    assert collector.closed == 1
    for table in (
        tables.snapshots,
        tables.object_states,
        tables.objects,
        tables.resource_coverage,
        tables.sources,
    ):
        assert table_rows(store, table) == before[table.name]
    assert count(store, tables.change_events) == 0
    assert count(store, tables.change_items) == 0
    failed = run_rows(store)[1]
    assert (failed.status, failed.error_class) == ("failed", "RuntimeError")
    assert failed.finished_at is not None
    assert bool(failed.stored_new_snapshot) is False
    assert "CANARY" not in repr(run_rows(store))


def test_the_controller_version_is_kept_and_a_missing_one_changes_nothing(rig: Rig) -> None:
    rig.run(FakeCollector({"networks": networks()}, version="10.0.1"))
    assert source_row(rig.database).controller_version == "10.0.1"
    rig.run(FakeCollector({"networks": networks()}, version=None))
    assert source_row(rig.database).controller_version == "10.0.1"


def test_an_error_summary_is_one_short_line_without_credentials() -> None:
    text = f"first line\nsecond   line {JWT} " + "word " * 100
    summary = error_summary(text)
    assert "\n" not in summary
    assert len(summary) <= MAX_ERROR_TEXT_CHARS == 200
    assert summary.startswith("first line second line ")
    assert JWT_MARK not in summary
    assert error_summary("plain text") == "plain text"
    assert QUERY_SECRET not in error_summary(QUERY_URL)


def test_a_failed_run_stores_a_scrubbed_single_line_summary(rig: Rig) -> None:
    collector = FakeCollector({"networks": networks()})
    message = f"line one\nline two {JWT} " + "padding " * 60
    collector.probe_errors = [CollectorError(ERROR_HTTP, message, status="401")]
    report = rig.run(collector)
    (run,) = run_rows(rig.database)
    assert report.error_summary == run.error_summary
    assert "\n" not in str(run.error_summary)
    assert len(str(run.error_summary)) <= MAX_ERROR_TEXT_CHARS
    assert JWT_MARK not in str(run.error_summary)
    assert str(run.error_summary).startswith("line one line two")
