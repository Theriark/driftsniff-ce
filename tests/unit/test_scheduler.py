"""The scheduler (sources/scheduler.py): timing, backoff, run-now and one run at a time.

The clock is a fake: ``Sleeper`` records every wait and returns at once, then blocks for good at
the wait it was told to stop at, so no test waits for an interval. Worker threads are real; a
``Pipeline`` fake hands out scripted run reports and can hold a run open with a threading event.
One test at the end drives the real run pipeline and the real source service on a migrated
database with a fake collector.
"""

import asyncio
import logging
import random
import threading
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from driftsniff.collectors.base import Collector, FetchResult, ResourceSpec
from driftsniff.core.normalize import FieldClass
from driftsniff.db import tables
from driftsniff.db.engine import Database
from driftsniff.main import create_app
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import RuleIndex
from driftsniff.rules.schema import ResourceTable
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.runs import RunPipeline, RunReport, RunStatus
from driftsniff.sources.scheduler import (
    JITTER_FRACTION,
    MAX_BACKOFF_SECONDS,
    POOL_SIZE,
    RUN_NOW_GAP_SECONDS,
    RunNowStatus,
    Scheduler,
    base_wait,
    jittered,
)
from driftsniff.sources.service import (
    DEFAULT_INTERVAL_SECONDS,
    SourceNotFoundError,
    SourceService,
    SourceValidationError,
    SourceView,
    interval_of,
)

WAIT_SECONDS: Final = 10.0
ADDRESS = "https://203.0.113.10:8443"
ACTOR = "admin"
CANARY = "CANARY-scheduler-factory-0001"
NO_JITTER: Final = 0.0


def no_jitter(low: float, high: float) -> float:
    return NO_JITTER


def view(
    source_id: int = 1,
    *,
    source_type: str = "unifi",
    enabled: bool = True,
    options: Mapping[str, object] | None = None,
) -> SourceView:
    return SourceView(
        id=source_id,
        name=f"source-{source_id}",
        type=source_type,
        base_url=None if source_type == "push" else ADDRESS,
        options=dict(options or {}),
        enabled=enabled,
        state="new",
        has_credential=source_type != "push",
        last_checked_at=None,
        last_success_at=None,
        controller_version=None,
    )


class FakeSources:
    """The two calls of the source service the scheduler uses, over a dict."""

    def __init__(self, *views: SourceView) -> None:
        self.views = {item.id: item for item in views}

    def get(self, source_id: int) -> SourceView:
        if source_id not in self.views:
            raise SourceNotFoundError(f"source {source_id} does not exist")
        return self.views[source_id]

    def list_sources(self) -> list[SourceView]:
        return list(self.views.values())


class NullCollector(Collector):
    def probe(self) -> str | None:
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        return []

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        raise AssertionError("the pipeline fake never reads")


def null_factory(item: SourceView) -> Collector:
    return NullCollector()


def report(status: RunStatus) -> RunReport:
    return RunReport(1, status)


class Pipeline:
    """Answers each run with the next scripted status (``ok`` when the script is used up)."""

    def __init__(self, *script: RunStatus) -> None:
        self.script = list(script)
        self.calls: list[int] = []
        self.hook: Callable[[int], None] | None = None
        self.gate: threading.Event | None = None
        self.entered = threading.Event()
        self.finished = threading.Event()

    def run(self, source_id: int, collector: Collector) -> RunReport:
        self.calls.append(source_id)
        self.entered.set()
        if self.hook is not None:
            self.hook(len(self.calls))
        if self.gate is not None:
            assert self.gate.wait(WAIT_SECONDS), "the test never released the run"
        status: RunStatus = self.script.pop(0) if self.script else "ok"
        self.finished.set()
        return report(status)


class Sleeper:
    """A fake ``sleep``: records the wait, returns at once, blocks for good at wait ``stop_at``.

    ``Sleeper(1)`` therefore never lets a timer run happen: the source only runs on run-now.
    """

    def __init__(self, stop_at: int) -> None:
        self.stop_at = stop_at
        self.waits: list[float] = []
        self.reached = asyncio.Event()
        self._never = asyncio.Event()

    async def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)
        if len(self.waits) >= self.stop_at:
            self.reached.set()
            await self._never.wait()
        await asyncio.sleep(0)


class Timer:
    """A monotonic clock that only moves when a test moves it."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_scheduler(
    sources: FakeSources,
    pipeline: Pipeline,
    *,
    sleeper: Sleeper | None = None,
    timer: Timer | None = None,
    factory: Callable[[SourceView], Collector] = null_factory,
) -> Scheduler:
    return Scheduler(
        sources,
        pipeline,
        factory,
        sleep=Sleeper(1) if sleeper is None else sleeper,
        monotonic=Timer() if timer is None else timer,
        uniform=no_jitter,
    )


def run_async[T](test: Callable[[], Awaitable[T]]) -> T:
    return asyncio.run(asyncio.wait_for(test(), timeout=60))


async def until(event: asyncio.Event) -> None:
    await asyncio.wait_for(event.wait(), WAIT_SECONDS)


async def thread_event(event: threading.Event) -> None:
    assert await asyncio.to_thread(event.wait, WAIT_SECONDS), "the event never came"


async def manual_runs_done(scheduler: Scheduler) -> None:
    await asyncio.gather(*scheduler._manual)


# --- the numbers ------------------------------------------------------------------------------


def test_the_numbers_are_those_of_the_plan() -> None:
    assert (DEFAULT_INTERVAL_SECONDS, MAX_BACKOFF_SECONDS) == (300, 900)
    assert (JITTER_FRACTION, RUN_NOW_GAP_SECONDS, POOL_SIZE) == (0.10, 30.0, 4)


def test_backoff_follows_300_600_900_900() -> None:
    assert [base_wait(300, failures) for failures in range(6)] == [
        300,
        600,
        900,
        900,
        900,
        900,
    ]


def test_backoff_starts_from_a_short_interval_and_never_shortens_a_long_one() -> None:
    assert [base_wait(60, failures) for failures in range(7)] == [60, 120, 240, 480, 900, 900, 900]
    assert [base_wait(1200, failures) for failures in range(3)] == [1200, 1200, 1200]
    assert base_wait(3600, 10_000) == 3600


def test_jitter_stays_within_ten_percent_in_1000_samples() -> None:
    uniform = random.SystemRandom().uniform
    samples = [jittered(300.0, uniform) for _ in range(1000)]
    assert all(270.0 <= sample <= 330.0 for sample in samples)
    assert len(set(samples)) > 100


def test_jitter_reaches_exactly_the_two_ends_and_no_further() -> None:
    assert jittered(300.0, lambda low, high: low) == pytest.approx(270.0)
    assert jittered(300.0, lambda low, high: high) == pytest.approx(330.0)
    assert jittered(300.0, no_jitter) == 300.0


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({}, 300),
        ({"interval_seconds": 60}, 60),
        ({"interval_seconds": 3600}, 3600),
        ({"interval_seconds": 59}, 300),
        ({"interval_seconds": 3601}, 300),
        ({"interval_seconds": True}, 300),
        ({"interval_seconds": "120"}, 300),
        ({"allow_plain_http": True}, 300),
    ],
)
def test_interval_of_reads_the_option_or_falls_back(
    options: Mapping[str, object], expected: int
) -> None:
    assert interval_of(options) == expected


# --- the loop of one source -------------------------------------------------------------------


def waits_for(
    script: Sequence[RunStatus],
    *,
    stop_at: int,
    options: Mapping[str, object] | None = None,
    factory: Callable[[SourceView], Collector] = null_factory,
    pipeline: Pipeline | None = None,
) -> list[float]:
    """Run one source until the scheduler has waited ``stop_at`` times; return every wait."""
    used = Pipeline(*script) if pipeline is None else pipeline
    sleeper = Sleeper(stop_at)
    scheduler = make_scheduler(
        FakeSources(view(options=options)), used, sleeper=sleeper, factory=factory
    )

    async def scenario() -> list[float]:
        await scheduler.start()
        try:
            await until(sleeper.reached)
        finally:
            await scheduler.stop()
        return sleeper.waits

    return run_async(scenario)


def test_the_first_run_waits_only_a_share_of_the_interval() -> None:
    seen: list[tuple[float, float]] = []

    def uniform(low: float, high: float) -> float:
        seen.append((low, high))
        return high

    sleeper = Sleeper(1)
    scheduler = Scheduler(
        FakeSources(view(options={"interval_seconds": 600})),
        Pipeline(),
        null_factory,
        sleep=sleeper,
        uniform=uniform,
    )

    async def scenario() -> None:
        await scheduler.start()
        try:
            await until(sleeper.reached)
        finally:
            await scheduler.stop()

    run_async(scenario)
    assert len(seen) == 1
    assert seen[0][0] == 0.0
    assert seen[0][1] == pytest.approx(60.0)
    assert sleeper.waits == [pytest.approx(60.0)]


def test_a_healthy_source_waits_its_interval_between_runs() -> None:
    assert waits_for([], stop_at=4) == [0.0, 300.0, 300.0, 300.0]


def test_backoff_doubles_to_900_and_resets_after_a_good_run() -> None:
    waits = waits_for(["failed", "failed", "failed", "ok"], stop_at=5)
    assert waits == [0.0, 600.0, 900.0, 900.0, 300.0]


def test_a_partial_run_ends_the_failure_streak() -> None:
    assert waits_for(["failed", "partial"], stop_at=3) == [0.0, 600.0, 300.0]


def test_a_skipped_run_changes_nothing() -> None:
    assert waits_for(["failed", "skipped", "ok"], stop_at=4) == [0.0, 600.0, 600.0, 300.0]


def test_the_interval_option_sets_the_wait() -> None:
    assert waits_for([], stop_at=3, options={"interval_seconds": 120}) == [0.0, 120.0, 120.0]


def test_a_changed_interval_is_used_from_the_next_cycle() -> None:
    sources = FakeSources(view())
    pipeline = Pipeline()

    def change_interval(call: int) -> None:
        if call == 1:
            sources.views[1] = view(options={"interval_seconds": 120})

    pipeline.hook = change_interval
    sleeper = Sleeper(4)
    scheduler = make_scheduler(sources, pipeline, sleeper=sleeper)

    async def scenario() -> None:
        await scheduler.start()
        try:
            await until(sleeper.reached)
        finally:
            await scheduler.stop()

    run_async(scenario)
    # The source was read before run 1 (300 s); run 2 read the new value.
    assert sleeper.waits == [0.0, 300.0, 120.0, 120.0]


def test_a_collector_that_cannot_be_made_counts_as_a_failure_and_leaks_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[int] = []

    def factory(item: SourceView) -> Collector:
        calls.append(item.id)
        if len(calls) == 1:
            raise RuntimeError(CANARY)
        return NullCollector()

    pipeline = Pipeline()
    with caplog.at_level(logging.WARNING):
        waits = waits_for([], stop_at=3, factory=factory, pipeline=pipeline)
    assert waits == [0.0, 600.0, 300.0]
    assert pipeline.calls == [1]
    assert "RuntimeError" in caplog.text
    assert CANARY not in caplog.text


def test_a_pipeline_that_raises_counts_as_a_failure() -> None:
    class Raising(Pipeline):
        def run(self, source_id: int, collector: Collector) -> RunReport:
            self.calls.append(source_id)
            if len(self.calls) == 1:
                raise OSError(CANARY)
            return report("ok")

    assert waits_for([], stop_at=3, pipeline=Raising()) == [0.0, 600.0, 300.0]


def test_a_deleted_source_ends_its_task() -> None:
    sources = FakeSources(view())
    pipeline = Pipeline()
    scheduler = make_scheduler(sources, pipeline, sleeper=Sleeper(2))

    async def scenario() -> None:
        await scheduler.start()
        task = scheduler._loops[1]
        del sources.views[1]
        await asyncio.wait_for(task, WAIT_SECONDS)
        assert scheduler.scheduled() == frozenset()
        assert pipeline.calls == []
        await scheduler.stop()

    run_async(scenario)


def test_a_disabled_source_ends_its_task_without_a_run() -> None:
    sources = FakeSources(view())
    pipeline = Pipeline()
    scheduler = make_scheduler(sources, pipeline, sleeper=Sleeper(2))

    async def scenario() -> None:
        await scheduler.start()
        task = scheduler._loops[1]
        sources.views[1] = view(enabled=False)
        await asyncio.wait_for(task, WAIT_SECONDS)
        assert pipeline.calls == []
        await scheduler.stop()

    run_async(scenario)


# --- sync, start and stop ---------------------------------------------------------------------


def test_only_enabled_polled_sources_get_a_task() -> None:
    sources = FakeSources(
        view(1),
        view(2, source_type="xo"),
        view(3, source_type="push"),
        view(4, enabled=False),
    )
    scheduler = make_scheduler(sources, Pipeline())

    async def scenario() -> None:
        await scheduler.start()
        assert scheduler.scheduled() == frozenset({1, 2})
        await scheduler.stop()

    run_async(scenario)


def test_sync_follows_created_enabled_disabled_and_deleted_sources() -> None:
    sources = FakeSources(view(1), view(2))
    scheduler = make_scheduler(sources, Pipeline())

    async def scenario() -> None:
        await scheduler.start()
        assert scheduler.scheduled() == frozenset({1, 2})
        sources.views[2] = view(2, enabled=False)
        sources.views[3] = view(3, source_type="xo")
        await scheduler.sync()
        assert scheduler.scheduled() == frozenset({1, 3})
        first = scheduler._loops[1]
        await scheduler.sync()
        assert scheduler._loops[1] is first  # nothing restarted
        del sources.views[1]
        await scheduler.sync()
        assert scheduler.scheduled() == frozenset({3})
        await scheduler.stop()
        assert scheduler.scheduled() == frozenset()

    run_async(scenario)


def test_after_stop_nothing_starts_again() -> None:
    sources = FakeSources(view(1))
    scheduler = make_scheduler(sources, Pipeline())

    async def scenario() -> None:
        await scheduler.start()
        await scheduler.stop()
        await scheduler.sync()
        assert scheduler.scheduled() == frozenset()
        assert scheduler.run_now(1).status is RunNowStatus.NOT_SCHEDULED

    run_async(scenario)


# --- one run at a time, run-now ---------------------------------------------------------------


def test_two_overlapping_triggers_produce_one_run() -> None:
    sources = FakeSources(view())
    pipeline = Pipeline()
    gate = threading.Event()
    pipeline.gate = gate
    sleeper = Sleeper(2)
    scheduler = make_scheduler(sources, pipeline, sleeper=sleeper)

    async def scenario() -> None:
        await scheduler.start()
        try:
            # The timer fired and its run is held open in a worker thread.
            await thread_event(pipeline.entered)
            assert scheduler.run_now(1).status is RunNowStatus.ALREADY_RUNNING
            assert scheduler.run_now(1).status is RunNowStatus.ALREADY_RUNNING
            gate.set()
            await until(sleeper.reached)
        finally:
            await scheduler.stop()

    run_async(scenario)
    assert pipeline.calls == [1]


def test_two_run_now_requests_at_once_start_one_run() -> None:
    sources = FakeSources(view())
    pipeline = Pipeline()
    gate = threading.Event()
    pipeline.gate = gate
    scheduler = make_scheduler(sources, pipeline)

    async def scenario() -> None:
        await scheduler.start()
        try:
            assert scheduler.run_now(1).status is RunNowStatus.STARTED
            assert scheduler.run_now(1).status is RunNowStatus.ALREADY_RUNNING
            await thread_event(pipeline.entered)
            gate.set()
            await manual_runs_done(scheduler)
        finally:
            await scheduler.stop()

    run_async(scenario)
    assert pipeline.calls == [1]


def test_run_now_is_refused_inside_30_seconds_with_the_time_left() -> None:
    sources = FakeSources(view())
    pipeline = Pipeline()
    timer = Timer()
    scheduler = make_scheduler(sources, pipeline, timer=timer)

    async def scenario() -> None:
        await scheduler.start()
        try:
            assert scheduler.run_now(1).status is RunNowStatus.STARTED
            await manual_runs_done(scheduler)
            timer.now += 10.0
            refused = scheduler.run_now(1)
            assert refused.status is RunNowStatus.TOO_SOON
            assert refused.retry_after_seconds == pytest.approx(20.0)
            timer.now += 19.9
            assert scheduler.run_now(1).status is RunNowStatus.TOO_SOON
            timer.now += 0.1
            assert scheduler.run_now(1).status is RunNowStatus.STARTED
            await manual_runs_done(scheduler)
        finally:
            await scheduler.stop()

    run_async(scenario)
    assert pipeline.calls == [1, 1]


def test_the_30_seconds_are_counted_per_source() -> None:
    sources = FakeSources(view(1), view(2, source_type="xo"))
    scheduler = make_scheduler(sources, Pipeline())

    async def scenario() -> None:
        await scheduler.start()
        try:
            assert scheduler.run_now(1).status is RunNowStatus.STARTED
            assert scheduler.run_now(2).status is RunNowStatus.STARTED
            await manual_runs_done(scheduler)
            assert scheduler.run_now(1).status is RunNowStatus.TOO_SOON
            assert scheduler.run_now(2).status is RunNowStatus.TOO_SOON
        finally:
            await scheduler.stop()

    run_async(scenario)


def test_a_run_now_result_feeds_the_backoff() -> None:
    sources = FakeSources(view())
    scheduler = make_scheduler(sources, Pipeline("failed", "failed", "ok"))

    async def scenario() -> None:
        await scheduler.start()
        try:
            for expected in (1, 2, 0):
                assert scheduler.run_now(1).status is RunNowStatus.STARTED
                await manual_runs_done(scheduler)
                assert scheduler._failures[1] == expected
                scheduler._last_manual.clear()  # skip the 30 second gap
        finally:
            await scheduler.stop()

    run_async(scenario)


def test_run_now_for_a_source_without_a_task_says_so() -> None:
    sources = FakeSources(view(1), view(3, source_type="push"), view(4, enabled=False))
    scheduler = make_scheduler(sources, Pipeline())

    async def scenario() -> None:
        await scheduler.start()
        try:
            for source_id in (2, 3, 4):  # 2 does not exist, 3 is a push source, 4 is disabled
                assert scheduler.run_now(source_id).status is RunNowStatus.NOT_SCHEDULED
        finally:
            await scheduler.stop()

    run_async(scenario)


# --- the application lifespan -----------------------------------------------------------------


def test_the_application_starts_and_stops_the_scheduler() -> None:
    events: list[str] = []

    class Recording(Scheduler):
        async def start(self) -> None:
            events.append("start")
            await super().start()

        async def stop(self) -> None:
            events.append("stop")
            await super().stop()

    scheduler = Recording(FakeSources(view()), Pipeline(), null_factory, sleep=Sleeper(1))
    with TestClient(create_app(scheduler=scheduler)) as client:
        assert events == ["start"]
        assert client.get("/healthz").status_code == 200
    assert events == ["start", "stop"]
    assert scheduler.scheduled() == frozenset()


def test_the_application_runs_without_a_scheduler() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/healthz").status_code == 200


# --- the option -------------------------------------------------------------------------------


@pytest.fixture
def service(store: Database) -> SourceService:
    cipher = CredentialCipher.from_master(MasterKey(bytes(range(32))))
    return SourceService(store, cipher)


@pytest.mark.parametrize("value", [60, 300, 3600])
def test_the_service_stores_an_interval_from_60_to_3600(service: SourceService, value: int) -> None:
    created = service.create(
        name="polled",
        source_type="xo",
        actor=ACTOR,
        base_url=ADDRESS,
        credential=CANARY,
        options={"interval_seconds": value},
    )
    assert created.options == {"interval_seconds": value}
    assert interval_of(created.options) == value


@pytest.mark.parametrize("value", [0, 59, 3601, -300, True, 300.0, "300"])
def test_the_service_refuses_any_other_interval(service: SourceService, value: object) -> None:
    with pytest.raises(SourceValidationError, match="interval_seconds"):
        service.create(
            name="polled",
            source_type="xo",
            actor=ACTOR,
            base_url=ADDRESS,
            credential=CANARY,
            options={"interval_seconds": value},
        )
    with pytest.raises(SourceValidationError, match="interval_seconds"):
        service.update(1, actor=ACTOR, options={"interval_seconds": value})


# --- the real pipeline ------------------------------------------------------------------------

NETWORKS = ResourceTable(
    resource="networks",
    object_key_field="_id",
    name_field="name",
    field_classes={"_id": FieldClass.CONFIG, "name": FieldClass.CONFIG, "vlan": FieldClass.CONFIG},
)
INDEX = RuleIndex(
    pack_version="pack-s1", rules=(), by_resource={}, type_tables={"networks": NETWORKS}
)


@dataclass
class Bench:
    """What the scripted controller serves: the vlan of the second network, one value per read."""

    vlans: Sequence[int] = (20, 30, 30)
    reads: list[int] = field(default_factory=list)


class BenchCollector(Collector):
    def __init__(self, bench: Bench) -> None:
        self.bench = bench

    def probe(self) -> str | None:
        return "10.0.1"

    def resources(self) -> Sequence[ResourceSpec]:
        return [ResourceSpec("networks")]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        vlans = self.bench.vlans
        vlan = vlans[min(len(self.bench.reads), len(vlans) - 1)]
        self.bench.reads.append(vlan)
        objects: list[Mapping[str, Any]] = [
            {"_id": "n1", "name": "Lab", "vlan": 10},
            {"_id": "n2", "name": "Guest", "vlan": vlan},
        ]
        return FetchResult.success(objects, bytes_fetched=50)


def test_the_scheduler_drives_the_real_pipeline_on_a_real_database(
    store: Database, service: SourceService
) -> None:
    created = service.create(
        name="lab-unifi",
        source_type="unifi",
        actor=ACTOR,
        base_url=ADDRESS,
        credential=CANARY,
        options={"interval_seconds": 60},
    )
    bench = Bench()
    pipeline = RunPipeline(store, RuleEngine(INDEX), Fingerprinter(bytes(range(32)), "0a1b2c3d"))
    sleeper = Sleeper(4)
    scheduler = Scheduler(
        service,
        pipeline,
        lambda item: BenchCollector(bench),
        sleep=sleeper,
        uniform=no_jitter,
    )

    async def scenario() -> None:
        await scheduler.start()
        try:
            await until(sleeper.reached)  # three runs, then the fourth wait
        finally:
            await scheduler.stop()

    run_async(scenario)
    assert sleeper.waits == [0.0, 60.0, 60.0, 60.0]
    assert bench.reads == [20, 30, 30]
    with store.read() as connection:
        run_rows = connection.execute(
            sa.select(tables.runs.c.status, tables.runs.c.stored_new_snapshot)
            .where(tables.runs.c.source_id == created.id)
            .order_by(tables.runs.c.id)
        ).all()
        snapshots = connection.execute(
            sa.select(sa.func.count())
            .select_from(tables.snapshots)
            .where(tables.snapshots.c.source_id == created.id)
        ).scalar_one()
        events = connection.execute(
            sa.select(sa.func.count())
            .select_from(tables.change_events)
            .where(tables.change_events.c.source_id == created.id)
        ).scalar_one()
    assert [(row.status, bool(row.stored_new_snapshot)) for row in run_rows] == [
        ("ok", True),
        ("ok", True),
        ("ok", False),
    ]
    assert (snapshots, events) == (2, 1)
