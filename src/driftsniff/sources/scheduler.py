"""The scheduler: when each polled source is collected (docs/scheduler.md has the user view).

One asyncio task per enabled ``unifi`` or ``xo`` source sleeps until the next run is due, then has
a bounded pool of four worker threads do the blocking work (``RunPipeline.run``). Rules:

* the wait between runs is the ``interval_seconds`` option of the source (default 300, allowed
  60 to 3600) with plus or minus 10 percent jitter, so sources do not all fire together;
* after each consecutive failed run the wait doubles, up to 900 seconds (never less than the
  interval itself), and returns to the interval after a run that did not fail;
* a source never has two runs at once: a trigger that finds a run going does nothing;
* ``run_now`` starts an extra run at once, at most once per 30 seconds per source, and answers
  with a status that says what happened.

A run counts as failed when the run record says ``failed``, when no collector could be made, or
when the pipeline raised. ``ok`` and ``partial`` end a failure streak (the controller answered);
``skipped`` changes nothing. The source is read again before every run, so a changed interval is
used from the next cycle and a deleted or disabled source ends its task.

Time is injected (``sleep``, ``monotonic`` and ``uniform``), so tests never wait. Only the class
of an unexpected exception is logged: its text may hold a payload or a credential.
"""

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal, Protocol

from driftsniff.collectors.base import Collector
from driftsniff.sources.runs import RunReport
from driftsniff.sources.service import (
    DEFAULT_INTERVAL_SECONDS,
    POLLED_TYPES,
    SourceNotFoundError,
    SourceView,
    interval_of,
)

logger = logging.getLogger(__name__)

POOL_SIZE: Final = 4
JITTER_FRACTION: Final = 0.10
MAX_BACKOFF_SECONDS: Final = 900
RUN_NOW_GAP_SECONDS: Final = 30.0
_MAX_DOUBLINGS: Final = 16
_SYSTEM_RANDOM: Final = random.SystemRandom()

_Outcome = Literal["ok", "failed", "skipped", "gone"]


class RunNowStatus(StrEnum):
    """What ``Scheduler.run_now`` did."""

    STARTED = "started"
    TOO_SOON = "too_soon"
    ALREADY_RUNNING = "already_running"
    NOT_SCHEDULED = "not_scheduled"


@dataclass(frozen=True, slots=True)
class RunNowResult:
    """The status of a run-now request; ``retry_after_seconds`` is set for ``too_soon``."""

    status: RunNowStatus
    retry_after_seconds: float = 0.0


class _Sources(Protocol):
    def get(self, source_id: int) -> SourceView: ...

    def list_sources(self) -> list[SourceView]: ...


class _Pipeline(Protocol):
    def run(self, source_id: int, collector: Collector) -> RunReport: ...


@dataclass(frozen=True, slots=True)
class _Cycle:
    """What one attempt to run a source gave, and the interval it was read with."""

    outcome: _Outcome
    interval: int


def base_wait(interval: int, failures: int) -> float:
    """Seconds to wait after ``failures`` failed runs in a row, before jitter.

    The interval doubles for each failure and stops at 900 seconds; an interval longer than that
    is never shortened by a failure.
    """
    cap = max(MAX_BACKOFF_SECONDS, interval)
    return float(min(interval * 2 ** min(failures, _MAX_DOUBLINGS), cap))


def jittered(base: float, uniform: Callable[[float, float], float]) -> float:
    """``base`` moved by a random share of at most 10 percent either way."""
    return base * (1.0 + uniform(-JITTER_FRACTION, JITTER_FRACTION))


async def _real_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


class Scheduler:
    """Runs the polled sources of one database on their intervals.

    ``collector_factory`` makes the collector for one run of a source (the UniFi and XO
    collectors of P7 and P8 provide it); it is called in a worker thread and may raise. Every
    method except ``__init__`` must be used from the thread of the event loop.
    """

    def __init__(
        self,
        sources: _Sources,
        pipeline: _Pipeline,
        collector_factory: Callable[[SourceView], Collector],
        *,
        sleep: Callable[[float], Awaitable[None]] = _real_sleep,
        monotonic: Callable[[], float] = time.monotonic,
        uniform: Callable[[float, float], float] = _SYSTEM_RANDOM.uniform,
        pool_size: int = POOL_SIZE,
    ) -> None:
        self._sources = sources
        self._pipeline = pipeline
        self._factory = collector_factory
        self._sleep = sleep
        self._monotonic = monotonic
        self._uniform = uniform
        self._pool = ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="driftsniff-run")
        self._loops: dict[int, asyncio.Task[None]] = {}
        self._manual: set[asyncio.Task[_Cycle]] = set()
        self._running: set[int] = set()
        self._failures: dict[int, int] = {}
        self._last_manual: dict[int, float] = {}
        self._closed = False

    def scheduled(self) -> frozenset[int]:
        """The ids of the sources that have a task."""
        return frozenset(self._loops)

    async def start(self) -> None:
        """Start a task for every enabled polled source."""
        await self.sync()

    async def sync(self) -> None:
        """Make the tasks match the sources: start new ones, cancel those that no longer apply.

        Call it after a source is created, enabled, disabled or deleted.
        """
        if self._closed:
            return
        views = await asyncio.to_thread(self._sources.list_sources)
        wanted = {view.id: view for view in views if view.enabled and view.type in POLLED_TYPES}
        for source_id in [known for known in self._loops if known not in wanted]:
            self._loops.pop(source_id).cancel()
            self._forget(source_id)
        for source_id, view in wanted.items():
            if source_id not in self._loops:
                loop = asyncio.get_running_loop()
                self._loops[source_id] = loop.create_task(
                    self._loop(source_id, interval_of(view.options)),
                    name=f"driftsniff-source-{source_id}",
                )

    async def stop(self) -> None:
        """Cancel every task. A run already inside a worker thread ends by its own time limit."""
        self._closed = True
        loops = list(self._loops.values())
        manual = list(self._manual)
        for task in (*loops, *manual):
            task.cancel()
        await asyncio.gather(*loops, return_exceptions=True)
        await asyncio.gather(*manual, return_exceptions=True)
        self._loops.clear()
        self._manual.clear()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def run_now(self, source_id: int) -> RunNowResult:
        """Start a run of ``source_id`` at once, unless one is going or one was asked for lately.

        The run happens in the background; its result is in the run record.
        """
        if self._closed or source_id not in self._loops:
            return RunNowResult(RunNowStatus.NOT_SCHEDULED)
        if source_id in self._running:
            return RunNowResult(RunNowStatus.ALREADY_RUNNING)
        now = self._monotonic()
        last = self._last_manual.get(source_id)
        if last is not None and now - last < RUN_NOW_GAP_SECONDS:
            return RunNowResult(RunNowStatus.TOO_SOON, RUN_NOW_GAP_SECONDS - (now - last))
        self._last_manual[source_id] = now
        self._running.add(source_id)
        task = asyncio.get_running_loop().create_task(self._execute(source_id))
        self._manual.add(task)
        task.add_done_callback(self._manual.discard)
        return RunNowResult(RunNowStatus.STARTED)

    def _forget(self, source_id: int) -> None:
        self._failures.pop(source_id, None)
        self._last_manual.pop(source_id, None)

    async def _loop(self, source_id: int, interval: int) -> None:
        # The first run starts after a random wait of up to 10 percent of the interval, so the
        # sources of a restarted application do not all read their controllers at the same second.
        wait = self._uniform(0.0, JITTER_FRACTION * interval)
        try:
            while True:
                await self._sleep(wait)
                if source_id not in self._running:
                    self._running.add(source_id)
                    cycle = await self._execute(source_id)
                    if cycle.outcome == "gone":
                        return
                    interval = cycle.interval
                failures = self._failures.get(source_id, 0)
                wait = jittered(base_wait(interval, failures), self._uniform)
        finally:
            if self._loops.get(source_id) is asyncio.current_task():
                del self._loops[source_id]
                self._forget(source_id)

    async def _execute(self, source_id: int) -> _Cycle:
        """Run one cycle in a worker thread. The caller has put ``source_id`` in ``_running``."""
        loop = asyncio.get_running_loop()
        try:
            cycle = await loop.run_in_executor(self._pool, self._work, source_id)
        finally:
            self._running.discard(source_id)
        if cycle.outcome == "ok":
            self._failures[source_id] = 0
        elif cycle.outcome == "failed":
            self._failures[source_id] = self._failures.get(source_id, 0) + 1
        elif cycle.outcome == "gone":
            self._forget(source_id)
        return cycle

    def _work(self, source_id: int) -> _Cycle:
        """The blocking part, in a worker thread: read the source, make a collector, run."""
        interval = DEFAULT_INTERVAL_SECONDS
        try:
            view = self._sources.get(source_id)
            interval = interval_of(view.options)
            if not view.enabled:
                return _Cycle("gone", interval)
            collector = self._factory(view)
            report = self._pipeline.run(source_id, collector)
        except SourceNotFoundError:
            return _Cycle("gone", interval)
        except Exception as error:
            name = type(error).__name__
            logger.warning("source %s: the run could not start: %s", source_id, name)
            return _Cycle("failed", interval)
        if report.status == "failed":
            return _Cycle("failed", interval)
        if report.status == "skipped":
            return _Cycle("skipped", interval)
        return _Cycle("ok", interval)
