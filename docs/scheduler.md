# Scheduler

The scheduler (`driftsniff.sources.scheduler`) decides when each polled source is collected.
It starts the run pipeline (see `collectors.md`) for every enabled `unifi` and `xo` source.
`push` sources are not polled: their sender decides when to post.

## What it does

- One asyncio task per enabled polled source, started with the application (the lifespan of
  `create_app` starts and stops it). The blocking work runs in a pool of 4 worker threads, so at
  most 4 controllers are read at the same moment.
- The wait between two runs is the `interval_seconds` source option, **300 seconds by default**,
  allowed 60 to 3600, plus or minus 10 percent random jitter.
- The first run of each source starts after a random wait of up to 10 percent of its interval,
  so the sources of a restarted application do not all call their controllers together.
- A source never has two runs at once. A timer that fires while a run is going, or a run-now
  request that finds one, starts nothing.
- The source is read again before every run. A changed interval is used from the next cycle; a
  deleted or disabled source ends its task.

## Backoff

After each consecutive failed run the wait doubles, up to 900 seconds, and goes back to the
interval after a run that did not fail:

| Failed runs in a row | 0 | 1 | 2 | 3 and more |
|---|---|---|---|---|
| Wait with interval 300 | 300 s | 600 s | 900 s | 900 s |

An interval longer than 900 seconds is never shortened by a failure (with interval 1200 the wait
stays 1200).

A run counts as **failed** when its run record says `failed`, when no collector could be made
for it, or when the pipeline raised. `ok` and `partial` end a failure streak (the controller
answered; a `partial` run lists the resources that failed). `skipped` changes nothing.

## Run now

`Scheduler.run_now(source_id)` starts an extra run at once and returns a status:

| Status | Meaning |
|---|---|
| `started` | the run was started in the background; its result is in the run record |
| `already_running` | a run of this source is going; nothing was started |
| `too_soon` | run-now was accepted less than 30 seconds ago for this source; `retry_after_seconds` says how long to wait |
| `not_scheduled` | the source does not exist, is disabled, is a push source, or the scheduler is stopped |

A run started this way counts for the backoff like any other run. The web layer (P9) calls it
from a button; it must be called from the thread of the event loop.

## Keeping it in step with the sources

`Scheduler.sync()` makes the tasks match the sources table: it starts a task for a new or newly
enabled source and cancels the task of a disabled or deleted one. `start()` calls it once. The
code that creates, enables, disables or deletes a source calls `sync()` afterwards (the
interval option needs no call).

## What is not built yet

- `serve` does not create a scheduler yet: it needs a collector factory, which the UniFi
  (P7) and Xen Orchestra (P8) collectors provide. Until then `create_app(scheduler=...)` is the
  only way to run one.
- Stopping the scheduler cancels its tasks at once, but a run that is already inside a worker
  thread ends by its own limit (5 minutes) and is not interrupted.

## Tests

`tests/unit/test_scheduler.py`. Time is injected (`sleep`, `monotonic` and the random source),
so no test waits for an interval. One test drives the real run pipeline and source service on a
migrated database with a fake collector. Run with `pytest tests/unit/test_scheduler.py`.
