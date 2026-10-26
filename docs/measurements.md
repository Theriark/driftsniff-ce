# Load test and measurements (P11-T1)

This page says how driftsniff is measured under load, what the targets are and what the numbers
are. It is for the people who judge the product's size and speed. The fixture, the method and the
verdict rules are fixed in `scripts/load_test.py`; the unit tests are `tests/unit/test_load_test.py`.

## Targets (plan P11-T1)

| Target | Value |
|---|---|
| Resident memory at the peak | 150 to 250 MB |
| First page (the dashboard `/`), cold | under 1 second |
| Memory limit of the container | 512 MB holds: no container is killed for memory |
| Database growth | in line with section 14 of rnd-report-1 (not compared here, see Limits) |
| Noisy source | run once to show the volatility warning (see Noisy fixture) |

A result outside a target is reported as a miss, with its number. It is never hidden or rounded
into a pass. A miss needs a revision note and a decision by the R&D Lead. What was not measured is
a **gap**, never a pass.

## The fixture

Synthetic only: ids start with `ld-`, names with `LOAD`, domains end in `.example`, there is no
address of any kind, and every secret is a `CANARY-` value that the pipeline stores as a
fingerprint only.

| Part | Size |
|---|---|
| Objects | 1,000: 100 networks, 100 WiFi broadcasts, 40 firewall zones, 200 firewall policies (the ordered collection), 250 DNS policies, 10 VPN servers, 20 RADIUS profiles, 280 devices |
| Changes | 2,000 change items: each is one scalar configuration field of one object (a name, a VLAN, a flag, a firmware version or a secret), never two in one object in one poll |
| History | 90 days, 4 polls a day, 361 pushes with the baseline, each dated by an injected clock (the oldest is just under 90 days old) |
| Polls with changes | 2 a day (180), about 11 changes each |
| Polls with no change | 2 a day (180): only `uptimeSec` and `lastHeartbeatAt` of every device differ. Both are ignore class in the type table, so a poll like this must store no manifest |

The fixture runs through one push source. Push is the same `RunPipeline` a polled source uses
(redaction, normaliser, fingerprints, compressed storage, diff, ordering, rule engine, change
event); only the collector differs. It was chosen because a poll needs a controller and the real
UniFi interface is not verified (docs/vendor-notes/unifi.md). The fixture check fails the run when
the stored numbers differ from the plan: change items stored, objects in the last manifest, a quiet
poll that stored a manifest, a change poll without an event.

## Method

`python3 scripts/load_test.py container --image <image>` needs only Python's standard library and
the docker command. It does three things, each in a container started with the flags of
`compose.yaml` and the container smoke test: read-only root file system, `/tmp` as tmpfs, all
capabilities dropped, no new privileges, `--memory 512m --memory-swap 512m` (no swap, so the limit
is hard).

1. **Seed.** A container on fresh `/data` and `/keys` volumes runs `scripts/load_test.py seed`
   (the script is mounted read-only; the image is not changed). It makes the push source, runs the
   361 pushes through the pipeline and makes a throwaway admin session. A thread samples resident
   memory and CPU every 0.25 s. It reports peak resident memory (`VmHWM`, read before the admin is
   made, because hashing a password briefly needs 64 MiB), the container's cgroup peak, average and
   best-1-second CPU, the time of every run, the size of the database and what the run records say
   was added.
2. **Serve.** A second container starts the real server on the same volumes (`driftsniff serve`,
   the image entry point), waits for its health check, and the host requests `/` and `/changes`
   with the session of the seed (one cold request, then 20 warm ones). Idle memory, peak memory
   (`VmHWM`) and CPU of the server process are read from inside with `docker exec`.
3. **Noisy.** A third container, on its own volumes, runs a source whose configuration differs at
   every poll (3 changes every 15 minutes, 48 polls) and looks for any volatility warning.

Containers and volumes are always removed.

### When a container is killed or the server stops answering

This is the likeliest way for the 512 MB limit to fail, so it is a result and not a harness error.
The script always ends with a report and never with a traceback:

- A seed or noisy container that docker reports as killed for memory gives a partial result. The
  server step is skipped when the seed was killed (there is nothing to serve).
- A server that is killed, stops, refuses or drops a connection, or times out gives page status
  0 ("the server did not answer"); its memory is read only if it still runs, and shows `n/a`
  otherwise. A server that stops before its health check is reported the same way.
- The verdicts then show `miss` for the 512 MB limit (and for RAM: a kill at 512 MB means the
  peak was above 250 MB) and for the first page, and `gap` for what could not be measured. The
  Markdown says the run is incomplete. Exit code 1.

Only a fault of the harness itself (docker missing, the image missing, a container that exits with
an error and was not killed for memory, a server that never becomes healthy) ends with exit code 2
and no report; the message says what failed.

### The `local` mode

The same fixture runs in one process with `scripts/load_test.py local` (no docker, no limit). It
proves the fixture and the pipeline and is what the unit tests run, but it measures nothing against
the targets: its RAM, first page and 512 MB checks are reported as `gap` ("not measured: local mode
has no container"), with the process figures only as a remark for development.

### What counts as what

| Number | Where it comes from |
|---|---|
| Peak RAM | the larger of the seed and the server peak resident memory (`VmHWM`) |
| 512 MB limit holds | neither container was killed (`OOMKilled`), the seed exited 0, the server is still running. The cgroup peak is reported too; it includes file cache that the kernel can drop, so a peak at the limit without a kill is a note, not a miss |
| First page | wall time of the first request to `/` on the loopback after the container is healthy (cold: first template render, cold database pages), then the median and p95 of 20 warm requests |
| Database growth | the compressed bytes the run records say each run added (`new_state_bytes` plus `manifest_bytes`): the baseline, and the sum for the rest divided by the days; and the file size of the database |
| CPU | CPU seconds of the process over the whole seed, divided by its wall time; the burst is the best one-second window |

| Outcome | Meaning |
|---|---|
| `pass` | measured and the target is met |
| `below` | measured, lower than the planned range (RAM only); not a miss |
| `note` | measured, met, with a remark |
| `miss` | measured (or the container was killed) and the target is not met |
| `gap` | not measured; neither met nor missed |

Exit code of the script: 0 no check is a miss, 1 at least one miss (the report is complete or
partial as above), 2 the harness failed. Every check is also written as a `::notice` line and, in
a CI job, to the job summary. Until the product has a volatility warning, the exit code of a
container run is 1 because of that check; a CI job has to accept that or run report-only.

## Noisy fixture and the volatility warning

Section P11-T1 asks for a noisy fixture "to prove the volatility warning". At development commit
`0ff6a65` the product has **no volatility warning**: no run record, log line, dashboard row or rule
in `src/` warns that a source changes at every poll. The only volatility handling is the ignore
class of the type tables, which keeps counters and timestamps out of the comparison, and the
Xen Orchestra backup-run test (docs/xo-volatility.md). The noisy run therefore shows the effect
(one manifest and one event for every poll, and the database growth per poll) and the search for a
warning finds nothing, so check 2 is reported as a **miss**.

**Revision note for the R&D Lead.** Decide one of: (a) a small task builds the warning (for
example a source whose last N polls each stored a manifest gets a "changes at every check" row in
needs-attention, with the changed paths most often involved), after which this check passes
without a change to the script; or (b) the acceptance check is reworded to "the noisy run shows
the growth per poll", which it already does. The quiet polls of the main fixture show the
opposite case: counters that are ignore class cost no manifest at all.

## Results

**No container result exists yet.** The numbers for peak RAM, CPU, database size, first page and
the 512 MB limit are a **gap**: nothing has been measured against the targets, and no target is
met or missed. The pull request that adds the script has only the unit tests and the small
end-to-end run in its checks (`tests/unit/test_load_test.py`), which prove the fixture, the
verdicts and the partial-report paths but measure nothing about the image. The first container
run replaces this paragraph with its table (copy the Markdown the script prints) and the commit
and image digest it measured. To run it by hand:

```
docker build --build-arg SOURCE_SHA=load-test --tag driftsniff:load .
python3 scripts/load_test.py container --image driftsniff:load --markdown measured.md --report-json measured.json
```

To run it in CI, Platform & Release Engineer adds one job (workflow files are not part of this
change) that downloads the `driftsniff-ci-image` artifact the way the `smoke` job does, loads it
and runs `python3 scripts/load_test.py container --image driftsniff:ci`. It needs about 5 to
15 minutes on a hosted runner.

## Limits

- A hosted runner is not VM-09 or VM-10; the numbers are for comparing with the targets and with
  later runs on the same kind of runner, not a promise for another machine. One run is one sample.
- The fixture objects are small synthetic objects. Real UniFi or Xen Orchestra objects are larger
  and have more fields, and no real controller was read (Gate A is open), so memory and growth for
  a real installation may be higher.
- The UniFi and Xen Orchestra collectors (HTTP, paging, streaming) are not exercised; the push
  collector hands the pipeline the same raw objects. Their own memory bounds are tested in
  `tests/contract` (docs/xo-client.md).
- The container steps are tested against a fake docker command and, for a server that drops the
  connection, a local socket; they have not run against the image yet.
- The database growth target refers to section 14 of rnd-report-1, which this task could not read.
  The growth per day and per baseline are reported so the R&D Lead can compare.
- The retention job (03:30 UTC daily) is not part of the run; the oldest manifest is dated just
  under 90 days so it is not thinned if a run crosses that time.
- The session used for the page is made in the seed container for a throwaway admin on a throwaway
  volume. It never appears in a report or a log.

## Rollback

The script, its tests and this page change no product code, setting, image or workflow. Remove the
three files to roll back.
