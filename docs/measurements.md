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
| Noisy source | run once: a source that differs only in ignore class fields adds nothing (see Noisy fixture) |

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
3. **Noisy.** A third container, on its own volumes, runs a source whose polls differ at every
   poll only in ignore class fields (`uptimeSec` and `lastHeartbeatAt` of every device, 48 polls
   every 15 minutes, no configuration change) and counts what the polls after the baseline added.

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
- A server that dies right after its health check (a failed `docker exec` read from a container
  that is no longer running) gives the same partial result, with `stopped_after_healthy`. If the
  container still runs and the read fails, that is a harness fault (exit code 2).

Only a fault of the harness itself (docker missing, the image missing, a container that exits with
an error and was not killed for memory, a server that never becomes healthy) ends with exit code 2
and no report; the message says what failed.

### The `local` mode

The same fixture runs in one process with `scripts/load_test.py local` (no docker, no limit). It
proves the fixture and the pipeline and is what the unit tests run, but it measures nothing against
the targets: its RAM, first page and 512 MB checks are reported as `gap` ("not measured: local mode
has no container"), with the process figures only as a remark for development. The suppression
check does not need a container, so it is a real result in this mode too.

### What counts as what

| Number | Where it comes from |
|---|---|
| Peak RAM | the larger of the seed and the server peak resident memory (`VmHWM`) |
| 512 MB limit holds | neither container was killed (`OOMKilled`), the seed exited 0, the server is still running. The cgroup peak is reported too; it includes file cache that the kernel can drop, so a peak at the limit without a kill is a note, not a miss |
| First page | wall time of the first request to `/` on the loopback after the container is healthy (cold: first template render, cold database pages), then the median and p95 of 20 warm requests |
| Database growth | the compressed bytes the run records say each run added (`new_state_bytes` plus `manifest_bytes`): the baseline, and the sum for the rest divided by the days; and the file size of the database |
| Volatile-field suppression | after the baseline, the counters-only polls added no change item, event, manifest, state or stored byte. The database file size after the baseline and after the last poll is reported next to it |
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
a CI job, to the job summary. A run in which every target is met exits 0.

## Noisy fixture and volatile-field suppression

The noisy fixture checks that fields in the ignore class of the type tables (counters and
timestamps that differ at every poll) cost nothing. It pushes 48 polls of 200 objects whose only
differences are `uptimeSec` and `lastHeartbeatAt` of the devices. After the baseline the run must
add **no change item, no event, no manifest, no state and no stored byte**, and no poll may store a
snapshot. The check passes or is a miss on that basis alone; the script reports the database file
size after the baseline and after the last poll next to it. The file size is information, not the
criterion: every poll still writes a small run record, so the file can grow by those rows without
any manifest or state being stored.

**Revision note (R&D Lead ruling, THE-1377 report rev 1).** The first version of this check looked
for a volatility warning and reported a miss, because the product has none. The ruling is that a
volatility warning is not in the approved Community Edition scope and that "prove the volatility
warning" in P11-T1 was an analysis error. The check is therefore the one above. No warning is built
and no miss is reported by design. The main fixture already shows the same property for its 180
counters-only polls (`quiet_polls_stored_snapshot` is 0).

## Results

**No container result is recorded here yet.** The numbers for peak RAM, CPU, database size, first
page and the 512 MB limit are a **gap** in this document: nothing is copied until it is read from
the job summary or the report artifact of a container run of the merged script (CI runs
40266867617 and 40263139852 are named for that, and need someone with access to the Actions
artifacts). A figure that was not read from there is not entered, and no target is claimed met
or missed. The pull request that adds the script has only the unit tests and the small
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
  connection, a local socket; their numbers are not in this document yet (see Results).
- The suppression check counts what the product stored for the source. It does not compare the
  database file size as a pass criterion, because the run records of the polls add rows.
- The database growth target refers to section 14 of rnd-report-1, which this task could not read.
  The growth per day and per baseline are reported so the R&D Lead can compare.
- The retention job (03:30 UTC daily) is not part of the run; the oldest manifest is dated just
  under 90 days so it is not thinned if a run crosses that time.
- The session used for the page is made in the seed container for a throwaway admin on a throwaway
  volume. It never appears in a report or a log.

## Rollback

The script, its tests and this page change no product code, setting, image or workflow. Remove the
three files to roll back.
