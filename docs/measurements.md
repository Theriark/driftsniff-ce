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
warning" in P11-T1 was an analysis error. The check is therefore the one above. No warning is
built; the check passes or misses only on what the polls stored. The main fixture already shows
the same property for its 180 counters-only polls (`quiet_polls_stored_snapshot` is 0).

## Results

One container run of the script, read from the job log of the CI job `Container measurement`.
Every target is met; the RAM peak is below the planned range, which is not a miss.

**Where it comes from**

| Item | Value |
|---|---|
| CI run, job | 40279708378, `Container measurement` (job 121430295032), conclusion success |
| Artifact | `load-test-measurements` (artifact 12632121214, 2,312 bytes, kept 30 days) with the report JSON and the Markdown |
| Source measured | the merge ref of pull request 120 (commit a4bad74c61a62975002a5bad7830708b74530b9e: head a9884adc3c1b4a31e9f13e0d4f687ea005ef2235 merged into 3b3457a9a4f435481b2c6419fb99a2f7bf3f37d7). It is not the later merge commit of that pull request on `development` |
| Image | `driftsniff:ci`, loaded from the `driftsniff-ci-image` artifact of the same run (artifact digest sha256:cec227f093e1dcb0f0af4dc35924e0bd1d91f82377dfc776a2bad90b54c4ad6e); the image digest itself was not printed in the log |
| Mode, fixture | `container`; 1,000 objects, 2,000 change items, 90 days, 4 polls a day, seed 20261025 |
| Runner | a GitHub-hosted runner, one sample |

**Verdicts**

| Check | Result | Detail |
|---|---|---|
| fixture | pass | 1000 objects, 2000 change items, 181 manifests over 90 days; 180 polls with only volatile counters stored no snapshot |
| ram | below | peak 92 MB is below the planned 150-250 MB |
| first page | pass | 0.10 s, target under 1 s |
| 512 MB limit | pass | cgroup peak 134 MB, no container was killed or stopped |
| volatile-field suppression | pass | 48 polls that differ only in ignore class fields added no change item, event, manifest, state or stored byte; database file 330 KB after the baseline, 256 KB after the last poll |

**Measurements**

| Measurement | Value |
|---|---|
| Peak resident memory, pipeline (seed) | 87 MB |
| Peak resident memory, server | 92 MB |
| Resident memory, server idle | 87 MB |
| Container memory peak (cgroup), seed and server | 134 MB and 122 MB |
| CPU, average over the pipeline run | 100 % of one CPU |
| CPU, burst (best 1 s) | 101 % of one CPU |
| Pipeline run time per poll (volatile only, with changes, p95) | 22 ms, 75 ms, 85 ms |
| Whole fixture | 18 s for 361 polls |
| Database file | 8.7 MB |
| Growth, baseline then per day | 0.15 MB, 78 KB a day |
| Stored rows | 181 manifests, 180 events, 2000 items, 2787 states |
| Server CPU, first page and 20 more | 0.26 CPU s |
| First page `/` (cold) | 0.10 s |
| First page `/` (warm median, p95) | 0.01 s, 0.01 s |
| Change list `/changes` (cold, warm median) | 0.04 s, 0.00 s |
| Counters-only fixture | 48 polls added 0 items, 0 manifests, 0 states and 0 stored bytes; database file 330 KB then 256 KB |

**Reading the numbers**

- The peak resident memory (92 MB) is under the planned 150 to 250 MB. The plan's range is
  therefore an overestimate for this fixture; the 512 MB limit has a wide margin (cgroup peak
  134 MB, which includes file cache).
- The CPU figures say that the pipeline run is limited by one CPU; a runner with a slower core
  takes longer for the 361 polls, and the figure is not a promise for another machine.
- Database growth is reported (0.15 MB for the baseline, 78 KB a day) for the R&D Lead to compare
  with section 14 of rnd-report-1; it is not compared here.
- The database file after the last counters-only poll (256 KB) is smaller than after the baseline
  (330 KB). The file size is information only; the criterion is that nothing was stored.

This is a measurement of the image against a synthetic fixture in CI. It is not a measurement on
Stage or VM-09, not a test of a real controller and not a human QA result.

To run it by hand:

```
docker build --build-arg SOURCE_SHA=load-test --tag driftsniff:load .
python3 scripts/load_test.py container --image driftsniff:load --markdown measured.md --report-json measured.json
```

In CI the job `Container measurement` downloads the `driftsniff-ci-image` artifact the way the
`smoke` job does, loads it and runs `python3 scripts/load_test.py container --image driftsniff:ci`.
It reports only: it never gates a deployment. It needs about 5 to 15 minutes on a hosted runner.

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
  connection, a local socket. The numbers in Results come from one real container run in CI.
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
three files to roll back; to undo only the recorded results, revert the commit that added the
Results table.
