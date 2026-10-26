"""Load test and measurements (P11-T1). The method and the numbers are in docs/measurements.md.

The fixture is synthetic only: 1,000 objects, 2,000 changes and 90 days of manifests, pushed to one
push source through the real run pipeline (the shipped rules, the real normaliser, fingerprints
and compressed storage) with a clock that dates every poll. Nothing is made up by this script
that the product does not already do; it only feeds the pipeline and reads back what the product
stored. Values are ``ld-`` ids, ``LOAD`` names, ``.example`` domains and ``CANARY-`` secrets.

Commands:

* ``container --image IMAGE``: the real measurement. Starts the image with the hardening flags and
  the 512 MB memory limit of compose.yaml, seeds the fixture inside it, starts the server on the
  same volumes, times the first page and reads memory and CPU from inside the container. Needs
  only the standard library and the docker command on the host. This is the run to record.
* ``local``: the same fixture in this process (no docker, no memory limit). For development and
  the unit tests; it measures nothing against the targets, so those checks are gaps.
* ``seed`` and ``noisy``: run inside the container by ``container``; they import the product.

A miss against a target is reported as a miss and makes the exit code 1. A check that could not be
measured is a gap, never a pass. A container that is killed for memory, or a server that stops
answering, gives a partial report with those misses and gaps, not a traceback. The report is
always written; exit code 2 means only that the harness itself failed.

The noisy fixture checks volatile-field suppression: a source whose polls differ only in ignore
class fields must add no change item, manifest, state or stored byte after the baseline.
"""

import argparse
import http.client
import json
import math
import os
import random
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

SESSION_COOKIE_NAME: Final = "ds_session"
SOURCE_NAME: Final = "LOAD-FIXTURE synthetic"
NOISY_SOURCE_NAME: Final = "LOAD-FIXTURE counters"
ADMIN_NAME: Final = "load-admin"

TARGET_RSS_MB: Final = (150.0, 250.0)
TARGET_FIRST_PAGE_SECONDS: Final = 1.0
MEMORY_LIMIT_MB: Final = 512.0
SAMPLE_INTERVAL_SECONDS: Final = 0.25
WARM_REQUESTS: Final = 20
HEALTH_WAIT_SECONDS: Final = 90
MB: Final = 1024 * 1024

# Resource type and its share of 1,000 objects. Names and fields are those of the shipped UniFi
# type table (rules/types/unifi.yaml); the firewall policies are the ordered collection.
RESOURCE_WEIGHTS: Final = (
    ("unifi-networks", 100),
    ("unifi-wifi-broadcasts", 100),
    ("unifi-firewall-zones", 40),
    ("unifi-firewall-policies", 200),
    ("unifi-dns-policies", 250),
    ("unifi-vpn-servers", 10),
    ("unifi-radius-profiles", 20),
    ("unifi-devices", 280),
)

# The fields the push source keeps. uptimeSec and lastHeartbeatAt are ignore class in the table:
# they differ at every poll, like the counters of a real controller, and must cost no snapshot.
PUSH_FIELDS: Final[dict[str, list[str]]] = {
    "unifi-networks": ["id", "name", "enabled", "management", "vlanId", "internetAccessEnabled"],
    "unifi-wifi-broadcasts": [
        "id",
        "name",
        "enabled",
        "network",
        "securityConfiguration",
        "clientIsolationEnabled",
    ],
    "unifi-firewall-zones": ["id", "name", "networkIds"],
    "unifi-firewall-policies": [
        "id",
        "name",
        "description",
        "enabled",
        "actionType",
        "ipProtocolScope",
        "loggingEnabled",
    ],
    "unifi-dns-policies": ["id", "type", "enabled", "domain"],
    "unifi-vpn-servers": ["id", "name", "type", "enabled", "preSharedKey"],
    "unifi-radius-profiles": ["id", "name", "sharedSecret"],
    "unifi-devices": [
        "id",
        "name",
        "model",
        "firmwareVersion",
        "state",
        "uptimeSec",
        "lastHeartbeatAt",
    ],
}

Document = dict[str, list[dict[str, Any]]]


class LoadTestError(Exception):
    """The harness cannot run or cannot finish; this is not a result about the product."""


@dataclass(frozen=True, slots=True)
class FixtureSpec:
    """The size of the fixture; the defaults are the plan's (1,000, 2,000 and 90 days)."""

    objects: int = 1000
    changes: int = 2000
    days: int = 90
    polls_per_day: int = 4
    seed: int = 20261025
    noisy_polls: int = 48
    noisy_objects: int = 200

    @property
    def change_polls_per_day(self) -> int:
        """How many polls of a day find changes; the others find only volatile counters."""
        return min(2, self.polls_per_day)

    @property
    def total_polls(self) -> int:
        """The polls after the baseline."""
        return self.days * self.polls_per_day

    def validate(self) -> None:
        """Raise LoadTestError when the numbers cannot make a fixture."""
        if self.objects < len(RESOURCE_WEIGHTS):
            raise LoadTestError(f"objects must be at least {len(RESOURCE_WEIGHTS)}")
        if self.changes < 1 or self.days < 1 or self.polls_per_day < 1:
            raise LoadTestError("changes, days and polls-per-day must be at least 1")
        slots = self.days * self.change_polls_per_day
        if -(-self.changes // slots) > self.objects:
            raise LoadTestError("a poll would change more objects than the fixture has")
        if self.noisy_polls < 2:
            raise LoadTestError("the noisy fixture needs at least 2 polls")
        if self.noisy_objects < len(RESOURCE_WEIGHTS):
            raise LoadTestError(f"noisy-objects must be at least {len(RESOURCE_WEIGHTS)}")


def distribute(total: int, slots: int) -> list[int]:
    """Split ``total`` into ``slots`` whole numbers that differ by at most one."""
    base, extra = divmod(total, slots)
    return [base + 1 if index < extra else base for index in range(slots)]


def resource_counts(total: int) -> dict[str, int]:
    """How many objects each resource gets for ``total`` objects (the weights, rounded to fit)."""
    weight_sum = sum(weight for _, weight in RESOURCE_WEIGHTS)
    exact = {name: total * weight / weight_sum for name, weight in RESOURCE_WEIGHTS}
    counts = {name: max(1, int(value)) for name, value in exact.items()}
    by_remainder = sorted(exact, key=lambda name: exact[name] - int(exact[name]), reverse=True)
    step = 0
    while sum(counts.values()) < total:
        counts[by_remainder[step % len(by_remainder)]] += 1
        step += 1
    while sum(counts.values()) > total:
        largest = max(counts, key=lambda name: counts[name])
        counts[largest] -= 1
    return counts


def _canary(kind: str, index: int, revision: int = 0) -> str:
    """A synthetic secret, built here so no secret-shaped literal is committed."""
    return f"CANARY-load-{kind}-{index:04d}-r{revision}"


def base_document(counts: Mapping[str, int]) -> Document:
    """The first document: every object once, nothing changed yet."""
    networks = counts["unifi-networks"]
    document: Document = {
        "unifi-networks": [
            {
                "id": f"ld-net-{index:04d}",
                "name": f"LOAD net {index:04d}",
                "enabled": True,
                "management": "GATEWAY",
                "vlanId": 100 + index,
                "internetAccessEnabled": index % 3 != 0,
            }
            for index in range(networks)
        ],
        "unifi-wifi-broadcasts": [
            {
                "id": f"ld-wifi-{index:04d}",
                "name": f"LOAD wifi {index:04d}",
                "enabled": True,
                "network": {"networkId": f"ld-net-{index % networks:04d}"},
                "securityConfiguration": {
                    "type": "WPA3_PERSONAL",
                    "passphrase": _canary("wifi", index),
                },
                "clientIsolationEnabled": index % 2 == 0,
            }
            for index in range(counts["unifi-wifi-broadcasts"])
        ],
        "unifi-firewall-zones": [
            {
                "id": f"ld-zone-{index:04d}",
                "name": f"LOAD zone {index:04d}",
                "networkIds": [f"ld-net-{index % networks:04d}"],
            }
            for index in range(counts["unifi-firewall-zones"])
        ],
        "unifi-firewall-policies": [
            {
                "id": f"ld-policy-{index:04d}",
                "name": f"LOAD policy {index:04d}",
                "description": f"LOAD synthetic policy {index:04d}",
                "enabled": True,
                "actionType": "block" if index % 4 == 0 else "allow",
                "ipProtocolScope": "TCP_UDP",
                "loggingEnabled": False,
            }
            for index in range(counts["unifi-firewall-policies"])
        ],
        "unifi-dns-policies": [
            {
                "id": f"ld-dns-{index:04d}",
                "type": "A_RECORD",
                "enabled": True,
                "domain": f"host-{index:04d}.load.example",
            }
            for index in range(counts["unifi-dns-policies"])
        ],
        "unifi-vpn-servers": [
            {
                "id": f"ld-vpn-{index:04d}",
                "name": f"LOAD vpn {index:04d}",
                "type": "WIREGUARD",
                "enabled": True,
                "preSharedKey": _canary("vpn", index),
            }
            for index in range(counts["unifi-vpn-servers"])
        ],
        "unifi-radius-profiles": [
            {
                "id": f"ld-radius-{index:04d}",
                "name": f"LOAD radius {index:04d}",
                "sharedSecret": _canary("radius", index),
            }
            for index in range(counts["unifi-radius-profiles"])
        ],
        "unifi-devices": [
            {
                "id": f"ld-dev-{index:04d}",
                "name": f"LOAD device {index:04d}",
                "model": "LD-AP-6",
                "firmwareVersion": "1.0.0",
                "state": "ONLINE",
                "uptimeSec": 0,
                "lastHeartbeatAt": "synthetic-heartbeat-0",
            }
            for index in range(counts["unifi-devices"])
        ],
    }
    return document


def mutate(resource: str, entry: dict[str, Any], revision: int) -> None:
    """Change one configuration field of ``entry`` to a value it never had.

    ``revision`` rises with every call, so a text or number is always new, and a flag is flipped
    (an object changes at most once per poll, so a flip is a real change from the poll before).
    Only scalar configuration fields are used, so one call is exactly one change item.
    """
    options = revision % 3
    if resource == "unifi-networks":
        if options == 0:
            entry["vlanId"] = 2000 + revision
        else:
            entry["name"] = f"LOAD net r{revision}"
    elif resource == "unifi-wifi-broadcasts":
        if options == 0:
            entry["securityConfiguration"]["passphrase"] = _canary("wifi", revision, revision)
        elif options == 1:
            entry["name"] = f"LOAD wifi r{revision}"
        else:
            entry["enabled"] = not entry["enabled"]
    elif resource == "unifi-firewall-zones":
        entry["name"] = f"LOAD zone r{revision}"
    elif resource == "unifi-firewall-policies":
        if options == 0:
            entry["description"] = f"LOAD synthetic policy r{revision}"
        elif options == 1:
            entry["enabled"] = not entry["enabled"]
        else:
            entry["loggingEnabled"] = not entry["loggingEnabled"]
    elif resource == "unifi-dns-policies":
        if options == 0:
            entry["domain"] = f"host-r{revision}.load.example"
        else:
            entry["enabled"] = not entry["enabled"]
    elif resource == "unifi-vpn-servers":
        if options == 0:
            entry["preSharedKey"] = _canary("vpn", revision, revision)
        elif options == 1:
            entry["name"] = f"LOAD vpn r{revision}"
        else:
            entry["enabled"] = not entry["enabled"]
    elif resource == "unifi-radius-profiles":
        if options == 0:
            entry["sharedSecret"] = _canary("radius", revision, revision)
        else:
            entry["name"] = f"LOAD radius r{revision}"
    elif resource == "unifi-devices":
        if options == 0:
            entry["firmwareVersion"] = f"1.{revision}.0"
        elif options == 1:
            entry["name"] = f"LOAD device r{revision}"
        else:
            entry["state"] = "OFFLINE" if entry["state"] == "ONLINE" else "ONLINE"
    else:
        raise LoadTestError(f"no mutation for resource {resource}")


def touch_volatile(document: Document, poll: int) -> None:
    """Move the ignore class counters of every device, as a controller does between two polls."""
    for index, device in enumerate(document["unifi-devices"]):
        device["uptimeSec"] = 1000 * (poll + 1) + index
        device["lastHeartbeatAt"] = f"synthetic-heartbeat-{poll}"


@dataclass(slots=True)
class Poll:
    """One push: when it happened, the document, and how many changes it must produce.

    The document is reused and changed in place for the next poll, so it is valid only until the
    consumer asks for the next one.
    """

    index: int
    at: datetime
    document: Document
    planned_changes: int


def _flat_positions(counts: Mapping[str, int]) -> list[tuple[str, int]]:
    return [(resource, index) for resource, count in counts.items() for index in range(count)]


def _apply_changes(
    document: Document,
    flat: Sequence[tuple[str, int]],
    rng: random.Random,
    count: int,
    revision: int,
) -> int:
    """Change ``count`` distinct objects by one field each; return the new revision counter."""
    for position in rng.sample(range(len(flat)), count):
        resource, index = flat[position]
        revision += 1
        mutate(resource, document[resource][index], revision)
    return revision


def polls(spec: FixtureSpec, now: datetime) -> Iterator[Poll]:
    """The baseline and then ``days * polls_per_day`` polls, the last one at ``now``.

    Two polls of each day (the first and the third of four) find changes; the other polls differ
    only in the volatile counters. The planned changes add up to ``spec.changes``.
    """
    counts = resource_counts(spec.objects)
    document = base_document(counts)
    flat = _flat_positions(counts)
    rng = random.Random(spec.seed)  # noqa: S311 (a reproducible fixture, not a secret)
    per_day = spec.change_polls_per_day
    change_slots = {(slot * spec.polls_per_day) // per_day for slot in range(per_day)}
    per_slot = distribute(spec.changes, spec.days * per_day)
    # One hour short of the full span, so the oldest manifest is not older than the 90 days the
    # retention job thins.
    span = timedelta(days=spec.days) - timedelta(hours=1)
    total = spec.total_polls
    revision = 0
    slot = 0
    for poll in range(total + 1):
        planned = 0
        if poll > 0 and (poll - 1) % spec.polls_per_day in change_slots:
            planned = per_slot[slot]
            slot += 1
            revision = _apply_changes(document, flat, rng, planned, revision)
        touch_volatile(document, poll)
        yield Poll(poll, now - span + span * poll / total, document, planned)


def noisy_polls(spec: FixtureSpec, now: datetime) -> Iterator[Poll]:
    """A source that differs at every poll only in ignore class fields, every 15 minutes.

    The configuration never changes, so no poll after the baseline plans a change.
    """
    document = base_document(resource_counts(spec.noisy_objects))
    for poll in range(spec.noisy_polls + 1):
        touch_volatile(document, poll)
        at = now - timedelta(minutes=15 * (spec.noisy_polls - poll))
        yield Poll(poll, at, document, 0)


def _after_baseline(feed: Iterator[Poll], on_baseline: Callable[[], None]) -> Iterator[Poll]:
    """Yield ``feed`` and call ``on_baseline`` once the baseline poll has been consumed."""
    for poll in feed:
        if poll.index == 1:
            on_baseline()
        yield poll


# ---- what the process uses ---------------------------------------------------------------------


def _proc_kb(field: str, path: str = "/proc/self/status") -> float | None:
    """A kB value (VmRSS, VmHWM) of a /proc status file, in MB; None when it cannot be read."""
    try:
        for line in Path(path).read_text(encoding="ascii").splitlines():
            if line.startswith(field + ":"):
                return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _cgroup_mb(name: str) -> float | None:
    """A cgroup v2 memory value in MB (memory.peak, memory.max); None when absent or unlimited."""
    try:
        text = Path("/sys/fs/cgroup", name).read_text(encoding="ascii").strip()
        return int(text) / MB
    except (OSError, ValueError):
        return None


def cpu_seconds() -> float:
    """User plus system CPU time of this process."""
    times = os.times()
    return times.user + times.system


def burst_percent(samples: Sequence[tuple[float, float]], window: float = 1.0) -> float:
    """The highest CPU use over any ``window`` seconds, in percent of one CPU.

    ``samples`` are (wall time, cumulative CPU seconds) pairs in time order.
    """
    best = 0.0
    end = 0
    for start, (started, cpu_started) in enumerate(samples):
        while end < len(samples) and samples[end][0] - started < window:
            end += 1
        if end >= len(samples):
            break
        elapsed = samples[end][0] - started
        best = max(best, 100.0 * (samples[end][1] - cpu_started) / elapsed)
        if start >= end:
            end = start + 1
    return best


class ResourceSampler:
    """Samples the resident memory and CPU of this process every 0.25 s on its own thread."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="load-sampler", daemon=True)
        self.samples: list[tuple[float, float]] = []
        self.rss_peak_mb = 0.0

    def start(self) -> None:
        self._sample()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._sample()

    def _sample(self) -> None:
        self.samples.append((time.monotonic(), cpu_seconds()))
        self.rss_peak_mb = max(self.rss_peak_mb, _proc_kb("VmRSS") or 0.0)

    def _loop(self) -> None:
        while not self._stop.wait(SAMPLE_INTERVAL_SECONDS):
            self._sample()


def percentile(values: Sequence[float], fraction: float) -> float:
    """The value at ``fraction`` (0 to 1) of the sorted values; 0 for no values."""
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))]


def median(values: Sequence[float]) -> float:
    """The middle value; 0 for no values."""
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def database_bytes(path: Path) -> int:
    """The size of the database file and its write-ahead log."""
    wal = path.with_name(path.name + "-wal")
    return sum(file.stat().st_size for file in (path, wal) if file.exists())


# ---- inside the container: the product pipeline -------------------------------------------------


class PollClock:
    """UTC timestamps one second apart, starting at the time of the poll that is running."""

    def __init__(self) -> None:
        self._start = datetime.now(UTC)
        self._calls = 0

    def begin(self, moment: datetime) -> None:
        self._start = moment
        self._calls = 0

    def __call__(self) -> str:
        moment = self._start + timedelta(seconds=self._calls)
        self._calls += 1
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _push_source(data_dir: Path, key_file: Path, name: str) -> tuple[Any, Any, Any, Any, int]:
    """Open the database, migrate it, load or make the key and make the push source.

    Returns the database, the run pipeline, its clock, the master key and the source id.
    """
    from driftsniff.db.engine import Database, database_path
    from driftsniff.db.migrate import upgrade_to_head
    from driftsniff.rules.engine import RuleEngine
    from driftsniff.rules.loader import load_rules
    from driftsniff.secrets.crypto import CredentialCipher
    from driftsniff.secrets.fingerprint import Fingerprinter
    from driftsniff.secrets.keys import master_key_or_exit
    from driftsniff.secrets.scanner import load_overrides
    from driftsniff.sources.runs import RunPipeline
    from driftsniff.sources.service import OPTION_PUSH_FIELDS, SourceService
    from driftsniff.web.auth import ACTOR_SYSTEM

    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = Database(database_path(data_dir))
    upgrade_to_head(database)
    master = master_key_or_exit(key_file, database)
    clock = PollClock()
    pipeline = RunPipeline(
        database,
        RuleEngine(load_rules()),
        Fingerprinter.from_master(master),
        overrides=load_overrides(),
        clock=clock,
    )
    service = SourceService(database, CredentialCipher.from_master(master))
    view = service.create(
        name=name,
        source_type="push",
        actor=ACTOR_SYSTEM,
        options={OPTION_PUSH_FIELDS: PUSH_FIELDS},
    )
    return database, pipeline, clock, master, int(view.id)


def _run_polls(
    pipeline: Any, clock: PollClock, source_id: int, feed: Iterator[Poll]
) -> dict[str, Any]:
    """Push every poll through the pipeline; return what the run reports said, and the timings."""
    from driftsniff.collectors.push import PushCollector

    quiet_seconds: list[float] = []
    change_seconds: list[float] = []
    outcome: dict[str, Any] = {
        "polls": 0,
        "quiet_polls": 0,
        "quiet_polls_stored_snapshot": 0,
        "change_polls": 0,
        "change_polls_without_event": 0,
        "planned_changes": 0,
        "last_object_count": 0,
        "body_bytes": 0,
    }
    for poll in feed:
        clock.begin(poll.at)
        body = json.dumps(poll.document).encode()
        collector = PushCollector(poll.document, PUSH_FIELDS, body_bytes=len(body))
        started = time.perf_counter()
        report = pipeline.run(source_id, collector)
        elapsed = time.perf_counter() - started
        if report.status != "ok":
            raise LoadTestError(
                f"poll {poll.index} ended {report.status} ({report.error_class or 'no class'})"
            )
        outcome["polls"] += 1
        outcome["last_object_count"] = report.object_count
        outcome["body_bytes"] = len(body)
        if poll.index == 0:
            continue
        outcome["planned_changes"] += poll.planned_changes
        if poll.planned_changes == 0:
            outcome["quiet_polls"] += 1
            outcome["quiet_polls_stored_snapshot"] += int(report.stored_new_snapshot)
            quiet_seconds.append(elapsed)
        else:
            outcome["change_polls"] += 1
            outcome["change_polls_without_event"] += int(report.event_id is None)
            change_seconds.append(elapsed)
    outcome["run_seconds_quiet_median"] = median(quiet_seconds)
    outcome["run_seconds_change_median"] = median(change_seconds)
    outcome["run_seconds_p95"] = percentile(quiet_seconds + change_seconds, 0.95)
    outcome["run_seconds_max"] = max(quiet_seconds + change_seconds, default=0.0)
    return outcome


def _count_rows(connection: Any, table: Any, source_id: int | None) -> int:
    """How many rows ``table`` holds, for one source when ``source_id`` is given."""
    import sqlalchemy as sa

    query = sa.select(sa.func.count()).select_from(table)
    if source_id is not None:
        query = query.where(table.c.source_id == source_id)
    return int(connection.execute(query).scalar_one())


def _stored_counts(database: Any, source_id: int) -> dict[str, int]:
    """What the product stored for the source: rows, and the bytes its run records report."""
    import sqlalchemy as sa

    from driftsniff.db import tables

    items = (
        sa.select(sa.func.count())
        .select_from(tables.change_items)
        .join(tables.change_events, tables.change_items.c.event_id == tables.change_events.c.id)
        .where(tables.change_events.c.source_id == source_id)
    )
    size = tables.runs.c.new_state_bytes + tables.runs.c.manifest_bytes
    run_sizes = (
        sa.select(tables.runs.c.id, size)
        .where(tables.runs.c.source_id == source_id)
        .order_by(tables.runs.c.id)
    )
    with database.read() as connection:
        stored = {
            "runs": _count_rows(connection, tables.runs, source_id),
            "snapshots": _count_rows(connection, tables.snapshots, source_id),
            "events": _count_rows(connection, tables.change_events, source_id),
            "objects": _count_rows(connection, tables.objects, source_id),
            "states": _count_rows(connection, tables.object_states, None),
            "change_items": int(connection.execute(items).scalar_one()),
        }
        sizes = connection.execute(run_sizes).all()
    stored["baseline_bytes"] = int(sizes[0][1]) if sizes else 0
    stored["growth_bytes"] = sum(int(row[1]) for row in sizes[1:])
    return stored


def _session_cookie(database: Any) -> str:
    """Make a throwaway admin and return the cookie value of a session for it (never printed)."""
    from driftsniff.web.auth import AuthService

    auth = AuthService(database)
    password = secrets.token_urlsafe(24)
    auth.create_user(ADMIN_NAME, password, "admin")
    return str(auth.login(ADMIN_NAME, password, "127.0.0.1").cookie_value)


def seed(spec: FixtureSpec, data_dir: Path, key_file: Path) -> dict[str, Any]:
    """Run the 90-day fixture through the real pipeline; return the measurements.

    The returned ``session`` is the cookie value of a throwaway admin, for the first page timing.
    """
    spec.validate()
    database, pipeline, clock, _master, source_id = _push_source(data_dir, key_file, SOURCE_NAME)
    sampler = ResourceSampler()
    wall_start = time.perf_counter()
    cpu_start = cpu_seconds()
    sampler.start()
    try:
        outcome = _run_polls(pipeline, clock, source_id, polls(spec, datetime.now(UTC)))
    finally:
        sampler.stop()
    wall = time.perf_counter() - wall_start
    cpu = cpu_seconds() - cpu_start
    # Read before the admin is made: hashing its password briefly needs 64 MiB, which the
    # pipeline does not.
    rss_high_water = _proc_kb("VmHWM")
    cgroup_peak = _cgroup_mb("memory.peak")
    stored = _stored_counts(database, source_id)
    cookie = _session_cookie(database)
    database.close()
    return {
        "phase": "seed",
        **outcome,
        **{f"stored_{name}": value for name, value in stored.items()},
        "wall_seconds": wall,
        "cpu_seconds": cpu,
        "cpu_average_percent": 100.0 * cpu / wall if wall else 0.0,
        "cpu_burst_percent": burst_percent(sampler.samples),
        "rss_peak_sampled_mb": sampler.rss_peak_mb,
        "rss_peak_mb": rss_high_water,
        "cgroup_peak_mb": cgroup_peak,
        "cgroup_limit_mb": _cgroup_mb("memory.max"),
        "database_bytes": database_bytes(data_dir / "driftsniff.db"),
        "session": cookie,
    }


def noisy(spec: FixtureSpec, data_dir: Path, key_file: Path) -> dict[str, Any]:
    """Run a source that differs at every poll only in ignore class fields; report what it added.

    What the baseline stored is read once the baseline poll is done; ``added_*`` is the difference
    after the last poll. ``added_bytes`` is what the run records say the polls after the baseline
    stored (new state plus manifest); the database file size before and after is reported too.
    """
    spec.validate()
    database, pipeline, clock, _master, source_id = _push_source(
        data_dir, key_file, NOISY_SOURCE_NAME
    )
    database_file = data_dir / "driftsniff.db"
    baseline: dict[str, Any] = {}

    def read_baseline() -> None:
        baseline.update(_stored_counts(database, source_id))
        baseline["database_bytes"] = database_bytes(database_file)

    feed = _after_baseline(noisy_polls(spec, datetime.now(UTC)), read_baseline)
    outcome = _run_polls(pipeline, clock, source_id, feed)
    stored = _stored_counts(database, source_id)
    database.close()
    return {
        "phase": "noisy",
        **outcome,
        **{f"stored_{name}": value for name, value in stored.items()},
        "added_snapshots": stored["snapshots"] - baseline["snapshots"],
        "added_events": stored["events"] - baseline["events"],
        "added_change_items": stored["change_items"] - baseline["change_items"],
        "added_states": stored["states"] - baseline["states"],
        "added_bytes": stored["growth_bytes"],
        "database_bytes_baseline": baseline["database_bytes"],
        "database_bytes": database_bytes(database_file),
    }


def local_first_page(data_dir: Path, key_file: Path, cookie: str) -> dict[str, Any]:
    """Time the dashboard in this process with the test client (no network, no container)."""
    from fastapi.testclient import TestClient

    from driftsniff.config import Settings
    from driftsniff.db.engine import Database, database_path
    from driftsniff.main import create_app
    from driftsniff.web.auth import AuthService
    from driftsniff.web.dashboard import DashboardService

    origin = "http://127.0.0.1:8080"
    settings = Settings.from_env(
        {
            "DRIFTSNIFF_BASE_URL": origin,
            "DRIFTSNIFF_DATA_DIR": str(data_dir),
            "DRIFTSNIFF_KEY_FILE": str(key_file),
        }
    )
    database = Database(database_path(data_dir))
    try:
        app = create_app(settings, auth=AuthService(database), dashboard=DashboardService(database))
        headers = {"Accept": "text/html", "Cookie": f"{SESSION_COOKIE_NAME}={cookie}"}
        timings: list[float] = []
        status = 0
        size = 0
        with TestClient(app, base_url=origin, follow_redirects=False) as client:
            for _ in range(1 + WARM_REQUESTS):
                started = time.perf_counter()
                response = client.get("/", headers=headers)
                timings.append(time.perf_counter() - started)
                status, size = response.status_code, len(response.content)
    finally:
        database.close()
    return {"status": status, "bytes": size, **_page_summary(timings)}


def _page_summary(timings: Sequence[float]) -> dict[str, Any]:
    """The first (cold) time and the figures of the later (warm) ones."""
    warm = list(timings[1:])
    return {
        "cold_seconds": timings[0],
        "warm_median_seconds": median(warm),
        "warm_p95_seconds": percentile(warm, 0.95),
        "warm_max_seconds": max(warm, default=0.0),
    }


# ---- on the host: the container run ------------------------------------------------------------


def hardening_flags() -> list[str]:
    """The runtime flags of compose.yaml and the container smoke test, with the 512 MB limit."""
    return [
        "--read-only",
        "--tmpfs",
        "/tmp",  # noqa: S108 (a tmpfs mount point inside the container)
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
    ]


def _docker_status(*args: str, timeout: float = 1800.0) -> subprocess.CompletedProcess[str]:
    """Run a docker command (fixed words and our own names) and return its outcome."""
    command = ["docker", *args]
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603


def _docker(*args: str, timeout: float = 1800.0) -> str:
    """Run a docker command and return its standard output; LoadTestError when it fails."""
    done = _docker_status(*args, timeout=timeout)
    if done.returncode != 0:
        tail = " ".join(done.stderr.split())[-300:]
        raise LoadTestError(f"docker {args[0]} failed ({done.returncode}): {tail}")
    return done.stdout


def _last_json(text: str) -> dict[str, Any]:
    """The last line of ``text`` that is a JSON object."""
    for line in reversed(text.splitlines()):
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
    raise LoadTestError("the container printed no JSON result")


def _inspect(name: str, template: str) -> str:
    return _docker("inspect", "--format", template, name).strip()


def _spec_arguments(spec: FixtureSpec) -> list[str]:
    return [
        "--objects",
        str(spec.objects),
        "--changes",
        str(spec.changes),
        "--days",
        str(spec.days),
        "--polls-per-day",
        str(spec.polls_per_day),
        "--seed",
        str(spec.seed),
        "--noisy-polls",
        str(spec.noisy_polls),
        "--noisy-objects",
        str(spec.noisy_objects),
    ]


def _run_phase(image: str, name: str, command: str, spec: FixtureSpec) -> dict[str, Any]:
    """Run ``seed`` or ``noisy`` in a hardened container on its own volumes; return its result.

    A container killed for memory is a result about the product, not a harness failure: the
    answer is a partial result (``partial`` and ``oom_killed`` true, no measurements) that the
    verdicts turn into a miss and gaps.
    """
    script = Path(__file__).resolve()
    data, keys = f"{name}-data", f"{name}-keys"
    _docker("volume", "create", data)
    _docker("volume", "create", keys)
    done = _docker_status(
        "run",
        "--name",
        name,
        *hardening_flags(),
        "--volume",
        f"{data}:/data",
        "--volume",
        f"{keys}:/keys",
        "--volume",
        f"{script}:/load/load_test.py:ro",
        "--entrypoint",
        "python",
        image,
        "/load/load_test.py",
        command,
        *_spec_arguments(spec),
    )
    exit_code = int(_inspect(name, "{{.State.ExitCode}}"))
    if _inspect(name, "{{.State.OOMKilled}}") == "true":
        return {"phase": command, "partial": True, "oom_killed": True, "exit_code": exit_code}
    if done.returncode != 0:
        tail = " ".join(done.stderr.split())[-300:]
        raise LoadTestError(f"the {command} container failed ({done.returncode}): {tail}")
    result = _last_json(done.stdout)
    result["oom_killed"] = False
    result["exit_code"] = exit_code
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect to the sign-in page must show as a failure, not be followed."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _fetch(port: str, path: str, cookie: str) -> tuple[int, int, float]:
    """GET a page of the running container; return the status, the size and the seconds.

    A server that does not answer (connection refused or reset, no status line, a time-out, as when
    the container was killed) gives status 0, which the verdicts report; it never raises.
    """
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(  # noqa: S310 (a fixed http address on the loopback)
        f"http://127.0.0.1:{port}{path}",
        headers={"Accept": "text/html", "Cookie": f"{SESSION_COOKIE_NAME}={cookie}"},
    )
    started = time.perf_counter()
    try:
        with opener.open(request, timeout=30) as response:  # noqa: S310
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    except (OSError, http.client.HTTPException):
        status, body = 0, b""
    return status, len(body), time.perf_counter() - started


def _process_cpu(name: str) -> float:
    """CPU seconds the server process (pid 1 of the container) has used so far."""
    fields = _docker("exec", name, "cat", "/proc/1/stat").rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def _process_mb(name: str, field: str) -> float | None:
    text = _docker("exec", name, "cat", "/proc/1/status")
    for line in text.splitlines():
        if line.startswith(field + ":"):
            return int(line.split()[1]) / 1024
    return None


def _cgroup_peak(name: str) -> float | None:
    try:
        return int(_docker("exec", name, "cat", "/sys/fs/cgroup/memory.peak").strip()) / MB
    except (LoadTestError, ValueError):
        return None


def _server_state(name: str) -> tuple[bool, bool]:
    """Whether the server container is running, and whether it was killed for memory."""
    running = _inspect(name, "{{.State.Running}}") == "true"
    killed = _inspect(name, "{{.State.OOMKilled}}") == "true"
    return running, killed


def _server_readings(name: str) -> dict[str, Any]:
    """Peak memory of the server process; None for what cannot be read (it may have stopped)."""
    readings: dict[str, Any] = {"peak_rss_mb": None, "cgroup_peak_mb": None}
    try:
        readings["peak_rss_mb"] = _process_mb(name, "VmHWM")
    except LoadTestError:
        return readings
    readings["cgroup_peak_mb"] = _cgroup_peak(name)
    return readings


def _stopped_server(name: str, **reason: bool) -> dict[str, Any]:
    """The partial result of a server container with nothing measured; docker says why it ended."""
    running, killed = _server_state(name)
    return {
        "idle_rss_mb": None,
        "peak_rss_mb": None,
        "cgroup_peak_mb": None,
        "pages": {},
        "running": running,
        "oom_killed": killed,
        **reason,
    }


def _cpu_or_none(name: str) -> float | None:
    """CPU seconds of the server process, or None when it cannot be read (it may have stopped)."""
    try:
        return _process_cpu(name)
    except LoadTestError:
        return None


def _serve_and_time(image: str, name: str, cookie: str, volumes: tuple[str, str]) -> dict[str, Any]:
    """Start the server on the seeded volumes, time the pages and read its memory and CPU.

    A server that stops, is killed for memory or stops answering gives a partial result
    (``running`` false or a page with status 0, ``oom_killed`` as docker reports it). This holds
    for a server that dies right after its health check too: a failed read from a container that
    is no longer running is that partial result, not a harness failure.
    """
    data, keys = volumes
    _docker(
        "run",
        "--detach",
        "--name",
        name,
        *hardening_flags(),
        "--publish",
        "127.0.0.1::8080",
        "--volume",
        f"{data}:/data",
        "--volume",
        f"{keys}:/keys",
        "--env",
        "DRIFTSNIFF_BASE_URL=http://127.0.0.1:8080",
        image,
    )
    health = ""
    for _ in range(HEALTH_WAIT_SECONDS):
        if not _server_state(name)[0]:
            return _stopped_server(name, stopped_before_healthy=True)
        health = _inspect(name, "{{if .State.Health}}{{.State.Health.Status}}{{end}}")
        if health == "healthy":
            break
        time.sleep(1)
    if health != "healthy":
        raise LoadTestError(f"the server container is not healthy after {HEALTH_WAIT_SECONDS} s")
    port = _inspect(name, '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}')
    time.sleep(2)
    try:
        result: dict[str, Any] = {"idle_rss_mb": _process_mb(name, "VmRSS"), "pages": {}}
        cpu_before = _process_cpu(name)
    except LoadTestError:
        stopped = _stopped_server(name, stopped_after_healthy=True)
        if stopped["running"]:
            raise
        return stopped
    for path in ("/", "/changes"):
        timings: list[float] = []
        status = size = 0
        for _ in range(1 + WARM_REQUESTS):
            status, size, seconds = _fetch(port, path, cookie)
            timings.append(seconds)
            if status != 200:
                break
        result["pages"][path] = {"status": status, "bytes": size, **_page_summary(timings)}
        if status == 0:
            break
        cpu_after = _cpu_or_none(name) if path == "/" else None
        if cpu_after is not None:
            result["cpu_seconds_first_page_and_warm"] = cpu_after - cpu_before
    result.update(_server_readings(name))
    result["running"], result["oom_killed"] = _server_state(name)
    return result


def run_container(image: str, spec: FixtureSpec) -> dict[str, Any]:
    """The whole measurement against ``image``; containers and volumes are always removed.

    A container killed for memory or a server that stops answering gives a partial report (see
    ``evaluate``), not an exception. ``server`` then holds ``skipped`` when there is nothing to
    serve because the seed was killed.
    """
    spec.validate()
    _docker("image", "inspect", image)
    tag = f"driftsniff-load-{os.getpid()}"
    containers = [f"{tag}-seed", f"{tag}-noisy", f"{tag}-server"]
    volumes = [f"{tag}-seed-data", f"{tag}-seed-keys", f"{tag}-noisy-data", f"{tag}-noisy-keys"]
    try:
        seeded = _run_phase(image, f"{tag}-seed", "seed", spec)
        if seeded.get("partial"):
            server: dict[str, Any] = {
                "skipped": "the seed container was killed for memory, so there was nothing to serve"
            }
        else:
            cookie = str(seeded.pop("session"))
            server = _serve_and_time(image, f"{tag}-server", cookie, (volumes[0], volumes[1]))
        noisy_result = _run_phase(image, f"{tag}-noisy", "noisy", spec)
    finally:
        for container in containers:
            _docker_status("rm", "--force", container, timeout=120.0)
        for volume in volumes:
            _docker_status("volume", "rm", "--force", volume, timeout=120.0)
    return {
        "mode": "container",
        "image": image,
        "spec": asdict(spec),
        "seed": seeded,
        "server": server,
        "noisy": noisy_result,
    }


def run_local(spec: FixtureSpec) -> dict[str, Any]:
    """The same fixture in this process, for development and tests; not the acceptance numbers."""
    spec.validate()
    with tempfile.TemporaryDirectory(prefix="driftsniff-load-") as scratch:
        root = Path(scratch)
        (root / "keys").mkdir(mode=0o700)
        seeded = seed(spec, root / "data", root / "keys" / "master.key")
        cookie = str(seeded.pop("session"))
        page = local_first_page(root / "data", root / "keys" / "master.key", cookie)
        noisy_result = noisy(spec, root / "noisy-data", root / "keys" / "master.key")
    return {
        "mode": "local",
        "image": None,
        "spec": asdict(spec),
        "seed": seeded,
        "server": {
            "idle_rss_mb": None,
            "peak_rss_mb": seeded["rss_peak_mb"],
            "cgroup_peak_mb": None,
            "pages": {"/": page},
            "running": True,
            "oom_killed": False,
        },
        "noisy": noisy_result,
    }


# ---- the verdicts and the report ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Verdict:
    """One check against a target.

    ``pass``, ``below`` (better than planned), ``miss`` (the target is not met), ``note`` (met,
    with a remark) or ``gap`` (not measured, so neither met nor missed; never a pass).
    """

    check: str
    outcome: str
    detail: str


def _fixture_verdict(seed_part: Mapping[str, Any], spec: Mapping[str, Any]) -> Verdict:
    if seed_part.get("partial"):
        return Verdict(
            "fixture", "gap", "the seed container was killed, so there is no fixture result"
        )
    problems = []
    if seed_part["stored_change_items"] != seed_part["planned_changes"]:
        problems.append(
            f"{seed_part['stored_change_items']} change items stored, "
            f"{seed_part['planned_changes']} planned"
        )
    if seed_part["last_object_count"] != spec["objects"]:
        problems.append(f"{seed_part['last_object_count']} objects in the last manifest")
    if seed_part["quiet_polls_stored_snapshot"]:
        problems.append(
            f"{seed_part['quiet_polls_stored_snapshot']} polls with only volatile counters "
            "stored a snapshot"
        )
    if seed_part["change_polls_without_event"]:
        problems.append(f"{seed_part['change_polls_without_event']} change polls had no event")
    return Verdict(
        "fixture",
        "miss" if problems else "pass",
        "; ".join(problems)
        or (
            f"{seed_part['last_object_count']} objects, {seed_part['stored_change_items']} "
            f"change items, {seed_part['stored_snapshots']} manifests over {spec['days']} "
            f"days; {seed_part['quiet_polls']} polls with only volatile counters stored "
            "no snapshot"
        ),
    )


def _ram_verdict(seed_part: Mapping[str, Any], server: Mapping[str, Any], local: bool) -> Verdict:
    peaks = [seed_part.get("rss_peak_mb"), server.get("peak_rss_mb")]
    peak = max((value for value in peaks if value is not None), default=None)
    low, high = TARGET_RSS_MB
    if local:
        seen = "" if peak is None else f" (this process peaked at {peak:.0f} MB, for development)"
        return Verdict("ram", "gap", f"not measured: local mode has no container{seen}")
    if seed_part.get("oom_killed") or server.get("oom_killed"):
        seen = "" if peak is None else f"; last reading {peak:.0f} MB"
        detail = f"a container was killed at the 512 MB limit, so the peak is above {high:.0f} MB"
        return Verdict("ram", "miss", detail + seen)
    if peak is None:
        return Verdict("ram", "gap", "no resident memory could be read")
    if peak > high:
        return Verdict("ram", "miss", f"peak {peak:.0f} MB is above {high:.0f} MB")
    if peak < low:
        detail = f"peak {peak:.0f} MB is below the planned {low:.0f}-{high:.0f} MB"
        return Verdict("ram", "below", detail)
    return Verdict("ram", "pass", f"peak {peak:.0f} MB, target {low:.0f}-{high:.0f} MB")


def _page_verdict(server: Mapping[str, Any], local: bool) -> Verdict:
    if server.get("skipped"):
        return Verdict("first page", "gap", f"not measured: {server['skipped']}")
    page = server["pages"].get("/")
    if page is None:
        return Verdict("first page", "gap", "the server stopped before the page was requested")
    if page.get("status") == 0:
        return Verdict("first page", "miss", "the server did not answer the request")
    if page.get("status") != 200:
        return Verdict("first page", "miss", f"the page answered {page.get('status')}")
    cold = page["cold_seconds"]
    if local:
        detail = f"not measured: local mode times the test client ({cold:.2f} s), not the container"
        return Verdict("first page", "gap", detail)
    if cold >= TARGET_FIRST_PAGE_SECONDS:
        return Verdict("first page", "miss", f"{cold:.2f} s, target under 1 s")
    return Verdict("first page", "pass", f"{cold:.2f} s, target under 1 s")


def _limit_verdict(
    seed_part: Mapping[str, Any],
    server: Mapping[str, Any],
    noisy_part: Mapping[str, Any],
    local: bool,
) -> Verdict:
    if local:
        return Verdict(
            "512 MB limit", "gap", "not measured: local mode has no container and no memory limit"
        )
    parts = (("seed", seed_part), ("server", server), ("noisy", noisy_part))
    killed = [name for name, part in parts if part.get("oom_killed")]
    if killed:
        detail = f"killed for memory at the limit: {', '.join(killed)}"
        return Verdict("512 MB limit", "miss", detail)
    stopped = [
        name
        for name, part in parts
        if part.get("exit_code", 0) != 0 or part.get("running") is False
    ]
    if stopped:
        return Verdict("512 MB limit", "miss", f"stopped before it finished: {', '.join(stopped)}")
    cgroup = [
        value
        for value in (seed_part.get("cgroup_peak_mb"), server.get("cgroup_peak_mb"))
        if value is not None
    ]
    if server.get("skipped"):
        return Verdict("512 MB limit", "gap", f"not measured for the server: {server['skipped']}")
    if cgroup and max(cgroup) >= MEMORY_LIMIT_MB:
        return Verdict(
            "512 MB limit",
            "note",
            f"no container was killed; the cgroup peak {max(cgroup):.0f} MB reached the "
            "limit (it counts file cache the kernel can drop)",
        )
    seen = f"cgroup peak {max(cgroup):.0f} MB, " if cgroup else ""
    return Verdict("512 MB limit", "pass", f"{seen}no container was killed or stopped")


def _suppression_verdict(noisy_part: Mapping[str, Any]) -> Verdict:
    """Polls that differ only in ignore class fields must add nothing after the baseline."""
    check = "volatile-field suppression"
    if noisy_part.get("partial"):
        return Verdict(check, "gap", "the noisy container was killed, so nothing was checked")
    added = (
        ("change items", noisy_part["added_change_items"]),
        ("events", noisy_part["added_events"]),
        ("manifests", noisy_part["added_snapshots"]),
        ("states", noisy_part["added_states"]),
        ("stored bytes", noisy_part["added_bytes"]),
        ("polls that stored a snapshot", noisy_part["quiet_polls_stored_snapshot"]),
    )
    problems = [f"{value} {what}" for what, value in added if value]
    file_size = (
        f"database file {noisy_part['database_bytes_baseline'] / 1024:.0f} KB after the "
        f"baseline, {noisy_part['database_bytes'] / 1024:.0f} KB after the last poll"
    )
    polls = noisy_part["polls"] - 1
    if problems:
        return Verdict(check, "miss", f"{polls} polls added {', '.join(problems)}; {file_size}")
    return Verdict(
        check,
        "pass",
        f"{polls} polls that differ only in ignore class fields added no change item, event, "
        f"manifest, state or stored byte; {file_size}",
    )


def evaluate(report: Mapping[str, Any]) -> list[Verdict]:
    """Compare a report with the targets of P11-T1. A miss is never softened.

    What was not measured is a gap, never a pass: everything about the container in ``local``
    mode, and whatever a killed or stopped container could not report.
    """
    seed_part: Mapping[str, Any] = report["seed"]
    server: Mapping[str, Any] = report["server"]
    noisy_part: Mapping[str, Any] = report["noisy"]
    local = report.get("mode") == "local"
    return [
        _fixture_verdict(seed_part, report["spec"]),
        _ram_verdict(seed_part, server, local),
        _page_verdict(server, local),
        _limit_verdict(seed_part, server, noisy_part, local),
        _suppression_verdict(noisy_part),
    ]


def _mb(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0f} MB"


def _seconds(page: Mapping[str, Any], key: str) -> str:
    """A time of a page that answered; n/a for a page that did not (or was not requested)."""
    return f"{page[key]:.2f} s" if page.get("status") == 200 and key in page else "n/a"


def _header(report: Mapping[str, Any], verdicts: Sequence[Verdict]) -> list[str]:
    spec: Mapping[str, Any] = report["spec"]
    return [
        "## Load test results",
        "",
        f"Mode `{report['mode']}`, image `{report['image'] or 'none'}`. Fixture: "
        f"{spec['objects']} objects, {spec['changes']} changes, {spec['days']} days, "
        f"{spec['polls_per_day']} polls a day, seed {spec['seed']}.",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
        *(f"| {item.check} | {item.outcome} | {item.detail} |" for item in verdicts),
        "",
    ]


def render_markdown(report: Mapping[str, Any], verdicts: Sequence[Verdict]) -> str:
    """The measurements as Markdown tables, for the job summary and docs/measurements.md."""
    seed_part: Mapping[str, Any] = report["seed"]
    server: Mapping[str, Any] = report["server"]
    noisy_part: Mapping[str, Any] = report["noisy"]
    spec: Mapping[str, Any] = report["spec"]
    lines = _header(report, verdicts)
    if seed_part.get("partial") or server.get("skipped") or noisy_part.get("partial"):
        lines += [
            "The run is incomplete: a container was killed, so only the checks above are "
            "reported. A gap is not measured and is not a pass.",
            "",
        ]
        return "\n".join(lines)
    page = server["pages"].get("/", {})
    changes_page = server["pages"].get("/changes")
    day_growth = seed_part["stored_growth_bytes"] / max(1, spec["days"])
    lines += [
        "| Measurement | Value |",
        "|---|---|",
        f"| Peak resident memory, pipeline (seed) | {_mb(seed_part.get('rss_peak_mb'))} |",
        f"| Peak resident memory, server | {_mb(server.get('peak_rss_mb'))} |",
        f"| Resident memory, server idle | {_mb(server.get('idle_rss_mb'))} |",
        "| Container memory peak (cgroup), seed and server | "
        f"{_mb(seed_part.get('cgroup_peak_mb'))} and {_mb(server.get('cgroup_peak_mb'))} |",
        "| CPU, average over the pipeline run | "
        f"{seed_part['cpu_average_percent']:.0f} % of one CPU |",
        f"| CPU, burst (best 1 s) | {seed_part['cpu_burst_percent']:.0f} % of one CPU |",
        "| Pipeline run time per poll (volatile only, with changes, p95) | "
        f"{seed_part['run_seconds_quiet_median'] * 1000:.0f} ms, "
        f"{seed_part['run_seconds_change_median'] * 1000:.0f} ms, "
        f"{seed_part['run_seconds_p95'] * 1000:.0f} ms |",
        f"| Whole fixture | {seed_part['wall_seconds']:.0f} s for {seed_part['polls']} polls |",
        f"| Database file | {seed_part['database_bytes'] / MB:.1f} MB |",
        f"| Growth, baseline then per day | {seed_part['stored_baseline_bytes'] / MB:.2f} MB, "
        f"{day_growth / 1024:.0f} KB a day |",
        f"| Stored rows | {seed_part['stored_snapshots']} manifests, {seed_part['stored_events']} "
        f"events, {seed_part['stored_change_items']} items, {seed_part['stored_states']} states |",
        f"| Server CPU, first page and {WARM_REQUESTS} more | "
        f"{server.get('cpu_seconds_first_page_and_warm', 0):.2f} CPU s |",
        f"| First page `/` (cold) | {_seconds(page, 'cold_seconds')} |",
        f"| First page `/` (warm median, p95) | {_seconds(page, 'warm_median_seconds')}, "
        f"{_seconds(page, 'warm_p95_seconds')} |",
    ]
    if changes_page is not None:
        lines.append(
            "| Change list `/changes` (cold, warm median) | "
            f"{_seconds(changes_page, 'cold_seconds')}, "
            f"{_seconds(changes_page, 'warm_median_seconds')} |"
        )
    lines += [
        f"| Counters-only fixture | {noisy_part['polls'] - 1} polls added "
        f"{noisy_part['added_change_items']} items, {noisy_part['added_snapshots']} manifests, "
        f"{noisy_part['added_states']} states and {noisy_part['added_bytes']} stored bytes; "
        f"database file {noisy_part['database_bytes_baseline'] / 1024:.0f} KB then "
        f"{noisy_part['database_bytes'] / 1024:.0f} KB |",
        "",
    ]
    return "\n".join(lines)


# ---- command line ------------------------------------------------------------------------------


def _fixture_arguments(parser: argparse.ArgumentParser) -> None:
    defaults = FixtureSpec()
    parser.add_argument("--objects", type=int, default=defaults.objects)
    parser.add_argument("--changes", type=int, default=defaults.changes)
    parser.add_argument("--days", type=int, default=defaults.days)
    parser.add_argument("--polls-per-day", type=int, default=defaults.polls_per_day)
    parser.add_argument("--seed", type=int, default=defaults.seed)
    parser.add_argument("--noisy-polls", type=int, default=defaults.noisy_polls)
    parser.add_argument("--noisy-objects", type=int, default=defaults.noisy_objects)


def _report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--report-json", type=Path, help="write the full report as JSON")
    parser.add_argument("--markdown", type=Path, help="write the results as Markdown")


def build_parser() -> argparse.ArgumentParser:
    """The command line: container, local, seed and noisy."""
    parser = argparse.ArgumentParser(description="driftsniff load test (P11-T1)")
    commands = parser.add_subparsers(dest="command", required=True)
    container = commands.add_parser("container", help="measure a built image (the real run)")
    container.add_argument("--image", required=True)
    _fixture_arguments(container)
    _report_arguments(container)
    local = commands.add_parser("local", help="the same fixture in this process (no docker)")
    _fixture_arguments(local)
    _report_arguments(local)
    for name in ("seed", "noisy"):
        inner = commands.add_parser(name, help="run inside the container; prints one JSON line")
        data_dir = os.environ.get("DRIFTSNIFF_DATA_DIR", "/data")
        key_file = os.environ.get("DRIFTSNIFF_KEY_FILE", "/keys/master.key")
        inner.add_argument("--data-dir", type=Path, default=Path(data_dir))
        inner.add_argument("--key-file", type=Path, default=Path(key_file))
        _fixture_arguments(inner)
    return parser


def _spec_from(args: argparse.Namespace) -> FixtureSpec:
    return FixtureSpec(
        objects=args.objects,
        changes=args.changes,
        days=args.days,
        polls_per_day=args.polls_per_day,
        seed=args.seed,
        noisy_polls=args.noisy_polls,
        noisy_objects=args.noisy_objects,
    )


def _publish(report: dict[str, Any], args: argparse.Namespace) -> int:
    """Print and save the report; return 1 when any check is a miss."""
    verdicts = evaluate(report)
    markdown = render_markdown(report, verdicts)
    report["verdicts"] = [asdict(item) for item in verdicts]
    print(markdown)
    for item in verdicts:
        print(f"::notice title=load-test {item.check}::{item.outcome}: {item.detail}")
    if args.report_json is not None:
        args.report_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.markdown is not None:
        args.markdown.write_text(markdown, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")
    return 1 if any(item.outcome == "miss" for item in verdicts) else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run a command; return 0 no miss, 1 at least one miss (the report is written), 2 harness."""
    args = build_parser().parse_args(argv)
    try:
        spec = _spec_from(args)
        if args.command == "container":
            return _publish(run_container(args.image, spec), args)
        if args.command == "local":
            return _publish(run_local(spec), args)
        runner = seed if args.command == "seed" else noisy
        result = runner(spec, args.data_dir, args.key_file)
        print(json.dumps(result))
        return 0
    except LoadTestError as error:
        print(f"load_test: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
