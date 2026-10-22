"""The run pipeline: one collection of one source, from the lock to the change event.

``RunPipeline.run(source_id, collector)`` does everything a collector must not do itself
(docs/collectors.md has the user view):

1. take the lock of the source (one run per source at a time, in this process) or record a
   ``skipped`` run; a disabled source is skipped the same way;
2. probe the controller and read every resource, with retries on timeouts and HTTP 5xx and a time
   limit for the whole run; no database lock is held while the controller is read;
3. redact, normalise and key every object, resource by resource; a resource that cannot be read or
   understood fails alone and keeps its previous state;
4. store, compare and classify in one transaction (snapshot, objects, change event, coverage and
   the run record), so a failure leaves nothing half written;
5. tell the notifier, after the commit.

A collector is only asked for raw objects. The error text of a run record is a class word and a
short single line with credential patterns scrubbed; for an exception nobody expected only the
name of its class is kept.
"""

import logging
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from itertools import batched
from typing import Final, Literal

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.collectors.base import (
    MAX_ERROR_TEXT_CHARS,
    RETRY_BACKOFF_SECONDS,
    STATUS_ERROR,
    STATUS_OK,
    Collector,
    CollectorError,
    FetchResult,
    ResourceSpec,
)
from driftsniff.core.canonical import JsonValue
from driftsniff.core.collection import record_collection
from driftsniff.core.diff import ChangeItem, compare
from driftsniff.core.normalize import CollectionMode, normalize_object
from driftsniff.core.order import compare_order
from driftsniff.core.runs import finish_run, start_run
from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    Manifest,
    SnapshotOutcome,
    build_manifest,
    latest_snapshot,
)
from driftsniff.core.states import MAX_STATE_BYTES, StateMissingError, decompress_bytes, get_state
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    change_events,
    change_items,
    object_states,
    objects,
    resource_coverage,
    runs,
    sources,
)
from driftsniff.rules.engine import RuleEngine, highest
from driftsniff.rules.schema import ResourceTable, Severity
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.redact import redact_object, scrub_text
from driftsniff.secrets.scanner import NO_OVERRIDES, Overrides
from driftsniff.sources.service import SourceNotFoundError, utc_now

logger = logging.getLogger(__name__)

RUN_LIMIT_SECONDS: Final = 300.0

ERROR_ALREADY_RUNNING: Final = "already_running"
ERROR_DISABLED: Final = "disabled"
ERROR_INTERRUPTED: Final = "interrupted"
ERROR_RUN_TIMEOUT: Final = "run_timeout"
ERROR_UNKNOWN_RESOURCE: Final = "unknown_resource"
ERROR_BAD_OBJECT: Final = "bad_object"
ERROR_DUPLICATE_KEY: Final = "duplicate_key"
ERROR_DUPLICATE_RESOURCE: Final = "duplicate_resource"
ERROR_NO_RESOURCES: Final = "no_resources"

RunStatus = Literal["ok", "partial", "failed", "skipped"]

_BATCH: Final = 500


def error_summary(text: str) -> str:
    """One line of at most 200 characters with credential patterns and query strings scrubbed."""
    return " ".join(scrub_text(text).split())[:MAX_ERROR_TEXT_CHARS]


@dataclass(frozen=True, slots=True)
class RunReport:
    """What one run did. ``event_id`` is set when it found changes."""

    run_id: int
    status: RunStatus
    error_class: str | None = None
    error_summary: str | None = None
    stored_new_snapshot: bool = False
    event_id: int | None = None
    object_count: int = 0


@dataclass(frozen=True, slots=True)
class _Outcome:
    """What reading one resource gave: its collected objects, or why it failed."""

    name: str
    status: str
    bytes_fetched: int
    collected: CollectedResource | None = None
    error_class: str | None = None
    error_text: str | None = None
    warning_class: str | None = None
    warning_text: str | None = None


def _failure(
    name: str, error_class: str, text: str, *, status: str = STATUS_ERROR, fetched: int = 0
) -> _Outcome:
    return _Outcome(name, status, fetched, None, error_class, text)


class _SourceLocks:
    """The sources that have a run going in this process."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._held: set[int] = set()

    def try_acquire(self, source_id: int) -> bool:
        with self._guard:
            if source_id in self._held:
                return False
            self._held.add(source_id)
            return True

    def release(self, source_id: int) -> None:
        with self._guard:
            self._held.discard(source_id)


def _object_key(table: ResourceTable, state: Mapping[str, JsonValue]) -> str | None:
    """The key of a normalised object: its key field as text, or None when it has no usable one."""
    key_field = table.object_key_field
    if key_field is None:
        return None
    value = state.get(key_field)
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _stored_bodies(connection: Connection, hashes: set[str]) -> dict[str, bytes]:
    """The canonical bytes of states that are already stored."""
    bodies: dict[str, bytes] = {}
    for batch in batched(sorted(hashes), _BATCH):
        rows = connection.execute(
            sa.select(object_states.c.state_hash, object_states.c.body_zstd).where(
                object_states.c.state_hash.in_(batch)
            )
        )
        for row in rows:
            bodies[str(row.state_hash)] = decompress_bytes(row.body_zstd, MAX_STATE_BYTES)
    missing = hashes - bodies.keys()
    if missing:
        raise StateMissingError(f"{len(missing)} stored states are missing")
    return bodies


def _carry_over(connection: Connection, previous: Manifest | None, fresh: Manifest) -> Manifest:
    """Add every resource of the previous manifest that this run did not read.

    A resource that failed, or that a collector stopped listing, keeps its previous objects, so
    none of them is ever reported as removed.
    """
    if previous is None:
        return fresh
    carried_objects: dict[str, Mapping[str, str]] = dict(fresh.objects)
    carried_positions: dict[str, Sequence[str]] = dict(fresh.positions)
    carried_hashes: set[str] = set()
    for resource, hashes in previous.objects.items():
        if resource in fresh.objects:
            continue
        carried_objects[resource] = hashes
        if resource in previous.positions:
            carried_positions[resource] = previous.positions[resource]
        carried_hashes.update(hashes.values())
    if len(carried_objects) == len(fresh.objects):
        return fresh
    pending = dict(fresh.pending_states)
    pending.update(_stored_bodies(connection, carried_hashes - pending.keys()))
    return Manifest(
        fresh.controller_version,
        fresh.normaliser_version,
        carried_objects,
        carried_positions,
        pending,
        fresh.names,
    )


def _write_coverage(
    connection: Connection, source_id: int, outcomes: Sequence[_Outcome], at: str
) -> None:
    """Update the coverage row of every resource this run tried to read."""
    existing = {
        str(row.resource): row
        for row in connection.execute(
            sa.select(resource_coverage).where(resource_coverage.c.source_id == source_id)
        )
    }
    for outcome in outcomes:
        row = existing.get(outcome.name)
        values: dict[str, object]
        if outcome.collected is not None:
            values = {
                "last_status": STATUS_OK,
                "last_ok_at": at,
                "stale_since": None,
                "object_count": len(outcome.collected.objects),
            }
        else:
            last_ok = None if row is None else row.last_ok_at
            stale = None if row is None else row.stale_since
            values = {
                "last_status": outcome.status,
                "last_ok_at": last_ok,
                "stale_since": stale or last_ok or at,
                "object_count": 0 if row is None else row.object_count,
            }
        if row is None:
            connection.execute(
                sa.insert(resource_coverage).values(
                    source_id=source_id, resource=outcome.name, **values
                )
            )
        else:
            connection.execute(
                sa.update(resource_coverage)
                .where(
                    resource_coverage.c.source_id == source_id,
                    resource_coverage.c.resource == outcome.name,
                )
                .values(**values)
            )


def _object_ids(
    connection: Connection, source_id: int, items: Sequence[ChangeItem]
) -> dict[tuple[str, str], int]:
    """The ids of the objects the items belong to, by resource and key."""
    keys = {item.object_key for item in items if item.object_key is not None}
    found: dict[tuple[str, str], int] = {}
    for batch in batched(sorted(keys), _BATCH):
        rows = connection.execute(
            sa.select(objects.c.id, objects.c.resource, objects.c.object_key).where(
                objects.c.source_id == source_id, objects.c.object_key.in_(batch)
            )
        )
        for row in rows:
            found[(str(row.resource), str(row.object_key))] = int(row.id)
    return found


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _write_event(
    connection: Connection,
    source_id: int,
    snapshot: SnapshotOutcome,
    items: Sequence[ChangeItem],
    *,
    window_start: str,
    window_end: str,
    rule_pack_version: str,
) -> int:
    """Store one change event with its items and return the id of the event."""
    if snapshot.snapshot_id is None:
        raise ValueError("a change event needs a stored snapshot")
    top: Severity = "low"
    for item in items:
        top = highest(top, item.severity or "low")
    resource_count = len({item.resource for item in items})
    summary = (
        f"{_plural(len(items), 'change')} in {_plural(resource_count, 'resource type')}, "
        f"highest severity {top}"
    )
    event_id = int(
        connection.execute(
            sa.insert(change_events)
            .values(
                source_id=source_id,
                snapshot_id=snapshot.snapshot_id,
                previous_snapshot_id=snapshot.previous_snapshot_id,
                window_start=window_start,
                window_end=window_end,
                max_severity=top,
                item_count=len(items),
                summary=summary,
                rule_pack_version=rule_pack_version,
                status="open",
                created_at=window_end,
            )
            .returning(change_events.c.id)
        ).scalar_one()
    )
    ids = _object_ids(connection, source_id, items)
    rows: list[dict[str, object]] = []
    for item in items:
        object_id = None if item.object_key is None else ids.get((item.resource, item.object_key))
        rows.append(
            {
                "event_id": event_id,
                "object_id": object_id,
                "resource": item.resource,
                "object_name_at_time": item.object_name,
                "change_kind": item.change_kind,
                "path": item.path,
                "field_class": item.field_class.value,
                "before_value": item.before_value,
                "after_value": item.after_value,
                "before_fp": item.before_fp,
                "after_fp": item.after_fp,
                "severity": item.severity or "low",
                "rule_id": item.rule_id,
                "rationale": item.rationale,
                "order_detail": None if item.order_detail is None else dict(item.order_detail),
            }
        )
    connection.execute(sa.insert(change_items), rows)
    return event_id


class RunPipeline:
    """Runs collectors for sources of one database, with one rule engine and one fingerprint key.

    ``clock``, ``sleep`` and ``monotonic`` are there for tests. ``notifier`` is called with the
    id of a change event after the run was committed; whatever it raises is logged and dropped.
    """

    def __init__(
        self,
        database: Database,
        engine: RuleEngine,
        fingerprinter: Fingerprinter,
        *,
        overrides: Overrides = NO_OVERRIDES,
        notifier: Callable[[int], None] | None = None,
        clock: Callable[[], str] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        run_limit_seconds: float = RUN_LIMIT_SECONDS,
    ) -> None:
        self._database = database
        self._engine = engine
        self._fingerprinter = fingerprinter
        self._overrides = overrides
        self._notifier = notifier
        self._clock = clock
        self._sleep = sleep
        self._monotonic = monotonic
        self._run_limit = run_limit_seconds
        self._locks = _SourceLocks()

    def run(self, source_id: int, collector: Collector) -> RunReport:
        """Collect one source with ``collector`` and record the result.

        The collector is closed once, whatever happens. Raises ``SourceNotFoundError`` for a
        source that does not exist; every other problem ends in the run record.
        """
        try:
            return self._run(source_id, collector)
        finally:
            self._close(collector)

    def _run(self, source_id: int, collector: Collector) -> RunReport:
        if not self._source_enabled(source_id):
            return self._skip(source_id, ERROR_DISABLED, "the source is disabled")
        if not self._locks.try_acquire(source_id):
            return self._skip(source_id, ERROR_ALREADY_RUNNING, "a run of this source is going")
        try:
            report = self._locked_run(source_id, collector)
        finally:
            self._locks.release(source_id)
        if report.event_id is not None:
            self._notify(report.event_id)
        return report

    def _source_enabled(self, source_id: int) -> bool:
        with self._database.read() as connection:
            row = connection.execute(
                sa.select(sources.c.enabled).where(sources.c.id == source_id)
            ).first()
        if row is None:
            raise SourceNotFoundError(f"source {source_id} does not exist")
        return bool(row.enabled)

    def _skip(self, source_id: int, error_class: str, text: str) -> RunReport:
        now = self._clock()
        with self._database.write() as connection:
            run_id = start_run(connection, source_id, now)
            finish_run(
                connection,
                run_id,
                finished_at=now,
                status="skipped",
                error_class=error_class,
                error_summary=text,
            )
        return RunReport(run_id, "skipped", error_class, text)

    def _close(self, collector: Collector) -> None:
        try:
            collector.close()
        except Exception as error:
            logger.warning("closing a collector failed: %s", type(error).__name__)

    def _notify(self, event_id: int) -> None:
        if self._notifier is None:
            return
        try:
            self._notifier(event_id)
        except Exception as error:
            logger.warning("the notifier failed for event %s: %s", event_id, type(error).__name__)

    def _locked_run(self, source_id: int, collector: Collector) -> RunReport:
        started = self._clock()
        with self._database.write() as connection:
            # The lock is held, so a run record that is still open belongs to a process that died.
            connection.execute(
                sa.update(runs)
                .where(runs.c.source_id == source_id, runs.c.status.is_(None))
                .values(
                    finished_at=started,
                    status="failed",
                    error_class=ERROR_INTERRUPTED,
                    error_summary="the run was interrupted before it finished",
                )
            )
            run_id = start_run(connection, source_id, started)
        deadline = self._monotonic() + self._run_limit
        try:
            version = self._probe(collector, deadline)
            outcomes = self._read_all(collector, deadline)
        except CollectorError as error:
            return self._fail(source_id, run_id, error.error_class, str(error), ())
        except Exception as error:
            return self._fail(source_id, run_id, type(error).__name__, type(error).__name__, ())
        if not any(outcome.collected is not None for outcome in outcomes):
            first = outcomes[0] if outcomes else None
            if first is None:
                return self._fail(
                    source_id, run_id, ERROR_NO_RESOURCES, "the collector lists no resources", ()
                )
            text = first.error_text or first.error_class or ERROR_NO_RESOURCES
            return self._fail(
                source_id, run_id, first.error_class or ERROR_NO_RESOURCES, text, outcomes
            )
        try:
            return self._store(source_id, run_id, version, outcomes)
        except Exception as error:
            # The transaction was rolled back: nothing of this run is stored.
            logger.warning("run %s could not be stored: %s", run_id, type(error).__name__)
            return self._fail(source_id, run_id, type(error).__name__, type(error).__name__, ())

    def _fail(
        self,
        source_id: int,
        run_id: int,
        error_class: str,
        text: str,
        outcomes: Sequence[_Outcome],
    ) -> RunReport:
        summary = error_summary(text)
        now = self._clock()
        with self._database.write() as connection:
            _write_coverage(connection, source_id, outcomes, now)
            finish_run(
                connection,
                run_id,
                finished_at=now,
                status="failed",
                bytes_fetched=sum(outcome.bytes_fetched for outcome in outcomes),
                error_class=error_class,
                error_summary=summary,
            )
        return RunReport(run_id, "failed", error_class, summary)

    def _probe(self, collector: Collector, deadline: float) -> str | None:
        attempt = 0
        while True:
            try:
                return collector.probe()
            except CollectorError as error:
                if not error.retryable or attempt >= len(RETRY_BACKOFF_SECONDS):
                    raise
                delay = RETRY_BACKOFF_SECONDS[attempt]
                if self._monotonic() + delay >= deadline:
                    raise
                self._sleep(delay)
                attempt += 1

    def _read_all(self, collector: Collector, deadline: float) -> list[_Outcome]:
        specs = list(collector.resources())
        names = [spec.name for spec in specs]
        if len(set(names)) != len(names):
            raise CollectorError(ERROR_DUPLICATE_RESOURCE, "a collector lists a resource twice")
        return [self._read_one(collector, spec, deadline) for spec in specs]

    def _read_one(self, collector: Collector, spec: ResourceSpec, deadline: float) -> _Outcome:
        table = self._engine.index.type_tables.get(spec.name)
        if table is None:
            return _failure(spec.name, ERROR_UNKNOWN_RESOURCE, "the resource has no type table")
        if self._monotonic() >= deadline:
            return _failure(spec.name, ERROR_RUN_TIMEOUT, "the time limit of the run was reached")
        result, fetched = self._fetch(collector, spec, deadline)
        if not result.ok:
            text = result.error_text or result.error_class or STATUS_ERROR
            return _failure(
                spec.name,
                result.error_class or STATUS_ERROR,
                text,
                status=result.status,
                fetched=fetched,
            )
        return self._collect_objects(spec.name, table, result, fetched)

    def _fetch(
        self, collector: Collector, spec: ResourceSpec, deadline: float
    ) -> tuple[FetchResult, int]:
        """Read one resource, trying again after 1, 2 and 4 seconds when waiting could help."""
        fetched = 0
        attempt = 0
        while True:
            result = self._fetch_once(collector, spec)
            fetched += result.bytes_fetched
            if result.ok or not result.retryable or attempt >= len(RETRY_BACKOFF_SECONDS):
                return result, fetched
            delay = RETRY_BACKOFF_SECONDS[attempt]
            if self._monotonic() + delay >= deadline:
                return result, fetched
            self._sleep(delay)
            attempt += 1

    @staticmethod
    def _fetch_once(collector: Collector, spec: ResourceSpec) -> FetchResult:
        try:
            return collector.fetch(spec)
        except CollectorError as error:
            return FetchResult.failure(error.error_class, str(error), status=error.status)
        except Exception as error:
            # Nothing but the class name: the text of an unexpected exception may hold a payload.
            name = type(error).__name__
            return FetchResult.failure(name, name)

    def _collect_objects(
        self, name: str, table: ResourceTable, result: FetchResult, fetched: int
    ) -> _Outcome:
        """Redact, normalise and key the objects of one resource."""
        collected: list[CollectedObject] = []
        seen: set[str] = set()
        for raw in result.objects:
            try:
                redacted = redact_object(table, name, raw, self._fingerprinter, self._overrides)
                state = normalize_object(table, redacted.value)
            except TypeError:
                return _failure(name, ERROR_BAD_OBJECT, "an object is unreadable", fetched=fetched)
            key = _object_key(table, state)
            if key is None:
                return _failure(
                    name, ERROR_BAD_OBJECT, "an object has no usable key", fetched=fetched
                )
            if key in seen:
                return _failure(
                    name, ERROR_DUPLICATE_KEY, "two objects have the same key", fetched=fetched
                )
            seen.add(key)
            shown = None if table.name_field is None else state.get(table.name_field)
            collected.append(CollectedObject(key, state, shown if isinstance(shown, str) else None))
        ordered = table.collection is CollectionMode.ORDERED_KEYED
        return _Outcome(
            name,
            STATUS_OK,
            fetched,
            CollectedResource(collected, ordered=ordered),
            warning_class=result.warning_class,
            warning_text=result.warning_text,
        )

    def _store(
        self, source_id: int, run_id: int, version: str | None, outcomes: Sequence[_Outcome]
    ) -> RunReport:
        """Store, compare and classify in one transaction, then close the run record."""
        fresh = build_manifest(
            {
                outcome.name: outcome.collected
                for outcome in outcomes
                if outcome.collected is not None
            },
            controller_version=version,
        )
        failed = [outcome for outcome in outcomes if outcome.collected is None]
        # A resource that was read but needed a repair (an ordering list that did not match its
        # objects) is stored, and still makes the run partial.
        warned = [
            outcome
            for outcome in outcomes
            if outcome.collected is not None and outcome.warning_class is not None
        ]
        status: Literal["ok", "partial"] = "partial" if failed or warned else "ok"
        failed_class = failed[0].error_class if failed else None
        failed_summary: str | None = None
        if failed:
            listed = "; ".join(f"{outcome.name} ({outcome.status})" for outcome in failed)
            failed_summary = f"failed: {listed}"
        if warned:
            repaired = "; ".join(
                f"{outcome.name} ({outcome.warning_class}: {outcome.warning_text or 'repaired'})"
                for outcome in warned
            )
            failed_summary = (
                f"repaired: {repaired}"
                if failed_summary is None
                else f"{failed_summary}; repaired: {repaired}"
            )
            if failed_class is None:
                failed_class = warned[0].warning_class
        if failed_summary is not None:
            failed_summary = error_summary(failed_summary)
        with self._database.write() as connection:
            last_success = connection.execute(
                sa.select(sources.c.last_success_at).where(sources.c.id == source_id)
            ).scalar_one()
            previous = latest_snapshot(connection, source_id)
            manifest = _carry_over(
                connection, None if previous is None else previous.manifest, fresh
            )
            finished = self._clock()
            window_start = last_success or (finished if previous is None else previous.taken_at)
            result = record_collection(
                connection,
                source_id=source_id,
                run_id=run_id,
                manifest=manifest,
                bytes_fetched=sum(outcome.bytes_fetched for outcome in outcomes),
                finished_at=finished,
                status=status,
                error_class=failed_class,
                error_summary=failed_summary,
            )
            event_id: int | None = None
            if result.snapshot.stored and previous is not None:
                items = self._classify(
                    connection, previous.manifest, manifest, window_start, finished
                )
                if items:
                    event_id = _write_event(
                        connection,
                        source_id,
                        result.snapshot,
                        items,
                        window_start=window_start,
                        window_end=finished,
                        rule_pack_version=self._engine.pack_version,
                    )
            _write_coverage(connection, source_id, outcomes, finished)
        return RunReport(
            run_id,
            status,
            failed_class,
            failed_summary,
            result.snapshot.stored,
            event_id,
            manifest.object_count,
        )

    def _classify(
        self,
        connection: Connection,
        previous: Manifest,
        new: Manifest,
        window_start: str,
        window_end: str,
    ) -> list[ChangeItem]:
        def states(state_hash: str) -> Mapping[str, JsonValue]:
            return get_state(connection, state_hash)

        tables = self._engine.index.type_tables
        items = compare(
            previous,
            new,
            states,
            window_start=window_start,
            window_end=window_end,
            fingerprinter=self._fingerprinter,
            type_tables=tables,
        )
        items.extend(
            compare_order(
                previous,
                new,
                states,
                window_start=window_start,
                window_end=window_end,
                type_tables=tables,
            )
        )
        return [self._engine.apply(item) for item in items]
