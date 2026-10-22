"""A read that needed a repair is stored and still makes the run partial (P7-T4).

``FetchResult.success(..., warning_class=...)`` is how a collector says that it had to repair what
it read (the UniFi ordering lists, class ``ordering_mismatch``). The pipeline keeps the objects and
their coverage, and reports the run as partial with that class.
"""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import ERROR_HTTP, Collector, FetchResult, ResourceSpec
from driftsniff.core.canonical import JsonValue
from driftsniff.core.normalize import FieldClass
from driftsniff.db import tables
from driftsniff.db.engine import Database
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import RuleIndex
from driftsniff.rules.schema import ResourceTable
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline

SOURCE_ID = 1
WARNING = "ordering_mismatch"
CONFIG = FieldClass.CONFIG


def table(resource: str) -> ResourceTable:
    return ResourceTable(
        resource=resource,
        object_key_field="id",
        name_field="name",
        field_classes={"id": CONFIG, "name": CONFIG, "size": CONFIG},
    )


INDEX = RuleIndex(
    pack_version="pack-t1",
    rules=(),
    by_resource={},
    type_tables={"things": table("things"), "others": table("others")},
)


def things(size: int) -> list[dict[str, JsonValue]]:
    return [{"id": "t1", "name": "One", "size": size}]


def repaired(size: int, text: str | None = "1 appended") -> FetchResult:
    return FetchResult.success(
        things(size), bytes_fetched=10, warning_class=WARNING, warning_text=text
    )


class Scripted(Collector):
    """Hands over one prepared result per resource."""

    def __init__(self, results: Mapping[str, FetchResult]) -> None:
        self._results = dict(results)

    def probe(self) -> str | None:
        return "1.0.0"

    def resources(self) -> Sequence[ResourceSpec]:
        return [ResourceSpec(name) for name in self._results]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        return self._results[spec.name]


class Clock:
    """UTC timestamps one second apart."""

    def __init__(self) -> None:
        self.second = 0

    def __call__(self) -> str:
        self.second += 1
        moment = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC) + timedelta(seconds=self.second)
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def pipeline(store: Database) -> RunPipeline:
    return RunPipeline(
        store,
        RuleEngine(INDEX),
        Fingerprinter(bytes(range(32)), "0a1b2c3d"),
        clock=Clock(),
        sleep=lambda seconds: None,
    )


def rows(database: Database, table_: sa.Table) -> list[sa.Row[tuple[object, ...]]]:
    with database.read() as connection:
        return list(connection.execute(sa.select(table_).order_by(*table_.primary_key.columns)))


def baseline(pipeline: RunPipeline) -> None:
    pipeline.run(
        SOURCE_ID,
        Scripted(
            {
                "things": FetchResult.success(things(1)),
                "others": FetchResult.success(things(1)),
            }
        ),
    )


def test_a_repaired_resource_is_stored_and_the_run_is_partial(
    store: Database, pipeline: RunPipeline
) -> None:
    baseline(pipeline)
    first_run = rows(store, tables.runs)[0]
    report = pipeline.run(
        SOURCE_ID, Scripted({"things": repaired(2), "others": FetchResult.success(things(1))})
    )
    assert report.status == "partial"
    assert report.error_class == WARNING
    assert report.error_summary == "repaired: things (ordering_mismatch: 1 appended)"
    assert report.object_count == 2
    assert report.stored_new_snapshot is True
    assert report.event_id is not None
    second_run = rows(store, tables.runs)[1]
    assert (second_run.status, second_run.error_class) == ("partial", WARNING)
    # A partial run is a check but not a success.
    source = rows(store, tables.sources)[0]
    assert source.last_checked_at == second_run.finished_at
    assert source.last_success_at == first_run.finished_at
    # The resource was read, so its coverage is good and its change is stored.
    coverage = {str(row.resource): row for row in rows(store, tables.resource_coverage)}
    assert (coverage["things"].last_status, coverage["things"].stale_since) == ("200", None)
    (item,) = rows(store, tables.change_items)
    assert (item.resource, item.path, item.change_kind) == ("things", "size", "modified")


def test_a_failed_resource_decides_the_error_class_before_a_repaired_one(
    store: Database, pipeline: RunPipeline
) -> None:
    baseline(pipeline)
    refused = FetchResult.failure(ERROR_HTTP, "refused", status="403")
    report = pipeline.run(SOURCE_ID, Scripted({"things": repaired(1), "others": refused}))
    assert report.status == "partial"
    assert report.error_class == ERROR_HTTP
    assert report.error_summary == (
        "failed: others (403); repaired: things (ordering_mismatch: 1 appended)"
    )
    coverage = {str(row.resource): row for row in rows(store, tables.resource_coverage)}
    assert coverage["others"].last_status == "403"
    assert coverage["things"].last_status == "200"


def test_a_repair_without_a_text_is_still_reported(pipeline: RunPipeline) -> None:
    results = {"things": repaired(1, None), "others": FetchResult.success(things(1))}
    report = pipeline.run(SOURCE_ID, Scripted(results))
    assert (report.status, report.error_class) == ("partial", WARNING)
    assert report.error_summary == "repaired: things (ordering_mismatch: repaired)"


def test_a_good_read_may_carry_a_warning_and_a_failed_one_may_not() -> None:
    warned = repaired(1)
    assert (warned.ok, warned.warning_class, warned.warning_text) == (True, WARNING, "1 appended")
    assert warned.error_class is None
    assert warned.retryable is False
    plain = FetchResult.success(things(1))
    assert (plain.warning_class, plain.warning_text) == (None, None)
    assert FetchResult.failure(ERROR_HTTP, "refused").warning_class is None
    with pytest.raises(ValueError, match="no warning"):
        FetchResult(False, error_class=ERROR_HTTP, warning_class=WARNING)
    with pytest.raises(ValueError, match="needs a warning class"):
        FetchResult(True, warning_text="1 appended")
