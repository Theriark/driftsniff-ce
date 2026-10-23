"""The read-only probe behind test connection (P10-T5): what it reports and what it never keeps.

A fake collector stands in for UniFi and Xen Orchestra, so every answer a resource can give is
covered: 200 with objects, 403, 404, an error without an answer, a collector that raises, and a
test that runs out of time. The credential is a canary that must never reach a result.
"""

from collections.abc import Mapping, Sequence

import pytest

from driftsniff.collectors.base import Collector, CollectorError, FetchResult, ResourceSpec
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.probe import (
    ERROR_NOT_STARTED,
    ERROR_UNEXPECTED,
    HIDDEN_TEXT,
    ProbeResult,
    ProbeTarget,
    run_probe,
    start_probe,
)

CANARY = "CANARY-5c0ffee5c0ffee5c0ffee5c0"
TARGET = ProbeTarget("unifi", "https://controller.example", CANARY.encode("utf-8"), {})
OBJECTS: Sequence[Mapping[str, JsonValue]] = ({"id": "a"}, {"id": "b"}, {"id": "c"})


class FakeCollector(Collector):
    """Answers each resource with the result (or the exception) it was given."""

    def __init__(
        self,
        answers: Mapping[str, FetchResult | Exception],
        *,
        version: str | None = "10.1.84",
        probe_error: Exception | None = None,
    ) -> None:
        self.answers = answers
        self.version = version
        self.probe_error = probe_error
        self.read: list[str] = []
        self.closed = 0

    def probe(self) -> str | None:
        if self.probe_error is not None:
            raise self.probe_error
        return self.version

    def resources(self) -> Sequence[ResourceSpec]:
        return [ResourceSpec(name, f"/{name}") for name in self.answers]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        self.read.append(spec.name)
        answer = self.answers[spec.name]
        if isinstance(answer, Exception):
            raise answer
        return answer

    def close(self) -> None:
        self.closed += 1


def assert_no_credential(result: ProbeResult) -> None:
    text = repr(result) + repr(TARGET)
    assert CANARY not in text
    assert CANARY.removeprefix("CANARY-") not in text


def test_a_good_probe_keeps_the_version_and_one_row_per_resource() -> None:
    collector = FakeCollector(
        {
            "unifi-sites": FetchResult.success(OBJECTS),
            "unifi-dns-policies": FetchResult.failure(
                "forbidden", "the controller refused this resource", status="403"
            ),
            "unifi-acl-rules": FetchResult.failure(
                "not_available", "the resource is not on this version", status="404"
            ),
            "unifi-devices": FetchResult.failure(
                "timeout", "the controller did not answer in time"
            ),
        }
    )
    result = run_probe(collector, TARGET)
    assert result.ok and result.version == "10.1.84"
    assert [(row.resource, row.status, row.object_count) for row in result.rows] == [
        ("unifi-sites", "200", 3),
        ("unifi-dns-policies", "403", 0),
        ("unifi-acl-rules", "404", 0),
        ("unifi-devices", "error", 0),
    ]
    assert result.rows[0].error_text is None
    assert result.rows[3].error_text == "the controller did not answer in time"
    assert collector.closed == 1
    assert_no_credential(result)


def test_a_resource_that_raises_is_one_failed_row_and_the_others_are_still_read() -> None:
    collector = FakeCollector(
        {
            "vms": CollectorError(
                "http_error", "the controller answered with HTTP 502", status="502"
            ),
            "hosts": RuntimeError(f"boom {CANARY}"),
            "pools": FetchResult.success(OBJECTS[:1]),
        }
    )
    result = run_probe(collector, TARGET)
    assert collector.read == ["vms", "hosts", "pools"]
    assert [(row.status, row.object_count) for row in result.rows] == [
        ("502", 0),
        ("error", 0),
        ("200", 1),
    ]
    # an unexpected exception is reported by its class name only, never by its message
    assert result.rows[1].error_text == "the test stopped on an unexpected error (RuntimeError)"
    assert_no_credential(result)


def test_a_probe_that_fails_reports_the_class_and_reads_nothing() -> None:
    error = CollectorError("unauthorized", "the controller refused the credential", status="401")
    collector = FakeCollector({"vms": FetchResult.success(OBJECTS)}, probe_error=error)
    result = run_probe(collector, TARGET)
    assert not result.ok and result.rows == ()
    assert (result.error_class, result.error_text) == (
        "unauthorized",
        "the controller refused the credential",
    )
    assert collector.read == [] and collector.closed == 1


def test_an_unexpected_probe_error_keeps_only_the_class_name() -> None:
    collector = FakeCollector({}, probe_error=ValueError(f"key {CANARY} rejected"))
    result = run_probe(collector, TARGET)
    assert result.error_class == ERROR_UNEXPECTED
    assert result.error_text == "the test stopped on an unexpected error (ValueError)"
    assert_no_credential(result)


def test_a_text_that_would_carry_the_credential_is_replaced() -> None:
    leaky = CollectorError("http_error", f"refused {CANARY} for /x")
    collector = FakeCollector({"vms": leaky}, probe_error=None)
    result = run_probe(collector, TARGET)
    assert result.rows[0].error_text == HIDDEN_TEXT
    probe_leak = FakeCollector({}, probe_error=CollectorError("connection", f"no {CANARY}"))
    assert run_probe(probe_leak, TARGET).error_text == HIDDEN_TEXT


def test_the_test_stops_reading_after_its_time_limit() -> None:
    ticks = iter([0.0, 1.0, 61.0, 62.0])
    collector = FakeCollector(
        {"vms": FetchResult.success(OBJECTS), "hosts": FetchResult.success(OBJECTS)}
    )
    result = run_probe(collector, TARGET, monotonic=lambda: next(ticks), limit_seconds=60.0)
    assert collector.read == ["vms"]
    assert result.rows[1].status == "error"
    assert result.rows[1].error_text == "not read: the test stopped after 60 seconds"


def test_close_is_called_even_when_it_fails_itself() -> None:
    class BrokenClose(FakeCollector):
        def close(self) -> None:
            super().close()
            raise OSError("socket already gone")

    collector = BrokenClose({"vms": FetchResult.success(OBJECTS)})
    assert run_probe(collector, TARGET).ok
    assert collector.closed == 1


@pytest.mark.parametrize(
    ("raised", "error_class", "text"),
    [
        (CollectorError("blocked_address", "the address is blocked"), "blocked_address", None),
        (ValueError("the credential is blank or has characters a cookie cannot carry"), None, None),
        (RuntimeError(f"factory broke on {CANARY}"), ERROR_UNEXPECTED, None),
    ],
)
def test_a_factory_that_refuses_the_values_gives_a_result_not_an_error(
    raised: Exception, error_class: str | None, text: str | None
) -> None:
    def factory(_target: ProbeTarget) -> Collector:
        raise raised

    result = start_probe(factory, TARGET)
    assert not result.ok
    assert result.error_class == (error_class or ERROR_NOT_STARTED)
    assert result.error_text
    assert_no_credential(result)


def test_start_probe_hands_the_target_to_the_factory_and_runs_the_collector() -> None:
    seen: list[ProbeTarget] = []
    collector = FakeCollector({"vms": FetchResult.success(OBJECTS)})

    def factory(target: ProbeTarget) -> Collector:
        seen.append(target)
        return collector

    result = start_probe(factory, TARGET)
    assert seen == [TARGET] and seen[0].credential == CANARY.encode("utf-8")
    assert result.ok and result.rows[0].object_count == 3
    assert CANARY not in repr(seen[0])
