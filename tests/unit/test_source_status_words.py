"""The words of a source's status (THE-991, findings of the P10 live acceptance).

F1: a failed test connection gives its reason as a sentence before "Nothing was stored.".
"""

from datetime import UTC, datetime

from driftsniff.collectors.base import ERROR_CONNECTION, Collector, CollectorError
from driftsniff.sources.probe import ProbeResult, ProbeTarget, start_probe
from driftsniff.web.templating import Shell, render, sentence

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
UNRESOLVED = "the controller address cannot be resolved"


def unresolved(target: ProbeTarget) -> Collector:
    raise CollectorError(ERROR_CONNECTION, UNRESOLVED)


def probe_panel(error_text: str | None) -> str:
    """The test connection panel of a failed test, as the HTMX answer renders it."""
    target = ProbeTarget(
        source_type="unifi", base_url="https://nowhere.invalid", credential=b"", options={}
    )
    result = start_probe(unresolved, target)
    assert not result.ok and result.error_text == UNRESOLVED
    if error_text is None:
        result = ProbeResult(False, error_class=ERROR_CONNECTION)
    body = render(
        "sources/_probe.html",
        Shell(title=""),
        probe=result,
        probe_rows=(),
        problems=[],
        probe_unavailable=False,
        unavailable_text=("", ""),
        now=NOW,
    )
    return " ".join(body.split())


def test_sentence_capitalises_and_ends_with_one_full_stop() -> None:
    assert sentence(UNRESOLVED) == "The controller address cannot be resolved."
    assert sentence("Already a sentence.") == "Already a sentence."
    assert sentence("HTTP 503 from the controller") == "HTTP 503 from the controller."


def test_a_failed_test_connection_says_why_in_a_sentence() -> None:
    text = probe_panel(UNRESOLVED)
    assert "The connection test failed" in text
    assert "The controller address cannot be resolved. Nothing was stored." in text
    assert "the controller address cannot be resolved Nothing" not in text


def test_a_failed_test_connection_without_a_reason_keeps_its_fixed_sentence() -> None:
    text = probe_panel(None)
    assert "The controller could not be used. Nothing was stored." in text
