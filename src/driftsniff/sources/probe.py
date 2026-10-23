"""Test connection: the read-only probe behind the button of the source forms (P10-T5).

``run_probe`` takes a collector that was built from the values of a form (a new source, or the
edit form of a stored one) and asks it what a run would ask: the version (``probe``), the
resources (``resources``) and one read of each (``fetch``). It keeps the version and, per
resource, the status and the number of objects, and drops the objects themselves. Nothing is
stored: no source, run, coverage row, snapshot or audit event, so a test can be repeated freely.

The collector is made by a :data:`ProbeFactory` (type, address, credential and options of the
form to a :class:`~driftsniff.collectors.base.Collector`). The application gets one through
``create_app``; ``serve`` has none until the collector factory of the run pipeline exists, and
the interface then says that the test is not available.

Every text in a result is the fixed text of a collector error (``collectors/base.py``), cut to one
line by ``error_summary``. As a second guard, a text that holds the credential is replaced by a
fixed sentence, so a result can never carry it. An unexpected exception is reported by its class
name only. The whole test stops reading after :data:`PROBE_LIMIT_SECONDS`; the resources it did
not reach say so.
"""

import contextlib
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final

from driftsniff.collectors.base import (
    STATUS_ERROR,
    STATUS_OK,
    Collector,
    CollectorError,
    ResourceSpec,
)
from driftsniff.sources.runs import error_summary

PROBE_LIMIT_SECONDS: Final = 60.0
ERROR_UNEXPECTED: Final = "unexpected"
ERROR_NOT_STARTED: Final = "not_started"
HIDDEN_TEXT: Final = "the controller refused the request"
_UNEXPECTED_TEXT: Final = "the test stopped on an unexpected error"
_NOT_REACHED_TEXT: Final = "not read: the test stopped after {seconds} seconds"


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    """What a test connects to: the values of the form. The credential is never printed."""

    source_type: str
    base_url: str
    credential: bytes = field(repr=False)
    options: Mapping[str, object] = field(default_factory=dict)


ProbeFactory = Callable[[ProbeTarget], Collector]


@dataclass(frozen=True, slots=True)
class ProbeRow:
    """One resource as the test read it: ``200``, ``403``, ``404``, another status or ``error``."""

    resource: str
    status: str
    object_count: int = 0
    error_text: str | None = None


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The answer of a test: the version and the rows, or why the controller was not usable."""

    ok: bool
    version: str | None = None
    rows: tuple[ProbeRow, ...] = ()
    error_class: str | None = None
    error_text: str | None = None


def _safe_text(text: str, credential: bytes) -> str:
    """One line of fixed collector text; the fixed sentence if it would carry the credential."""
    line = error_summary(text)
    secret = credential.decode("utf-8", errors="replace").strip()
    if secret and secret in text:
        return HIDDEN_TEXT
    return line


def _unexpected(error: Exception) -> str:
    """The text of an unexpected exception: its class name only, never its message."""
    return f"{_UNEXPECTED_TEXT} ({type(error).__name__})"


def _read(collector: Collector, spec: ResourceSpec, credential: bytes) -> ProbeRow:
    try:
        result = collector.fetch(spec)
    except CollectorError as error:
        return ProbeRow(spec.name, error.status, 0, _safe_text(str(error), credential))
    except Exception as error:
        return ProbeRow(spec.name, STATUS_ERROR, 0, _unexpected(error))
    if result.ok:
        return ProbeRow(spec.name, STATUS_OK, len(result.objects))
    text = result.error_text or result.error_class or STATUS_ERROR
    return ProbeRow(spec.name, result.status, 0, _safe_text(text, credential))


def run_probe(
    collector: Collector,
    target: ProbeTarget,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    limit_seconds: float = PROBE_LIMIT_SECONDS,
) -> ProbeResult:
    """Ask ``collector`` for its version and read every resource once; store nothing.

    The collector is closed at the end, whatever happened.
    """
    credential = target.credential
    try:
        try:
            version = collector.probe()
            specs = list(collector.resources())
        except CollectorError as error:
            text = _safe_text(str(error), credential)
            return ProbeResult(False, error_class=error.error_class, error_text=text)
        except Exception as error:
            return ProbeResult(False, error_class=ERROR_UNEXPECTED, error_text=_unexpected(error))
        deadline = monotonic() + limit_seconds
        rows: list[ProbeRow] = []
        for spec in specs:
            if monotonic() > deadline:
                text = _NOT_REACHED_TEXT.format(seconds=int(limit_seconds))
                rows.append(ProbeRow(spec.name, STATUS_ERROR, 0, text))
                continue
            rows.append(_read(collector, spec, credential))
        return ProbeResult(True, version, tuple(rows))
    finally:
        with contextlib.suppress(Exception):
            collector.close()


def start_probe(factory: ProbeFactory, target: ProbeTarget) -> ProbeResult:
    """Build the collector of ``target`` with ``factory`` and run the probe; nothing is stored.

    A factory that refuses the values (an address or a credential it cannot use, a
    ``ValueError``) gives a result of the class ``not_started`` with its fixed text.
    """
    try:
        collector = factory(target)
    except CollectorError as error:
        text = _safe_text(str(error), target.credential)
        return ProbeResult(False, error_class=error.error_class, error_text=text)
    except ValueError as error:
        text = _safe_text(str(error), target.credential)
        return ProbeResult(False, error_class=ERROR_NOT_STARTED, error_text=text)
    except Exception as error:
        return ProbeResult(False, error_class=ERROR_UNEXPECTED, error_text=_unexpected(error))
    return run_probe(collector, target)
