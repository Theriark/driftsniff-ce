"""The collector contract and the limits every controller read obeys.

A collector knows how to read one kind of system. The run pipeline (``driftsniff.sources.runs``)
knows everything else: locking, retries, redaction, storing and classifying. A collector offers
three calls:

* ``probe()`` returns the version of the controller (or None when it has none to report), and
  fails with :class:`CollectorError` when the controller cannot be reached or refuses the
  credential;
* ``resources()`` lists the resources to read (:class:`ResourceSpec`); each name must have a type
  table in the rule packs;
* ``fetch(spec)`` reads one resource and returns a :class:`FetchResult`: an ok flag, the raw
  JSON objects, the status and, on failure, an error class.

``fetch`` hands over raw objects. Redaction, normalisation and keying happen in the pipeline, so
no collector can forget them.

Limits (the numbers of the plan): 30 seconds per request, 200 MB per response body enforced while
the body streams, redirects never followed. Retries (three, after 1, 2 and 4 seconds, on server
errors and timeouts) and the five minute limit per run belong to the pipeline.

Error messages are shown to the admin and stored in the run record, so a collector must never put
a payload, a credential or a request URL with a query string into one. The helpers here use fixed
texts for that reason.
"""

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import httpx

from driftsniff.collectors.tls import (
    ERROR_TLS,
    ERROR_TLS_PIN,
    TlsSettings,
    build_transport,
    classify_failure,
)
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.core.canonical import JsonValue
from driftsniff.sources.addresses import FOLLOW_REDIRECTS

REQUEST_TIMEOUT_SECONDS: Final = 30.0
MAX_BODY_BYTES: Final = 200 * 1024 * 1024
RETRY_BACKOFF_SECONDS: Final = (1.0, 2.0, 4.0)
MAX_ERROR_TEXT_CHARS: Final = 200

STATUS_OK: Final = "200"
STATUS_ERROR: Final = "error"

ERROR_TIMEOUT: Final = "timeout"
ERROR_CONNECTION: Final = "connection"
ERROR_HTTP: Final = "http_error"
ERROR_REDIRECT: Final = "redirect_refused"
ERROR_BODY_TOO_LARGE: Final = "body_too_large"
ERROR_BAD_JSON: Final = "bad_json"
_TLS_TEXT: Final = {
    ERROR_TLS: "the TLS certificate of the controller was not accepted",
    ERROR_TLS_PIN: "the certificate of the controller is not the pinned one; nothing was sent",
}


def is_retryable(status: str, error_class: str | None) -> bool:
    """A timeout or an HTTP 5xx answer may pass; anything else will not change by waiting."""
    server_error = len(status) == 3 and status.isdigit() and status.startswith("5")
    return error_class == ERROR_TIMEOUT or server_error


class CollectorError(Exception):
    """A collector could not read what it was asked to.

    ``error_class`` is a short machine readable word, ``status`` the HTTP status as text when
    there was one (``403``) and ``error`` otherwise. The message is stored and shown.
    """

    def __init__(self, error_class: str, message: str, *, status: str = STATUS_ERROR) -> None:
        super().__init__(message)
        self.error_class = error_class
        self.status = status

    @property
    def retryable(self) -> bool:
        """Whether the pipeline tries the same call again after a pause."""
        return is_retryable(self.status, self.error_class)


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    """One resource to read. ``name`` is its type in the type tables; ``path`` is where the
    collector reads it from (the pipeline never looks at it)."""

    name: str
    path: str = ""


@dataclass(frozen=True, slots=True)
class FetchResult:
    """What reading one resource gave.

    ``status`` is ``200`` for a good read, the HTTP status as text for a refused one (``403``,
    ``404``, ``502``) and ``error`` when there was no answer. A failed read carries an error class
    and a short text; a good one carries neither.

    A good read may carry a ``warning_class`` and ``warning_text``: the objects are usable but the
    collector had to repair something (for example an ordering list that did not match the
    objects). The pipeline stores the objects and marks the run ``partial`` with that class.
    """

    ok: bool
    objects: Sequence[Mapping[str, JsonValue]] = ()
    status: str = STATUS_OK
    error_class: str | None = None
    error_text: str | None = None
    bytes_fetched: int = 0
    warning_class: str | None = None
    warning_text: str | None = None

    def __post_init__(self) -> None:
        if self.ok and self.error_class is not None:
            raise ValueError("a good read has no error class")
        if not self.ok and self.warning_class is not None:
            raise ValueError("a failed read has no warning")
        if self.warning_class is None and self.warning_text is not None:
            raise ValueError("a warning text needs a warning class")
        if not self.ok and self.error_class is None:
            raise ValueError("a failed read needs an error class")
        if not self.ok and self.objects:
            raise ValueError("a failed read has no objects")

    @classmethod
    def success(
        cls,
        objects: Sequence[Mapping[str, JsonValue]],
        *,
        bytes_fetched: int = 0,
        warning_class: str | None = None,
        warning_text: str | None = None,
    ) -> "FetchResult":
        """A good read of ``objects``; ``bytes_fetched`` is what the controller sent.

        ``warning_class`` and ``warning_text`` say that the objects needed a repair (see above).
        """
        return cls(True, objects, STATUS_OK, None, None, bytes_fetched, warning_class, warning_text)

    @classmethod
    def failure(
        cls, error_class: str, text: str, *, status: str = STATUS_ERROR, bytes_fetched: int = 0
    ) -> "FetchResult":
        """A failed read."""
        return cls(False, (), status, error_class, text, bytes_fetched)

    @property
    def retryable(self) -> bool:
        """Whether the pipeline tries this read again after a pause."""
        return not self.ok and is_retryable(self.status, self.error_class)


class Collector(ABC):
    """What the run pipeline needs from a source reader. One instance serves one run."""

    @abstractmethod
    def probe(self) -> str | None:
        """The controller version, or None when the system reports none."""

    @abstractmethod
    def resources(self) -> Sequence[ResourceSpec]:
        """The resources to read, in the order to read them; names must be unique."""

    @abstractmethod
    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """Read one resource and return its raw objects."""

    def close(self) -> None:
        """Release connections. The pipeline calls it once after the run, even a failed one."""
        return None


def make_client(
    *,
    transport: httpx.BaseTransport | None = None,
    tls: TlsSettings | None = None,
    data_dir: Path | str = DEFAULT_DATA_DIR,
) -> httpx.Client:
    """An HTTP client with the limits of this module: 30 second timeout, no redirects.

    The environment is not consulted (no proxy settings from variables). ``tls`` selects the TLS
    mode of the source (``driftsniff.collectors.tls``; without it the default trust store is
    used); ``transport`` is there for tests and excludes ``tls``. A caller adds its own credential
    header.
    """
    if tls is not None:
        if transport is not None:
            raise ValueError("a transport and TLS settings exclude each other")
        transport = build_transport(tls, data_dir)
    return httpx.Client(
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=FOLLOW_REDIRECTS,
        trust_env=False,
        transport=transport,
    )


def read_limited(response: httpx.Response, *, max_bytes: int = MAX_BODY_BYTES) -> bytes:
    """Read the body of a streamed response, stopping as soon as it exceeds ``max_bytes``."""
    message = f"the response is larger than {max_bytes} bytes"
    declared = response.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > max_bytes:
        raise CollectorError(ERROR_BODY_TOO_LARGE, message)
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise CollectorError(ERROR_BODY_TOO_LARGE, message)
        chunks.append(chunk)
    return b"".join(chunks)


def fetch_json(
    client: httpx.Client,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    max_bytes: int = MAX_BODY_BYTES,
) -> tuple[JsonValue, int]:
    """GET ``url`` and return the parsed JSON and the number of bytes received.

    A redirect is an error (``redirect_refused``) and the new location is never requested. An
    HTTP error status, a timeout, a connection problem, a body over ``max_bytes`` and a body that
    is not JSON each raise :class:`CollectorError` with a fixed message: the URL, the headers and
    the body never appear in it.
    """
    try:
        with client.stream("GET", url, headers=headers) as response:
            status = response.status_code
            if 300 <= status < 400:
                raise CollectorError(
                    ERROR_REDIRECT,
                    "the controller answered with a redirect, which is never followed",
                    status=str(status),
                )
            if status >= 400:
                raise CollectorError(
                    ERROR_HTTP, f"the controller answered with HTTP {status}", status=str(status)
                )
            body = read_limited(response, max_bytes=max_bytes)
    except httpx.TimeoutException:
        raise CollectorError(ERROR_TIMEOUT, "the controller did not answer in time") from None
    except httpx.HTTPError as error:
        tls_class = classify_failure(error)
        if tls_class is not None:
            raise CollectorError(tls_class, _TLS_TEXT[tls_class]) from None
        raise CollectorError(ERROR_CONNECTION, "the controller could not be reached") from None
    try:
        parsed: JsonValue = json.loads(body)
    except ValueError:
        raise CollectorError(ERROR_BAD_JSON, "the response is not valid JSON") from None
    return parsed, len(body)
