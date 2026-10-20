"""Redaction at the collector boundary, and the log filter that backs it up.

``redact_object`` runs on the raw object a collector received, before the normaliser. Walking
the object, it:

- drops fields of the ``ignore`` class;
- replaces the value of a ``secret`` field with its fingerprint (``fp1:<key id>:<hex>``);
- scans every other string (free text and map values included) and, when a scanner rule fires
  and no reviewed override covers it, replaces that value with its fingerprint too;
- leaves everything else as it was.

A ``null`` stays ``null``: null and missing are the same state. The result reports how many
fingerprints it holds and which paths the scanner forced (path and rule, never the value), so
the type table can be improved. The caller stores the redacted object; the storage layer sets
the ``fp_in_use`` flag in the transaction that stores the first fingerprint
(:func:`driftsniff.core.states.put_canonical_state`).

The logging filter is a safety net, not the plan: payloads and query strings are never logged
on purpose. It scrubs the patterns of the scanner (PEM blocks, JWTs, passwords in URLs,
credential prefixes, long high-entropy words) and the query string of any URL from every log
record, including exception text. Words with a slash, a backslash or a dot are not judged by
entropy in logs, so file names, host names and module names stay readable.
"""

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass

from driftsniff.core.canonical import JsonValue
from driftsniff.core.normalize import FieldClass, TypeTable
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.scanner import (
    JWT_SHAPE,
    NO_OVERRIDES,
    PEM_BLOCK,
    PREFIXED_CREDENTIAL,
    Overrides,
    ScanRule,
    entropy_spans,
    scan_text,
    url_credential_spans,
)

REDACTED = "***REDACTED***"

_LOG_PATH_CHARS = frozenset("/\\.")
_QUERY_STRING = re.compile(r"(?<=[^\s?])\?[^\s\x22\x27<>#]*=[^\s\x22\x27<>#]*")


@dataclass(frozen=True, slots=True)
class ForcedSecret:
    """A path where the scanner, not the type table, made a value a secret."""

    path: str
    rule: ScanRule


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """The redacted object and what the redaction did (never the redacted values)."""

    value: dict[str, JsonValue]
    fingerprints: int
    forced: tuple[ForcedSecret, ...]

    @property
    def has_fingerprints(self) -> bool:
        return self.fingerprints > 0


class _Redactor:
    def __init__(
        self,
        type_table: TypeTable,
        resource_type: str,
        fingerprinter: Fingerprinter,
        overrides: Overrides,
    ) -> None:
        self._type_table = type_table
        self._resource_type = resource_type
        self._fingerprinter = fingerprinter
        self._overrides = overrides
        self.fingerprints = 0
        self.forced: list[ForcedSecret] = []

    def mapping(self, path: str, raw: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in raw.items():
            if not isinstance(key, str):
                raise TypeError(f"object keys must be strings, got {type(key).__name__}")
            child_path = f"{path}.{key}" if path else key
            field_class = self._type_table.field_class(child_path)
            if field_class is not FieldClass.IGNORE:
                result[key] = self._value(child_path, value, field_class)
        return result

    def _value(self, path: str, value: JsonValue, field_class: FieldClass) -> JsonValue:
        if field_class is FieldClass.SECRET:
            return self._fingerprint(path, value)
        if isinstance(value, Mapping):
            return self.mapping(path, value)
        if isinstance(value, list | tuple):
            return [self._value(path, member, field_class) for member in value]
        if isinstance(value, str):
            return self._scan(path, value)
        return value

    def _fingerprint(self, path: str, value: JsonValue) -> JsonValue:
        if value is None:
            return None
        self.fingerprints += 1
        return self._fingerprinter.fingerprint(self._resource_type, path, value).marker()

    def _scan(self, path: str, text: str) -> JsonValue:
        for rule in scan_text(text):
            if not self._overrides.suppresses(self._resource_type, path, rule):
                self.forced.append(ForcedSecret(path, rule))
                return self._fingerprint(path, text)
        return text


def redact_object(
    type_table: TypeTable,
    resource_type: str,
    raw: Mapping[str, JsonValue],
    fingerprinter: Fingerprinter,
    overrides: Overrides = NO_OVERRIDES,
) -> RedactionResult:
    """Redact one raw controller object of ``resource_type``; the input is not changed."""
    if not isinstance(raw, Mapping):
        raise TypeError("a raw object must be a mapping")
    redactor = _Redactor(type_table, resource_type, fingerprinter, overrides)
    value = redactor.mapping("", raw)
    return RedactionResult(value, redactor.fingerprints, tuple(redactor.forced))


def _log_spans(text: str) -> list[tuple[int, int]]:
    spans = [match.span() for match in PEM_BLOCK.finditer(text)]
    spans.extend(match.span() for match in JWT_SHAPE.finditer(text))
    spans.extend(match.span() for match in PREFIXED_CREDENTIAL.finditer(text))
    spans.extend(url_credential_spans(text))
    spans.extend(
        (start, end)
        for start, end in entropy_spans(text)
        if _LOG_PATH_CHARS.isdisjoint(text[start:end])
    )
    # Keep the question mark, hide what follows it.
    spans.extend((match.start() + 1, match.end()) for match in _QUERY_STRING.finditer(text))
    return spans


def scrub_text(text: str) -> str:
    """Replace every credential pattern and every URL query string in ``text``."""
    merged: list[list[int]] = []
    for start, end in sorted(_log_spans(text)):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    if not merged:
        return text
    pieces: list[str] = []
    position = 0
    for start, end in merged:
        pieces.append(text[position:start])
        pieces.append(REDACTED)
        position = end
    pieces.append(text[position:])
    return "".join(pieces)


class RedactingFilter(logging.Filter):
    """Scrubs the message, the arguments, the exception text and the stack of a log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg = scrub_text(message)
        record.args = None
        if record.exc_info:
            record.exc_text = scrub_text(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = scrub_text(record.exc_text)
        if record.stack_info:
            record.stack_info = scrub_text(record.stack_info)
        return True


def install_log_filter() -> int:
    """Attach the filter to every handler of the root logger; returns how many were new."""
    added = 0
    for handler in logging.getLogger().handlers:
        if not any(isinstance(existing, RedactingFilter) for existing in handler.filters):
            handler.addFilter(RedactingFilter())
            added += 1
    return added
