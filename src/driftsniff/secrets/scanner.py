"""Secret scanner: finds values that look like credentials, whatever their field class.

A finding forces the secret class on the value, so only its fingerprint is stored. Rules:

- ``pem``: a PEM header (five dashes, BEGIN, a label, five dashes).
- ``jwt``: three base64url parts, the first starting with ``eyJ``.
- ``url_credentials``: a URL with both a user and a password in front of the host.
- ``prefixed_credential``: a well-known credential prefix (AKIA, ASIA, AIza, ghp_, gho_,
  github_pat_, xoxb-, xoxp-, sk_live_, glpat-) followed by at least 8 token characters.
- ``high_entropy``: a word of 20 or more characters with Shannon entropy above 4.2 bits per
  character. UUIDs and pure hexadecimal words of length 32, 40 or 64 are exempt.
- ``fingerprint_marker``: text shaped like a stored fingerprint. Such text could only come from
  a controller trying to pass itself off as one, so it is fingerprinted again.

The entropy rule looks at words (runs of characters between white space, quotes, brackets,
commas and semicolons), not at the whole string: a plain sentence such as a network description
has an entropy above 4.2 bits per character and would otherwise always count as a secret. A
single-word value is judged as a whole, as the plan words it.

A path that is known to hold harmless text that trips a rule is listed in ``rules/overrides.yaml``
(:class:`Overrides`). Every entry names the rules it silences and gives a reason; the
``fingerprint_marker`` rule and the secret field class can never be overridden.

Every pattern is linear in the length of the text: no nested quantifiers, and every search
starts at a fixed marker or at a word boundary, so a very long value cannot stall a collection.
"""

import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path

import yaml

from driftsniff.secrets.fingerprint import MARKER_PATTERN

ENTROPY_MIN_LENGTH = 20
ENTROPY_THRESHOLD = 4.2
EXEMPT_HEX_LENGTHS = frozenset({32, 40, 64})
PREFIX_MIN_BODY = 8
OVERRIDES_FILE_NAME = "overrides.yaml"
OVERRIDES_VERSION = 1

CREDENTIAL_PREFIXES = (
    "AKIA",
    "ASIA",
    "AIza",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "sk_live_",
    "glpat-",
)


class ScanRule(StrEnum):
    """The scanner rules, in the order they are reported."""

    PEM = "pem"
    JWT = "jwt"
    URL_CREDENTIALS = "url_credentials"
    PREFIXED_CREDENTIAL = "prefixed_credential"
    HIGH_ENTROPY = "high_entropy"
    FINGERPRINT_MARKER = "fingerprint_marker"


PEM_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]{1,40}-----")
PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]{1,40}-----(?:.*?-----END [A-Z0-9 ]{1,40}-----|.*\Z)", re.DOTALL
)
JWT_SHAPE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_PREFIX_ALTERNATIVES = "|".join(re.escape(prefix) for prefix in CREDENTIAL_PREFIXES)
PREFIXED_CREDENTIAL = re.compile(
    rf"(?<![A-Za-z0-9])(?:{_PREFIX_ALTERNATIVES})[A-Za-z0-9_-]{{{PREFIX_MIN_BODY},}}"
)
MARKER_LOOKALIKE = re.compile(MARKER_PATTERN)

# The part of a URL after "://" up to the first character that ends the authority.
_AUTHORITY = re.compile(r"[^/?#\s\x22\x27<>]*")
# A word: everything between white space, quotes, angle brackets, brackets, commas, semicolons.
_WORDS = re.compile(r"[^\s\x22\x27<>(),;]+")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_HEX = re.compile(r"[0-9a-fA-F]+")


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character (0.0 for an empty string)."""
    if not text:
        return 0.0
    total = len(text)
    entropy = -sum((count / total) * math.log2(count / total) for count in Counter(text).values())
    return entropy + 0.0


def _is_exempt(word: str) -> bool:
    if _UUID.fullmatch(word) is not None:
        return True
    return len(word) in EXEMPT_HEX_LENGTHS and _HEX.fullmatch(word) is not None


def entropy_spans(text: str) -> Iterator[tuple[int, int]]:
    """Spans of the words that the high-entropy rule flags."""
    for match in _WORDS.finditer(text):
        word = match.group()
        if len(word) < ENTROPY_MIN_LENGTH or _is_exempt(word):
            continue
        if shannon_entropy(word) > ENTROPY_THRESHOLD:
            yield match.span()


def url_credential_spans(text: str) -> Iterator[tuple[int, int]]:
    """Spans of the ``user:password`` part of every ``scheme://user:password@host`` URL."""
    position = 0
    while (found := text.find("://", position)) != -1:
        start = found + 3
        match = _AUTHORITY.match(text, start)
        end = start if match is None else match.end()
        at_sign = text.rfind("@", start, end)
        if found > 0 and text[found - 1].isalnum() and at_sign != -1:
            user, separator, password = text[start:at_sign].partition(":")
            if separator and user and password:
                yield start, at_sign
        position = max(end, start)


def scan_text(text: str) -> tuple[ScanRule, ...]:
    """Every rule that fires on ``text``, in the order of :class:`ScanRule`."""
    found: list[ScanRule] = []
    if PEM_HEADER.search(text) is not None:
        found.append(ScanRule.PEM)
    if JWT_SHAPE.search(text) is not None:
        found.append(ScanRule.JWT)
    if next(url_credential_spans(text), None) is not None:
        found.append(ScanRule.URL_CREDENTIALS)
    if PREFIXED_CREDENTIAL.search(text) is not None:
        found.append(ScanRule.PREFIXED_CREDENTIAL)
    if next(entropy_spans(text), None) is not None:
        found.append(ScanRule.HIGH_ENTROPY)
    if MARKER_LOOKALIKE.search(text) is not None:
        found.append(ScanRule.FINGERPRINT_MARKER)
    return tuple(found)


class OverrideFileError(ValueError):
    """The overrides file is missing, unreadable or not in the expected form."""


@dataclass(frozen=True, slots=True)
class Override:
    """One reviewed exception: a path where a scanner finding is a known false positive.

    ``resource_type`` is a resource type or ``*`` for every type; ``path`` is the dot separated
    field path; ``rules`` limits the exception to some rules (None means every rule that can be
    overridden).
    """

    resource_type: str
    path: str
    reason: str
    rules: frozenset[ScanRule] | None = None


class Overrides:
    """The reviewed false-positive exceptions, looked up by resource type and field path."""

    def __init__(self, entries: Iterable[Override] = ()) -> None:
        index: dict[tuple[str, str], Override] = {}
        for entry in entries:
            key = (entry.resource_type, entry.path)
            if key in index:
                message = f"duplicate override for {entry.resource_type} {entry.path}"
                raise OverrideFileError(message)
            index[key] = entry
        self._index = index

    @property
    def entries(self) -> tuple[Override, ...]:
        return tuple(self._index.values())

    def suppresses(self, resource_type: str, path: str, rule: ScanRule) -> bool:
        """True when a finding of ``rule`` at ``path`` is a reviewed false positive."""
        if rule is ScanRule.FINGERPRINT_MARKER:
            return False
        for resource in (resource_type, "*"):
            entry = self._index.get((resource, path))
            if entry is not None and (entry.rules is None or rule in entry.rules):
                return True
        return False


NO_OVERRIDES = Overrides()

_ENTRY_KEYS = frozenset({"resource_type", "path", "rules", "reason"})


def _text_field(position: int, entry: Mapping[object, object], name: str) -> str:
    value = entry.get(name)
    if not isinstance(value, str) or not value.strip():
        raise OverrideFileError(f"override {position}: {name} must be non-empty text")
    return value.strip()


def _parse_rules(position: int, value: object) -> frozenset[ScanRule] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value:
        raise OverrideFileError(f"override {position}: rules must be a non-empty list")
    rules: set[ScanRule] = set()
    for name in value:
        try:
            rule = ScanRule(name)
        except ValueError:
            raise OverrideFileError(f"override {position}: unknown rule {name!r}") from None
        if rule is ScanRule.FINGERPRINT_MARKER:
            message = f"override {position}: the {rule.value} rule cannot be overridden"
            raise OverrideFileError(message)
        rules.add(rule)
    return frozenset(rules)


def _parse_entry(position: int, entry: object) -> Override:
    if not isinstance(entry, Mapping):
        raise OverrideFileError(f"override {position} must be a mapping")
    unknown = sorted(str(key) for key in entry if key not in _ENTRY_KEYS)
    if unknown:
        raise OverrideFileError(f"override {position}: unknown keys {', '.join(unknown)}")
    return Override(
        resource_type=_text_field(position, entry, "resource_type"),
        path=_text_field(position, entry, "path"),
        reason=_text_field(position, entry, "reason"),
        rules=_parse_rules(position, entry.get("rules")),
    )


def parse_overrides(text: str) -> Overrides:
    """Read the text of an overrides file; anything unexpected raises OverrideFileError."""
    try:
        document: object = yaml.safe_load(text)
    except yaml.YAMLError:
        raise OverrideFileError("the overrides file is not valid YAML") from None
    if not isinstance(document, Mapping) or document.get("version") != OVERRIDES_VERSION:
        message = f"the overrides file must be a mapping with version {OVERRIDES_VERSION}"
        raise OverrideFileError(message)
    unknown = sorted(str(key) for key in document if key not in ("version", "overrides"))
    if unknown:
        raise OverrideFileError(f"the overrides file has unknown keys {', '.join(unknown)}")
    entries = document.get("overrides")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise OverrideFileError("overrides must be a list")
    parsed = [_parse_entry(position, entry) for position, entry in enumerate(entries, start=1)]
    return Overrides(parsed)


def load_overrides(path: Path | None = None) -> Overrides:
    """Load the overrides file at ``path``, or the one that ships with the package."""
    try:
        if path is None:
            packaged = resources.files("driftsniff.rules").joinpath(OVERRIDES_FILE_NAME)
            text = packaged.read_text(encoding="utf-8")
        else:
            text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise OverrideFileError(f"cannot read the overrides file: {error.strerror}") from None
    return parse_overrides(text)
