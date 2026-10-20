"""Secret fingerprints: keyed hashes that show a secret changed without storing it.

A fingerprint is HMAC-SHA-256 over these bytes, in this order:

    driftsniff-fp-v1 "/" <resource type> "/" <normalised field path> NUL <canonical JSON of value>

keyed with the fingerprint key derived from the master key. The first 128 bits are kept and
written as 32 hex characters, together with the id of the key that made them. The interface
shows only the first 8 to 12 characters. Two equal secrets in different fields, or in different
resource types, never share a fingerprint (domain separation); the same secret in the same field
always does, for as long as the master key stays the same.

The value is written as canonical JSON (:mod:`driftsniff.core.canonical`), not as raw text, so
the string "1", the number 1 and the boolean true are three different values.

Stored form: a fingerprint inside a stored object is the text ``fp1:<key id>:<32 hex>``.
:func:`contains_fingerprint` finds it in canonical bytes; the storage layer uses it to set the
``fp_in_use`` flag in the same transaction that stores the first fingerprint.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Self

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.secrets.keys import FINGERPRINT_LABEL, KEY_BYTES, MasterKey

FP_CONTEXT = b"driftsniff-fp-v1"
FP_HEX_CHARS = 32
MARKER_PREFIX = "fp1:"
MARKER_PATTERN = r"fp1:[0-9a-f]{8}:[0-9a-f]{32}"
DISPLAY_MIN_CHARS = 8
DISPLAY_MAX_CHARS = 12

_PARSE = re.compile(r"fp1:([0-9a-f]{8}):([0-9a-f]{32})")
_IN_CANONICAL_JSON = re.compile(rb'"fp1:[0-9a-f]{8}:[0-9a-f]{32}"')
_KEY_ID = re.compile(r"[0-9a-f]{8}")


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """One fingerprint and the id of the master key that made it."""

    key_id: str
    digest: str

    def marker(self) -> str:
        """The stored form, ``fp1:<key id>:<digest>``."""
        return f"{MARKER_PREFIX}{self.key_id}:{self.digest}"

    def short(self, chars: int = DISPLAY_MIN_CHARS) -> str:
        """The first ``chars`` characters of the digest, for display (8 to 12)."""
        if not DISPLAY_MIN_CHARS <= chars <= DISPLAY_MAX_CHARS:
            raise ValueError("a displayed fingerprint has 8 to 12 characters")
        return self.digest[:chars]

    def same_as(self, other: Self) -> bool:
        """Equal key id and equal digest; the digests are compared in constant time."""
        left = self.digest.encode("ascii")
        right = other.digest.encode("ascii")
        return hmac.compare_digest(left, right) and self.key_id == other.key_id

    @classmethod
    def parse(cls, text: str) -> Self | None:
        """Read the stored form; anything that is not exactly that form gives None."""
        match = _PARSE.fullmatch(text)
        if match is None:
            return None
        return cls(key_id=match.group(1), digest=match.group(2))


def contains_fingerprint(body: bytes) -> bool:
    """True when canonical JSON bytes hold a stored fingerprint as a string value or key."""
    return _IN_CANONICAL_JSON.search(body) is not None


def _check_text(name: str, text: str, *, allow_slash: bool) -> None:
    if not text or "\x00" in text or (not allow_slash and "/" in text):
        forbidden = "NUL" if allow_slash else "NUL or a slash"
        raise ValueError(f"{name} must be non-empty and must not contain {forbidden}")


class Fingerprinter:
    """Makes and checks fingerprints with one fingerprint key; the repr never shows the key."""

    __slots__ = ("_key", "key_id")

    def __init__(self, key: bytes, key_id: str) -> None:
        if len(key) != KEY_BYTES:
            raise ValueError(f"a fingerprint key must hold exactly {KEY_BYTES} bytes")
        if _KEY_ID.fullmatch(key_id) is None:
            raise ValueError("a key id is 8 lowercase hex characters")
        self._key = key
        self.key_id = key_id

    @classmethod
    def from_master(cls, master: MasterKey) -> Self:
        """Use the fingerprint key derived from ``master``."""
        return cls(master.derive(FINGERPRINT_LABEL), master.key_id)

    def fingerprint(self, resource_type: str, path: str, value: JsonValue) -> Fingerprint:
        """Fingerprint ``value`` of the field at ``path`` of a ``resource_type`` object."""
        _check_text("a resource type", resource_type, allow_slash=False)
        _check_text("a field path", path, allow_slash=True)
        label = FP_CONTEXT + b"/" + resource_type.encode("utf-8") + b"/" + path.encode("utf-8")
        message = label + b"\x00" + canonical_dumps(value)
        digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()[:FP_HEX_CHARS]
        return Fingerprint(self.key_id, digest)

    def matches(
        self, fingerprint: Fingerprint, resource_type: str, path: str, value: JsonValue
    ) -> bool:
        """True when ``fingerprint`` was made from ``value`` with this key."""
        if fingerprint.key_id != self.key_id:
            return False
        return fingerprint.same_as(self.fingerprint(resource_type, path, value))

    def __repr__(self) -> str:
        return f"Fingerprinter(key_id={self.key_id!r})"
