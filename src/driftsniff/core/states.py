"""Object states: normalised objects stored once, compressed, addressed by their SHA-256.

A state is the canonical JSON of one normalised object (:mod:`driftsniff.core.canonical`).
Its address is the SHA-256 of those bytes, so two objects with equal content, in one source or
in many, are stored once. The bytes are compressed with zstd level 3.

All writes go through ``Database.write()``, which holds the single writer lock, so the
"already stored?" check and the insert cannot interleave with another writer.

A state that holds a secret fingerprint sets the ``fp_in_use`` flag in the same transaction,
before it is inserted: the key file must never be replaceable while a fingerprint exists.
"""

import io
import json
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

import sqlalchemy as sa
import zstandard
from sqlalchemy import Connection

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.normalize import NORMALISER_VERSION
from driftsniff.db.tables import object_states
from driftsniff.secrets.fingerprint import contains_fingerprint
from driftsniff.secrets.keys import mark_fingerprints_in_use_in

ZSTD_LEVEL = 3
MAX_STATE_BYTES = 32 * 1024 * 1024
_READ_CHUNK = 64 * 1024


class StoredDataError(Exception):
    """Stored data is missing, damaged or does not match its address."""


class StateMissingError(StoredDataError):
    """A state that a manifest refers to is not in the database."""


class StateCorruptError(StoredDataError):
    """A stored state does not decompress, or does not hash to its own address."""


@dataclass(frozen=True)
class StateWrite:
    """What ``put_state`` did."""

    state_hash: str
    is_new: bool
    # Compressed bytes added to the database; 0 when the state was already stored.
    stored_bytes: int


def compress_bytes(body: bytes) -> bytes:
    """Compress ``body`` with zstd level 3."""
    return zstandard.ZstdCompressor(level=ZSTD_LEVEL).compress(body)


def decompress_bytes(data: bytes, limit: int) -> bytes:
    """Decompress a zstd frame, refusing to produce more than ``limit`` bytes.

    A damaged or hostile frame can announce a huge size, so the output is read in chunks and
    the limit is checked as it grows.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
            while chunk := reader.read(_READ_CHUNK):
                total += len(chunk)
                if total > limit:
                    raise StoredDataError(f"stored data is larger than the limit of {limit} bytes")
                chunks.append(chunk)
    except zstandard.ZstdError as error:
        raise StoredDataError("stored data is not a valid zstd frame") from error
    return b"".join(chunks)


def canonical_state(state: Mapping[str, JsonValue]) -> tuple[str, bytes]:
    """Return the address and the canonical bytes of a normalised object."""
    body = canonical_dumps(state)
    if len(body) > MAX_STATE_BYTES:
        raise ValueError(f"an object state is larger than {MAX_STATE_BYTES} bytes")
    return sha256(body).hexdigest(), body


def put_canonical_state(
    connection: Connection,
    state_hash: str,
    body: bytes,
    *,
    normaliser_version: int = NORMALISER_VERSION,
) -> StateWrite:
    """Store canonical state bytes under their address unless they are already stored.

    When the state holds a secret fingerprint, the ``fp_in_use`` flag is set first, in the
    same transaction as the insert.
    """
    exists = connection.execute(
        sa.select(object_states.c.state_hash).where(object_states.c.state_hash == state_hash)
    ).first()
    if exists is not None:
        return StateWrite(state_hash, is_new=False, stored_bytes=0)
    if contains_fingerprint(body):
        mark_fingerprints_in_use_in(connection)
    compressed = compress_bytes(body)
    connection.execute(
        sa.insert(object_states).values(
            state_hash=state_hash,
            body_zstd=compressed,
            normaliser_version=normaliser_version,
            size_bytes=len(body),
        )
    )
    return StateWrite(state_hash, is_new=True, stored_bytes=len(compressed))


def put_state(
    connection: Connection,
    state: Mapping[str, JsonValue],
    *,
    normaliser_version: int = NORMALISER_VERSION,
) -> StateWrite:
    """Store a normalised object once, addressed by the SHA-256 of its canonical JSON."""
    state_hash, body = canonical_state(state)
    return put_canonical_state(connection, state_hash, body, normaliser_version=normaliser_version)


def get_state(connection: Connection, state_hash: str) -> dict[str, JsonValue]:
    """Return the stored object, after checking that it still hashes to its address."""
    stored = connection.execute(
        sa.select(object_states.c.body_zstd).where(object_states.c.state_hash == state_hash)
    ).scalar_one_or_none()
    if stored is None:
        raise StateMissingError(f"state {state_hash} is not stored")
    try:
        body = decompress_bytes(stored, MAX_STATE_BYTES)
    except StoredDataError as error:
        raise StateCorruptError(f"state {state_hash}: {error}") from error
    if sha256(body).hexdigest() != state_hash:
        raise StateCorruptError(f"state {state_hash} does not match its address")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise StateCorruptError(f"state {state_hash} is not a JSON object")
    return value
