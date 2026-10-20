"""Tests for core/states.py: states are stored once, compressed, addressed by their SHA-256."""

from hashlib import sha256

import pytest
import sqlalchemy as sa
import zstandard

from driftsniff.core import states
from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.states import (
    StateCorruptError,
    StateMissingError,
    StoredDataError,
    compress_bytes,
    decompress_bytes,
    get_state,
    put_state,
)
from driftsniff.db import tables
from driftsniff.db.engine import Database

STATE: dict[str, JsonValue] = {
    "_id": "n-1",
    "name": "Lab LAN",
    "vlan": 20,
    "dns": ["192.0.2.53", "192.0.2.54"],
}


def state_rows(database: Database) -> list[tuple[str, bytes, int, int]]:
    """Every stored row as (state_hash, body_zstd, normaliser_version, size_bytes)."""
    with database.read() as connection:
        rows = connection.execute(
            sa.select(
                tables.object_states.c.state_hash,
                tables.object_states.c.body_zstd,
                tables.object_states.c.normaliser_version,
                tables.object_states.c.size_bytes,
            )
        ).all()
    return [(row[0], row[1], row[2], row[3]) for row in rows]


def test_the_address_is_the_sha256_of_the_canonical_json(store: Database) -> None:
    with store.write() as connection:
        written = put_state(connection, STATE)
    assert written.state_hash == sha256(canonical_dumps(STATE)).hexdigest()
    assert written.is_new is True
    assert written.stored_bytes > 0


def test_the_body_is_zstd_compressed_canonical_json(store: Database) -> None:
    with store.write() as connection:
        put_state(connection, STATE)
    ((state_hash, body_zstd, version, size_bytes),) = state_rows(store)
    body = zstandard.ZstdDecompressor().decompress(body_zstd)
    assert body == canonical_dumps(STATE)
    assert size_bytes == len(body)
    assert version == 1
    assert state_hash == sha256(body).hexdigest()


def test_a_state_is_stored_once(store: Database) -> None:
    with store.write() as connection:
        first = put_state(connection, STATE)
        second = put_state(connection, dict(reversed(list(STATE.items()))))
    assert second.state_hash == first.state_hash
    assert second.is_new is False
    assert second.stored_bytes == 0
    assert len(state_rows(store)) == 1


def test_different_content_gets_a_different_address(store: Database) -> None:
    with store.write() as connection:
        first = put_state(connection, STATE)
        second = put_state(connection, {**STATE, "vlan": 21})
    assert first.state_hash != second.state_hash
    assert len(state_rows(store)) == 2


def test_the_normaliser_version_is_recorded(store: Database) -> None:
    with store.write() as connection:
        put_state(connection, STATE, normaliser_version=7)
    assert state_rows(store)[0][2] == 7


def test_get_state_returns_what_was_put(store: Database) -> None:
    nested: dict[str, JsonValue] = {
        "a": {"b": [1, 2, {"c": "é"}]},
        "n": 12345678901234567890,
        "e": [],
    }
    with store.write() as connection:
        written = put_state(connection, nested)
    with store.read() as connection:
        assert get_state(connection, written.state_hash) == nested


def test_a_missing_state_is_reported(store: Database) -> None:
    with store.read() as connection, pytest.raises(StateMissingError, match="is not stored"):
        get_state(connection, "0" * 64)


def test_a_state_that_no_longer_matches_its_address_is_refused(store: Database) -> None:
    with store.write() as connection:
        written = put_state(connection, STATE)
        connection.execute(
            sa.update(tables.object_states).values(body_zstd=compress_bytes(b'{"x":1}'))
        )
    with store.read() as connection, pytest.raises(StateCorruptError, match="does not match"):
        get_state(connection, written.state_hash)


def test_bytes_that_are_not_zstd_are_refused(store: Database) -> None:
    with store.write() as connection:
        written = put_state(connection, STATE)
        connection.execute(sa.update(tables.object_states).values(body_zstd=b"not a zstd frame"))
    with store.read() as connection, pytest.raises(StateCorruptError, match="valid zstd"):
        get_state(connection, written.state_hash)


def test_a_state_that_is_not_a_json_object_is_refused(store: Database) -> None:
    body = b"[1,2]"
    with store.write() as connection:
        connection.execute(
            sa.insert(tables.object_states).values(
                state_hash=sha256(body).hexdigest(),
                body_zstd=compress_bytes(body),
                normaliser_version=1,
                size_bytes=len(body),
            )
        )
    with store.read() as connection, pytest.raises(StateCorruptError, match="not a JSON object"):
        get_state(connection, sha256(body).hexdigest())


def test_an_oversized_state_is_refused_on_write(
    store: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(states, "MAX_STATE_BYTES", 10)
    with store.write() as connection, pytest.raises(ValueError, match="larger than"):
        put_state(connection, {"key": "x" * 50})
    assert state_rows(store) == []


def test_an_oversized_state_is_refused_on_read(
    store: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    with store.write() as connection:
        written = put_state(connection, {"key": "x" * 50})
    monkeypatch.setattr(states, "MAX_STATE_BYTES", 10)
    with store.read() as connection, pytest.raises(StateCorruptError, match="larger than"):
        get_state(connection, written.state_hash)


def test_compression_round_trips_and_shrinks_repetitive_data() -> None:
    body = canonical_dumps({"rules": [{"action": "accept", "port": 443}] * 200})
    packed = compress_bytes(body)
    assert states.ZSTD_LEVEL == 3
    assert len(packed) < len(body) // 4
    assert decompress_bytes(packed, len(body)) == body


def test_decompression_stops_at_the_limit() -> None:
    packed = compress_bytes(b"a" * 100_000)
    assert len(decompress_bytes(packed, 100_000)) == 100_000
    with pytest.raises(StoredDataError, match="larger than the limit of 99999"):
        decompress_bytes(packed, 99_999)


def test_decompression_refuses_garbage() -> None:
    with pytest.raises(StoredDataError, match="valid zstd"):
        decompress_bytes(b"definitely not zstd", 1000)
