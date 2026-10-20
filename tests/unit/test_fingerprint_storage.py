"""The fp_in_use flag is set in the transaction that stores the first fingerprint."""

from pathlib import Path

import pytest
import sqlalchemy as sa

from driftsniff.core.canonical import JsonValue
from driftsniff.core.normalize import FieldClass, StaticTypeTable, normalize_object
from driftsniff.core.states import get_state, put_state
from driftsniff.db import tables
from driftsniff.db.engine import Database
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import (
    FP_IN_USE_SETTING,
    MasterKeyMissingError,
    ensure_master_key,
    fingerprints_in_use,
)
from driftsniff.secrets.redact import redact_object

TABLE = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "psk": FieldClass.SECRET,
    },
)
FINGERPRINTER = Fingerprinter(bytes(range(32)), "0a1b2c3d")


def stored_object(psk: str) -> dict[str, JsonValue]:
    """What a collector stores for one WiFi network: redacted, then normalised."""
    raw: dict[str, JsonValue] = {"_id": "w1", "name": "Guest", "psk": psk}
    return normalize_object(TABLE, redact_object(TABLE, "unifi-wlan", raw, FINGERPRINTER).value)


def flag_rows(connection: sa.Connection) -> list[str]:
    rows = connection.execute(
        sa.select(tables.settings.c.value).where(tables.settings.c.key == FP_IN_USE_SETTING)
    ).all()
    return [row[0] for row in rows]


def test_a_state_without_a_fingerprint_does_not_set_the_flag(store: Database) -> None:
    with store.write() as connection:
        put_state(connection, {"_id": "n1", "name": "Lab LAN", "vlan": 20})
    assert fingerprints_in_use(store) is False


def test_a_state_that_only_mentions_a_fingerprint_does_not_set_the_flag(store: Database) -> None:
    with store.write() as connection:
        put_state(connection, {"_id": "n1", "note": "see fp1:0a1b2c3d:aaaa in the docs"})
    assert fingerprints_in_use(store) is False


def test_the_first_stored_fingerprint_sets_the_flag(store: Database) -> None:
    state = stored_object("CANARY-psk-0001")
    with store.write() as connection:
        written = put_state(connection, state)
    assert fingerprints_in_use(store) is True
    with store.read() as connection:
        assert get_state(connection, written.state_hash) == state


def test_the_flag_is_set_before_the_state_is_inserted(store: Database) -> None:
    with store.write() as connection:
        assert flag_rows(connection) == []
        put_state(connection, stored_object("CANARY-psk-0001"))
        assert flag_rows(connection) == ["1"]


def test_the_flag_and_the_state_commit_or_roll_back_together(store: Database) -> None:
    with pytest.raises(RuntimeError, match="rollback"):
        with store.write() as connection:
            put_state(connection, stored_object("CANARY-psk-0001"))
            raise RuntimeError("rollback")
    assert fingerprints_in_use(store) is False
    with store.read() as connection:
        count = connection.execute(sa.select(sa.func.count()).select_from(tables.object_states))
        assert count.scalar_one() == 0


def test_a_second_fingerprint_keeps_one_flag_row(store: Database) -> None:
    with store.write() as connection:
        put_state(connection, stored_object("CANARY-psk-0001"))
    with store.write() as connection:
        put_state(connection, stored_object("CANARY-psk-0002"))
        assert flag_rows(connection) == ["1"]


def test_a_missing_key_is_refused_once_a_fingerprint_is_stored(store: Database, tmp_path: Path) -> None:
    path = tmp_path / "keys" / "master.key"
    with store.write() as connection:
        put_state(connection, stored_object("CANARY-psk-0001"))
    with pytest.raises(MasterKeyMissingError, match="never creates a replacement"):
        ensure_master_key(path, fingerprints_exist=fingerprints_in_use(store))
    assert not path.exists()
