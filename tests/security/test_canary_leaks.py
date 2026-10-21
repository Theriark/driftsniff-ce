"""Canary leak tests (P3-T4): no canary on any surface, and proof that the harness can fail."""

import base64
import logging
import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
import sqlalchemy as sa

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.normalize import FieldClass, StaticTypeTable
from driftsniff.core.snapshots import resolve_current_state
from driftsniff.core.states import put_state
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.secrets.crypto import MAX_CREDENTIAL_BYTES, CredentialCipher
from driftsniff.secrets.fingerprint import MARKER_PREFIX, Fingerprinter
from driftsniff.secrets.keys import MasterKey
from driftsniff.secrets.redact import RedactionResult, redact_object
from driftsniff.secrets.scanner import ENTROPY_THRESHOLD, NO_OVERRIDES, Overrides, shannon_entropy

from . import canary as harness
from .canary import (
    CANARY_PREFIX,
    SERVER,
    SURFACE_LOGS,
    SURFACE_OUTPUT,
    SURFACE_ROWS,
    WLAN,
    WLAN_TYPE,
    CanaryFactory,
    CanaryLeakError,
    CanaryScanner,
    FakeSource,
    Leak,
    assert_no_leaks,
    capture_logs,
    collect,
    insert_source,
    raised_by,
    scan_database,
    scan_database_files,
    scan_error,
    scan_logs,
)

SOURCE_ID = 1
CANARY_FORMAT = re.compile(r"CANARY-[0-9a-f]{24}")


@dataclass
class World:
    """A migrated database with one source whose credential and push key are canaries."""

    database: Database
    factory: CanaryFactory
    master: MasterKey
    fingerprinter: Fingerprinter
    cipher: CredentialCipher

    def scanner(self) -> CanaryScanner:
        """A scanner for every canary issued so far; build it after the last one is issued."""
        return CanaryScanner(self.factory.issued)


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    database = Database(database_path(tmp_path))
    try:
        upgrade_to_head(database)
        factory = CanaryFactory()
        master = MasterKey(os.urandom(32))
        cipher = CredentialCipher.from_master(master)
        insert_source(database, factory, cipher, SOURCE_ID)
        yield World(database, factory, master, Fingerprinter.from_master(master), cipher)
    finally:
        database.close()


def dig(state: Mapping[str, JsonValue], path: str) -> JsonValue:
    """The value at a dot separated path of a stored state."""
    value: JsonValue = state
    for part in path.split("."):
        assert isinstance(value, Mapping)
        value = value[part]
    return value


def provoke_errors(world: World) -> dict[str, BaseException]:
    """Raise the errors that the secret handling code raises, with canaries in their input."""
    factory = world.factory
    cipher = world.cipher
    sealed = cipher.encrypt(SOURCE_ID, factory.new("error test credential").value.encode())
    mapping_with_bad_key = cast("dict[str, JsonValue]", {1: factory.new("non-text key").value})
    not_a_mapping = cast("dict[str, JsonValue]", [factory.new("not a mapping").value])
    not_json = cast("JsonValue", object())
    nan = float("nan")
    oversize = factory.new("oversize credential").value.encode() + bytes(MAX_CREDENTIAL_BYTES)
    secret = factory.new("fingerprint input").value
    damaged = base64.b64encode(os.urandom(64)).decode()
    return {
        "decrypt with another key id": raised_by(
            lambda: cipher.decrypt(SOURCE_ID, sealed.ciphertext, "00000000")
        ),
        "decrypt for another source": raised_by(
            lambda: cipher.decrypt(SOURCE_ID + 1, sealed.ciphertext, sealed.key_id)
        ),
        "decrypt data that was damaged": raised_by(
            lambda: cipher.decrypt(SOURCE_ID, damaged, cipher.key_id)
        ),
        "encrypt an oversize credential": raised_by(lambda: cipher.encrypt(SOURCE_ID, oversize)),
        "redact an object with a non-text key": raised_by(
            lambda: redact_object(WLAN_TYPE, WLAN, mapping_with_bad_key, world.fingerprinter)
        ),
        "redact something that is not an object": raised_by(
            lambda: redact_object(WLAN_TYPE, WLAN, not_a_mapping, world.fingerprinter)
        ),
        "fingerprint with a bad path": raised_by(
            lambda: world.fingerprinter.fingerprint(WLAN, "a\x00b", secret)
        ),
        "canonical JSON of a value that is not JSON": raised_by(
            lambda: canonical_dumps({"secret": secret, "other": not_json})
        ),
        "canonical JSON of a NaN number": raised_by(
            lambda: canonical_dumps({"secret": secret, "other": nan})
        ),
    }


def test_canaries_are_unique_and_shaped_as_documented() -> None:
    factory = CanaryFactory()
    issued = [factory.new(f"place {number}") for number in range(500)]
    assert len({canary.value for canary in issued}) == 500
    assert all(CANARY_FORMAT.fullmatch(canary.value) for canary in issued)
    assert all(canary.value.startswith(CANARY_PREFIX) for canary in issued)
    assert all(shannon_entropy(canary.value) < ENTROPY_THRESHOLD for canary in issued)


def test_secret_and_free_text_fields_are_stored_as_fingerprints(world: World) -> None:
    source = FakeSource(world.factory)
    report = collect(
        world.database, world.fingerprinter, source.raw_objects(0), source_id=SOURCE_ID, second=0
    )
    injected = sorted(path for _resource, _key, path in source.free_text_locations)
    assert sorted(forced.path for forced in report.forced) == injected
    assert report.fingerprints > len(report.forced)
    with world.database.read() as connection:
        state = resolve_current_state(connection, SOURCE_ID)
    assert state is not None
    wlan = state[WLAN]["w0"]
    for path in (
        "x_passphrase",
        "radius_secret",
        "api_tokens",
        "options.shared_key",
        "description",
        "comment",
        "options.owner_note",
        "options.vendor.hint",
    ):
        assert str(dig(wlan, path)).startswith(MARKER_PREFIX), path
    notes = dig(wlan, "notes")
    assert isinstance(notes, list)
    assert str(notes[0]).startswith(MARKER_PREFIX)
    assert notes[1] == "revision 0"
    assert str(dig(state[SERVER]["s0"], "address")).startswith(MARKER_PREFIX)
    # What is configuration stays readable: the harness is not hiding everything.
    assert dig(wlan, "name") == "Lab 0"
    assert dig(wlan, "vlan") == 100
    assert dig(wlan, "enabled") is True


def test_a_full_collection_leaves_no_canary_on_any_surface(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    with capture_logs() as logs:
        first = collect(
            world.database,
            world.fingerprinter,
            FakeSource(world.factory).raw_objects(0),
            source_id=SOURCE_ID,
            second=0,
        )
        second = collect(
            world.database,
            world.fingerprinter,
            FakeSource(world.factory).raw_objects(1),
            source_id=SOURCE_ID,
            second=10,
        )
    assert first.result.snapshot.stored
    assert second.result.snapshot.stored
    assert logs.lines, "the collection logged nothing, so the log surface was not exercised"
    errors = provoke_errors(world)
    output = capsys.readouterr()
    scanner = world.scanner()

    leaks = scan_database(scanner, world.database)
    leaks += scan_logs(scanner, logs)
    for name, error in errors.items():
        leaks += scan_error(scanner, name, error)
    leaks += scanner.find(SURFACE_OUTPUT, "standard output", output.out)
    leaks += scanner.find(SURFACE_OUTPUT, "standard error", output.err)
    assert_no_leaks(leaks)

    # Closing the database checkpoints the write-ahead log into the main file; look again.
    world.database.close()
    assert_no_leaks(scan_database_files(scanner, world.database))


def test_the_source_credential_is_encrypted_and_the_push_key_is_hashed(world: World) -> None:
    with world.database.read() as connection:
        row = connection.execute(sa.select(tables.sources)).one()
    assert row.credential_ciphertext
    assert re.fullmatch(r"[0-9a-f]{64}", row.push_token_hash)
    credential = world.cipher.decrypt(SOURCE_ID, row.credential_ciphertext, row.key_id)
    assert credential.decode().startswith(CANARY_PREFIX)
    assert_no_leaks(scan_database(world.scanner(), world.database))


def test_the_harness_fails_when_a_canary_is_logged(world: World) -> None:
    secret = world.factory.new("deliberately logged value")
    with capture_logs() as logs:
        logging.getLogger("driftsniff.test").warning("sync failed, password %s", secret.value)
    leaks = scan_logs(world.scanner(), logs)
    assert [leak.surface for leak in leaks] == [SURFACE_LOGS]
    with pytest.raises(CanaryLeakError, match="deliberately logged value"):
        assert_no_leaks(leaks)


def test_the_harness_fails_when_a_canary_is_logged_in_an_extra_field(world: World) -> None:
    secret = world.factory.new("value in a log extra")
    with capture_logs() as logs:
        logging.getLogger("driftsniff.test").warning("sync failed", extra={"detail": secret.value})
    assert [leak.where for leak in scan_logs(world.scanner(), logs)] == ["value in a log extra"]


def test_the_log_filter_still_scrubs_a_credential_shaped_canary(world: World) -> None:
    secret = world.factory.new("password in a URL")
    with capture_logs() as logs:
        logging.getLogger("driftsniff.test").warning(
            "connecting to https://svc:%s@controller.example.invalid/", secret.value
        )
    assert logs.lines
    assert_no_leaks(scan_logs(world.scanner(), logs))


def test_the_harness_fails_when_a_canary_is_in_an_error_message(world: World) -> None:
    secret = world.factory.new("value in an error message")
    error = raised_by(lambda: _fail_with(secret.value))
    leaks = scan_error(world.scanner(), "a test call", error)
    assert [leak.where for leak in leaks] == ["value in an error message"]


def _fail_with(value: str) -> None:
    try:
        raise KeyError("inner")
    except KeyError as inner:
        raise ValueError(f"cannot use {value}") from inner


def test_the_harness_looks_into_the_chained_cause_of_an_error(world: World) -> None:
    secret = world.factory.new("value in the cause of an error")

    def outer() -> None:
        try:
            raise ValueError(f"inner {secret.value}")
        except ValueError as inner:
            raise RuntimeError("collection failed") from inner

    leaks = scan_error(world.scanner(), "a chained call", raised_by(outer))
    assert [leak.where for leak in leaks] == ["value in the cause of an error"]


def test_the_harness_finds_a_canary_in_a_plain_text_column(world: World) -> None:
    secret = world.factory.new("plain text column")
    with world.database.write() as connection:
        connection.execute(
            sa.insert(tables.settings).values(
                workspace_id=tables.DEFAULT_WORKSPACE_ID, key="note", value=secret.value
            )
        )
    scanner = world.scanner()
    leaks = scan_database(scanner, world.database)
    rows = [leak for leak in leaks if leak.surface == SURFACE_ROWS]
    assert len(rows) == 1
    assert rows[0].location.startswith("settings.value row ")
    assert rows[0].location.endswith("(text)")
    assert scan_database_files(scanner, world.database), "the file bytes show it too"


def test_the_harness_finds_a_canary_inside_a_compressed_state(world: World) -> None:
    secret = world.factory.new("compressed state")
    with world.database.write() as connection:
        put_state(connection, {"_id": "x1", "leaked": secret.value})
    leaks = scan_database(world.scanner(), world.database)
    assert any(
        leak.location.startswith("object_states.body_zstd") and "(decompressed)" in leak.location
        for leak in leaks
    )


def test_the_harness_finds_a_base64_encoded_canary(world: World) -> None:
    secret = world.factory.new("base64 text column")
    encoded = base64.b64encode(secret.value.encode()).decode()
    with world.database.write() as connection:
        connection.execute(
            sa.insert(tables.settings).values(
                workspace_id=tables.DEFAULT_WORKSPACE_ID, key="blob", value=encoded
            )
        )
    leaks = scan_database_rows_only(world)
    assert len(leaks) == 1
    assert leaks[0].location.startswith("settings.value row ")
    assert leaks[0].location.endswith("(text) (base64 decoded)")


def scan_database_rows_only(world: World) -> list[Leak]:
    return harness.scan_database_rows(world.scanner(), world.database)


def test_the_harness_fails_when_redaction_is_bypassed(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def passthrough(
        table: StaticTypeTable,
        resource_type: str,
        raw: Mapping[str, JsonValue],
        fingerprinter: Fingerprinter,
        overrides: Overrides = NO_OVERRIDES,
    ) -> RedactionResult:
        return RedactionResult(dict(raw), 0, ())

    monkeypatch.setattr(harness, "redact_object", passthrough)
    collect(
        world.database,
        world.fingerprinter,
        FakeSource(world.factory).raw_objects(0),
        source_id=SOURCE_ID,
        second=0,
    )
    leaks = scan_database(world.scanner(), world.database)
    where = {leak.where for leak in leaks}
    assert "unifi-wlan/w0/x_passphrase (secret)" in where
    assert "xo-server/s1/address (free text)" in where
    with pytest.raises(CanaryLeakError):
        assert_no_leaks(leaks)


def test_a_plain_canary_in_a_configuration_text_field_is_not_redacted(world: World) -> None:
    """The documented limit: free text is configuration unless it looks like a credential."""
    table = StaticTypeTable(
        object_key_field="_id",
        name_field="name",
        field_classes={"_id": FieldClass.CONFIG, "description": FieldClass.CONFIG},
    )
    plain = world.factory.new("plain sentence in a description")
    raw: dict[str, JsonValue] = {"_id": "d1", "description": f"office switch {plain.value}"}
    redacted = redact_object(table, WLAN, raw, world.fingerprinter)
    assert redacted.forced == ()
    assert redacted.value["description"] == raw["description"]


def test_scanning_a_clean_database_finds_nothing(world: World) -> None:
    assert scan_database(CanaryScanner([]), world.database) == []
    assert_no_leaks([])


def test_a_leak_report_names_the_place_and_never_the_value() -> None:
    factory = CanaryFactory()
    secret = factory.new("some place")
    leak = CanaryScanner(factory.issued).find(SURFACE_LOGS, "log line 3", f"x {secret.value} y")
    with pytest.raises(CanaryLeakError) as caught:
        assert_no_leaks(leak)
    assert "log line 3" in str(caught.value)
    assert "some place" in str(caught.value)
    assert secret.value not in str(caught.value)
    assert secret.hex_part not in str(caught.value)
