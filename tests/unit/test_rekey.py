"""Rekey: fingerprint verdicts across a key change, the cycle state and credential re-encryption."""

import pytest
import sqlalchemy as sa

from driftsniff.db.engine import Database
from driftsniff.db.tables import DEFAULT_WORKSPACE_ID, audit_events, settings, sources
from driftsniff.secrets.crypto import CredentialCipher, CredentialDecryptError
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import KEY_BYTES, MasterKey
from driftsniff.secrets.rekey import (
    EVENT_BASELINE,
    EVENT_REKEY,
    MODE_OLD_KEY,
    MODE_OLD_KEY_LOST,
    REKEY_SETTING,
    STATUS_COMPLETE,
    RekeyError,
    RekeyInProgressError,
    RekeyState,
    Verdict,
    begin_rekey,
    check_fingerprint,
    load_rekey_state,
    record_clean_cycle,
    rekey_credentials,
    run_rekey,
)

OLD = MasterKey(bytes(range(KEY_BYTES)))
NEW = MasterKey(bytes(reversed(range(KEY_BYTES))))
OLD_FP = Fingerprinter.from_master(OLD)
NEW_FP = Fingerprinter.from_master(NEW)
CANARY = "CANARY-secret-0001"
AT = "2026-10-21T10:00:00Z"
LATER = "2026-10-21T10:05:00Z"
TYPE = "firewall_rule"
PATH = "psk"


def add_source(database: Database, source_id: int, *, enabled: bool = True) -> None:
    with database.write() as connection:
        connection.execute(
            sa.insert(sources).values(
                id=source_id, name=f"source-{source_id}", type="push", enabled=enabled
            )
        )


def set_credential(database: Database, source_id: int, master: MasterKey, plain: str) -> None:
    sealed = CredentialCipher.from_master(master).encrypt(source_id, plain.encode())
    with database.write() as connection:
        connection.execute(
            sa.update(sources)
            .where(sources.c.id == source_id)
            .values(credential_ciphertext=sealed.ciphertext, key_id=sealed.key_id)
        )


def stored_credential(database: Database, source_id: int) -> tuple[str, str]:
    with database.read() as connection:
        row = connection.execute(
            sa.select(sources.c.credential_ciphertext, sources.c.key_id).where(
                sources.c.id == source_id
            )
        ).one()
    return str(row[0]), str(row[1])


def audit_actions(database: Database) -> list[str]:
    with database.read() as connection:
        rows = connection.execute(sa.select(audit_events.c.action).order_by(audit_events.c.id))
        return [str(action) for action in rows.scalars()]


def state_of(database: Database) -> RekeyState:
    with database.read() as connection:
        state = load_rekey_state(connection)
    assert state is not None
    return state


# --- fingerprint verdicts -------------------------------------------------------------------


def test_an_unchanged_secret_under_the_current_key_is_unchanged() -> None:
    stored = NEW_FP.fingerprint(TYPE, PATH, CANARY)
    check = check_fingerprint(stored, NEW_FP, None, TYPE, PATH, CANARY)
    assert check.verdict is Verdict.UNCHANGED
    assert check.fingerprint == stored
    assert check.is_change is False


def test_a_changed_secret_under_the_current_key_is_a_change() -> None:
    stored = NEW_FP.fingerprint(TYPE, PATH, CANARY)
    check = check_fingerprint(stored, NEW_FP, None, TYPE, PATH, CANARY + "-2")
    assert check.verdict is Verdict.CHANGED
    assert check.is_change is True
    assert check.fingerprint.key_id == NEW.key_id


def test_a_fingerprint_of_the_old_key_is_restamped_when_the_secret_is_equal() -> None:
    stored = OLD_FP.fingerprint(TYPE, PATH, CANARY)
    check = check_fingerprint(stored, NEW_FP, OLD_FP, TYPE, PATH, CANARY)
    assert check.verdict is Verdict.RESTAMPED
    assert check.is_change is False
    assert check.fingerprint == NEW_FP.fingerprint(TYPE, PATH, CANARY)
    assert check.fingerprint.key_id == NEW.key_id


def test_a_real_change_during_the_cycle_still_shows() -> None:
    stored = OLD_FP.fingerprint(TYPE, PATH, CANARY)
    check = check_fingerprint(stored, NEW_FP, OLD_FP, TYPE, PATH, "CANARY-secret-0002")
    assert check.verdict is Verdict.CHANGED
    assert check.is_change is True
    assert check.fingerprint == NEW_FP.fingerprint(TYPE, PATH, "CANARY-secret-0002")


def test_without_the_old_key_the_fingerprint_is_restamped_without_a_comparison() -> None:
    stored = OLD_FP.fingerprint(TYPE, PATH, CANARY)
    for value in (CANARY, "CANARY-secret-0002"):
        check = check_fingerprint(stored, NEW_FP, None, TYPE, PATH, value)
        assert check.verdict is Verdict.UNKNOWN
        assert check.is_change is False
        assert check.fingerprint == NEW_FP.fingerprint(TYPE, PATH, value)


def test_an_old_key_that_did_not_make_the_fingerprint_gives_no_comparison() -> None:
    third = Fingerprinter(bytes(KEY_BYTES), "0a1b2c3d")
    stored = third.fingerprint(TYPE, PATH, CANARY)
    check = check_fingerprint(stored, NEW_FP, OLD_FP, TYPE, PATH, CANARY)
    assert check.verdict is Verdict.UNKNOWN


def test_a_whole_cycle_with_no_secret_change_produces_no_change() -> None:
    fields = {f"field{index}": f"CANARY-value-{index:04d}" for index in range(20)}
    checks = [
        check_fingerprint(OLD_FP.fingerprint(TYPE, path, value), NEW_FP, OLD_FP, TYPE, path, value)
        for path, value in fields.items()
    ]
    assert not any(check.is_change for check in checks)
    assert {check.verdict for check in checks} == {Verdict.RESTAMPED}


def test_after_the_restamp_the_next_check_is_a_plain_comparison() -> None:
    stored = OLD_FP.fingerprint(TYPE, PATH, CANARY)
    restamped = check_fingerprint(stored, NEW_FP, OLD_FP, TYPE, PATH, CANARY).fingerprint
    again = check_fingerprint(restamped, NEW_FP, OLD_FP, TYPE, PATH, CANARY)
    assert again.verdict is Verdict.UNCHANGED


# --- the cycle state ------------------------------------------------------------------------


def test_begin_opens_an_active_cycle_for_the_given_sources(store: Database) -> None:
    with store.write() as connection:
        state = begin_rekey(
            connection,
            old_key_id=OLD.key_id,
            new_key_id=NEW.key_id,
            mode=MODE_OLD_KEY,
            source_ids=(3, 1, 3),
            at=AT,
        )
    assert state.active
    assert state.remaining == (1, 3)
    assert state_of(store) == state
    assert audit_actions(store) == []


def test_a_rekey_with_the_same_key_is_refused(store: Database) -> None:
    with pytest.raises(RekeyError, match="same key"):
        with store.write() as connection:
            begin_rekey(
                connection,
                old_key_id=OLD.key_id,
                new_key_id=OLD.key_id,
                mode=MODE_OLD_KEY,
                source_ids=(1,),
                at=AT,
            )


def test_an_unknown_mode_is_refused(store: Database) -> None:
    with pytest.raises(RekeyError, match="unknown rekey mode"):
        with store.write() as connection:
            begin_rekey(
                connection,
                old_key_id=OLD.key_id,
                new_key_id=NEW.key_id,
                mode="other",
                source_ids=(1,),
                at=AT,
            )


def test_a_second_rekey_cannot_start_while_one_runs(store: Database) -> None:
    run_rekey(store, OLD, NEW, AT)
    with pytest.raises(RekeyInProgressError, match="already in progress"):
        run_rekey(store, OLD, NEW, LATER)


def test_the_rekey_completes_when_every_source_has_a_clean_cycle(store: Database) -> None:
    add_source(store, 2)
    run_rekey(store, OLD, NEW, AT)
    with store.write() as connection:
        first = record_clean_cycle(connection, 1, restamped=4, at=AT)
    assert first is not None
    assert first.active
    assert first.remaining == (2,)
    assert audit_actions(store) == []
    with store.write() as connection:
        last = record_clean_cycle(connection, 2, restamped=3, at=LATER)
    assert last is not None
    assert last.status == STATUS_COMPLETE
    assert last.active is False
    assert last.restamped == 7
    assert last.completed_at == LATER
    assert state_of(store) == last


def test_completion_writes_exactly_one_fingerprint_rekey_event(store: Database) -> None:
    add_source(store, 2)
    run_rekey(store, OLD, NEW, AT)
    with store.write() as connection:
        record_clean_cycle(connection, 1, restamped=1, at=AT)
        record_clean_cycle(connection, 2, restamped=1, at=LATER)
        record_clean_cycle(connection, 2, restamped=1, at=LATER)
    assert audit_actions(store) == [EVENT_REKEY]
    with store.read() as connection:
        row = connection.execute(
            sa.select(audit_events.c.actor, audit_events.c.detail, audit_events.c.at)
        ).one()
    assert row[0] == "system"
    assert row[1] == {"old_key_id": OLD.key_id, "new_key_id": NEW.key_id, "restamped": 2}
    assert row[2] == LATER


def test_a_source_that_is_not_waited_for_changes_nothing(store: Database) -> None:
    add_source(store, 2)
    run_rekey(store, OLD, NEW, AT)
    with store.write() as connection:
        record_clean_cycle(connection, 1, restamped=2, at=AT)
        again = record_clean_cycle(connection, 1, restamped=5, at=AT)
        stranger = record_clean_cycle(connection, 99, restamped=5, at=AT)
    assert again is not None
    assert again == stranger
    assert again.remaining == (2,)
    assert again.restamped == 2


def test_a_negative_count_does_not_reduce_the_total(store: Database) -> None:
    run_rekey(store, OLD, NEW, AT)
    with store.write() as connection:
        done = record_clean_cycle(connection, 1, restamped=-5, at=AT)
    assert done is not None
    assert done.restamped == 0


def test_nothing_is_recorded_when_no_rekey_runs(store: Database) -> None:
    with store.write() as connection:
        assert record_clean_cycle(connection, 1, restamped=1, at=AT) is None


def test_nothing_is_recorded_after_the_rekey_completed(store: Database) -> None:
    run_rekey(store, OLD, NEW, AT)
    with store.write() as connection:
        record_clean_cycle(connection, 1, restamped=1, at=AT)
        assert record_clean_cycle(connection, 1, restamped=1, at=LATER) is None
    assert audit_actions(store) == [EVENT_REKEY]


def test_a_new_rekey_can_start_after_one_completed(store: Database) -> None:
    run_rekey(store, OLD, NEW, AT)
    with store.write() as connection:
        record_clean_cycle(connection, 1, restamped=1, at=AT)
    result = run_rekey(store, NEW, OLD, LATER)
    assert result.state.active
    assert result.state.old_key_id == NEW.key_id


def test_a_rekey_with_no_enabled_source_completes_at_once(store: Database) -> None:
    with store.write() as connection:
        connection.execute(sa.update(sources).values(enabled=False))
    result = run_rekey(store, OLD, NEW, AT)
    assert result.state.status == STATUS_COMPLETE
    assert result.state.completed_at == AT
    assert audit_actions(store) == [EVENT_REKEY]


def test_a_disabled_source_is_not_waited_for(store: Database) -> None:
    add_source(store, 2, enabled=False)
    result = run_rekey(store, OLD, NEW, AT)
    assert result.state.remaining == (1,)


def test_a_damaged_state_row_is_reported(store: Database) -> None:
    for text in ("not json", '{"status": "active"}', '{"remaining": 5}'):
        with store.write() as connection:
            connection.execute(sa.delete(settings).where(settings.c.key == REKEY_SETTING))
            connection.execute(
                sa.insert(settings).values(
                    workspace_id=DEFAULT_WORKSPACE_ID, key=REKEY_SETTING, value=text
                )
            )
        with pytest.raises(RekeyError, match="damaged"):
            with store.read() as connection:
                load_rekey_state(connection)


def test_no_state_exists_before_the_first_rekey(store: Database) -> None:
    with store.read() as connection:
        assert load_rekey_state(connection) is None


# --- credentials ----------------------------------------------------------------------------


def test_credentials_still_decrypt_after_the_rekey(store: Database) -> None:
    add_source(store, 2)
    set_credential(store, 1, OLD, "CANARY-password-one")
    set_credential(store, 2, OLD, "CANARY-password-two")
    result = run_rekey(store, OLD, NEW, AT)
    assert result.credentials_rekeyed == 2
    new_cipher = CredentialCipher.from_master(NEW)
    for source_id, expected in ((1, "CANARY-password-one"), (2, "CANARY-password-two")):
        ciphertext, key_id = stored_credential(store, source_id)
        assert key_id == NEW.key_id
        assert new_cipher.decrypt(source_id, ciphertext, key_id) == expected.encode()


def test_the_old_key_no_longer_decrypts_after_the_rekey(store: Database) -> None:
    set_credential(store, 1, OLD, "CANARY-password-one")
    run_rekey(store, OLD, NEW, AT)
    ciphertext, key_id = stored_credential(store, 1)
    with pytest.raises(CredentialDecryptError, match="encrypted with key"):
        CredentialCipher.from_master(OLD).decrypt(1, ciphertext, key_id)


def test_a_source_without_a_credential_is_left_alone(store: Database) -> None:
    result = run_rekey(store, OLD, NEW, AT)
    assert result.credentials_rekeyed == 0
    with store.read() as connection:
        row = connection.execute(sa.select(sources.c.credential_ciphertext, sources.c.key_id)).one()
    assert tuple(row) == (None, None)


def test_a_credential_that_already_has_the_new_key_is_skipped(store: Database) -> None:
    set_credential(store, 1, NEW, "CANARY-password-one")
    before = stored_credential(store, 1)
    with store.write() as connection:
        count = rekey_credentials(
            connection, CredentialCipher.from_master(OLD), CredentialCipher.from_master(NEW)
        )
    assert count == 0
    assert stored_credential(store, 1) == before


def test_a_credential_of_a_third_key_stops_the_rekey_and_changes_nothing(
    store: Database,
) -> None:
    add_source(store, 2)
    third = MasterKey(bytes([7] * KEY_BYTES))
    set_credential(store, 1, OLD, "CANARY-password-one")
    set_credential(store, 2, third, "CANARY-password-two")
    before = (stored_credential(store, 1), stored_credential(store, 2))
    with pytest.raises(RekeyError, match="neither the old key"):
        run_rekey(store, OLD, NEW, AT)
    assert (stored_credential(store, 1), stored_credential(store, 2)) == before
    with store.read() as connection:
        assert load_rekey_state(connection) is None
    assert audit_actions(store) == []


def test_a_damaged_credential_stops_the_rekey(store: Database) -> None:
    set_credential(store, 1, OLD, "CANARY-password-one")
    with store.write() as connection:
        connection.execute(sa.update(sources).values(credential_ciphertext="AAAA"))
    with pytest.raises(RekeyError, match="source 1"):
        run_rekey(store, OLD, NEW, AT)
    assert stored_credential(store, 1) == ("AAAA", OLD.key_id)


# --- the old key is lost --------------------------------------------------------------------


def test_a_lost_old_key_writes_exactly_one_event(store: Database) -> None:
    set_credential(store, 1, OLD, "CANARY-password-one")
    result = run_rekey(store, None, NEW, AT)
    assert audit_actions(store) == [EVENT_BASELINE]
    assert result.state.mode == MODE_OLD_KEY_LOST
    assert result.state.old_key_id == OLD.key_id
    assert result.credentials_rekeyed == 0
    with store.write() as connection:
        record_clean_cycle(connection, 1, restamped=3, at=LATER)
    assert audit_actions(store) == [EVENT_BASELINE]
    assert state_of(store).status == STATUS_COMPLETE


def test_the_lost_key_event_says_that_secret_changes_in_the_gap_are_unknown(
    store: Database,
) -> None:
    run_rekey(store, None, NEW, AT)
    with store.read() as connection:
        detail = connection.execute(sa.select(audit_events.c.detail)).scalar_one()
    assert "secret changes during the gap are unknown" in detail["message"]
    assert detail["new_key_id"] == NEW.key_id


def test_a_lost_key_leaves_credentials_unchanged_and_undecryptable(store: Database) -> None:
    set_credential(store, 1, OLD, "CANARY-password-one")
    before = stored_credential(store, 1)
    run_rekey(store, None, NEW, AT)
    assert stored_credential(store, 1) == before
    with pytest.raises(CredentialDecryptError, match="encrypted with key"):
        CredentialCipher.from_master(NEW).decrypt(1, before[0], before[1])


def test_a_lost_key_with_no_credentials_records_an_unknown_old_key_id(store: Database) -> None:
    result = run_rekey(store, None, NEW, AT)
    assert result.state.old_key_id == "unknown"


def test_a_lost_key_is_not_a_change_for_any_stored_fingerprint() -> None:
    stored = OLD_FP.fingerprint(TYPE, PATH, CANARY)
    check = check_fingerprint(stored, NEW_FP, None, TYPE, PATH, CANARY)
    assert check.is_change is False
    assert check.verdict is Verdict.UNKNOWN
