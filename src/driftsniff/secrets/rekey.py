"""Rekey: move credentials and secret fingerprints to a new master key.

Credentials are encrypted with a key derived from the master key, so they are re-encrypted in
one transaction when the rekey starts (:func:`run_rekey`). Secret fingerprints cannot be
converted: a fingerprint is a keyed hash and the secret itself is not stored. They are
re-stamped during one full collection cycle instead. While the cycle runs, the old key file is
supplied through ``DRIFTSNIFF_OLD_KEY_FILE``, and for each stored fingerprint
:func:`check_fingerprint` computes it again with the key that made it:

* equal: the secret did not change; the fingerprint is stored again under the new key
  (verdict ``restamped``) and no change item is produced;
* different: the secret really changed (verdict ``changed``);
* the key that made it is not available (old key lost): the fingerprint is re-stamped without a
  comparison (verdict ``unknown``); the gap is recorded once, see below.

The state of a rekey lives in the ``settings`` table under ``rekey_state`` (key ids and source
ids only). When every enabled source has finished one clean cycle (:func:`record_clean_cycle`)
the rekey is complete and the admin is told to remove the old key file. Exactly one audit event
is written per rekey: ``fingerprint_rekey`` when it completes with the old key, or
``baseline_reestablished`` when the old key is lost.

The callers in these functions own the transaction (as in :mod:`driftsniff.secrets.keys`).
"""

import json
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Self

import sqlalchemy as sa
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from driftsniff.core.canonical import JsonValue
from driftsniff.db.engine import Database
from driftsniff.db.tables import DEFAULT_WORKSPACE_ID, audit_events, settings, sources
from driftsniff.secrets.crypto import CredentialCipher, CredentialCryptoError
from driftsniff.secrets.fingerprint import Fingerprint, Fingerprinter
from driftsniff.secrets.keys import MasterKey

REKEY_SETTING = "rekey_state"
SYSTEM_ACTOR = "system"
EVENT_REKEY = "fingerprint_rekey"
EVENT_BASELINE = "baseline_reestablished"

MODE_OLD_KEY = "old_key"
MODE_OLD_KEY_LOST = "old_key_lost"
MODES = (MODE_OLD_KEY, MODE_OLD_KEY_LOST)
STATUS_ACTIVE = "active"
STATUS_COMPLETE = "complete"

BASELINE_MESSAGE = (
    "the old master key is lost: stored secret fingerprints were re-stamped without a "
    "comparison, so secret changes during the gap are unknown"
)


class RekeyError(Exception):
    """A rekey cannot start or continue; messages never contain key material."""


class RekeyInProgressError(RekeyError):
    """A rekey is already running; it must finish before another one starts."""


class Verdict(StrEnum):
    """What a stored fingerprint turned out to be when it was checked during a rekey."""

    UNCHANGED = "unchanged"
    RESTAMPED = "restamped"
    CHANGED = "changed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FingerprintCheck:
    """The verdict and the fingerprint to store (always made with the current key)."""

    verdict: Verdict
    fingerprint: Fingerprint

    @property
    def is_change(self) -> bool:
        """True only when the secret really changed; a re-stamp or a gap is never a change."""
        return self.verdict is Verdict.CHANGED


def check_fingerprint(
    stored: Fingerprint,
    current: Fingerprinter,
    old: Fingerprinter | None,
    resource_type: str,
    path: str,
    value: JsonValue,
) -> FingerprintCheck:
    """Compare a stored fingerprint with the value just collected, across a key change.

    ``current`` is the fingerprinter of the new master key; ``old`` is the one of the old key
    while a rekey runs (None otherwise or when the old key is lost). Outside a rekey the stored
    fingerprint always carries the current key id, so the first branch decides.
    """
    fresh = current.fingerprint(resource_type, path, value)
    if stored.key_id == current.key_id:
        verdict = Verdict.UNCHANGED if stored.same_as(fresh) else Verdict.CHANGED
        return FingerprintCheck(verdict, fresh)
    if old is not None and old.key_id == stored.key_id:
        same = old.matches(stored, resource_type, path, value)
        return FingerprintCheck(Verdict.RESTAMPED if same else Verdict.CHANGED, fresh)
    return FingerprintCheck(Verdict.UNKNOWN, fresh)


@dataclass(frozen=True, slots=True)
class RekeyState:
    """Where a rekey stands: stored as JSON in the settings table."""

    status: str
    mode: str
    old_key_id: str
    new_key_id: str
    remaining: tuple[int, ...]
    restamped: int
    started_at: str
    completed_at: str | None = None

    @property
    def active(self) -> bool:
        """True while sources still have to finish their clean cycle."""
        return self.status == STATUS_ACTIVE

    def to_json(self) -> str:
        """The stored form."""
        return json.dumps(
            {
                "status": self.status,
                "mode": self.mode,
                "old_key_id": self.old_key_id,
                "new_key_id": self.new_key_id,
                "remaining": list(self.remaining),
                "restamped": self.restamped,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> Self:
        """Read the stored form; anything else is a RekeyError (the row was edited by hand)."""
        try:
            data: Any = json.loads(text)
            return cls(
                status=str(data["status"]),
                mode=str(data["mode"]),
                old_key_id=str(data["old_key_id"]),
                new_key_id=str(data["new_key_id"]),
                remaining=tuple(int(item) for item in data["remaining"]),
                restamped=int(data["restamped"]),
                started_at=str(data["started_at"]),
                completed_at=None if data["completed_at"] is None else str(data["completed_at"]),
            )
        except (ValueError, KeyError, TypeError):
            raise RekeyError("the stored rekey state is damaged") from None


def load_rekey_state(connection: sa.Connection) -> RekeyState | None:
    """The state of the latest rekey, or None when none was ever started."""
    text = connection.execute(
        sa.select(settings.c.value).where(
            settings.c.workspace_id == DEFAULT_WORKSPACE_ID,
            settings.c.key == REKEY_SETTING,
        )
    ).scalar_one_or_none()
    return None if text is None else RekeyState.from_json(text)


def _save_state(connection: sa.Connection, state: RekeyState) -> None:
    statement = sqlite_insert(settings).values(
        workspace_id=DEFAULT_WORKSPACE_ID, key=REKEY_SETTING, value=state.to_json()
    )
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[settings.c.workspace_id, settings.c.key],
            set_={"value": statement.excluded.value},
        )
    )


def _write_event(
    connection: sa.Connection, action: str, at: str, detail: dict[str, JsonValue]
) -> None:
    connection.execute(
        sa.insert(audit_events).values(
            at=at, actor=SYSTEM_ACTOR, action=action, target=None, detail=detail
        )
    )


def _finish(connection: sa.Connection, state: RekeyState, at: str) -> RekeyState:
    """Mark a rekey complete; with the old key this writes the single ``fingerprint_rekey``."""
    done = replace(state, status=STATUS_COMPLETE, remaining=(), completed_at=at)
    _save_state(connection, done)
    if done.mode == MODE_OLD_KEY:
        detail: dict[str, JsonValue] = {
            "old_key_id": done.old_key_id,
            "new_key_id": done.new_key_id,
            "restamped": done.restamped,
        }
        _write_event(connection, EVENT_REKEY, at, detail)
    return done


def begin_rekey(
    connection: sa.Connection,
    *,
    old_key_id: str,
    new_key_id: str,
    mode: str,
    source_ids: tuple[int, ...],
    at: str,
) -> RekeyState:
    """Start the collection cycle of a rekey.

    With ``mode`` old_key_lost the single ``baseline_reestablished`` event is written now.
    A rekey with no source to wait for is complete at once.
    """
    if mode not in MODES:
        raise RekeyError(f"unknown rekey mode {mode!r}")
    if old_key_id == new_key_id:
        raise RekeyError("the old and the new master key are the same key")
    existing = load_rekey_state(connection)
    if existing is not None and existing.active:
        raise RekeyInProgressError(
            "a rekey is already in progress; wait until every source has finished one clean "
            "collection cycle"
        )
    state = RekeyState(
        status=STATUS_ACTIVE,
        mode=mode,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        remaining=tuple(sorted(set(source_ids))),
        restamped=0,
        started_at=at,
    )
    _save_state(connection, state)
    if mode == MODE_OLD_KEY_LOST:
        detail: dict[str, JsonValue] = {
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "message": BASELINE_MESSAGE,
        }
        _write_event(connection, EVENT_BASELINE, at, detail)
    if not state.remaining:
        return _finish(connection, state, at)
    return state


def record_clean_cycle(
    connection: sa.Connection, source_id: int, *, restamped: int, at: str
) -> RekeyState | None:
    """Record that a source finished a clean cycle (every resource fetched, run status ok).

    ``restamped`` is the number of fingerprints that run re-stamped. Returns the new state, or
    None when no rekey is running. When this was the last source the rekey completes: the state
    is ``complete`` and the caller tells the admin to remove the old key file.
    """
    state = load_rekey_state(connection)
    if state is None or not state.active:
        return None
    if source_id not in state.remaining:
        return state
    updated = replace(
        state,
        remaining=tuple(item for item in state.remaining if item != source_id),
        restamped=state.restamped + max(restamped, 0),
    )
    if not updated.remaining:
        return _finish(connection, updated, at)
    _save_state(connection, updated)
    return updated


def rekey_credentials(
    connection: sa.Connection, old: CredentialCipher, new: CredentialCipher
) -> int:
    """Re-encrypt every stored source credential from the old key to the new one.

    A credential that already carries the new key id is left alone (a second run does no
    harm). A credential made with any other key stops the rekey, so the caller's transaction
    rolls back and nothing changes. Returns the number of credentials re-encrypted.
    """
    rows = connection.execute(
        sa.select(sources.c.id, sources.c.credential_ciphertext, sources.c.key_id).where(
            sources.c.credential_ciphertext.is_not(None)
        )
    ).all()
    count = 0
    for source_id, ciphertext, key_id in rows:
        if key_id == new.key_id:
            continue
        if key_id != old.key_id:
            raise RekeyError(
                f"the credential of source {source_id} was encrypted with key {key_id}, "
                f"which is neither the old key {old.key_id} nor the new key {new.key_id}"
            )
        try:
            plaintext = old.decrypt(source_id, ciphertext, key_id)
            sealed = new.encrypt(source_id, plaintext)
        except CredentialCryptoError as error:
            raise RekeyError(f"the credential of source {source_id}: {error}") from None
        connection.execute(
            sa.update(sources)
            .where(sources.c.id == source_id)
            .values(credential_ciphertext=sealed.ciphertext, key_id=sealed.key_id)
        )
        count += 1
    return count


@dataclass(frozen=True, slots=True)
class RekeyResult:
    """What starting a rekey did."""

    credentials_rekeyed: int
    state: RekeyState


def run_rekey(database: Database, old: MasterKey | None, new: MasterKey, at: str) -> RekeyResult:
    """Start a rekey in one transaction: re-encrypt credentials, then open the cycle.

    ``old`` is None when the old master key is lost; credentials made with it can then not be
    decrypted and stay as they are (the admin enters them again), and the baseline event is
    written. Anything that fails rolls the whole transaction back.
    """
    with database.write() as connection:
        if old is None:
            count = 0
            old_key_id = _lost_key_id(connection, new.key_id)
        else:
            old_key_id = old.key_id
            count = rekey_credentials(
                connection,
                CredentialCipher.from_master(old),
                CredentialCipher.from_master(new),
            )
        source_ids = tuple(
            connection.execute(sa.select(sources.c.id).where(sources.c.enabled.is_(True)))
            .scalars()
            .all()
        )
        state = begin_rekey(
            connection,
            old_key_id=old_key_id,
            new_key_id=new.key_id,
            mode=MODE_OLD_KEY if old is not None else MODE_OLD_KEY_LOST,
            source_ids=source_ids,
            at=at,
        )
    return RekeyResult(count, state)


def _lost_key_id(connection: sa.Connection, new_key_id: str) -> str:
    """The id of the lost key, read from the stored credentials; ``unknown`` when none exist."""
    ids = (
        connection.execute(
            sa.select(sources.c.key_id)
            .where(sources.c.key_id.is_not(None), sources.c.key_id != new_key_id)
            .distinct()
            .order_by(sources.c.key_id)
        )
        .scalars()
        .all()
    )
    return str(ids[0]) if ids else "unknown"
