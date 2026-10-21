"""TLS options of a source: validated, insecure needs the typed text and is audited (P7-T3)."""

from typing import Any

import pytest

from driftsniff.db.engine import Database
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.service import (
    ACTION_TLS_INSECURE,
    SourceService,
    SourceValidationError,
)

PIN = "ab" * 32
NOW = "2026-10-21T10:00:00Z"
CONFIRM = "I understand the risk"
BASE: dict[str, Any] = {
    "name": "lab-unifi",
    "source_type": "unifi",
    "actor": "admin",
    "base_url": "https://203.0.113.10:8443",
    "credential": "CANARY-tls-source-0001",
}


@pytest.fixture
def service(store: Database) -> SourceService:
    cipher = CredentialCipher.from_master(MasterKey(bytes(range(32))))
    return SourceService(store, cipher, clock=lambda: NOW)


def actions(store: Database) -> list[str]:
    with store.read() as connection:
        rows = connection.exec_driver_sql("SELECT action FROM audit_events ORDER BY id")
        return [str(row[0]) for row in rows]


def test_pinned_and_ca_file_options_are_stored_normalised(service: SourceService) -> None:
    pinned = service.create(**BASE, options={"tls_mode": "pinned", "tls_pin": PIN.upper()})
    assert pinned.options == {"tls_mode": "pinned", "tls_pin": PIN}
    other = {**BASE, "name": "lab-two"}
    ca = service.create(**other, options={"tls_mode": "ca_file", "tls_ca_file": "corp.pem"})
    assert ca.options == {"tls_mode": "ca_file", "tls_ca_file": "corp.pem"}


@pytest.mark.parametrize(
    "options",
    [
        {"tls_mode": "pinned"},
        {"tls_mode": "pinned", "tls_pin": "abc"},
        {"tls_mode": "ca_file", "tls_ca_file": "../etc/passwd"},
        {"tls_mode": "other"},
        {"tls_mode": "verify", "tls_pin": PIN},
        {"tls_mode": "verify", "insecure": True},
        {"tls_mode": "pinned", "tls_pin": PIN, "allow_plain_http": True},
    ],
)
def test_bad_tls_options_are_refused(service: SourceService, options: dict[str, object]) -> None:
    with pytest.raises(SourceValidationError):
        service.create(**BASE, options=options)


def test_insecure_needs_the_typed_text_and_writes_the_audit_event(
    service: SourceService, store: Database
) -> None:
    options = {"tls_mode": "insecure"}
    for wrong in (None, "", "yes", "i understand the risk", "I understand the risk!"):
        with pytest.raises(SourceValidationError, match="confirm"):
            service.create(**BASE, options=options, tls_confirmation=wrong)
    assert ACTION_TLS_INSECURE not in actions(store)
    created = service.create(**BASE, options=options, tls_confirmation=f" {CONFIRM} ")
    assert created.options == {"tls_mode": "insecure", "insecure": True}
    assert actions(store).count(ACTION_TLS_INSECURE) == 1


def test_switching_to_insecure_later_needs_the_text_once(
    service: SourceService, store: Database
) -> None:
    created = service.create(**BASE)
    options = {"tls_mode": "insecure"}
    with pytest.raises(SourceValidationError, match="confirm"):
        service.update(created.id, actor="admin", options=options)
    assert service.get(created.id).options == {}
    service.update(created.id, actor="admin", options=options, tls_confirmation=CONFIRM)
    assert service.get(created.id).options == {"tls_mode": "insecure", "insecure": True}
    # The stored options come back as they were stored; no second confirmation, no second event.
    service.update(created.id, actor="admin", options=dict(service.get(created.id).options))
    assert actions(store).count(ACTION_TLS_INSECURE) == 1


def test_leaving_insecure_removes_the_flag(service: SourceService) -> None:
    created = service.create(**BASE, options={"tls_mode": "insecure"}, tls_confirmation=CONFIRM)
    updated = service.update(created.id, actor="admin", options={"tls_mode": "verify"})
    assert updated.options == {"tls_mode": "verify"}


def test_a_push_source_has_no_tls_options(service: SourceService) -> None:
    with pytest.raises(SourceValidationError, match="only a unifi or xo"):
        service.create(
            name="pusher", source_type="push", actor="admin", options={"tls_mode": "verify"}
        )
