"""The push parts of the source service: the field allow-list option and the sender key."""

import hashlib
import json
import logging
import re
from typing import Any

import pytest

from driftsniff.db.engine import Database
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.service import (
    ACTION_PUSH_ROTATE,
    OPTION_PUSH_FIELDS,
    PUSH_KEY_PREFIX,
    SourceNotFoundError,
    SourceService,
    SourceValidationError,
    hash_push_key,
    push_key_matches,
)

NOW = "2026-10-21T10:00:00Z"
ACTOR = "admin"
PUSH_ID = 1  # created by the store fixture
MASTER = MasterKey(bytes(range(32)))
FIELDS = {"networks": ["_id", "name", "vlan"], "hosts": ["id"]}
XO_LOGIN = "CANARY-xo-login-0001"


@pytest.fixture
def service(store: Database) -> SourceService:
    return SourceService(store, CredentialCipher.from_master(MASTER), clock=lambda: NOW)


def stored_hash(store: Database, source_id: int = PUSH_ID) -> str | None:
    with store.read() as connection:
        value = connection.exec_driver_sql(
            "SELECT push_token_hash FROM sources WHERE id = ?", (source_id,)
        ).scalar_one()
    return None if value is None else str(value)


def audit_rows(store: Database) -> list[tuple[str, str]]:
    with store.read() as connection:
        rows = connection.exec_driver_sql("SELECT action, detail FROM audit_events ORDER BY id")
        return [(str(row[0]), str(row[1])) for row in rows]


def test_a_push_source_can_declare_its_fields(service: SourceService) -> None:
    view = service.update(PUSH_ID, actor=ACTOR, options={OPTION_PUSH_FIELDS: FIELDS})
    assert view.options == {OPTION_PUSH_FIELDS: FIELDS}
    target = service.push_target(PUSH_ID)
    assert target is not None
    assert target.fields == FIELDS


def test_a_push_source_can_declare_its_fields_when_it_is_created(service: SourceService) -> None:
    view = service.create(
        name="sender",
        source_type="push",
        actor=ACTOR,
        options={OPTION_PUSH_FIELDS: FIELDS},
    )
    target = service.push_target(view.id)
    assert target is not None
    assert target.fields == FIELDS


@pytest.mark.parametrize(
    "declared",
    [
        [],
        "networks",
        {"networks": "vlan"},
        {"networks": []},
        {"networks": ["vlan", "vlan"]},
        {"networks": [1]},
        {"networks": [""]},
        {"networks": ["bad\nname"]},
        {"networks": ["x" * 101]},
        {"": ["vlan"]},
        {"bad name": ["vlan"]},
        {"x" * 101: ["vlan"]},
        {1: ["vlan"]},
        {f"resource{number}": ["id"] for number in range(101)},
        {"networks": [f"field{number}" for number in range(201)]},
    ],
)
def test_a_bad_field_declaration_is_refused(service: SourceService, declared: Any) -> None:
    with pytest.raises(SourceValidationError):
        service.update(PUSH_ID, actor=ACTOR, options={OPTION_PUSH_FIELDS: declared})
    assert service.get(PUSH_ID).options == {}


def test_only_a_push_source_has_a_field_declaration(service: SourceService) -> None:
    with pytest.raises(SourceValidationError, match="only a push source"):
        service.create(
            name="lab-xo",
            source_type="xo",
            actor=ACTOR,
            base_url="https://203.0.113.10:8443",
            credential=XO_LOGIN,
            options={OPTION_PUSH_FIELDS: FIELDS},
        )
    xo = service.create(
        name="lab-xo",
        source_type="xo",
        actor=ACTOR,
        base_url="https://203.0.113.10:8443",
        credential=XO_LOGIN,
    )
    with pytest.raises(SourceValidationError, match="only a push source"):
        service.update(xo.id, actor=ACTOR, options={OPTION_PUSH_FIELDS: FIELDS})


def test_a_new_push_key_is_returned_once_and_only_its_hash_is_stored(
    service: SourceService, store: Database, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    assert service.get(PUSH_ID).has_push_key is False
    key = service.set_push_key(PUSH_ID, actor=ACTOR)
    assert key.startswith(PUSH_KEY_PREFIX)
    assert len(key) > 40
    assert stored_hash(store) == hashlib.sha256(key.encode()).hexdigest()
    assert re.fullmatch(r"[0-9a-f]{64}", stored_hash(store) or "")
    view = service.get(PUSH_ID)
    assert view.has_push_key is True
    assert key not in repr(view)
    target = service.push_target(PUSH_ID)
    assert target is not None
    assert target.key_hash == stored_hash(store)
    assert key not in repr(target)
    assert key not in caplog.text
    assert caplog.records, "the service should log what it did"
    assert key not in json.dumps(audit_rows(store))


def test_a_new_key_replaces_the_old_one_and_the_audit_event_says_so(
    service: SourceService, store: Database
) -> None:
    first = service.set_push_key(PUSH_ID, actor=ACTOR)
    first_hash = stored_hash(store)
    second = service.set_push_key(PUSH_ID, actor=ACTOR)
    assert first != second
    assert stored_hash(store) != first_hash
    assert audit_rows(store) == [
        (ACTION_PUSH_ROTATE, json.dumps({"replaced": False})),
        (ACTION_PUSH_ROTATE, json.dumps({"replaced": True})),
    ]


def test_only_a_push_source_gets_a_key(service: SourceService) -> None:
    xo = service.create(
        name="lab-xo",
        source_type="xo",
        actor=ACTOR,
        base_url="https://203.0.113.10:8443",
        credential=XO_LOGIN,
    )
    with pytest.raises(SourceValidationError, match="only a push source"):
        service.set_push_key(xo.id, actor=ACTOR)
    with pytest.raises(SourceNotFoundError):
        service.set_push_key(999, actor=ACTOR)
    assert service.push_target(xo.id) is None
    assert service.push_target(999) is None


def test_a_source_without_a_key_or_fields_has_an_empty_target(service: SourceService) -> None:
    target = service.push_target(PUSH_ID)
    assert target is not None
    assert (target.key_hash, target.fields, target.enabled) == (None, {}, True)
    service.set_enabled(PUSH_ID, False, actor=ACTOR)
    disabled = service.push_target(PUSH_ID)
    assert disabled is not None
    assert disabled.enabled is False


def test_changing_options_keeps_the_key(service: SourceService, store: Database) -> None:
    service.set_push_key(PUSH_ID, actor=ACTOR)
    before = stored_hash(store)
    service.update(PUSH_ID, actor=ACTOR, options={OPTION_PUSH_FIELDS: FIELDS})
    assert stored_hash(store) == before


def test_a_key_matches_only_its_own_hash() -> None:
    sender = PUSH_KEY_PREFIX + "CANARY-push-sender-0001"
    digest = hash_push_key(sender)
    assert push_key_matches(sender, digest)
    assert not push_key_matches(sender + "x", digest)
    assert not push_key_matches("", digest)
    assert not push_key_matches(sender, hash_push_key("CANARY-push-sender-0002"))


def test_nothing_matches_a_missing_hash() -> None:
    assert not push_key_matches("", None)
    assert not push_key_matches("CANARY-push-sender-0001", None)
