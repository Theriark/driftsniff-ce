"""Source service: credentials stay secret, blocked addresses are refused, delete leaves nothing."""

import json
import logging
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    build_manifest,
    store_if_changed,
)
from driftsniff.db.engine import Database
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources import service as service_module
from driftsniff.sources.service import (
    ACTION_ALLOW_PLAIN_HTTP,
    ACTION_CREATE,
    ACTION_DELETE,
    ACTION_DISABLE,
    ACTION_ENABLE,
    ACTION_UPDATE,
    SourceNameTakenError,
    SourceNotFoundError,
    SourceService,
    SourceValidationError,
    SourceView,
)

CANARY = "CANARY-source-credential-0001"
CANARY_NEW = "CANARY-source-credential-0002"
NOW = "2026-10-21T10:00:00Z"
LATER = "2026-10-21T10:05:00Z"
ADDRESS = "https://203.0.113.10:8443"
PLAIN_ADDRESS = "http://203.0.113.10"
ACTOR = "admin"
EXISTING_ID = 1  # created by the store fixture
MASTER = MasterKey(bytes(range(32)))
VALID_XO: dict[str, Any] = {
    "name": "lab-xo",
    "source_type": "xo",
    "base_url": ADDRESS,
    "credential": CANARY,
}


@pytest.fixture
def service(store: Database) -> SourceService:
    return SourceService(store, CredentialCipher.from_master(MASTER), clock=lambda: NOW)


def make_unifi(service: SourceService, name: str = "lab-unifi") -> SourceView:
    return service.create(
        name=name,
        source_type="unifi",
        actor=ACTOR,
        base_url=ADDRESS,
        credential=CANARY,
    )


def audit_actions(store: Database) -> list[str]:
    with store.read() as connection:
        rows = connection.exec_driver_sql("SELECT action FROM audit_events ORDER BY id")
        return [str(row[0]) for row in rows]


def count(store: Database, table: str, where: str = "1=1") -> int:
    query = sa.select(sa.func.count()).select_from(sa.table(table)).where(sa.text(where))
    with store.read() as connection:
        return int(connection.execute(query).scalar_one())


def database_text(store: Database) -> str:
    """Every audit event and every source row as text, to search for a credential."""
    with store.read() as connection:
        audit = connection.exec_driver_sql("SELECT action, target, detail FROM audit_events").all()
        stored = connection.exec_driver_sql(
            "SELECT name, base_url, options, credential_ciphertext FROM sources"
        ).all()
    return json.dumps([[str(cell) for cell in row] for row in [*audit, *stored]])


def test_a_stored_credential_never_appears_in_a_return_value_or_a_log_line(
    service: SourceService, store: Database, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    created = make_unifi(service)
    updated = service.update(created.id, actor=ACTOR, credential=CANARY_NEW)
    toggled = service.set_enabled(created.id, False, actor=ACTOR)
    fetched = service.get(created.id)
    listed = service.list_sources()
    with pytest.raises(SourceNameTakenError) as duplicate:
        service.create(actor=ACTOR, **{**VALID_XO, "name": "lab-unifi"})
    returned = repr([created, updated, toggled, fetched, listed]) + str(duplicate.value)
    assert "CANARY" not in returned
    assert created.has_credential
    assert caplog.records, "the service should log what it did"
    assert "CANARY" not in caplog.text
    assert "CANARY" not in database_text(store)
    result = service.delete(created.id, actor=ACTOR)
    assert "CANARY" not in repr(result) + caplog.text + database_text(store)


def test_the_credential_is_encrypted_at_rest_and_the_collector_can_read_it(
    service: SourceService, store: Database
) -> None:
    created = make_unifi(service)
    with store.read() as connection:
        row = connection.exec_driver_sql(
            "SELECT credential_ciphertext, key_id FROM sources WHERE id = ?", (created.id,)
        ).one()
    assert row[0]
    assert CANARY not in row[0]
    assert row[1] == CredentialCipher.from_master(MASTER).key_id
    assert service.credential_for_collector(created.id) == CANARY.encode()
    service.update(created.id, actor=ACTOR, credential=CANARY_NEW)
    assert service.credential_for_collector(created.id) == CANARY_NEW.encode()


@pytest.mark.parametrize(
    "address",
    [
        "https://169.254.169.254/",
        "https://[fe80::1]/",
        "https://100.100.100.200/",
        "https://2852039166/",
        "http://169.254.169.254/",
    ],
)
def test_a_blocked_address_is_refused_and_nothing_is_stored(
    service: SourceService, store: Database, address: str
) -> None:
    fields = {**VALID_XO, "base_url": address, "options": {"allow_plain_http": True}}
    with pytest.raises(SourceValidationError, match="blocked"):
        service.create(actor=ACTOR, **fields)
    assert count(store, "sources") == 1
    assert count(store, "audit_events") == 0


def test_an_update_to_a_blocked_address_is_refused_and_the_old_address_stays(
    service: SourceService,
) -> None:
    created = make_unifi(service)
    with pytest.raises(SourceValidationError, match="blocked"):
        service.update(created.id, actor=ACTOR, base_url="https://169.254.169.254")
    assert service.get(created.id).base_url == ADDRESS


def test_plain_http_needs_the_option_and_setting_it_is_audited_once(
    service: SourceService, store: Database
) -> None:
    with pytest.raises(SourceValidationError, match="https"):
        service.create(actor=ACTOR, **{**VALID_XO, "base_url": PLAIN_ADDRESS})
    assert ACTION_ALLOW_PLAIN_HTTP not in audit_actions(store)
    allowed = {"allow_plain_http": True}
    fields = {**VALID_XO, "base_url": PLAIN_ADDRESS, "options": allowed}
    created = service.create(actor=ACTOR, **fields)
    assert created.base_url == PLAIN_ADDRESS
    assert audit_actions(store).count(ACTION_ALLOW_PLAIN_HTTP) == 1
    service.update(created.id, actor=ACTOR, options=allowed)
    assert audit_actions(store).count(ACTION_ALLOW_PLAIN_HTTP) == 1
    with pytest.raises(SourceValidationError, match="https"):
        service.update(created.id, actor=ACTOR, options={})
    assert service.get(created.id).options == allowed


def test_turning_the_option_on_later_is_audited(service: SourceService, store: Database) -> None:
    created = make_unifi(service)
    service.update(
        created.id,
        actor=ACTOR,
        base_url=PLAIN_ADDRESS,
        options={"allow_plain_http": True},
    )
    assert audit_actions(store).count(ACTION_ALLOW_PLAIN_HTTP) == 1
    assert service.get(created.id).base_url == PLAIN_ADDRESS


def test_create_update_enable_and_disable_write_audit_events(
    service: SourceService, store: Database
) -> None:
    created = make_unifi(service)
    assert created.enabled
    assert created.state == "new"
    service.update(created.id, actor=ACTOR, name="renamed", base_url="https://203.0.113.11/")
    assert service.set_enabled(created.id, False, actor=ACTOR).enabled is False
    assert service.set_enabled(created.id, True, actor=ACTOR).enabled is True
    view = service.get(created.id)
    assert (view.name, view.base_url) == ("renamed", "https://203.0.113.11")
    assert audit_actions(store) == [ACTION_CREATE, ACTION_UPDATE, ACTION_DISABLE, ACTION_ENABLE]
    with store.read() as connection:
        detail = connection.exec_driver_sql(
            "SELECT detail FROM audit_events WHERE action = ?", (ACTION_UPDATE,)
        ).scalar_one()
    assert json.loads(detail) == {"changed": ["name", "base_url"]}


@pytest.mark.parametrize("extra", [{"base_url": ADDRESS}, {"credential": CANARY}])
def test_a_push_source_takes_no_address_and_no_credential(
    service: SourceService, extra: dict[str, Any]
) -> None:
    created = service.create(name="pushed", source_type="push", actor=ACTOR)
    assert created.base_url is None
    assert created.has_credential is False
    assert service.credential_for_collector(created.id) is None
    with pytest.raises(SourceValidationError, match="push source"):
        service.create(name="pushed-2", source_type="push", actor=ACTOR, **extra)
    with pytest.raises(SourceValidationError, match="push source"):
        service.update(created.id, actor=ACTOR, **extra)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"source_type": "snmp"}, "unknown source type"),
        ({"base_url": None}, "address and a credential"),
        ({"credential": None}, "address and a credential"),
        ({"name": "  "}, "needs a name"),
        ({"name": "x" * 101}, "at most 100"),
        ({"name": "a" + chr(7) + "b"}, "control characters"),
        ({"credential": "  "}, "blank"),
        ({"options": {"x": 1}}, "unknown source option"),
        ({"options": {"allow_plain_http": "yes"}}, "must be bool"),
    ],
)
def test_invalid_values_are_refused(
    service: SourceService, store: Database, override: dict[str, Any], message: str
) -> None:
    with pytest.raises(SourceValidationError, match=message):
        service.create(actor=ACTOR, **{**VALID_XO, **override})
    assert count(store, "sources") == 1


def test_a_source_name_is_unique(service: SourceService) -> None:
    first = make_unifi(service, "one")
    second = make_unifi(service, "two")
    with pytest.raises(SourceNameTakenError):
        make_unifi(service, "one")
    with pytest.raises(SourceNameTakenError):
        service.update(second.id, actor=ACTOR, name="one")
    service.update(first.id, actor=ACTOR, name="one")  # its own name is not a conflict
    assert [view.name for view in service.list_sources()] == ["lab-controller", "one", "two"]


def test_a_missing_source_is_reported(service: SourceService, store: Database) -> None:
    with pytest.raises(SourceNotFoundError):
        service.get(99)
    with pytest.raises(SourceNotFoundError):
        service.update(99, actor=ACTOR, name="x")
    with pytest.raises(SourceNotFoundError):
        service.set_enabled(99, False, actor=ACTOR)
    with pytest.raises(SourceNotFoundError):
        service.delete(99, actor=ACTOR)
    assert count(store, "audit_events") == 0


def networks(*keys: str) -> dict[str, CollectedResource]:
    objects = [CollectedObject(key, {"_id": key, "name": f"net {key}"}, key) for key in keys]
    return {"networks": CollectedResource(objects)}


def insert_row(connection: Connection, statement: str, *parameters: object) -> int:
    return int(connection.exec_driver_sql(statement, parameters).scalar_one())


def fill_source(store: Database, source_id: int, keys: tuple[str, ...]) -> None:
    """Give a source two snapshots and one row in every other table that belongs to it."""
    first = build_manifest(networks(*keys), controller_version="10.0.1")
    second = build_manifest(networks(*keys, f"extra-{source_id}"), controller_version="10.0.1")
    with store.write() as connection:
        before = store_if_changed(connection, source_id, first, taken_at=NOW)
        after = store_if_changed(connection, source_id, second, taken_at=LATER)
        connection.exec_driver_sql(
            "INSERT INTO runs (source_id, started_at, status) VALUES (?, ?, 'ok')",
            (source_id, NOW),
        )
        connection.exec_driver_sql(
            "INSERT INTO resource_coverage (source_id, resource, last_status)"
            " VALUES (?, 'networks', '200')",
            (source_id,),
        )
        object_id = insert_row(
            connection,
            "INSERT INTO objects (source_id, resource, object_key, first_seen_at, last_seen_at)"
            " VALUES (?, 'networks', ?, ?, ?) RETURNING id",
            source_id,
            keys[0],
            NOW,
            NOW,
        )
        user_id = insert_row(
            connection,
            "INSERT INTO users (username, password_hash, role, created_at)"
            " VALUES (?, 'x', 'admin', ?) RETURNING id",
            f"user-{source_id}",
            NOW,
        )
        token_id = insert_row(
            connection,
            "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, scopes)"
            " VALUES (?, 't', 'p', ?, '[]') RETURNING id",
            user_id,
            f"hash-{source_id}",
        )
        channel_id = insert_row(
            connection,
            "INSERT INTO notification_channel (type, config_ciphertext)"
            " VALUES ('webhook', 'x') RETURNING id",
        )
        event_id = insert_row(
            connection,
            "INSERT INTO change_events (source_id, snapshot_id, previous_snapshot_id,"
            " window_start, window_end, max_severity, summary, rule_pack_version, created_at)"
            " VALUES (?, ?, ?, ?, ?, 'high', 's', 'v', ?) RETURNING id",
            source_id,
            after.snapshot_id,
            before.snapshot_id,
            NOW,
            LATER,
            LATER,
        )
        for statement, parameters in (
            (
                "INSERT INTO change_items (event_id, object_id, resource, change_kind, path,"
                " field_class, severity) VALUES (?, ?, 'networks', 'modified', 'name',"
                " 'config', 'high')",
                (event_id, object_id),
            ),
            (
                "INSERT INTO acknowledgements (event_id, user_id, comment, created_at)"
                " VALUES (?, ?, 'c', ?)",
                (event_id, user_id, NOW),
            ),
            (
                "INSERT INTO notes (event_id, user_id, body, created_at) VALUES (?, ?, 'b', ?)",
                (event_id, user_id, NOW),
            ),
            (
                "INSERT INTO enrichments (event_id, token_id, provider_label, summary, created_at)"
                " VALUES (?, ?, 'p', 's', ?)",
                (event_id, token_id, NOW),
            ),
            (
                "INSERT INTO notification_deliveries (event_id, channel_id, attempt, status,"
                " created_at) VALUES (?, ?, 1, 'sent', ?)",
                (event_id, channel_id, NOW),
            ),
        ):
            connection.exec_driver_sql(statement, parameters)


SOURCE_TABLES = ("runs", "resource_coverage", "objects", "snapshots", "change_events")
EVENT_TABLES = (
    "change_items",
    "acknowledgements",
    "notes",
    "enrichments",
    "notification_deliveries",
)


def test_delete_leaves_no_orphan_rows_and_keeps_shared_states(
    service: SourceService, store: Database
) -> None:
    doomed = service.create(name="doomed", source_type="push", actor=ACTOR)
    fill_source(store, doomed.id, ("shared", "only-doomed"))
    fill_source(store, EXISTING_ID, ("shared", "only-kept"))
    # Five states: shared, only-doomed, only-kept and one "extra" per source.
    assert count(store, "object_states") == 5
    result = service.delete(doomed.id, actor=ACTOR)
    # "only-doomed" and the extra object of the deleted source were used by nobody else.
    assert result.removed_states == 2
    assert result.freed_bytes > 0
    assert count(store, "object_states") == 3
    for table in SOURCE_TABLES:
        assert count(store, table, f"source_id = {doomed.id}") == 0, table
        assert count(store, table, f"source_id = {EXISTING_ID}") >= 1, table
    assert count(store, "sources", f"id = {doomed.id}") == 0
    assert count(store, "change_events") == 1
    for table in EVENT_TABLES:
        assert count(store, table) == 1, table
    with store.read() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    assert audit_actions(store)[-1] == ACTION_DELETE
    # The kept source still resolves: storing its newest manifest again changes nothing.
    newest = build_manifest(networks("shared", "only-kept", "extra-1"), controller_version="10.0.1")
    with store.write() as connection:
        again = store_if_changed(connection, EXISTING_ID, newest, taken_at="2026-10-21T11:00:00Z")
    assert again.stored is False


def test_a_failure_while_deleting_rolls_everything_back(
    service: SourceService, store: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    doomed = service.create(name="doomed", source_type="push", actor=ACTOR)
    fill_source(store, doomed.id, ("only-doomed",))

    def explode(_connection: object) -> object:
        raise RuntimeError("disk full")

    monkeypatch.setattr(service_module, "gc_unreferenced_states", explode)
    with pytest.raises(RuntimeError, match="disk full"):
        service.delete(doomed.id, actor=ACTOR)
    assert service.get(doomed.id).name == "doomed"
    assert count(store, "snapshots", f"source_id = {doomed.id}") == 2
    assert count(store, "change_events", f"source_id = {doomed.id}") == 1
    assert ACTION_DELETE not in audit_actions(store)
