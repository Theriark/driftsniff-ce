"""POST /api/v1/push/{source_id}: key check, size limits and the normal pipeline behind it.

The tests drive the real endpoint with a real run pipeline on a migrated database; no network is
involved. The sender key is made by the source service, as an admin would.
"""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from starlette.requests import Request

from driftsniff.config import Settings
from driftsniff.core.normalize import FieldClass
from driftsniff.core.states import MAX_STATE_BYTES, decompress_bytes
from driftsniff.db import tables
from driftsniff.db.engine import Database
from driftsniff.main import create_app
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import RuleIndex
from driftsniff.rules.schema import ResourceTable
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.runs import RunPipeline, RunReport
from driftsniff.sources.service import OPTION_PUSH_FIELDS, SourceService
from driftsniff.web.routes_push import PushGateway

SOURCE_ID = 1  # a push source made by the store fixture
URL = f"/api/v1/push/{SOURCE_ID}"
HEADER = "X-Driftsniff-Push-Key"
MASTER = MasterKey(bytes(range(32)))
FINGERPRINTER = Fingerprinter(bytes(range(32)), "0a1b2c3d")
START = datetime(2026, 10, 21, 9, 0, 0, tzinfo=UTC)
MAX_BODY = 10 * 1024 * 1024
CANARY_FIRST = "CANARY-push-passphrase-0001"
CANARY_SECOND = "CANARY-push-passphrase-0002"
CANARY_UNDECLARED = "CANARY-push-undeclared-0001"
XO_LOGIN = "CANARY-xo-login-0001"
WRONG_SENDER = "CANARY-push-wrong-0001"
C = FieldClass.CONFIG
NETWORKS = ResourceTable(
    resource="networks",
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": C,
        "name": C,
        "vlan": C,
        "passphrase": FieldClass.SECRET,
        "uptime": FieldClass.IGNORE,
    },
    floors={"removed": "critical"},
)
HOSTS = ResourceTable(
    resource="hosts",
    object_key_field="id",
    name_field="hostname",
    field_classes={"id": C, "hostname": C, "ip": C},
)
INDEX = RuleIndex(
    pack_version="pack-t1",
    rules=(),
    by_resource={},
    type_tables={"networks": NETWORKS, "hosts": HOSTS},
)
DECLARED = {"networks": ["_id", "name", "vlan", "passphrase"]}
DECLARED_BOTH = {**DECLARED, "hosts": ["id", "hostname"]}


class Clock:
    """UTC timestamps one second apart, one for every call."""

    def __init__(self) -> None:
        self.second = 0

    def __call__(self) -> str:
        value = START + timedelta(seconds=self.second)
        self.second += 1
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class World:
    database: Database
    service: SourceService
    pipeline: RunPipeline
    client: TestClient
    key: str

    def post(self, body: object, *, key: str | None = None) -> Any:
        """Post ``body`` as JSON with the sender key (the real one unless ``key`` is given)."""
        return self.client.post(
            URL,
            content=json.dumps(body).encode(),
            headers={HEADER: self.key if key is None else key},
        )

    def count(self, table: sa.Table) -> int:
        with self.database.read() as connection:
            query = sa.select(sa.func.count()).select_from(table)
            return int(connection.execute(query).scalar_one())


def networks(*, vlan: int = 20, passphrase: str = CANARY_FIRST) -> dict[str, Any]:
    return {
        "networks": [
            {
                "_id": "n1",
                "name": "Lab",
                "vlan": vlan,
                "passphrase": passphrase,
                "notes": CANARY_UNDECLARED,
                "uptime": 5,
            },
            {"_id": "n2", "name": "Guest", "vlan": 30},
        ]
    }


def make_world(store: Database, *, fields: dict[str, list[str]] | None = DECLARED) -> World:
    service = SourceService(store, CredentialCipher.from_master(MASTER))
    if fields is not None:
        service.update(SOURCE_ID, actor="admin", options={OPTION_PUSH_FIELDS: fields})
    key = service.set_push_key(SOURCE_ID, actor="admin")
    pipeline = RunPipeline(store, RuleEngine(INDEX), FINGERPRINTER, clock=Clock())
    app = create_app(Settings.from_env({}), push_gateway=PushGateway(service, pipeline))
    return World(store, service, pipeline, TestClient(app), key)


@pytest.fixture
def world(store: Database) -> World:
    return make_world(store)


def stored_text(database: Database) -> str:
    """Every stored state body, every change item and every run record, as text."""
    parts: list[str] = []
    with database.read() as connection:
        for row in connection.execute(sa.select(tables.object_states.c.body_zstd)):
            parts.append(decompress_bytes(row.body_zstd, MAX_STATE_BYTES).decode())
        for table in (tables.change_items, tables.runs, tables.audit_events):
            parts.extend(str(row) for row in connection.execute(sa.select(table)))
    return "\n".join(parts)


def test_a_valid_push_creates_a_snapshot_through_the_normal_pipeline(world: World) -> None:
    response = world.post(networks())
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["stored_new_snapshot"] is True
    assert body["event_id"] is None  # the first snapshot is the baseline
    assert body["object_count"] == 2
    assert body["ignored_resources"] == 0
    assert world.count(tables.snapshots) == 1
    with world.database.read() as connection:
        run = connection.execute(sa.select(tables.runs)).one()
    assert (run.status, run.object_count) == ("ok", 2)
    assert run.bytes_fetched > 0


def test_a_changed_push_creates_a_change_event_and_the_same_push_does_not(world: World) -> None:
    world.post(networks())
    unchanged = world.post(networks())
    assert unchanged.status_code == 200
    assert unchanged.json()["stored_new_snapshot"] is False
    assert unchanged.json()["event_id"] is None
    changed = world.post(networks(vlan=99, passphrase=CANARY_SECOND))
    assert changed.status_code == 200
    event_id = changed.json()["event_id"]
    assert event_id is not None
    with world.database.read() as connection:
        items = connection.execute(
            sa.select(tables.change_items)
            .where(tables.change_items.c.event_id == event_id)
            .order_by(tables.change_items.c.path)
        ).all()
    assert [(item.path, item.change_kind) for item in items] == [
        ("passphrase", "modified"),
        ("vlan", "modified"),
    ]
    secret = items[0]
    assert secret.before_value is None
    assert secret.after_value is None
    assert secret.before_fp
    assert secret.after_fp
    assert secret.before_fp != secret.after_fp


def test_a_removed_object_in_a_later_push_is_a_removal(world: World) -> None:
    world.post(networks())
    smaller = {"networks": networks()["networks"][:1]}
    event_id = world.post(smaller).json()["event_id"]
    with world.database.read() as connection:
        items = connection.execute(
            sa.select(tables.change_items).where(tables.change_items.c.event_id == event_id)
        ).all()
    assert [(item.change_kind, item.severity) for item in items] == [("removed", "critical")]


def test_undeclared_fields_and_secret_values_are_never_stored(world: World) -> None:
    world.post(networks())
    world.post(networks(vlan=99, passphrase=CANARY_SECOND))
    text = stored_text(world.database)
    assert "CANARY" not in text
    assert "uptime" not in text


def test_an_undeclared_resource_is_ignored_and_reported(world: World) -> None:
    body = {**networks(), "hosts": [{"id": 1, "ip": "10.0.0.5"}]}
    response = world.post(body)
    assert response.status_code == 200
    assert response.json()["ignored_resources"] == 1
    assert "10.0.0.5" not in stored_text(world.database)


def test_a_resource_left_out_of_a_later_push_keeps_its_state(store: Database) -> None:
    world = make_world(store, fields=DECLARED_BOTH)
    hosts = [{"id": 1, "hostname": "nas"}, {"id": 2, "hostname": "printer"}]
    assert world.post({**networks(), "hosts": hosts}).json()["object_count"] == 4
    response = world.post(networks())
    assert response.status_code == 200
    body = response.json()
    assert body["object_count"] == 4  # the two hosts are carried over
    assert body["event_id"] is None
    with store.read() as connection:
        removed = connection.execute(
            sa.select(sa.func.count()).where(tables.objects.c.removed_at.is_not(None))
        ).scalar_one()
    assert removed == 0


@pytest.mark.parametrize("key", [None, "", "CANARY-push-wrong-0001"])
def test_a_missing_or_wrong_key_gets_401_and_no_data_is_read(
    world: World, monkeypatch: pytest.MonkeyPatch, key: str | None
) -> None:
    def refuse(_self: Request) -> Iterator[bytes]:
        raise AssertionError("the body was read")

    monkeypatch.setattr(Request, "stream", refuse)
    headers = {} if key is None else {HEADER: key}
    response = world.client.post(URL, content=json.dumps(networks()).encode(), headers=headers)
    assert response.status_code == 401
    assert CANARY_FIRST not in response.text
    assert world.count(tables.runs) == 0
    assert world.count(tables.snapshots) == 0


def test_an_old_key_stops_working_when_a_new_one_is_made(world: World) -> None:
    old = world.key
    new = world.service.set_push_key(SOURCE_ID, actor="admin")
    assert world.post(networks(), key=old).status_code == 401
    assert world.post(networks(), key=new).status_code == 200


@pytest.mark.parametrize("source_id", [2, 3, 999])
def test_an_unknown_source_or_one_that_is_not_a_push_source_gets_the_same_401(
    world: World, source_id: int
) -> None:
    world.service.create(
        name="lab-xo",
        source_type="xo",
        actor="admin",
        base_url="https://203.0.113.10:8443",
        credential=XO_LOGIN,
    )
    first = world.client.post(f"/api/v1/push/{source_id}", content=b"{}", headers={HEADER: "x"})
    wrong = world.client.post(URL, content=b"{}", headers={HEADER: "x"})
    assert first.status_code == 401
    assert first.json() == wrong.json()


def test_a_source_without_a_key_cannot_be_pushed_to(store: Database) -> None:
    service = SourceService(store, CredentialCipher.from_master(MASTER))
    pipeline = RunPipeline(store, RuleEngine(INDEX), FINGERPRINTER, clock=Clock())
    app = create_app(Settings.from_env({}), push_gateway=PushGateway(service, pipeline))
    client = TestClient(app)
    assert client.post(URL, content=b"{}", headers={HEADER: ""}).status_code == 401
    assert client.post(URL, content=b"{}").status_code == 401


def test_a_body_over_10_mb_gets_413_by_its_declared_length(world: World) -> None:
    response = world.client.post(URL, content=b"x" * (MAX_BODY + 1), headers={HEADER: world.key})
    assert response.status_code == 413
    assert world.count(tables.runs) == 0


def test_a_body_over_10_mb_gets_413_while_it_streams(world: World) -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(11):
            yield b"x" * (1024 * 1024)

    response = world.client.post(URL, content=chunks(), headers={HEADER: world.key})
    assert response.status_code == 413
    assert world.count(tables.runs) == 0


def test_a_body_of_exactly_10_mb_is_read(world: World) -> None:
    padding = " " * (MAX_BODY - len(json.dumps(networks()).encode()))
    body = json.dumps(networks()).encode() + padding.encode()
    assert len(body) == MAX_BODY
    response = world.client.post(URL, content=body, headers={HEADER: world.key})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body",
    [b"", b"not json", b"[]", b'{"networks": {"_id": "n1"}}', b'{"networks": [{"vlan": NaN}]}'],
)
def test_a_body_that_is_not_resource_lists_gets_400(world: World, body: bytes) -> None:
    response = world.client.post(URL, content=body, headers={HEADER: world.key})
    assert response.status_code == 400
    assert world.count(tables.runs) == 0


def test_a_body_without_a_declared_resource_gets_422(world: World) -> None:
    response = world.post({"hosts": [{"id": 1}]})
    assert response.status_code == 422
    assert world.count(tables.runs) == 0


def test_a_source_that_declares_no_fields_gets_409(store: Database) -> None:
    world = make_world(store, fields=None)
    response = world.post(networks())
    assert response.status_code == 409
    assert world.count(tables.runs) == 0


def test_a_disabled_source_gets_409_and_a_skipped_run(world: World) -> None:
    world.service.set_enabled(SOURCE_ID, False, actor="admin")
    response = world.post(networks())
    assert response.status_code == 409
    with world.database.read() as connection:
        run = connection.execute(sa.select(tables.runs)).one()
    assert (run.status, run.error_class) == ("skipped", "disabled")
    assert world.count(tables.snapshots) == 0


def test_objects_without_a_key_fail_the_run_with_422(world: World) -> None:
    response = world.post({"networks": [{"name": "Lab", "vlan": 1}]})
    assert response.status_code == 422
    assert response.json()["error_class"] == "bad_object"
    assert world.count(tables.snapshots) == 0
    with world.database.read() as connection:
        run = connection.execute(sa.select(tables.runs)).one()
    assert run.status == "failed"


def test_a_resource_without_a_type_table_fails_alone(store: Database) -> None:
    world = make_world(store, fields={**DECLARED, "switches": ["id"]})
    response = world.post({**networks(), "switches": [{"id": 1}]})
    assert response.status_code == 200
    assert response.json()["status"] == "partial"
    assert response.json()["object_count"] == 2


def test_the_endpoint_answers_503_without_a_gateway() -> None:
    client = TestClient(create_app(Settings.from_env({})))
    assert client.post(URL, content=b"{}", headers={HEADER: "x"}).status_code == 503


@pytest.mark.parametrize("path", ["/api/v1/push/0", "/api/v1/push/-1", "/api/v1/push/abc"])
def test_a_source_id_that_is_not_a_positive_number_is_refused(world: World, path: str) -> None:
    response = world.client.post(path, content=b"{}", headers={HEADER: world.key})
    assert response.status_code == 422


def test_the_pipeline_status_decides_the_answer(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def already_running(_source_id: int, _collector: object) -> RunReport:
        return RunReport(7, "skipped", "already_running", "a run of this source is going")

    monkeypatch.setattr(world.pipeline, "run", already_running)
    response = world.post(networks())
    assert response.status_code == 409
    assert response.json()["run_id"] == 7


def test_the_endpoint_does_not_log_the_key_or_the_body(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    world.post(networks())
    world.post(networks(), key=WRONG_SENDER)
    assert caplog.records
    assert world.key not in caplog.text
    assert "CANARY" not in caplog.text
