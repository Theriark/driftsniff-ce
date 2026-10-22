"""The change and enrichment API (P9-T5): lists, details, scopes, limits and the OpenAPI document.

The tests drive the real application with a migrated database and tokens made by the real token
service. Changes are written straight into the tables, the way the run pipeline writes them. Text
that must never come back in an answer starts with CANARY-.
"""

import json
from collections.abc import Iterator
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    audit_events,
    change_events,
    change_items,
    enrichments,
    notes,
    snapshots,
)
from driftsniff.enrich.api import (
    MAX_ENRICHMENTS_PER_CHANGE,
    MAX_ITEMS_PER_CHANGE,
    ChangeService,
    decode_cursor,
    encode_cursor,
)
from driftsniff.enrich.models import payload_depth
from driftsniff.main import create_app
from driftsniff.web.auth import AuthService, make_password_hasher
from driftsniff.web.bearer import TokenService

ORIGIN = "http://testserver"
CANARY = "CANARY-enrich-9f3a"
FINGERPRINT = "fp1:0a1b2c3d:" + "ab12cd34ef56" * 2 + "ab12cd34"


def bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def add_event(
    store: Database,
    *,
    source_id: int = 1,
    severity: str = "high",
    status: str = "open",
    created_at: str = "2026-10-22T08:00:00Z",
    items: tuple[dict[str, Any], ...] = (),
) -> int:
    with store.write() as connection:
        snapshot_id = connection.execute(
            sa.insert(snapshots)
            .values(
                source_id=source_id,
                taken_at=created_at,
                manifest_hash="m",
                manifest_zstd=b"x",
                normaliser_version=1,
            )
            .returning(snapshots.c.id)
        ).scalar_one()
        event_id: int = connection.execute(
            sa.insert(change_events)
            .values(
                source_id=source_id,
                snapshot_id=snapshot_id,
                window_start=created_at,
                window_end=created_at,
                max_severity=severity,
                item_count=len(items),
                summary=f"{len(items)} changes",
                rule_pack_version="pack-1",
                status=status,
                created_at=created_at,
            )
            .returning(change_events.c.id)
        ).scalar_one()
        for item in items:
            row = {
                "event_id": event_id,
                "resource": "networks",
                "change_kind": "changed",
                "path": "name",
                "field_class": "config",
                "severity": "low",
                **item,
            }
            connection.execute(sa.insert(change_items).values(**row))
    return event_id


def rows_of(store: Database, table: sa.Table) -> list[Any]:
    with store.read() as connection:
        return list(connection.execute(sa.select(table).order_by(table.c.id)).all())


@pytest.fixture
def tokens(store: Database) -> TokenService:
    return TokenService(store)


@pytest.fixture
def user_id(store: Database) -> int:
    auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    return auth.create_user("admin", "CANARY-correct horse battery", "admin")


@pytest.fixture
def app(store: Database, tokens: TokenService) -> FastAPI:
    return create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}),
        tokens=tokens,
        changes=ChangeService(store),
    )


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as test_client:
        yield test_client


def make_token(tokens: TokenService, user_id: int, *scopes: str) -> str:
    return tokens.create(user_id=user_id, actor="admin", name="t", scopes=scopes).value


@pytest.fixture
def reader(tokens: TokenService, user_id: int) -> dict[str, str]:
    return bearer(make_token(tokens, user_id, "read"))


@pytest.fixture
def enricher(tokens: TokenService, user_id: int) -> dict[str, str]:
    return bearer(make_token(tokens, user_id, "enrich"))


def good_body(**changes: Any) -> dict[str, Any]:
    return {"provider_label": "triage-bot", "summary": "Looks like a planned change.", **changes}


def post(client: TestClient, event_id: int, headers: dict[str, str], body: dict[str, Any]) -> Any:
    return client.post(f"/api/v1/changes/{event_id}/enrichments", headers=headers, json=body)


# -- cursor and payload helpers -----------------------------------------------------------------


def test_a_cursor_round_trips_and_other_text_is_refused() -> None:
    assert decode_cursor(encode_cursor(41)) == 41
    for bad in ("", "!!", "djE6", "djE6MA", "djE6LTE", "eDoxMg", encode_cursor(2**31)):
        with pytest.raises(ValueError, match="cursor"):
            decode_cursor(bad)


def test_payload_depth_counts_containers() -> None:
    assert payload_depth(1) == 0
    assert payload_depth({}) == 1
    assert payload_depth({"a": [1, {"b": 2}]}) == 3
    assert payload_depth([[[[[[[1]]]]]]]) == 7


# -- listing ------------------------------------------------------------------------------------


def test_the_list_is_newest_first_without_items(
    client: TestClient, store: Database, reader: dict[str, str]
) -> None:
    first = add_event(store, items=({"path": "name"},))
    second = add_event(store, severity="critical", created_at="2026-10-22T09:00:00Z")
    response = client.get("/api/v1/changes", headers=reader)
    assert response.status_code == 200
    body = response.json()
    assert [entry["id"] for entry in body["changes"]] == [second, first]
    assert body["next_cursor"] is None
    newest = body["changes"][0]
    assert newest["severity"] == "critical"
    assert newest["source"] == {"id": 1, "name": "lab-controller"}
    assert newest["rule_pack_version"] == "pack-1"
    assert "items" not in newest


def test_paging_walks_every_event_once(
    client: TestClient, store: Database, reader: dict[str, str]
) -> None:
    made = [add_event(store) for _ in range(5)]
    seen: list[int] = []
    cursor: str | None = None
    pages = 0
    while True:
        query: dict[str, Any] = {"limit": 2}
        if cursor is not None:
            query["cursor"] = cursor
        body = client.get("/api/v1/changes", headers=reader, params=query).json()
        seen.extend(entry["id"] for entry in body["changes"])
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert pages == 3
    assert seen == sorted(made, reverse=True)


def test_an_exact_page_has_no_next_cursor(
    client: TestClient, store: Database, reader: dict[str, str]
) -> None:
    for _ in range(2):
        add_event(store)
    body = client.get("/api/v1/changes", headers=reader, params={"limit": 2}).json()
    assert len(body["changes"]) == 2
    assert body["next_cursor"] is None


def test_the_filters_narrow_the_list(
    client: TestClient, store: Database, reader: dict[str, str]
) -> None:
    with store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (2, 'other', 'push')"
        )
    old = add_event(store, severity="low", created_at="2026-10-01T00:00:00Z")
    other = add_event(store, source_id=2, severity="high", status="acknowledged")
    recent = add_event(store, severity="critical", created_at="2026-10-22T09:00:00Z")

    def ids(**params: Any) -> list[int]:
        response = client.get("/api/v1/changes", headers=reader, params=params)
        assert response.status_code == 200, response.text
        return [entry["id"] for entry in response.json()["changes"]]

    assert ids(source=2) == [other]
    assert ids(severity="low") == [old]
    assert ids(status="acknowledged") == [other]
    assert ids(since="2026-10-22T00:00:00Z") == [recent, other]
    assert ids(source=1, severity="critical", status="open") == [recent]


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 101},
        {"limit": 0},
        {"severity": "urgent"},
        {"status": "closed"},
        {"source": 0},
        {"since": "yesterday"},
        {"since": "2026-13-45T00:00:00Z"},
        {"cursor": "not-a-cursor"},
    ],
)
def test_bad_query_values_are_refused(
    client: TestClient, reader: dict[str, str], params: dict[str, Any]
) -> None:
    assert client.get("/api/v1/changes", headers=reader, params=params).status_code == 422


# -- detail -------------------------------------------------------------------------------------


def test_the_detail_shows_values_for_config_and_short_fingerprints_for_secrets(
    client: TestClient, store: Database, reader: dict[str, str]
) -> None:
    event_id = add_event(
        store,
        items=(
            {
                "path": "name",
                "before_value": '"old"',
                "after_value": '"new"',
                "rule_id": "generic-name",
                "rationale": "A rename is low risk.",
                "object_name_at_time": "LAN",
            },
            {
                "path": "passphrase",
                "field_class": "secret",
                "before_fp": FINGERPRINT,
                "after_fp": FINGERPRINT.replace("ab12", "ff00"),
                "severity": "critical",
                # Never written by the pipeline; the API must still not show it.
                "before_value": f"{CANARY}-before",
                "after_value": f"{CANARY}-after",
            },
            {"path": "mystery", "field_class": "unclassified", "after_value": CANARY},
            {"path": "weird", "field_class": "config", "after_fp": f"{CANARY}-not-a-fingerprint"},
        ),
    )
    response = client.get(f"/api/v1/changes/{event_id}", headers=reader)
    assert response.status_code == 200
    assert CANARY not in response.text
    detail = response.json()
    name, secret, mystery, weird = detail["items"]
    assert (name["before"], name["after"]) == ('"old"', '"new"')
    assert name["rule_id"] == "generic-name"
    assert name["rationale"] == "A rename is low risk."
    assert name["object_name"] == "LAN"
    assert (name["before_fingerprint"], name["after_fingerprint"]) == (None, None)
    assert (secret["before"], secret["after"]) == (None, None)
    assert secret["before_fingerprint"] == "ab12cd34ef56"
    assert secret["after_fingerprint"] == "ff00cd34ef56"
    assert len(secret["before_fingerprint"]) == 12
    assert (mystery["before"], mystery["after"]) == (None, None)
    assert weird["after_fingerprint"] is None
    assert detail["items_truncated"] is False
    assert detail["item_count"] == 4


def test_the_detail_lists_notes_and_enrichments(
    client: TestClient, store: Database, reader: dict[str, str], user_id: int, tokens: TokenService
) -> None:
    event_id = add_event(store)
    with store.write() as connection:
        connection.execute(
            sa.insert(notes).values(
                event_id=event_id,
                user_id=user_id,
                body="planned window",
                created_at="2026-10-22T08:05:00Z",
            )
        )
    enrich = bearer(make_token(tokens, user_id, "enrich"))
    assert post(client, event_id, enrich, good_body(payload={"score": 3})).status_code == 201
    detail = client.get(f"/api/v1/changes/{event_id}", headers=reader).json()
    assert [(n["author"], n["body"]) for n in detail["notes"]] == [("admin", "planned window")]
    assert len(detail["enrichments"]) == 1
    assert detail["enrichments"][0]["provider_label"] == "triage-bot"
    assert detail["enrichments"][0]["payload"] == {"score": 3}


def test_a_change_with_too_many_items_is_cut_and_says_so(
    client: TestClient, store: Database, reader: dict[str, str]
) -> None:
    items = tuple({"path": f"field{number}"} for number in range(MAX_ITEMS_PER_CHANGE + 1))
    event_id = add_event(store, items=items)
    detail = client.get(f"/api/v1/changes/{event_id}", headers=reader).json()
    assert len(detail["items"]) == MAX_ITEMS_PER_CHANGE
    assert detail["items_truncated"] is True


def test_an_unknown_change_is_404(client: TestClient, reader: dict[str, str]) -> None:
    assert client.get("/api/v1/changes/99", headers=reader).status_code == 404
    assert client.get("/api/v1/changes/0", headers=reader).status_code == 422


# -- tokens and scopes --------------------------------------------------------------------------


def test_every_route_needs_its_own_scope(
    client: TestClient,
    store: Database,
    reader: dict[str, str],
    enricher: dict[str, str],
) -> None:
    event_id = add_event(store)
    read_routes = ("/api/v1/changes", f"/api/v1/changes/{event_id}")
    for path in read_routes:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=bearer("x" * 43)).status_code == 401
        assert client.get(path, headers=enricher).status_code == 403
        assert client.get(path, headers=reader).status_code == 200
    assert post(client, event_id, {}, good_body()).status_code == 401
    assert post(client, event_id, reader, good_body()).status_code == 403
    assert post(client, event_id, enricher, good_body()).status_code == 201
    assert len(rows_of(store, enrichments)) == 1


def test_a_revoked_token_is_refused(
    client: TestClient, store: Database, tokens: TokenService, user_id: int
) -> None:
    created = tokens.create(user_id=user_id, actor="admin", name="gone", scopes=["read", "enrich"])
    tokens.revoke(created.info.token_id, actor="admin")
    headers = bearer(created.value)
    event_id = add_event(store)
    assert client.get("/api/v1/changes", headers=headers).status_code == 401
    assert post(client, event_id, headers, good_body()).status_code == 401
    assert rows_of(store, enrichments) == []


def test_without_the_service_the_change_routes_answer_503(
    store: Database, tokens: TokenService, reader: dict[str, str]
) -> None:
    app = create_app(Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}), tokens=tokens)
    with TestClient(app, base_url=ORIGIN) as bare:
        assert bare.get("/api/v1/changes", headers=reader).status_code == 503
        assert bare.get("/api/v1/openapi.json").status_code == 200


# -- enrichments --------------------------------------------------------------------------------


def test_an_enrichment_is_stored_audited_and_changes_nothing_else(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store, severity="high", status="open")
    before = rows_of(store, change_events)
    payload = {"verdict": "benign", "tags": ["a", "b"], "nested": {"deep": {"x": 1.5, "y": None}}}
    response = post(client, event_id, enricher, good_body(payload=payload))
    assert response.status_code == 201
    body = response.json()
    assert body["provider_label"] == "triage-bot"
    assert body["summary"] == "Looks like a planned change."
    assert body["payload"] == payload
    assert rows_of(store, change_events) == before
    (stored,) = rows_of(store, enrichments)
    assert stored.id == body["id"]
    assert stored.event_id == event_id
    assert stored.payload == payload
    (audit,) = [row for row in rows_of(store, audit_events) if row.action == "enrichment.added"]
    assert audit.target == f"event:{event_id}"
    assert audit.actor.startswith("token:")
    assert "triage" in json.dumps(audit.detail)
    assert "Looks like" not in json.dumps(audit.detail)


def test_two_enrichments_are_both_kept_in_order(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    first = post(client, event_id, enricher, good_body(summary="first")).json()["id"]
    second = post(client, event_id, enricher, good_body(summary="second")).json()["id"]
    assert [row.id for row in rows_of(store, enrichments)] == [first, second]


def test_a_missing_payload_and_script_text_are_stored_as_given(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    script = "<script>alert(1)</script>"
    response = post(client, event_id, enricher, good_body(summary=script, payload=None))
    assert response.status_code == 201
    assert response.json()["summary"] == script
    assert response.json()["payload"] is None
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_an_unknown_change_gets_404_and_stores_nothing(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    assert post(client, 77, enricher, good_body()).status_code == 404
    assert rows_of(store, enrichments) == []


def test_a_change_holds_at_most_the_agreed_number_of_enrichments(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    for _ in range(MAX_ENRICHMENTS_PER_CHANGE):
        assert post(client, event_id, enricher, good_body()).status_code == 201
    assert post(client, event_id, enricher, good_body()).status_code == 409
    assert len(rows_of(store, enrichments)) == MAX_ENRICHMENTS_PER_CHANGE


def nested(depth: int) -> dict[str, Any]:
    value: dict[str, Any] = {"leaf": 1}
    for _ in range(depth - 1):
        value = {"in": value}
    return value


@pytest.mark.parametrize(
    ("body", "status"),
    [
        (good_body(provider_label="x" * 80), 201),
        (good_body(provider_label="x" * 81), 422),
        (good_body(provider_label="   "), 422),
        (good_body(provider_label="bad\x07label"), 422),
        (good_body(summary="s" * 2000), 201),
        (good_body(summary="s" * 2001), 422),
        (good_body(summary=""), 422),
        (good_body(summary="  \n "), 422),
        (good_body(summary="has\x00nul"), 422),
        (good_body(summary="line one\nline two\tend"), 201),
        (good_body(payload=nested(6)), 201),
        (good_body(payload=nested(7)), 422),
        (good_body(payload={"text": "x" * 40000}), 413),
        (good_body(payload=["not", "an", "object"]), 422),
        (good_body(payload="text"), 422),
        (good_body(severity="critical"), 422),
        ({"summary": "no label"}, 422),
        ({"provider_label": "no summary"}, 422),
        ({"provider_label": 5, "summary": "number label"}, 422),
    ],
)
def test_the_limits_of_an_enrichment(
    client: TestClient,
    store: Database,
    enricher: dict[str, str],
    body: dict[str, Any],
    status: int,
) -> None:
    event_id = add_event(store)
    assert post(client, event_id, enricher, body).status_code == status
    assert len(rows_of(store, enrichments)) == (1 if status == 201 else 0)


def test_a_payload_just_under_and_just_over_32_kb(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    overhead = len(json.dumps({"t": ""}, separators=(",", ":")))
    fits = {"t": "y" * (32 * 1024 - overhead)}
    too_big = {"t": "y" * (32 * 1024 - overhead + 1)}
    assert post(client, event_id, enricher, good_body(payload=fits)).status_code == 201
    assert post(client, event_id, enricher, good_body(payload=too_big)).status_code == 413
    assert len(rows_of(store, enrichments)) == 1


def test_a_body_over_64_kb_is_refused_before_it_is_parsed(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    huge = json.dumps(good_body(payload={"t": "z" * 70000}))
    response = client.post(
        f"/api/v1/changes/{event_id}/enrichments",
        headers={**enricher, "Content-Type": "application/json"},
        content=huge,
    )
    assert response.status_code == 413
    assert rows_of(store, enrichments) == []


def test_the_body_must_be_json(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    url = f"/api/v1/changes/{event_id}/enrichments"
    form = client.post(url, headers=enricher, data={"summary": "x", "provider_label": "y"})
    assert form.status_code == 415
    for text in ("{", "[]", "null", '{"summary": "x", "provider_label": "y"} trailing'):
        response = client.post(
            url, headers={**enricher, "Content-Type": "application/json"}, content=text
        )
        assert response.status_code == 422, text
    assert rows_of(store, enrichments) == []


def test_an_error_names_the_field_but_never_repeats_what_was_sent(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    response = post(
        client,
        event_id,
        enricher,
        good_body(summary="s" * 2001, provider_label=CANARY * 10, extra_field=CANARY),
    )
    assert response.status_code == 422
    assert CANARY not in response.text
    fields = {problem["field"] for problem in response.json()["errors"]}
    assert fields == {"summary", "provider_label", "extra_field"}


def test_nan_and_infinity_in_a_payload_are_refused(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    url = f"/api/v1/changes/{event_id}/enrichments"
    for literal in ("NaN", "Infinity", "-Infinity"):
        text = f'{{"provider_label": "a", "summary": "b", "payload": {{"x": {literal}}}}}'
        response = client.post(
            url, headers={**enricher, "Content-Type": "application/json"}, content=text
        )
        assert response.status_code == 422, literal
    assert rows_of(store, enrichments) == []


def test_a_deeply_nested_document_is_refused_without_a_crash(
    client: TestClient, store: Database, enricher: dict[str, str]
) -> None:
    event_id = add_event(store)
    depth = 5000
    text = (
        '{"provider_label": "a", "summary": "b", "payload": '
        + '{"k":' * depth
        + "1"
        + "}" * depth
        + "}"
    )
    response = client.post(
        f"/api/v1/changes/{event_id}/enrichments",
        headers={**enricher, "Content-Type": "application/json"},
        content=text,
    )
    assert response.status_code in (413, 422)
    assert rows_of(store, enrichments) == []


# -- OpenAPI ------------------------------------------------------------------------------------


API_ROUTE_TABLE = {
    ("GET", "/api/v1/changes"),
    ("GET", "/api/v1/changes/{event_id}"),
    ("POST", "/api/v1/changes/{event_id}/enrichments"),
    ("GET", "/api/v1/openapi.json"),
    ("POST", "/api/v1/push/{source_id}"),
}


def test_the_openapi_document_matches_the_real_route_table(client: TestClient) -> None:
    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    document = response.json()
    described = {
        (method.upper(), path) for path, methods in document["paths"].items() for method in methods
    }
    assert described == API_ROUTE_TABLE


def test_the_openapi_document_describes_the_body_the_token_and_the_limits(
    client: TestClient,
) -> None:
    document = client.get("/api/v1/openapi.json").json()
    assert document["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"
    enrich = document["paths"]["/api/v1/changes/{event_id}/enrichments"]["post"]
    schema = enrich["requestBody"]["content"]["application/json"]["schema"]
    assert schema["properties"]["summary"]["maxLength"] == 2000
    assert schema["properties"]["provider_label"]["maxLength"] == 80
    assert set(schema["required"]) == {"provider_label", "summary"}
    assert enrich["security"] == [{"bearerAuth": []}]
    assert {"401", "403", "404", "413", "415", "422"} <= set(enrich["responses"])
    listing = document["paths"]["/api/v1/changes"]["get"]
    names = {parameter["name"] for parameter in listing["parameters"]}
    assert names == {"source", "severity", "status", "since", "cursor", "limit"}


def test_the_openapi_document_is_public_and_holds_no_installation_data(
    client: TestClient, store: Database
) -> None:
    add_event(store, items=({"after_value": CANARY},))
    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    assert CANARY not in response.text
    assert "lab-controller" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


def test_the_openapi_document_follows_routes_added_later(client: TestClient, app: FastAPI) -> None:
    assert "/api/v1/late" not in client.get("/api/v1/openapi.json").json()["paths"]

    @app.get("/api/v1/late")
    def late() -> dict[str, str]:
        return {}

    assert "/api/v1/late" in client.get("/api/v1/openapi.json").json()["paths"]
