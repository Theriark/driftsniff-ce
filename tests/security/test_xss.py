"""Script text in every stored field (P9-T6).

There are no HTML pages until P10, so for now the question is whether text that carries script
can ever be taken as a page. Script payloads are planted in the source name, the object name, the
rationale, a note and every field of an enrichment. They must come back unchanged as JSON strings,
in answers that say they are JSON, that browsers must not sniff into anything else, and that carry
the content security policy. P10 adds its own page tests (the same payloads must render escaped);
``PAYLOADS`` is the list they reuse.

``test_template_scan.py`` already fails when a template uses the ``safe`` filter or switches
autoescape off.
"""

from typing import Any

import sqlalchemy as sa
from httpx import Response

from driftsniff.db.tables import sources
from driftsniff.web.csrf import CONTENT_SECURITY_POLICY

from .appkit import Kit, add_change, add_note

PAYLOADS = (
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "{{7*7}} ${7*7}",
)


def assert_inert(response: Response) -> None:
    """The answer is JSON that no browser may take for a page."""
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["cache-control"] == "no-store"
    assert not response.text.lstrip().startswith("<")


def plant(kit: Kit) -> int:
    """A change whose every text field, and its source, hold one of the payloads."""
    items = tuple(
        {"path": f"net.{number}", "object_name_at_time": text, "rationale": text}
        for number, text in enumerate(PAYLOADS)
    )
    event_id = add_change(kit.store, items)
    for text in PAYLOADS:
        add_note(kit.store, event_id, kit.user_ids["admin"], text)
    with kit.store.write() as connection:
        connection.execute(sa.update(sources).where(sources.c.id == 1).values(name=PAYLOADS[0]))
    for text in PAYLOADS:
        body: dict[str, Any] = {
            "provider_label": text,
            "summary": text,
            "payload": {"html": text, text: [text]},
        }
        response = kit.client.post(
            f"/api/v1/changes/{event_id}/enrichments", headers=kit.bearer("enrich"), json=body
        )
        assert response.status_code == 201, response.text
        assert_inert(response)
        assert response.json()["summary"] == text
    return event_id


def test_payloads_come_back_unchanged_as_inert_json(kit: Kit) -> None:
    event_id = plant(kit)
    response = kit.client.get(f"/api/v1/changes/{event_id}", headers=kit.bearer("read"))
    assert response.status_code == 200
    assert_inert(response)
    detail = response.json()
    assert detail["source"]["name"] == PAYLOADS[0]
    assert [item["object_name"] for item in detail["items"]] == list(PAYLOADS)
    assert [item["rationale"] for item in detail["items"]] == list(PAYLOADS)
    assert [note["body"] for note in detail["notes"]] == list(PAYLOADS)
    enrichments = detail["enrichments"]
    assert [found["summary"] for found in enrichments] == list(PAYLOADS)
    assert [found["provider_label"] for found in enrichments] == list(PAYLOADS)
    assert [found["payload"]["html"] for found in enrichments] == list(PAYLOADS)


def test_the_list_and_the_document_are_inert_too(kit: Kit) -> None:
    plant(kit)
    listing = kit.client.get("/api/v1/changes", headers=kit.bearer("read"))
    assert listing.status_code == 200
    assert_inert(listing)
    assert listing.json()["changes"][0]["source"]["name"] == PAYLOADS[0]
    document = kit.client.get("/api/v1/openapi.json")
    assert document.status_code == 200
    assert_inert(document)


def test_a_refusal_that_repeats_the_input_is_inert_as_well(kit: Kit) -> None:
    for text in PAYLOADS:
        response = kit.client.get(
            "/api/v1/changes", headers=kit.bearer("read"), params={"severity": text}
        )
        assert response.status_code == 422
        assert_inert(response)
    unauthorised = kit.client.get("/api/v1/changes", headers={"X-Probe": PAYLOADS[0]})
    assert unauthorised.status_code == 401
    assert_inert(unauthorised)
    assert PAYLOADS[0] not in unauthorised.text


def test_no_route_answers_with_a_page(kit: Kit) -> None:
    plant(kit)
    admin = kit.new_session("admin")
    for path in ("/healthz", "/tokens", "/notifications/channel", "/notifications/deliveries"):
        response = kit.client.get(path, headers=admin.headers())
        assert response.status_code == 200, path
        assert_inert(response)
    kit.client.cookies.clear()
