"""``GET /sources/{id}/replay`` through the real application (WP4a): roles, answers and canaries.

The role rules themselves are one row of ``ROUTE_TABLE`` (a viewer reads, nobody below does,
nothing writes) and are called as every kind of caller by ``test_route_table.py``; the tests here
add the shape of the answer, what a bad query becomes and that nothing a source stored about its
configuration leaves in an answer.

The canary tests plant text in every column a change item or event has (before and after values,
fingerprints, object name, path, rationale, rule id, summary), then read the route as a viewer and
look for the canaries in the whole answer, headers included. A hit names the surface and where the
canary was planted, never the canary.
"""

from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from httpx import Response

from driftsniff.db.tables import change_events
from driftsniff.web.replay import DEFAULT_DAYS, MAX_DAYS, ReplayService

from .appkit import Kit, add_change
from .canary import Canary, CanaryFactory, CanaryScanner, Leak, assert_no_leaks

SURFACE = "replay answer"
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
DAY = "2026-10-22"


def use_clock(kit: Kit) -> None:
    """Fix today, so the planted events (stamped 2026-10-22) are inside the window."""
    kit.app.state.replay = ReplayService(kit.store, clock=lambda: NOW)


def get(kit: Kit, path: str, role: str = "viewer", **params: Any) -> Response:
    response = kit.client.get(path, headers=kit.new_session(role).headers(), params=params)
    kit.client.cookies.clear()
    return response


def item(resource: str, severity: str, **columns: Any) -> dict[str, Any]:
    return {"resource": resource, "severity": severity, **columns}


def two_resources(kit: Kit) -> None:
    use_clock(kit)
    add_change(
        kit.store,
        (item("vms", "low"), item("vms", "low"), item("hosts", "critical")),
        severity="critical",
    )


# ---- the answers -------------------------------------------------------------------------------


def test_a_viewer_reads_the_counts_as_json(kit: Kit) -> None:
    two_resources(kit)
    response = get(kit, "/sources/1/replay")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    replay = response.json()["replay"]
    assert replay["source_id"] == 1
    assert (replay["first_day"], replay["last_day"]) == ("2026-09-23", DAY)
    assert (replay["days"], replay["total"]) == (DEFAULT_DAYS, 3)
    assert replay["severities"] == ["low", "medium", "high", "critical"]
    assert replay["cells"] == [
        {"day": DAY, "resource": "hosts", "severity": "critical", "count": 1},
        {"day": DAY, "resource": "vms", "severity": "low", "count": 2},
    ]
    assert replay["resources"] == [
        {"resource": "vms", "label": "Virtual machines", "count": 2},
        {"resource": "hosts", "label": "Hosts", "count": 1},
    ]


def test_every_role_that_may_read_a_source_reads_the_replay(kit: Kit) -> None:
    two_resources(kit)
    for role in ("viewer", "operator", "admin"):
        assert get(kit, "/sources/1/replay", role).status_code == 200, role


def test_a_source_without_changes_is_an_empty_answer_not_an_error(kit: Kit) -> None:
    use_clock(kit)
    response = get(kit, "/sources/1/replay")
    assert response.status_code == 200
    replay = response.json()["replay"]
    assert (replay["cells"], replay["resources"], replay["total"]) == ([], [], 0)


def test_the_days_of_the_query_set_the_window(kit: Kit) -> None:
    two_resources(kit)
    one = get(kit, "/sources/1/replay", days="1").json()["replay"]
    assert (one["days"], one["first_day"], one["total"]) == (1, DAY, 3)
    clamped = get(kit, "/sources/1/replay", days="9999").json()["replay"]
    assert clamped["days"] == MAX_DAYS
    assert get(kit, "/sources/1/replay", days="0").json()["replay"]["days"] == 1


def test_a_days_value_that_is_not_a_plain_number_is_the_default(kit: Kit) -> None:
    two_resources(kit)
    for bad in ("abc", "-1", "1.5", "٣", "9" * 12, "", " 7", "7 "):
        response = get(kit, "/sources/1/replay", days=bad)
        assert response.status_code == 200, bad
        assert response.json()["replay"]["days"] == DEFAULT_DAYS, bad


def test_an_event_of_another_day_stays_out_of_the_window(kit: Kit) -> None:
    two_resources(kit)
    with kit.store.write() as connection:
        connection.execute(sa.update(change_events).values(created_at="2026-10-21T23:59:59Z"))
    assert get(kit, "/sources/1/replay", days="1").json()["replay"]["cells"] == []
    assert get(kit, "/sources/1/replay", days="2").json()["replay"]["total"] == 3


def test_an_unknown_source_is_a_404(kit: Kit) -> None:
    use_clock(kit)
    response = get(kit, "/sources/99999/replay")
    assert response.status_code == 404
    assert response.json() == {"detail": "there is no such source"}


def test_a_source_id_that_is_not_a_positive_number_is_refused(kit: Kit) -> None:
    for path in ("/sources/0/replay", "/sources/abc/replay", "/sources/-3/replay"):
        assert get(kit, path).status_code == 422, path
    assert get(kit, "/sources/99999999999/replay").status_code == 422


# ---- who may call it ---------------------------------------------------------------------------


def test_nobody_without_a_session_reads_it(kit: Kit) -> None:
    two_resources(kit)
    anonymous = kit.client.get("/sources/1/replay")
    assert anonymous.status_code == 401
    assert "replay" not in anonymous.json()
    browser = kit.client.get("/sources/1/replay", headers={"Accept": "text/html"})
    assert browser.status_code in (303, 401)
    assert "vms" not in browser.text


def test_an_api_token_is_not_a_session(kit: Kit) -> None:
    two_resources(kit)
    for kind in ("read", "enrich", "both"):
        response = kit.client.get("/sources/1/replay", headers=kit.bearer(kind))
        assert response.status_code in (401, 403), kind
    assert "vms" not in response.text


def test_without_the_service_a_viewer_gets_503_and_nobody_else_gets_in(kit: Kit) -> None:
    kit.app.state.replay = None
    assert get(kit, "/sources/1/replay").status_code == 503
    assert kit.client.get("/sources/1/replay").status_code == 401


def test_a_read_needs_no_csrf_value_and_no_origin_like_every_other_get(kit: Kit) -> None:
    two_resources(kit)
    headers = kit.new_session("viewer").headers(csrf=False, origin=None)
    response = kit.client.get("/sources/1/replay", headers=headers)
    kit.client.cookies.clear()
    assert response.status_code == 200


def audit_count(kit: Kit) -> int:
    with kit.store.read() as connection:
        return int(connection.execute(sa.text("SELECT count(*) FROM audit_events")).scalar_one())


def test_the_route_has_no_write_method_and_reading_writes_no_audit_event(kit: Kit) -> None:
    two_resources(kit)
    before = audit_count(kit)
    assert get(kit, "/sources/1/replay", "admin").status_code == 200
    for method in ("post", "put", "patch", "delete"):
        headers = kit.new_session("admin").headers()
        refused = getattr(kit.client, method)("/sources/1/replay", headers=headers)
        kit.client.cookies.clear()
        assert refused.status_code == 405, method
    assert audit_count(kit) == before


# ---- canaries ----------------------------------------------------------------------------------


def plant(kit: Kit) -> tuple[CanaryScanner, tuple[Canary, ...]]:
    """One change whose every free column carries its own canary."""
    factory = CanaryFactory()
    use_clock(kit)
    columns = {
        "object_name_at_time": factory.new("the object name of an item").value,
        "path": factory.new("the path of an item").value,
        "before_value": factory.new("the before value of an item").value,
        "after_value": factory.new("the after value of an item").value,
        "before_fp": factory.new("the before fingerprint of an item").value,
        "after_fp": factory.new("the after fingerprint of an item").value,
        "rule_id": factory.new("the rule id of an item").value,
        "rationale": factory.new("the rationale of an item").value,
    }
    add_change(
        kit.store,
        (item("vms", "high", **columns), item("hosts", "low", **columns)),
        severity="high",
    )
    summary = factory.new("the summary of an event").value
    with kit.store.write() as connection:
        connection.execute(sa.update(change_events).values(summary=summary))
    return CanaryScanner(factory.issued), factory.issued


def whole(response: Response) -> str:
    """The body and every header of a response, as the client sees them."""
    return response.text + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())


def test_no_canary_reaches_the_replay(kit: Kit) -> None:
    scanner, issued = plant(kit)
    assert len(issued) == 9
    leaks: list[Leak] = []
    for params in ({}, {"days": "1"}, {"days": "90"}):
        response = get(kit, "/sources/1/replay", **params)
        assert response.status_code == 200, params
        assert response.json()["replay"]["total"] == 2
        leaks.extend(scanner.find(SURFACE, f"/sources/1/replay {params}", whole(response)))
    assert_no_leaks(leaks)


def test_the_answer_holds_only_counts_ids_severities_and_type_names(kit: Kit) -> None:
    plant(kit)
    replay = get(kit, "/sources/1/replay").json()["replay"]
    assert set(replay) == {
        "source_id",
        "first_day",
        "last_day",
        "days",
        "severities",
        "total",
        "resources",
        "cells",
    }
    assert all(set(cell) == {"day", "resource", "severity", "count"} for cell in replay["cells"])
    assert all(set(entry) == {"resource", "label", "count"} for entry in replay["resources"])


def test_the_scan_finds_a_canary_that_is_in_the_answer(kit: Kit) -> None:
    """A resource type name is shown by design, so a canary used as one must be reported."""
    factory = CanaryFactory()
    shown = factory.new("the resource type of an item, shown by design")
    use_clock(kit)
    add_change(kit.store, (item(shown.value, "low"),))
    response = get(kit, "/sources/1/replay")
    leaks = CanaryScanner(factory.issued).find(SURFACE, "/sources/1/replay", whole(response))
    assert [leak.where for leak in leaks] == [shown.where]
