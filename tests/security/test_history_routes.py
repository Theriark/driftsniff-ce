"""The History and Configuration routes through the real application (P10-T7, backend slice).

What the route table cannot say: the shape of the answers, what a bad query becomes, what a
damaged store becomes, and that nothing which must stay secret leaves in an answer. The role
rules themselves are rows of ``ROUTE_TABLE`` (a viewer reads, nobody else, nothing writes) and are
called as every kind of caller by ``test_route_table.py``.

The canary tests plant states the way an older or buggy collector could have stored them (secret
values and credential-shaped text in clear, no redaction), then read every route as a viewer and
look for the canaries in the whole answer. A hit names the surface and where the canary was
planted, never the canary. The last test shows the scan can find something: a config value is
shown by design and must be reported.
"""

from collections.abc import Mapping
from typing import Any

import sqlalchemy as sa
from httpx import Response

from driftsniff.core.canonical import JsonValue
from driftsniff.core.normalize import normalize_object
from driftsniff.core.objects import update_objects
from driftsniff.core.snapshots import (
    CollectedObject,
    CollectedResource,
    build_manifest,
    store_if_changed,
)
from driftsniff.db.tables import snapshots
from driftsniff.history.service import HistoryService
from driftsniff.secrets.fingerprint import Fingerprinter

from .appkit import MASTER, Kit
from .canary import (
    SERVER,
    TYPE_TABLES,
    WLAN,
    Canary,
    CanaryFactory,
    CanaryScanner,
    FakeSource,
    Leak,
    assert_no_leaks,
)
from .test_xss import PAYLOADS, assert_inert

SURFACE = "history answer"
STAMP = "2026-10-22T08:00:00Z"
LATER = "2026-10-22T09:00:00Z"
UNREADABLE = "the stored configuration cannot be read"


def seed(
    kit: Kit,
    raw: Mapping[str, list[dict[str, JsonValue]]],
    *,
    taken_at: str = STAMP,
    controller: str = "10.0.1",
) -> None:
    """Store a snapshot of source 1 the way a run would, but without the redaction step."""
    resources: dict[str, CollectedResource] = {}
    for resource, objects in raw.items():
        table = TYPE_TABLES[resource]
        collected: list[CollectedObject] = []
        for raw_object in objects:
            state = normalize_object(table, raw_object)
            name = state.get("name")
            display = name if isinstance(name, str) else None
            collected.append(CollectedObject(str(state["_id"]), state, display))
        resources[resource] = CollectedResource(collected)
    manifest = build_manifest(resources, controller_version=controller)
    with kit.store.write() as connection:
        store_if_changed(connection, 1, manifest, taken_at=taken_at)
        update_objects(connection, 1, manifest, seen_at=taken_at)


def use_tables(kit: Kit) -> None:
    """Give the application the type tables of the fake source, like a real install has its own."""
    fingerprinter = Fingerprinter.from_master(MASTER)
    kit.app.state.history = HistoryService(kit.store, fingerprinter, TYPE_TABLES)


def plain_lab(number: int, vlan: int) -> dict[str, JsonValue]:
    return {"_id": f"w{number}", "name": f"Lab {number}", "vlan": vlan, "enabled": True}


def get(kit: Kit, path: str, role: str = "viewer", **params: Any) -> Response:
    response = kit.client.get(path, headers=kit.new_session(role).headers(), params=params)
    kit.client.cookies.clear()
    return response


def two_snapshots(kit: Kit) -> None:
    use_tables(kit)
    seed(kit, {WLAN: [plain_lab(0, 100), plain_lab(1, 101)]}, taken_at=STAMP)
    seed(kit, {WLAN: [plain_lab(0, 100), plain_lab(1, 102)]}, taken_at=LATER, controller="10.0.2")


# ---- the answers ------------------------------------------------------------------------------


def test_a_viewer_reads_the_snapshot_history_as_json(kit: Kit) -> None:
    two_snapshots(kit)
    response = get(kit, "/history/1")
    assert response.status_code == 200, response.text
    assert_inert(response)
    history = response.json()["history"]
    assert history["source"] == {
        "id": 1,
        "name": "lab-controller",
        "type": "push",
        "enabled": True,
    }
    rows = history["rows"]
    assert [(row["taken_at"], row["kind"]) for row in rows] == [
        (LATER, "normal"),
        (STAMP, "baseline"),
    ]
    assert [row["is_baseline"] for row in rows] == [False, True]
    assert [row["is_current"] for row in rows] == [True, False]
    assert [row["controller_version"] for row in rows] == ["10.0.2", "10.0.1"]
    assert (history["total"], history["baseline_count"], history["page"]) == (2, 1, 1)


def test_the_source_picker_is_the_same_for_both_pages(kit: Kit) -> None:
    two_snapshots(kit)
    for path in ("/history", "/configuration"):
        response = get(kit, path)
        assert response.status_code == 200, path
        assert_inert(response)
        (row,) = response.json()["sources"]
        assert (row["id"], row["name"], row["snapshot_count"]) == (1, "lab-controller", 2)
        assert (row["baseline_count"], row["latest_taken_at"]) == (1, LATER)


def test_a_viewer_reads_the_newest_configuration_one_resource_at_a_time(kit: Kit) -> None:
    two_snapshots(kit)
    response = get(kit, "/configuration/1", resource=WLAN)
    assert response.status_code == 200, response.text
    assert_inert(response)
    view = response.json()["configuration"]
    assert view["snapshot"]["taken_at"] == LATER
    assert view["selected_resource"] == WLAN
    assert [summary["resource"] for summary in view["resources"]] == [WLAN]
    assert [obj["key"] for obj in view["objects"]] == ["w0", "w1"]
    second = {item["path"]: item["value"] for item in view["objects"][1]["fields"]}
    assert second["vlan"] == "102"
    assert second["name"] == "Lab 1"


def test_the_search_and_the_resource_are_read_from_the_query(kit: Kit) -> None:
    two_snapshots(kit)
    found = get(kit, "/configuration/1", resource=WLAN, q="lab 1").json()["configuration"]
    assert [obj["key"] for obj in found["objects"]] == ["w1"]
    assert (found["search"], found["total"]) == ("lab 1", 1)
    none = get(kit, "/configuration/1", resource=WLAN, q="nothing like this").json()
    assert none["configuration"]["objects"] == []
    unknown = get(kit, "/configuration/1", resource="no-such-resource").json()["configuration"]
    assert unknown["selected_resource"] == WLAN


def test_a_page_that_is_not_a_plain_number_is_the_first_page(kit: Kit) -> None:
    two_snapshots(kit)
    for bad in ("abc", "-1", "0", "1.5", "٣", "9" * 12, ""):
        history = get(kit, "/history/1", page=bad)
        configuration = get(kit, "/configuration/1", page=bad)
        assert history.status_code == configuration.status_code == 200, bad
        assert history.json()["history"]["page"] == 1, bad
        assert configuration.json()["configuration"]["page"] == 1, bad
    assert get(kit, "/history/1", page="99").json()["history"]["page"] == 1


def test_an_unknown_source_is_a_404_on_both_pages(kit: Kit) -> None:
    for path in ("/history/99999", "/configuration/99999"):
        response = get(kit, path)
        assert response.status_code == 404, path
        assert response.json() == {"detail": "there is no such source"}


def test_a_source_id_that_is_not_a_positive_number_is_refused(kit: Kit) -> None:
    for path in ("/history/0", "/history/abc", "/configuration/-3", "/configuration/99999999999"):
        assert get(kit, path).status_code == 422, path


def test_a_source_without_a_snapshot_is_an_empty_page_not_an_error(kit: Kit) -> None:
    use_tables(kit)
    history = get(kit, "/history/1").json()["history"]
    assert (history["rows"], history["total"]) == ([], 0)
    configuration = get(kit, "/configuration/1").json()["configuration"]
    assert (configuration["snapshot"], configuration["objects"]) == (None, [])


def test_a_damaged_store_is_a_500_with_a_fixed_text(kit: Kit) -> None:
    two_snapshots(kit)
    with kit.store.write() as connection:
        connection.execute(sa.update(snapshots).values(manifest_zstd=b"CANARY-junk"))
    response = get(kit, "/configuration/1")
    assert response.status_code == 500
    assert response.json() == {"detail": UNREADABLE}
    assert "CANARY" not in response.text
    # The history reads rows, not manifests, so it still answers.
    assert get(kit, "/history/1").status_code == 200


def test_without_the_service_a_viewer_gets_503_and_nobody_else_gets_in(kit: Kit) -> None:
    kit.app.state.history = None
    for path in ("/history", "/history/1", "/configuration", "/configuration/1"):
        assert get(kit, path).status_code == 503, path
        anonymous = kit.client.get(path)
        assert anonymous.status_code == 401, path


def audit_count(kit: Kit) -> int:
    with kit.store.read() as connection:
        return int(connection.execute(sa.text("SELECT count(*) FROM audit_events")).scalar_one())


def test_the_pages_have_no_write_route_and_reading_writes_no_audit_event(kit: Kit) -> None:
    two_snapshots(kit)
    before = audit_count(kit)
    for path in ("/history", "/history/1", "/configuration", "/configuration/1"):
        assert get(kit, path, "admin").status_code == 200
        headers = kit.new_session("admin").headers()
        refused = kit.client.post(path, headers=headers, json={})
        kit.client.cookies.clear()
        assert refused.status_code == 405, path
    assert audit_count(kit) == before


# ---- text that is not what it looks like ------------------------------------------------------


def test_payloads_come_back_unchanged_as_inert_json(kit: Kit) -> None:
    use_tables(kit)
    raw: list[dict[str, JsonValue]] = [
        {"_id": f"p{number}", "name": text, "description": text}
        for number, text in enumerate(PAYLOADS)
    ]
    seed(kit, {WLAN: raw}, controller=PAYLOADS[0])
    configuration = get(kit, "/configuration/1", resource=WLAN)
    assert configuration.status_code == 200
    assert_inert(configuration)
    objects = configuration.json()["configuration"]["objects"]
    assert [obj["name"] for obj in objects] == list(PAYLOADS)
    by_path = [{item["path"]: item["value"] for item in obj["fields"]} for obj in objects]
    assert [fields["name"] for fields in by_path] == list(PAYLOADS)
    assert [fields["description"] for fields in by_path] == list(PAYLOADS)
    history = get(kit, "/history/1")
    assert_inert(history)
    assert history.json()["history"]["rows"][0]["controller_version"] == PAYLOADS[0]


# ---- canaries ---------------------------------------------------------------------------------


def planted(kit: Kit) -> tuple[CanaryScanner, tuple[Canary, ...]]:
    factory = CanaryFactory()
    use_tables(kit)
    seed(kit, FakeSource(factory).raw_objects(1))
    return CanaryScanner(factory.issued), factory.issued


def every_path() -> list[str]:
    paths = ["/history", "/history/1", "/configuration", "/configuration/1"]
    paths.extend(f"/configuration/1?resource={resource}" for resource in (WLAN, SERVER))
    return paths


def whole(response: Response) -> str:
    """The body and every header of a response, as the client sees them."""
    return response.text + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())


def test_no_canary_reaches_the_history_or_the_configuration(kit: Kit) -> None:
    scanner, _issued = planted(kit)
    session = kit.new_session("viewer")
    leaks: list[Leak] = []
    for path in every_path():
        response = kit.client.get(path, headers=session.headers())
        assert response.status_code == 200, path
        leaks.extend(scanner.find(SURFACE, path, whole(response)))
    kit.client.cookies.clear()
    assert_no_leaks(leaks)


def test_a_search_cannot_find_a_hidden_value(kit: Kit) -> None:
    _scanner, issued = planted(kit)
    session = kit.new_session("viewer")
    assert issued
    for canary in issued:
        for resource in (WLAN, SERVER):
            response = kit.client.get(
                "/configuration/1",
                headers=session.headers(),
                params={"resource": resource, "q": canary.value},
            )
            assert response.status_code == 200
            view = response.json()["configuration"]
            assert (view["total"], view["objects"]) == (0, []), canary.where
    kit.client.cookies.clear()


def test_the_scan_finds_a_config_value_which_is_shown_by_design(kit: Kit) -> None:
    factory = CanaryFactory()
    shown = factory.new("the name of a WLAN, a config field that is shown by design")
    use_tables(kit)
    seed(kit, {WLAN: [{"_id": "w0", "name": shown.value}]})
    response = get(kit, "/configuration/1", resource=WLAN)
    leaks = CanaryScanner(factory.issued).find(SURFACE, "/configuration/1", whole(response))
    assert [leak.where for leak in leaks] == [shown.where]
