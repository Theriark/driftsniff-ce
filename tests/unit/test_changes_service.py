"""The change list, the change detail, and acknowledge, note and mute (P10-T6, backend slice).

The tests drive the services against a migrated database. Changes are written straight into the
tables, the way the run pipeline writes them. Text that must never come back starts with CANARY-.
The three acceptance checks of the task have a test each: markup in notes, names and enrichments
comes back as plain text and prints escaped (``test_every_text_is_plain_text_and_prints_escaped``),
every item shows a rule id and a rationale (``test_every_item_shows_a_rule_id_and_a_rationale``),
and acknowledging twice keeps both rows (``test_acknowledging_twice_keeps_both_rows``).
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import fields, is_dataclass
from datetime import UTC, date, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from markupsafe import Markup, escape

from driftsniff.changes.actions import (
    ACTION_ACKNOWLEDGED,
    ACTION_MUTE_ADDED,
    ACTION_MUTE_REMOVED,
    ACTION_NOTE_ADDED,
    MAX_ENTRIES_PER_CHANGE,
    ChangeActions,
)
from driftsniff.changes.errors import (
    ActionForbiddenError,
    EntryLimitError,
    InvalidTextError,
    NotMutableError,
    UnknownChangeError,
    UnknownItemError,
    UnknownMuteError,
)
from driftsniff.changes.filters import parse_filters
from driftsniff.changes.queries import ChangeQueries
from driftsniff.changes.views import (
    PAGE_SIZE,
    UNRATED_RATIONALE,
    UNRATED_RULE_ID,
    ChangeFilters,
)
from driftsniff.db.engine import Database
from driftsniff.db.tables import (
    acknowledgements,
    audit_events,
    change_events,
    change_items,
    enrichments,
    notes,
    path_mutes,
    snapshots,
    sources,
)
from driftsniff.web.auth import AuthService, Principal, make_password_hasher
from driftsniff.web.templating import make_environment

STAMP = "2026-10-22T08:00:00Z"
CORRECT = "CANARY-correct horse battery"
FINGERPRINT_BEFORE = "fp1:0a1b2c3d:" + "ab12cd34ef56" * 2 + "ab12cd34"
FINGERPRINT_AFTER = "fp1:0a1b2c3d:" + "ff00cd34ef56" * 2 + "ab12cd34"
PAYLOADS = (
    "<script>alert('CANARY-xss-0')</script>",
    '"><img src=x onerror=alert("CANARY-xss-1")>',
    "<svg onload=alert('CANARY-xss-2')>",
    "javascript:alert(1) CANARY-xss-3",
    "{{7*7}} ${7*7} CANARY-xss-4",
)


def make_principal(store: Database, name: str, role: str) -> Principal:
    auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    user_id = auth.create_user(name, CORRECT, role)
    return Principal(user_id=user_id, username=name, role=role, session_id=0, csrf_token="x")


def add_event(
    store: Database,
    *,
    items: Sequence[Mapping[str, Any]] = (),
    source_id: int = 1,
    severity: str = "high",
    status: str = "open",
    created_at: str = STAMP,
    summary: str | None = None,
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
                summary=summary or f"{len(items)} changes",
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
                "rule_id": "rule-1",
                "rationale": "A name is cosmetic.",
                **item,
            }
            connection.execute(sa.insert(change_items).values(**row))
    return event_id


def add_second_source(store: Database) -> None:
    statement = "INSERT INTO sources (id, name, type) VALUES (2, 'other', 'push')"
    with store.write() as connection:
        connection.exec_driver_sql(statement)


def add_mute_row(store: Database, user_id: int, resource: str, pattern: str) -> int:
    with store.write() as connection:
        mute_id: int = connection.execute(
            sa.insert(path_mutes)
            .values(
                resource=resource,
                path_pattern=pattern,
                user_id=user_id,
                created_at=STAMP,
            )
            .returning(path_mutes.c.id)
        ).scalar_one()
    return mute_id


def rows_of(store: Database, table: sa.Table) -> list[Any]:
    with store.read() as connection:
        return list(connection.execute(sa.select(table).order_by(table.c.id)).all())


def count_of(store: Database, table: sa.Table) -> int:
    return len(rows_of(store, table))


def audit_actions(store: Database) -> list[str]:
    return [str(row.action) for row in rows_of(store, audit_events)]


def first_item_id(store: Database, event_id: int) -> int:
    with store.read() as connection:
        found = connection.execute(
            sa.select(change_items.c.id).where(change_items.c.event_id == event_id)
        ).scalar_one()
    return int(found)


def listed_ids(store: Database, **filters: Any) -> list[int]:
    page = ChangeQueries(store).list_changes(ChangeFilters(**filters))
    return [row.id for row in page.rows]


def stored_state(store: Database) -> tuple[int, ...]:
    """Row counts of every table the actions write, to prove a refusal stored nothing."""
    tables = (acknowledgements, notes, path_mutes, audit_events)
    return tuple(count_of(store, table) for table in tables)


# -- the list -------------------------------------------------------------------------------------


def test_the_list_pages_by_fifty_and_clamps_the_page(store: Database) -> None:
    for number in range(PAGE_SIZE + 3):
        add_event(store, created_at=f"2026-10-22T08:{number:02d}:00Z")
    queries = ChangeQueries(store)
    first = queries.list_changes()
    assert (first.total, first.pages, first.page, len(first.rows)) == (53, 2, 1, 50)
    assert first.rows[0].created_at > first.rows[-1].created_at
    past_the_end = queries.list_changes(ChangeFilters(page=9))
    assert (past_the_end.page, len(past_the_end.rows)) == (2, 3)
    nothing = ChangeQueries(store).list_changes(ChangeFilters(severities=("low",)))
    assert (nothing.total, nothing.pages, nothing.page, nothing.rows) == (0, 1, 1, ())


def test_a_row_names_its_source_and_counts_what_people_added(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store, items=({"path": "name"},))
    actions = ChangeActions(store)
    actions.acknowledge(operator, event_id, "seen")
    actions.add_note(operator, event_id, "a note")
    actions.add_note(operator, event_id, "another note")
    page = ChangeQueries(store).list_changes()
    assert page.rows[0].source_name == "lab-controller"
    assert page.rows[0].status == "acknowledged"
    counts = (page.rows[0].acknowledgement_count, page.rows[0].note_count)
    assert counts == (1, 2)
    assert page.rows[0].enrichment_count == 0


def test_filters_narrow_the_list(store: Database) -> None:
    add_second_source(store)
    low = add_event(
        store,
        items=({"resource": "networks"},),
        severity="low",
        created_at="2026-10-20T10:00:00Z",
    )
    high = add_event(
        store,
        items=({"resource": "vms"},),
        source_id=2,
        created_at="2026-10-21T10:00:00Z",
    )
    critical = add_event(
        store,
        items=({"resource": "vms"},),
        severity="critical",
        status="acknowledged",
        created_at="2026-10-22T23:59:59Z",
    )
    assert listed_ids(store, source_id=2) == [high]
    assert listed_ids(store, severities=("high", "critical")) == [critical, high]
    assert listed_ids(store, status="acknowledged") == [critical]
    assert listed_ids(store, resource="vms") == [critical, high]
    assert listed_ids(store, created_from=date(2026, 10, 21)) == [critical, high]
    assert listed_ids(store, created_to=date(2026, 10, 22)) == [critical, high, low]
    assert listed_ids(store, created_to=date(2026, 10, 21)) == [high, low]
    day = date(2026, 10, 21)
    assert listed_ids(store, created_from=day, created_to=day) == [high]
    assert listed_ids(store, source_id=1, severities=("critical",)) == [critical]


def test_search_matches_the_summary_and_the_object_name_literally(store: Database) -> None:
    firewall = add_event(
        store,
        summary="Firewall rule removed",
        items=({"object_name_at_time": "Guest WiFi"},),
    )
    backup = add_event(
        store,
        summary="Backup retention changed",
        items=({"object_name_at_time": "nightly 100%_job"},),
    )
    assert listed_ids(store, search="firewall") == [firewall]
    assert listed_ids(store, search="GUEST wifi") == [firewall]
    assert listed_ids(store, search="100%_job") == [backup]
    assert listed_ids(store, search="%") == [backup]
    assert listed_ids(store, search="_") == [backup]
    assert listed_ids(store, search="no such text") == []
    assert listed_ids(store, search="' OR 1=1 --") == []
    assert listed_ids(store, search="   ") == [backup, firewall]


def test_the_list_sorts_by_time_or_by_severity(store: Database) -> None:
    middle = add_event(store, severity="high", created_at="2026-10-22T09:00:00Z")
    oldest = add_event(store, severity="critical", created_at="2026-10-22T08:00:00Z")
    newest = add_event(store, severity="low", created_at="2026-10-22T10:00:00Z")
    assert listed_ids(store) == [newest, middle, oldest]
    assert listed_ids(store, sort="oldest") == [oldest, middle, newest]
    assert listed_ids(store, sort="severity") == [oldest, middle, newest]
    assert listed_ids(store, sort="nonsense") == [newest, middle, oldest]


# -- mutes in the list ----------------------------------------------------------------------------


def test_a_change_with_only_muted_items_is_hidden_until_asked_for(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    muted = add_event(store, items=({"path": "name"},))
    mixed = add_event(store, items=({"path": "name"}, {"path": "dhcp.enabled"}))
    empty = add_event(store)
    critical = add_event(store, items=({"path": "name", "severity": "critical"},))
    add_mute_row(store, operator.user_id, "networks", "name")
    page = ChangeQueries(store).list_changes()
    assert [row.id for row in page.rows] == [critical, empty, mixed]
    assert (page.total, page.muted_hidden, page.mute_scan_truncated) == (3, 1, False)
    everything = ChangeQueries(store).list_changes(ChangeFilters(include_muted=True))
    assert [row.id for row in everything.rows] == [critical, empty, mixed, muted]
    assert everything.muted_hidden == 0


def test_a_mute_applies_to_its_own_resource_only(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    network = add_event(store, items=({"path": "name", "resource": "networks"},))
    vm = add_event(store, items=({"path": "name", "resource": "vms"},))
    add_mute_row(store, operator.user_id, "networks", "name")
    assert listed_ids(store) == [vm]
    assert listed_ids(store, include_muted=True) == [vm, network]


def test_a_mute_with_a_wildcard_never_hides_a_critical_change(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    critical = add_event(store, items=({"path": "name", "severity": "critical"},))
    add_event(store, items=({"path": "name"},))
    add_mute_row(store, operator.user_id, "networks", "**")
    assert listed_ids(store) == [critical]


def test_the_list_pages_over_the_changes_that_stay_visible(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    for _ in range(5):
        add_event(store, items=({"path": "name"},))
    for _ in range(PAGE_SIZE + 5):
        add_event(store, items=({"path": "dhcp.enabled"},))
    add_mute_row(store, operator.user_id, "networks", "name")
    queries = ChangeQueries(store)
    first = queries.list_changes()
    assert (first.total, first.pages, len(first.rows), first.muted_hidden) == (55, 2, 50, 5)
    second = queries.list_changes(ChangeFilters(page=2))
    assert (second.page, len(second.rows)) == (2, 5)
    assert {row.id for row in first.rows}.isdisjoint(row.id for row in second.rows)


def test_a_list_with_mutes_says_when_it_checked_only_the_newest_changes(
    store: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator = make_principal(store, "olga", "operator")
    newest = [add_event(store, items=({"path": "vlan"},)) for _ in range(5)]
    add_mute_row(store, operator.user_id, "vms", "name")
    monkeypatch.setattr("driftsniff.changes.queries.MUTE_SCAN_LIMIT", 3)
    page = ChangeQueries(store).list_changes()
    assert page.mute_scan_truncated is True
    assert [row.id for row in page.rows] == newest[:1:-1]
    assert page.total == 3


# -- the detail -----------------------------------------------------------------------------------


def test_the_detail_groups_items_by_object_and_hides_secret_values(store: Database) -> None:
    name_change = {
        "object_name_at_time": "Office WiFi",
        "resource": "wlans",
        "path": "name",
        "before_value": "old",
        "after_value": "new",
    }
    passphrase_change = {
        "object_name_at_time": "Office WiFi",
        "resource": "wlans",
        "path": "passphrase",
        "field_class": "secret",
        "severity": "critical",
        "before_value": "CANARY-secret-before",
        "after_value": "CANARY-secret-after",
        "before_fp": FINGERPRINT_BEFORE,
        "after_fp": FINGERPRINT_AFTER,
    }
    unknown_field = {
        "object_name_at_time": "Lab",
        "resource": "networks",
        "path": "vlan",
        "field_class": "unclassified",
        "before_value": "CANARY-unclassified-before",
        "after_value": "CANARY-unclassified-after",
    }
    event_id = add_event(store, items=(name_change, passphrase_change, unknown_field))
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    assert [group.object_name for group in detail.groups] == ["Office WiFi", "Lab"]
    office = detail.groups[0].items
    assert [item.path for item in office] == ["name", "passphrase"]
    assert (office[0].before, office[0].after, office[0].secret) == ("old", "new", False)
    assert (office[1].before, office[1].after, office[1].secret) == (None, None, True)
    assert office[1].before_fingerprint == "ab12cd34ef56"
    assert office[1].after_fingerprint == "ff00cd34ef56"
    lab = detail.groups[1].items[0]
    assert (lab.before, lab.after, lab.secret) == (None, None, True)
    assert "CANARY-secret" not in repr(detail)
    assert "CANARY-unclassified" not in repr(detail)


def test_the_detail_of_an_unknown_change_is_none(store: Database) -> None:
    assert ChangeQueries(store).get_change(99999) is None


def test_every_item_shows_a_rule_id_and_a_rationale(store: Database) -> None:
    rated = {"path": "name", "rule_id": "net-name", "rationale": "A rename is cosmetic."}
    without_rule = {"path": "mtu", "rule_id": None, "rationale": None}
    blank_rationale = {"path": "dhcp", "rule_id": "net-dhcp", "rationale": "   "}
    event_id = add_event(store, items=(rated, without_rule, blank_rationale))
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    items = [item for group in detail.groups for item in group.items]
    assert len(items) == 3
    assert all(item.rule_id and item.rationale for item in items)
    assert (items[0].rule_id, items[0].rationale) == ("net-name", "A rename is cosmetic.")
    assert items[0].rationale_recorded is True
    assert (items[1].rule_id, items[1].rationale) == (UNRATED_RULE_ID, UNRATED_RATIONALE)
    assert items[1].rationale_recorded is False
    assert (items[2].rule_id, items[2].rationale) == ("net-dhcp", UNRATED_RATIONALE)
    assert items[2].rationale_recorded is False


def test_an_order_move_is_read_into_its_parts(store: Database) -> None:
    move = {
        "path": "",
        "change_kind": "moved",
        "severity": "high",
        "order_detail": {
            "key": "r7",
            "from_after": "r2",
            "from_before": "r3",
            "to_after": None,
            "to_before": "r1",
            "summary": "r7 moved from after r2 to before r1",
        },
    }
    other = {"path": "name", "change_kind": "changed"}
    event_id = add_event(store, items=(move, other))
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    moved, renamed = detail.groups[0].items
    assert moved.move is not None
    assert (moved.move.key, moved.move.from_after, moved.move.to_after) == ("r7", "r2", None)
    assert moved.move.to_before == "r1"
    assert moved.move.summary == "r7 moved from after r2 to before r1"
    assert renamed.move is None


def test_vendor_text_passes_the_scrubber(store: Database) -> None:
    leaky = "https://user:CANARY-urlpass@host.example/path"
    item = {"object_name_at_time": leaky, "rationale": f"see {leaky}", "path": "url"}
    event_id = add_event(store, items=(item,))
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    assert "CANARY-urlpass" not in repr(detail)


def test_the_detail_flags_muted_items_and_says_which_can_be_muted(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    renamed = {"path": "name"}
    critical = {"path": "vlan", "severity": "critical"}
    drift = {"path": "a, b", "change_kind": "schema_drift", "object_name_at_time": None}
    event_id = add_event(store, items=(renamed, critical, drift))
    add_mute_row(store, operator.user_id, "networks", "name")
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    by_path = {item.path: item for group in detail.groups for item in group.items}
    assert (by_path["name"].muted, by_path["name"].mutable) == (True, True)
    assert (by_path["vlan"].muted, by_path["vlan"].mutable) == (False, False)
    assert (by_path["a, b"].muted, by_path["a, b"].mutable) == (False, False)
    assert detail.muted_item_count == 1


def test_the_detail_lists_notes_in_the_order_they_were_written(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    admin = make_principal(store, "ada", "admin")
    event_id = add_event(store)
    actions = ChangeActions(store)
    actions.add_note(operator, event_id, "first")
    actions.add_note(admin, event_id, "second")
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    written = [(note.author, note.body) for note in detail.notes]
    assert written == [("olga", "first"), ("ada", "second")]


# -- parsing a query string -----------------------------------------------------------------------


def test_a_query_string_is_read_into_filters() -> None:
    filters = parse_filters(
        {
            "q": [" firewall "],
            "source": ["3"],
            "severity": ["critical", "HIGH", "critical", "nonsense"],
            "status": ["open"],
            "resource": ["vms"],
            "from": ["2026-10-01"],
            "to": ["2026-10-22"],
            "sort": ["severity"],
            "page": ["4"],
            "muted": ["1"],
        }
    )
    assert filters == ChangeFilters(
        search="firewall",
        source_id=3,
        severities=("critical", "high"),
        status="open",
        resource="vms",
        created_from=date(2026, 10, 1),
        created_to=date(2026, 10, 22),
        sort="severity",
        page=4,
        include_muted=True,
    )


def test_a_query_string_with_bad_values_still_gives_filters() -> None:
    filters = parse_filters(
        {
            "source": ["x"],
            "status": ["everything"],
            "from": ["yesterday"],
            "to": ["2026-13-45"],
            "sort": ["random"],
            "page": ["-2"],
            "resource": [""],
        }
    )
    assert filters == ChangeFilters()
    assert parse_filters({}) == ChangeFilters()
    assert parse_filters({"source": ["99999999999"], "page": ["0"]}) == ChangeFilters()


# -- acknowledging, notes -------------------------------------------------------------------------


def test_acknowledging_twice_keeps_both_rows(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store, severity="critical", items=({"path": "name"},))
    moment = datetime(2026, 10, 22, 9, 0, tzinfo=UTC)
    actions = ChangeActions(store, clock=lambda: moment)
    first = actions.acknowledge(operator, event_id, "looked at it")
    second = actions.acknowledge(operator, event_id, "still fine")
    assert first.id != second.id
    assert first.created_at == "2026-10-22T09:00:00Z"
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    assert [row.comment for row in detail.acknowledgements] == ["looked at it", "still fine"]
    assert [row.author for row in detail.acknowledgements] == ["olga", "olga"]
    assert detail.change.status == "acknowledged"
    assert detail.change.severity == "critical"
    assert count_of(store, acknowledgements) == 2
    assert audit_actions(store).count(ACTION_ACKNOWLEDGED) == 2


def test_an_acknowledgement_may_have_no_comment_and_its_audit_event_holds_no_text(
    store: Database,
) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store)
    actions = ChangeActions(store)
    silent = actions.acknowledge(operator, event_id)
    loud = actions.acknowledge(operator, event_id, "CANARY-comment-text")
    assert silent.comment == ""
    assert loud.comment == "CANARY-comment-text"
    events = [row for row in rows_of(store, audit_events) if row.action == ACTION_ACKNOWLEDGED]
    assert [row.target for row in events] == [f"event:{event_id}"] * 2
    assert events[1].detail == {"acknowledgement_id": loud.id, "comment_chars": 19}
    assert "CANARY-comment-text" not in repr(events)


@pytest.mark.parametrize("role", ["operator", "admin"])
def test_an_operator_or_an_admin_may_acknowledge_and_note(store: Database, role: str) -> None:
    person = make_principal(store, "pat", role)
    event_id = add_event(store)
    actions = ChangeActions(store)
    assert actions.acknowledge(person, event_id, "ok").author == "pat"
    assert actions.add_note(person, event_id, "noted").author == "pat"
    assert audit_actions(store).count(ACTION_NOTE_ADDED) == 1


def test_a_viewer_can_read_but_not_act(store: Database) -> None:
    viewer = make_principal(store, "vera", "viewer")
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store, items=({"path": "name"},))
    mute_id = add_mute_row(store, operator.user_id, "vms", "name")
    item_id = first_item_id(store, event_id)
    before = stored_state(store)
    actions = ChangeActions(store)
    with pytest.raises(ActionForbiddenError):
        actions.acknowledge(viewer, event_id, "no")
    with pytest.raises(ActionForbiddenError):
        actions.add_note(viewer, event_id, "no")
    with pytest.raises(ActionForbiddenError):
        actions.mute_path(viewer, item_id)
    with pytest.raises(ActionForbiddenError):
        actions.remove_mute(viewer, mute_id)
    assert stored_state(store) == before
    assert ChangeQueries(store).get_change(event_id) is not None


def test_an_unknown_change_stores_nothing(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    before = stored_state(store)
    actions = ChangeActions(store)
    with pytest.raises(UnknownChangeError):
        actions.acknowledge(operator, 99999, "x")
    with pytest.raises(UnknownChangeError):
        actions.add_note(operator, 99999, "x")
    assert stored_state(store) == before


@pytest.mark.parametrize(
    "text",
    ["", "   \n", "x" * 4001, "bad\x00char", "bell\x07", "\ud800"],
    ids=["empty", "blank", "too-long", "nul", "bell", "lone-surrogate"],
)
def test_a_note_that_cannot_be_stored_is_refused(store: Database, text: str) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store)
    before = stored_state(store)
    with pytest.raises(InvalidTextError) as raised:
        ChangeActions(store).add_note(operator, event_id, text)
    assert "bell" not in str(raised.value)
    assert stored_state(store) == before


def test_an_acknowledgement_comment_has_a_limit_too(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store)
    with pytest.raises(InvalidTextError):
        ChangeActions(store).acknowledge(operator, event_id, "x" * 2001)
    assert count_of(store, acknowledgements) == 0
    assert ChangeActions(store).acknowledge(operator, event_id, "x" * 2000).comment == "x" * 2000


def test_markup_in_a_note_is_kept_as_typed(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store)
    note = ChangeActions(store).add_note(operator, event_id, "  <b>CANARY-bold</b>\nline two  ")
    assert note.body == "<b>CANARY-bold</b>\nline two"
    assert rows_of(store, notes)[0].body == "<b>CANARY-bold</b>\nline two"


def test_a_change_holds_a_bounded_number_of_notes(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store)
    with store.write() as connection:
        connection.execute(
            sa.insert(notes),
            [
                {
                    "event_id": event_id,
                    "user_id": operator.user_id,
                    "body": f"note {number}",
                    "created_at": STAMP,
                }
                for number in range(MAX_ENTRIES_PER_CHANGE)
            ],
        )
    before = stored_state(store)
    with pytest.raises(EntryLimitError):
        ChangeActions(store).add_note(operator, event_id, "one too many")
    assert stored_state(store) == before


# -- muting ---------------------------------------------------------------------------------------


def test_muting_a_path_stores_one_mute_and_hides_the_change(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store, items=({"path": "name"},))
    item_id = first_item_id(store, event_id)
    queries, actions = ChangeQueries(store), ChangeActions(store)
    result = actions.mute_path(operator, item_id, "  renamed by the lab  ")
    assert result.created is True
    assert result.mute.resource == "networks"
    assert (result.mute.path_pattern, result.mute.reason) == ("name", "renamed by the lab")
    assert queries.list_changes().rows == ()
    assert queries.list_changes(ChangeFilters(include_muted=True)).total == 1
    again = actions.mute_path(operator, item_id)
    assert (again.created, again.mute.id) == (False, result.mute.id)
    assert count_of(store, path_mutes) == 1
    assert audit_actions(store).count(ACTION_MUTE_ADDED) == 1
    listed = queries.list_mutes()
    assert [(mute.id, mute.author, mute.resource) for mute in listed] == [
        (result.mute.id, "olga", "networks")
    ]
    actions.remove_mute(operator, result.mute.id)
    assert queries.list_changes().total == 1
    assert audit_actions(store).count(ACTION_MUTE_REMOVED) == 1
    with pytest.raises(UnknownMuteError):
        actions.remove_mute(operator, result.mute.id)


def test_the_item_stays_stored_with_its_real_severity_when_muted(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store, severity="medium", items=({"path": "name", "severity": "medium"},))
    ChangeActions(store).mute_path(operator, first_item_id(store, event_id))
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    assert detail.change.severity == "medium"
    assert detail.groups[0].items[0].severity == "medium"
    assert detail.groups[0].items[0].muted is True


def test_the_same_path_in_another_spelling_is_the_same_mute(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    camel = add_event(store, items=({"path": "tlsVerify"},))
    snake = add_event(store, items=({"path": "tls_verify"},))
    actions = ChangeActions(store)
    first = actions.mute_path(operator, first_item_id(store, camel))
    second = actions.mute_path(operator, first_item_id(store, snake))
    assert (first.created, second.created) == (True, False)
    assert count_of(store, path_mutes) == 1


def test_the_reason_of_a_mute_has_a_limit(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    event_id = add_event(store, items=({"path": "name"},))
    before = stored_state(store)
    with pytest.raises(InvalidTextError):
        ChangeActions(store).mute_path(operator, first_item_id(store, event_id), "x" * 501)
    assert stored_state(store) == before


def test_items_that_cannot_be_muted_are_refused(store: Database) -> None:
    operator = make_principal(store, "olga", "operator")
    critical = add_event(store, items=({"path": "name", "severity": "critical"},))
    drift = add_event(store, items=({"path": "a, b", "change_kind": "schema_drift"},))
    wildcard = add_event(store, items=({"path": "rules.*"},))
    before = stored_state(store)
    actions = ChangeActions(store)
    for event_id in (critical, drift, wildcard):
        with pytest.raises(NotMutableError):
            actions.mute_path(operator, first_item_id(store, event_id))
    with pytest.raises(UnknownItemError):
        actions.mute_path(operator, 99999)
    assert stored_state(store) == before


# -- the escaping contract ------------------------------------------------------------------------

DETAIL_TEMPLATE = (
    "<h1>{{ view.change.source_name }} {{ view.change.summary }}</h1>"
    "{% for group in view.groups %}<h2>{{ group.object_name }}</h2>"
    "{% for item in group.items %}<p>{{ item.rationale }} {{ item.path }}</p>{% endfor %}"
    "{% endfor %}"
    "{% for ack in view.acknowledgements %}<li>{{ ack.comment }}</li>{% endfor %}"
    "{% for note in view.notes %}<li>{{ note.body }}</li>{% endfor %}"
    "{% for found in view.enrichments %}"
    "<p>{{ found.provider_label }} {{ found.summary }} {{ found.payload['html'] }}</p>"
    "{% endfor %}"
)


def plant_payloads(store: Database) -> int:
    """A change whose names, rationale, source, notes, comments and enrichments hold markup."""
    operator = make_principal(store, "olga", "operator")
    items = tuple(
        {
            "path": f"net.{number}",
            "object_name_at_time": text,
            "rationale": text,
            "resource": "networks",
        }
        for number, text in enumerate(PAYLOADS)
    )
    event_id = add_event(store, items=items, summary=PAYLOADS[0])
    actions = ChangeActions(store)
    for text in PAYLOADS:
        actions.add_note(operator, event_id, text)
        actions.acknowledge(operator, event_id, text)
    with store.write() as connection:
        connection.execute(sa.update(sources).where(sources.c.id == 1).values(name=PAYLOADS[1]))
        token_id = connection.execute(
            sa.text(
                "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, scopes) "
                "VALUES (:user_id, 'canary', 'CANARY-p', 'canary-hash', '[]') RETURNING id"
            ),
            {"user_id": operator.user_id},
        ).scalar_one()
        for text in PAYLOADS:
            connection.execute(
                sa.insert(enrichments).values(
                    event_id=event_id,
                    token_id=token_id,
                    provider_label=text,
                    summary=text,
                    payload={"html": text, text: [text]},
                    created_at=STAMP,
                )
            )
    return event_id


def walk_text(value: Any) -> Iterable[Any]:
    """Every value inside a view: dataclass fields, tuples, lists and dicts, depth first."""
    yield value
    if is_dataclass(value) and not isinstance(value, type):
        for part in fields(value):
            yield from walk_text(getattr(value, part.name))
    elif isinstance(value, tuple | list):
        for member in value:
            yield from walk_text(member)
    elif isinstance(value, dict):
        for key, member in value.items():
            yield from walk_text(key)
            yield from walk_text(member)


def test_every_text_is_plain_text_and_prints_escaped(store: Database) -> None:
    event_id = plant_payloads(store)
    detail = ChangeQueries(store).get_change(event_id)
    assert detail is not None
    # The contract: stored characters come back as they were, as plain str, never as Markup.
    assert not any(isinstance(value, Markup) for value in walk_text(detail))
    assert [note.body for note in detail.notes] == list(PAYLOADS)
    assert [row.comment for row in detail.acknowledgements] == list(PAYLOADS)
    assert [row.provider_label for row in detail.enrichments] == list(PAYLOADS)
    assert [row.summary for row in detail.enrichments] == list(PAYLOADS)
    assert [row.payload["html"] for row in detail.enrichments] == list(PAYLOADS)
    assert [group.object_name for group in detail.groups] == list(PAYLOADS)
    assert detail.change.source_name == PAYLOADS[1]
    # The template side: autoescape turns every payload into text.
    template = make_environment().from_string(DETAIL_TEMPLATE)
    html = template.render(view=detail)
    for tag in ("<script", "<img", "<svg"):
        assert tag not in html
    for text in PAYLOADS:
        assert str(escape(text)) in html
    assert "CANARY-xss-0" in html
    assert html.count("&lt;script&gt;") >= len(PAYLOADS)


def test_the_list_rows_are_plain_text_too(store: Database) -> None:
    plant_payloads(store)
    page = ChangeQueries(store).list_changes()
    assert not any(isinstance(value, Markup) for value in walk_text(page))
    assert page.rows[0].summary == PAYLOADS[0]
    assert page.rows[0].source_name == PAYLOADS[1]
    template = make_environment().from_string("{{ row.source_name }} {{ row.summary }}")
    html = template.render(row=page.rows[0])
    assert "<script" not in html
    assert "<img" not in html
