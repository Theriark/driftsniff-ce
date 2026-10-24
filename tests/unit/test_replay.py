"""The change replay data (WP4a): counts per UTC day, resource type and severity.

The service runs against a migrated database seeded with plain inserts, the way the run pipeline
writes events and items. The pure ``build_replay`` is checked on plain values. The role and
canary checks of the route are in ``tests/security/test_replay_routes.py``.
"""

from datetime import UTC, date, datetime, timedelta, timezone

import pytest
import sqlalchemy as sa

from driftsniff.db.engine import Database
from driftsniff.db.tables import change_events, change_items, snapshots
from driftsniff.web.replay import (
    DEFAULT_DAYS,
    MAX_DAYS,
    ReplayCell,
    ReplayResource,
    ReplayService,
    build_replay,
    clamp_days,
)
from driftsniff.web.templating import SEVERITIES

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
TODAY = NOW.date()


def add_event(
    store: Database,
    created_at: str,
    items: list[tuple[str, str]],
    *,
    source_id: int = 1,
) -> int:
    """An event of ``source_id`` made at ``created_at``, with one item per (resource, severity)."""
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
        event_id = int(
            connection.execute(
                sa.insert(change_events)
                .values(
                    source_id=source_id,
                    snapshot_id=snapshot_id,
                    window_start=created_at,
                    window_end=created_at,
                    max_severity=max((s for _, s in items), key=SEVERITIES.index, default="low"),
                    item_count=len(items),
                    summary="a summary",
                    rule_pack_version="pack-1",
                    created_at=created_at,
                )
                .returning(change_events.c.id)
            ).scalar_one()
        )
        for resource, severity in items:
            connection.execute(
                sa.insert(change_items).values(
                    event_id=event_id,
                    resource=resource,
                    change_kind="changed",
                    path="name",
                    field_class="config",
                    severity=severity,
                )
            )
    return event_id


def service(store: Database) -> ReplayService:
    return ReplayService(store, clock=lambda: NOW)


def cells(store: Database, days: int = DEFAULT_DAYS) -> list[tuple[str, str, str, int]]:
    replay = service(store).load(1, days)
    assert replay is not None
    return [(c.day, c.resource, c.severity, c.count) for c in replay.cells]


# ---- build_replay (pure) -----------------------------------------------------------------------


def test_no_rows_is_an_empty_replay_of_the_whole_window() -> None:
    replay = build_replay(7, date(2026, 10, 1), date(2026, 10, 30), [])
    assert (replay.source_id, replay.first_day, replay.last_day) == (7, "2026-10-01", "2026-10-30")
    assert (replay.days, replay.total, replay.cells, replay.resources) == (30, 0, (), ())
    assert replay.severities == SEVERITIES


def test_cells_are_ordered_by_day_then_resource_then_severity() -> None:
    rows = [
        ("2026-10-02", "networks", "high", 1),
        ("2026-10-01", "vms", "critical", 1),
        ("2026-10-01", "networks", "critical", 2),
        ("2026-10-01", "networks", "low", 3),
        ("2026-10-01", "networks", "medium", 4),
    ]
    replay = build_replay(1, date(2026, 10, 1), date(2026, 10, 2), rows)
    assert [(c.day, c.resource, c.severity) for c in replay.cells] == [
        ("2026-10-01", "networks", "low"),
        ("2026-10-01", "networks", "medium"),
        ("2026-10-01", "networks", "critical"),
        ("2026-10-01", "vms", "critical"),
        ("2026-10-02", "networks", "high"),
    ]
    assert replay.total == 11


def test_rows_of_one_cell_are_added_and_bad_rows_are_left_out() -> None:
    rows = [
        ("2026-10-01", "vms", "low", 2),
        ("2026-10-01", "vms", "low", 3),
        ("2026-10-01", "vms", "low", 0),
        ("2026-10-01", "vms", "bogus", 9),
    ]
    replay = build_replay(1, date(2026, 10, 1), date(2026, 10, 1), rows)
    assert replay.cells == (ReplayCell("2026-10-01", "vms", "low", 5),)
    assert replay.total == 5


def test_resources_are_ordered_by_total_then_name_with_readable_labels() -> None:
    rows = [
        ("2026-10-01", "vms", "low", 2),
        ("2026-10-02", "vms", "high", 1),
        ("2026-10-01", "networks", "low", 3),
        ("2026-10-01", "hosts", "low", 3),
    ]
    replay = build_replay(1, date(2026, 10, 1), date(2026, 10, 2), rows)
    assert replay.resources == (
        ReplayResource("hosts", "Hosts", 3),
        ReplayResource("networks", "Networks", 3),
        ReplayResource("vms", "Virtual machines", 3),
    )


@pytest.mark.parametrize(
    ("asked", "kept"), [(-5, 1), (0, 1), (1, 1), (30, 30), (MAX_DAYS, MAX_DAYS), (10_000, MAX_DAYS)]
)
def test_the_window_is_kept_between_one_day_and_the_maximum(asked: int, kept: int) -> None:
    assert clamp_days(asked) == kept


# ---- the service -------------------------------------------------------------------------------


def test_an_unknown_source_is_none(store: Database) -> None:
    assert service(store).load(99999) is None


def test_a_source_without_changes_has_an_empty_replay(store: Database) -> None:
    replay = service(store).load(1)
    assert replay is not None
    assert (replay.cells, replay.resources, replay.total) == ((), (), 0)
    assert replay.last_day == TODAY.isoformat()
    assert replay.first_day == (TODAY - timedelta(days=DEFAULT_DAYS - 1)).isoformat()
    assert replay.days == DEFAULT_DAYS


def test_several_days_are_counted_per_day(store: Database) -> None:
    add_event(store, "2026-10-20T08:00:00Z", [("networks", "low")])
    add_event(store, "2026-10-21T09:00:00Z", [("networks", "low"), ("networks", "low")])
    add_event(store, "2026-10-22T10:00:00Z", [("networks", "low")])
    assert cells(store) == [
        ("2026-10-20", "networks", "low", 1),
        ("2026-10-21", "networks", "low", 2),
        ("2026-10-22", "networks", "low", 1),
    ]


def test_events_of_one_day_are_added_into_one_cell(store: Database) -> None:
    add_event(store, "2026-10-22T01:00:00Z", [("vms", "high")])
    add_event(store, "2026-10-22T23:00:00Z", [("vms", "high"), ("vms", "high")])
    assert cells(store) == [("2026-10-22", "vms", "high", 3)]


def test_types_and_severities_are_counted_apart(store: Database) -> None:
    add_event(
        store,
        "2026-10-22T08:00:00Z",
        [("vms", "low"), ("vms", "critical"), ("hosts", "medium"), ("vms", "low")],
    )
    replay = service(store).load(1)
    assert replay is not None
    assert [(c.resource, c.severity, c.count) for c in replay.cells] == [
        ("hosts", "medium", 1),
        ("vms", "low", 2),
        ("vms", "critical", 1),
    ]
    assert [(r.resource, r.count) for r in replay.resources] == [("vms", 3), ("hosts", 1)]
    assert replay.total == 4


def test_the_day_of_an_item_is_the_utc_day_around_midnight(store: Database) -> None:
    add_event(store, "2026-10-20T23:59:59Z", [("vms", "low")])
    add_event(store, "2026-10-21T00:00:00Z", [("vms", "low")])
    add_event(store, "2026-10-21T00:00:01Z", [("vms", "low")])
    assert cells(store) == [("2026-10-20", "vms", "low", 1), ("2026-10-21", "vms", "low", 2)]


def test_the_window_starts_at_midnight_utc_of_its_first_day(store: Database) -> None:
    # days=3 on 2026-10-22: the first day is 2026-10-20.
    add_event(store, "2026-10-19T23:59:59Z", [("vms", "low")])
    add_event(store, "2026-10-20T00:00:00Z", [("vms", "medium")])
    assert cells(store, 3) == [("2026-10-20", "vms", "medium", 1)]
    replay = service(store).load(1, 3)
    assert replay is not None
    assert (replay.first_day, replay.last_day, replay.days) == ("2026-10-20", "2026-10-22", 3)


def test_the_window_ends_with_the_last_instant_of_today(store: Database) -> None:
    add_event(store, "2026-10-22T23:59:59Z", [("vms", "low")])
    add_event(store, "2026-10-23T00:00:00Z", [("vms", "high")])
    assert cells(store) == [("2026-10-22", "vms", "low", 1)]


def test_one_day_is_today_only(store: Database) -> None:
    add_event(store, "2026-10-21T23:59:59Z", [("vms", "low")])
    add_event(store, "2026-10-22T00:00:00Z", [("vms", "low")])
    assert cells(store, 1) == [("2026-10-22", "vms", "low", 1)]


def test_the_clock_is_read_in_utc_whatever_its_zone(store: Database) -> None:
    # 2026-10-23 01:30 at UTC+3 is 2026-10-22 22:30 UTC: today is still the 22nd.
    local = datetime(2026, 10, 23, 1, 30, tzinfo=timezone(timedelta(hours=3)))
    add_event(store, "2026-10-22T22:00:00Z", [("vms", "low")])
    replay = ReplayService(store, clock=lambda: local).load(1, 1)
    assert replay is not None
    assert replay.last_day == "2026-10-22"
    assert [(c.day, c.count) for c in replay.cells] == [("2026-10-22", 1)]


def test_a_window_longer_than_the_maximum_is_the_maximum(store: Database) -> None:
    oldest = TODAY - timedelta(days=MAX_DAYS - 1)
    add_event(store, f"{oldest.isoformat()}T00:00:00Z", [("vms", "low")])
    add_event(store, f"{(oldest - timedelta(days=1)).isoformat()}T23:59:59Z", [("vms", "low")])
    replay = service(store).load(1, 10_000)
    assert replay is not None
    assert replay.days == MAX_DAYS
    assert [(c.day, c.count) for c in replay.cells] == [(oldest.isoformat(), 1)]


def test_only_the_items_of_the_source_are_counted(store: Database) -> None:
    with store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (2, 'other', 'push')"
        )
    add_event(store, "2026-10-22T08:00:00Z", [("vms", "low")])
    add_event(store, "2026-10-22T08:00:00Z", [("hosts", "critical")] * 4, source_id=2)
    assert cells(store) == [("2026-10-22", "vms", "low", 1)]
    other = service(store).load(2)
    assert other is not None
    assert [(c.resource, c.count) for c in other.cells] == [("hosts", 4)]
