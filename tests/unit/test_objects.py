"""Tests for core/objects.py: first_seen_at, last_seen_at and removed_at of every object."""

import sqlalchemy as sa

from driftsniff.core.objects import ObjectChanges, update_objects
from driftsniff.core.snapshots import CollectedObject, CollectedResource, Manifest, build_manifest
from driftsniff.db import tables
from driftsniff.db.engine import Database

SOURCE_ID = 1
T1 = "2026-10-20T10:00:00Z"
T2 = "2026-10-20T10:05:00Z"
T3 = "2026-10-20T10:10:00Z"


def manifest_of(
    networks: dict[str, str | None], rules: dict[str, str | None] | None = None
) -> Manifest:
    resources = {
        "networks": CollectedResource(
            [CollectedObject(key, {"_id": key}, name) for key, name in networks.items()]
        )
    }
    if rules is not None:
        resources["rules"] = CollectedResource(
            [CollectedObject(key, {"_id": key}, name) for key, name in rules.items()]
        )
    return build_manifest(resources, controller_version=None)


def apply(database: Database, manifest: Manifest, seen_at: str) -> ObjectChanges:
    with database.write() as connection:
        return update_objects(connection, SOURCE_ID, manifest, seen_at=seen_at)


type Row = tuple[str | None, str, str, str | None]


def rows(database: Database, resource: str = "networks") -> dict[str, Row]:
    """object_key -> (display_name, first_seen_at, last_seen_at, removed_at)."""
    with database.read() as connection:
        found = connection.execute(
            sa.select(
                tables.objects.c.object_key,
                tables.objects.c.display_name,
                tables.objects.c.first_seen_at,
                tables.objects.c.last_seen_at,
                tables.objects.c.removed_at,
            ).where(tables.objects.c.resource == resource)
        ).all()
    return {row[0]: (row[1], row[2], row[3], row[4]) for row in found}


def test_new_objects_are_added_with_their_first_and_last_seen_time(store: Database) -> None:
    changes = apply(store, manifest_of({"n1": "LAN", "n2": "Guest"}), T1)
    assert changes == ObjectChanges(added=2, removed=0, reappeared=0)
    assert rows(store) == {"n1": ("LAN", T1, T1, None), "n2": ("Guest", T1, T1, None)}


def test_a_later_snapshot_moves_last_seen_and_keeps_first_seen(store: Database) -> None:
    apply(store, manifest_of({"n1": "LAN"}), T1)
    changes = apply(store, manifest_of({"n1": "LAN", "n2": "Guest"}), T2)
    assert changes == ObjectChanges(added=1, removed=0, reappeared=0)
    assert rows(store) == {"n1": ("LAN", T1, T2, None), "n2": ("Guest", T2, T2, None)}


def test_an_object_that_disappears_is_marked_removed(store: Database) -> None:
    apply(store, manifest_of({"n1": "LAN", "n2": "Guest"}), T1)
    changes = apply(store, manifest_of({"n1": "LAN"}), T2)
    assert changes == ObjectChanges(added=0, removed=1, reappeared=0)
    assert rows(store) == {"n1": ("LAN", T1, T2, None), "n2": ("Guest", T1, T1, T2)}


def test_a_removed_object_keeps_its_first_removal_time(store: Database) -> None:
    apply(store, manifest_of({"n1": "LAN", "n2": "Guest"}), T1)
    apply(store, manifest_of({"n1": "LAN"}), T2)
    changes = apply(store, manifest_of({"n1": "LAN", "n3": "Lab"}), T3)
    assert changes == ObjectChanges(added=1, removed=0, reappeared=0)
    assert rows(store)["n2"] == ("Guest", T1, T1, T2)


def test_an_object_that_comes_back_is_no_longer_removed(store: Database) -> None:
    apply(store, manifest_of({"n1": "LAN", "n2": "Guest"}), T1)
    apply(store, manifest_of({"n1": "LAN"}), T2)
    changes = apply(store, manifest_of({"n1": "LAN", "n2": "Guest"}), T3)
    assert changes == ObjectChanges(added=0, removed=0, reappeared=1)
    assert rows(store)["n2"] == ("Guest", T1, T3, None)
    assert len(rows(store)) == 2


def test_a_missing_name_keeps_the_old_one_and_a_new_name_replaces_it(store: Database) -> None:
    apply(store, manifest_of({"n1": "LAN"}), T1)
    apply(store, manifest_of({"n1": None}), T2)
    assert rows(store)["n1"][0] == "LAN"
    apply(store, manifest_of({"n1": "Office LAN"}), T3)
    assert rows(store)["n1"][0] == "Office LAN"


def test_an_object_without_any_name_stays_unnamed(store: Database) -> None:
    apply(store, manifest_of({"n1": None}), T1)
    assert rows(store)["n1"][0] is None


def test_resources_are_tracked_separately_and_only_those_in_the_manifest(store: Database) -> None:
    apply(store, manifest_of({"n1": "LAN"}, {"r1": "Allow DNS"}), T1)
    # The next manifest has no rules resource at all: its objects are left alone.
    changes = apply(store, manifest_of({"n1": "LAN"}), T2)
    assert changes == ObjectChanges(added=0, removed=0, reappeared=0)
    assert rows(store, "rules") == {"r1": ("Allow DNS", T1, T1, None)}
    # An empty rules resource is a collection that found no rules: the rule is removed.
    empty = build_manifest({"rules": CollectedResource([])}, controller_version=None)
    assert apply(store, empty, T3) == ObjectChanges(added=0, removed=1, reappeared=0)
    assert rows(store, "rules")["r1"][3] == T3


def test_many_removals_are_applied_in_batches(store: Database) -> None:
    keys = {f"n{number}": None for number in range(1200)}
    apply(store, manifest_of(keys), T1)
    changes = apply(store, manifest_of({}), T2)
    assert changes == ObjectChanges(added=0, removed=1200, reappeared=0)
    assert all(row[3] == T2 for row in rows(store).values())
