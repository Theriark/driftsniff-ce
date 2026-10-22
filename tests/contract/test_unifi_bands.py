"""The UniFi version-band fixtures through the real collector (P7-T5).

``tests/fixtures/unifi/band-*.json`` holds one hand written controller per version band: the floor
(10.1.84), a reference band (10.3.58) and the newest band (10.4.12). Every name in them is
unverified against the vendor reference (dependency D5 is open) and the newest band is invented.

The tests check that the files are well formed and hold no secret, that every band is collected in
full with one coverage row per resource, and that a field which is absent at the floor and present
at the newest band is reported once as schema drift and never as a change of every object.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.unifi.client import FLOOR_VERSION, parse_version
from driftsniff.collectors.unifi.resources import RESOURCES
from driftsniff.db.engine import Database
from driftsniff.sources.runs import RunReport

from .fake_unifi import fake_unifi
from .unifi_bands import (
    BANDS,
    PLACEHOLDER,
    SECRET_FIELDS,
    Seeds,
    band_path,
    band_scenario,
    change_item_rows,
    collect,
    coverage_rows,
    load_band_file,
    make_pipeline,
    open_database,
)

DRIFT_RULE = "builtin.schema_drift"


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    store = open_database(tmp_path)
    try:
        yield store
    finally:
        store.close()


def dig(value: Any, path: str) -> Any:
    for part in path.split("."):
        value = value[part]
    return value


def run_bands(database: Database, *bands: str, seeds: Seeds | None = None) -> list[RunReport]:
    """Collect the bands one after the other, into the same database, as upgrades of one source."""
    shared = seeds or Seeds()
    pipeline = make_pipeline(database)
    reports: list[RunReport] = []
    for band in bands:
        with fake_unifi(band_scenario(band, shared)) as server:
            reports.append(collect(pipeline, server))
    return reports


def stored_items(database: Database) -> list[tuple[str, str, str, str | None, str | None]]:
    """Resource, kind, path, severity and rule of every stored item, sorted."""
    return sorted(
        (row.resource, row.change_kind, row.path, row.severity, row.rule_id)
        for row in change_item_rows(database)
    )


# -- the files ---------------------------------------------------------------------------------


@pytest.mark.parametrize("band", BANDS)
def test_a_band_file_is_marked_unverified_and_holds_a_placeholder_in_every_secret_field(
    band: str,
) -> None:
    data = load_band_file(band)
    text = band_path(band).read_text(encoding="utf-8")
    assert data["band"] == band
    assert data["unverified"] is True
    assert "CANARY-" not in text
    seeded = 0
    for resource, path in SECRET_FIELDS.items():
        objects = data["objects"][resource]
        assert len(objects) >= 2
        for item in objects:
            assert dig(item, path).startswith(PLACEHOLDER)
            seeded += 1
    # The placeholders sit in the secret fields and nowhere else.
    assert text.count('"' + PLACEHOLDER) == seeded


def test_the_bands_rise_from_the_floor_and_cover_every_resource_the_client_reads() -> None:
    versions: list[tuple[int, int, int]] = []
    for band in BANDS:
        version = parse_version(load_band_file(band)["applicationVersion"])
        assert version is not None
        versions.append(version)
    assert versions[0] == FLOOR_VERSION
    assert versions == sorted(set(versions))
    wanted = {item.site_path.lstrip("/") for item in RESOURCES if item.site_path is not None}
    for band in BANDS:
        assert set(load_band_file(band)["objects"]) == wanted


def test_the_same_label_gives_the_same_secret_in_every_band() -> None:
    seeds = Seeds()
    floor = band_scenario("floor", seeds)
    newest = band_scenario("newest", seeds)
    assert floor.objects["radius/profiles"] == newest.objects["radius/profiles"]
    assert len(seeds.values) == 8
    other = band_scenario("floor", Seeds(lambda label: "other " + label))
    assert other.objects["radius/profiles"] != floor.objects["radius/profiles"]


# -- every band, in full -----------------------------------------------------------------------


@pytest.mark.parametrize("band", BANDS)
def test_a_band_is_collected_in_full_with_a_coverage_row_for_every_resource(
    band: str, database: Database
) -> None:
    scenario = band_scenario(band, Seeds())
    with fake_unifi(scenario) as server:
        report = collect(make_pipeline(database), server)
    assert (report.status, report.error_class) == ("ok", None)
    # The site, and every object of every resource.
    assert report.object_count == 1 + sum(len(objects) for objects in scenario.objects.values())
    rows = coverage_rows(database)
    assert sorted(rows) == sorted(item.name for item in RESOURCES)
    for item in RESOURCES:
        count = 1 if item.site_path is None else len(scenario.objects[item.site_path.lstrip("/")])
        row = rows[item.name]
        assert (row.last_status, row.object_count, row.stale_since) == ("200", count, None)
        assert row.last_ok_at is not None
    assert change_item_rows(database) == []


# -- an upgrade between bands ------------------------------------------------------------------


NEW_FIELD_ITEMS = [
    ("unifi-networks", "schema_drift", "igmpSnoopingEnabled", "low", DRIFT_RULE),
    ("unifi-wifi-broadcasts", "schema_drift", "bandSteeringEnabled", "low", DRIFT_RULE),
]


def test_fields_new_at_the_newest_band_are_schema_drift_and_not_a_change_per_object(
    database: Database,
) -> None:
    first, second = run_bands(database, "floor", "newest")
    assert (first.status, first.event_id) == ("ok", None)
    assert (second.status, second.error_class) == ("ok", None)
    assert second.event_id is not None
    assert stored_items(database) == NEW_FIELD_ITEMS
    assert all(row.object_id is None for row in change_item_rows(database))


def test_an_upgrade_through_the_reference_band_reports_the_drift_once_and_nothing_before(
    database: Database,
) -> None:
    floor, reference, newest, again = run_bands(database, "floor", "reference", "newest", "newest")
    # The reference band differs from the floor only in values the type table calls volatile.
    assert (reference.status, reference.event_id) == ("ok", None)
    assert stored_items(database) == NEW_FIELD_ITEMS
    assert (floor.event_id, newest.status) == (None, "ok")
    assert newest.event_id is not None
    assert (again.status, again.event_id, again.stored_new_snapshot) == ("ok", None, False)


def test_a_new_field_on_only_one_object_is_an_ordinary_change_and_not_drift(
    database: Database,
) -> None:
    seeds = Seeds()
    pipeline = make_pipeline(database)
    with fake_unifi(band_scenario("floor", seeds)) as server:
        collect(pipeline, server)
    scenario = band_scenario("newest", seeds)
    del scenario.objects["wifi/broadcasts"][1]["bandSteeringEnabled"]
    with fake_unifi(scenario) as server:
        report = collect(pipeline, server)
    assert report.event_id is not None
    items = [
        (row.resource, row.change_kind, row.path, row.object_name_at_time)
        for row in change_item_rows(database)
    ]
    assert sorted(items) == [
        ("unifi-networks", "schema_drift", "igmpSnoopingEnabled", None),
        ("unifi-wifi-broadcasts", "added", "bandSteeringEnabled", "Staff"),
    ]
