"""The UniFi version-band fixtures and the pipeline helpers the P7-T5 contract tests share.

``tests/fixtures/unifi/band-<name>.json`` is one hand written controller per version band: the
floor (10.1.84), a reference band (10.3.58) and a newest band (10.4.12). Everything in them is
**unverified** (dependency D5, the vendor reference, is open; no lab controller was used), and the
version of the newest band and the two fields it adds are invented.

The files hold no secret value, not even a made-up one. A string that starts with ``@canary:`` is a
placeholder; :func:`band_scenario` replaces it with the value its :class:`Seeds` gives for the
label, so the same label always gets the same value inside one test and a different value in the
next one.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import sqlalchemy as sa

from driftsniff.collectors.unifi.client import UnifiClient
from driftsniff.db import tables
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_unifi import CANARY_HEADER, FakeUnifi, Scenario

BANDS: Final = ("floor", "reference", "newest")
FIXTURE_DIR: Final = Path(__file__).resolve().parents[1] / "fixtures" / "unifi"
PLACEHOLDER: Final = "@canary:"
SOURCE_ID: Final = 1

# The secret class fields the bands seed: resource path below a site, and the path of the field.
SECRET_FIELDS: Final = {
    "wifi/broadcasts": "securityConfiguration.passphrase",
    "radius/profiles": "sharedSecret",
    "vpn/servers": "preSharedKey",
    "vpn/site-to-site-tunnels": "preSharedKey",
}


class Seeds:
    """The value of every placeholder label; one label always gives the same value."""

    def __init__(self, make: Callable[[str], str] | None = None) -> None:
        self._make = make or (lambda label: f"not a secret, label {label}")
        self.values: dict[str, str] = {}

    def value(self, label: str) -> str:
        if label not in self.values:
            self.values[label] = self._make(label)
        return self.values[label]


def band_path(name: str) -> Path:
    return FIXTURE_DIR / f"band-{name}.json"


def load_band_file(name: str) -> dict[str, Any]:
    """The JSON of one band, placeholders untouched."""
    loaded = json.loads(band_path(name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _seeded(value: Any, seeds: Seeds) -> Any:
    if isinstance(value, str) and value.startswith(PLACEHOLDER):
        return seeds.value(value.removeprefix(PLACEHOLDER))
    if isinstance(value, list):
        return [_seeded(item, seeds) for item in value]
    if isinstance(value, dict):
        return {key: _seeded(item, seeds) for key, item in value.items()}
    return value


def band_scenario(name: str, seeds: Seeds) -> Scenario:
    """The fake controller of one band, with the placeholders replaced by ``seeds``."""
    data = load_band_file(name)
    firewall_order = {
        (entry["site"], entry["source"], entry["destination"]): (
            list(entry["before"]),
            list(entry["after"]),
        )
        for entry in data["firewallOrder"]
    }
    return Scenario(
        version=data["applicationVersion"],
        objects=_seeded(data["objects"], seeds),
        firewall_order=firewall_order,
        acl_order={site: list(ids) for site, ids in data["aclOrder"].items()},
    )


class Clock:
    """UTC timestamps one second apart."""

    def __init__(self) -> None:
        self.second = 0

    def __call__(self) -> str:
        self.second += 1
        moment = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC) + timedelta(seconds=self.second)
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def open_database(directory: Path) -> Database:
    """A migrated database with one UniFi source (id 1)."""
    store = Database(database_path(directory))
    upgrade_to_head(store)
    with store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (1, 'lab-controller', 'unifi')"
        )
    return store


def make_pipeline(database: Database) -> RunPipeline:
    """The run pipeline with the shipped rules, a fixed fingerprint key and no waiting."""
    return RunPipeline(
        database,
        RuleEngine(load_rules()),
        Fingerprinter(bytes(range(32)), "0a1b2c3d"),
        clock=Clock(),
        sleep=lambda _seconds: None,
    )


def collect(
    pipeline: RunPipeline, server: FakeUnifi, *, key: str = CANARY_HEADER, **options: Any
) -> RunReport:
    """One run of the real client against the fake controller."""
    client = UnifiClient(server.url, key, allow_plain_http=True, **options)
    return pipeline.run(SOURCE_ID, client)


def coverage_rows(database: Database) -> dict[str, sa.Row[tuple[object, ...]]]:
    """The coverage row of every resource, by resource name."""
    with database.read() as connection:
        rows = connection.execute(sa.select(tables.resource_coverage))
        return {str(row.resource): row for row in rows}


def change_item_rows(database: Database) -> list[sa.Row[tuple[object, ...]]]:
    """Every stored change item, oldest first."""
    with database.read() as connection:
        return list(
            connection.execute(sa.select(tables.change_items).order_by(tables.change_items.c.id))
        )
