"""Development-only synthetic changes, so the populated screens can be judged (docs/dev-fixture.md).

On the Development site one push source and no change would leave the change list, the dashboard
and the history empty. This module makes one clearly labelled push source and runs four synthetic
documents through the real run pipeline (the one a polled source uses, with the shipped rules), so
there are change events across several resource types and all four severities. Rules, and why:

- It runs at start-up only for a ``ce-dev-<name>.theriark.dev`` address and no other environment
  badge (the guard of ``devseed``), so Stage and Production never get it.
- The source is named :data:`FIXTURE_SOURCE_NAME` and has no sender key: nothing can push to it
  from outside, and no credential is made. Delete the source on the Sources page (an admin) and
  everything recorded for it goes with it; a later start does not make it again.
- Every value is synthetic: ``fx-`` ids, ``FIXTURE`` names, ``.example`` domains and ``CANARY-``
  secrets, which the pipeline stores as fingerprints only. No address of any kind is used.
- A second start changes nothing: the steps that already ran are not run again, and a step that
  failed is tried again at the next start.
- It uses its own pipeline without a notifier, so the fixture sends no notification.
- A failure is logged and never stops the application from starting.
"""

import copy
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

from driftsniff.collectors.push import PushCollector
from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import audit_events, runs
from driftsniff.devseed import DevSeedRefusedError, check_development_startup
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import RuleLoadError, load_rules
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import MasterKey
from driftsniff.secrets.scanner import OverrideFileError, load_overrides
from driftsniff.sources.runs import RunPipeline
from driftsniff.sources.service import (
    ACTION_DELETE,
    OPTION_PUSH_FIELDS,
    SourceError,
    SourceService,
    SourceValidationError,
)
from driftsniff.web.auth import ACTOR_SYSTEM

FIXTURE_SOURCE_NAME: Final = "DEV-FIXTURE synthetic (removable)"

_LOG = logging.getLogger(__name__)

Document = dict[str, list[dict[str, Any]]]

# The top-level fields kept for each resource; the rest of a pushed object is dropped. The names are
# the ones of the shipped type tables (rules/types/unifi.yaml).
PUSH_FIELDS: Final[dict[str, list[str]]] = {
    "unifi-devices": ["id", "name", "model", "firmwareVersion", "state"],
    "unifi-dns-policies": ["id", "type", "enabled", "domain"],
    "unifi-firewall-zones": ["id", "name", "networkIds"],
    "unifi-networks": ["id", "name", "enabled", "management", "vlanId", "internetAccessEnabled"],
    "unifi-radius-profiles": ["id", "name", "sharedSecret"],
    "unifi-vpn-servers": ["id", "name", "type", "enabled", "preSharedKey"],
    "unifi-wifi-broadcasts": [
        "id",
        "name",
        "enabled",
        "network",
        "securityConfiguration",
        "clientIsolationEnabled",
    ],
}


class DevFixtureError(Exception):
    """The fixture cannot run or cannot finish; messages never hold a secret."""


def _canary(name: str) -> str:
    """A synthetic secret value, built here so that no secret-shaped literal is committed."""
    return f"CANARY-fixture-{name}"


@dataclass(frozen=True, slots=True)
class FixtureReport:
    """What a run did.

    ``removed`` is true when the source was deleted earlier, so nothing was made. ``created`` is
    true when this run made the source. ``pushed`` is the number of documents run now and
    ``events`` how many of them produced a change event.
    """

    created: bool
    removed: bool
    pushed: int
    events: int


def _baseline() -> Document:
    """The first document: nothing changed yet, so it is only the baseline snapshot."""
    return {
        "unifi-networks": [
            {
                "id": "fx-net-office",
                "name": "FIXTURE Office",
                "enabled": True,
                "management": "GATEWAY",
                "vlanId": 10,
                "internetAccessEnabled": True,
            },
            {
                "id": "fx-net-guest",
                "name": "FIXTURE Guest",
                "enabled": True,
                "management": "GATEWAY",
                "vlanId": 30,
                "internetAccessEnabled": True,
            },
            {
                "id": "fx-net-iot",
                "name": "FIXTURE IoT",
                "enabled": True,
                "management": "GATEWAY",
                "vlanId": 40,
                "internetAccessEnabled": False,
            },
        ],
        "unifi-wifi-broadcasts": [
            {
                "id": "fx-wifi-corp",
                "name": "FIXTURE Corp",
                "enabled": True,
                "network": {"networkId": "fx-net-office"},
                "securityConfiguration": {
                    "type": "WPA3_PERSONAL",
                    "passphrase": "CANARY-fixture-wifi-corp-0001",
                },
                "clientIsolationEnabled": False,
            },
            {
                "id": "fx-wifi-guest",
                "name": "FIXTURE Guest",
                "enabled": True,
                "network": {"networkId": "fx-net-guest"},
                "securityConfiguration": {
                    "type": "WPA2_PERSONAL",
                    "passphrase": "CANARY-fixture-wifi-guest-0001",
                },
                "clientIsolationEnabled": True,
            },
        ],
        "unifi-firewall-zones": [
            {"id": "fx-zone-internal", "name": "FIXTURE Internal", "networkIds": ["fx-net-office"]},
            {"id": "fx-zone-guest", "name": "FIXTURE Guest", "networkIds": ["fx-net-guest"]},
        ],
        "unifi-dns-policies": [
            {
                "id": "fx-dns-1",
                "type": "A_RECORD",
                "enabled": True,
                "domain": "intranet.fixture.example",
            },
            {
                "id": "fx-dns-2",
                "type": "A_RECORD",
                "enabled": True,
                "domain": "backup.fixture.example",
            },
        ],
        "unifi-vpn-servers": [
            {
                "id": "fx-vpn-1",
                "name": "FIXTURE VPN",
                "type": "WIREGUARD",
                "enabled": True,
                "preSharedKey": "CANARY-fixture-vpn-psk-0001",
            }
        ],
        "unifi-radius-profiles": [
            {
                "id": "fx-radius-1",
                "name": "FIXTURE RADIUS",
                "sharedSecret": _canary("radius-shared-0001"),
            }
        ],
        "unifi-devices": [
            {
                "id": "fx-dev-sw1",
                "name": "FIXTURE Switch",
                "model": "FX-SW-24",
                "firmwareVersion": "1.0.0",
                "state": "ONLINE",
            },
            {
                "id": "fx-dev-ap1",
                "name": "FIXTURE Access point",
                "model": "FX-AP-6",
                "firmwareVersion": "2.3.1",
                "state": "ONLINE",
            },
        ],
    }


def _object(document: Document, resource: str, object_id: str) -> dict[str, Any]:
    for entry in document[resource]:
        if entry["id"] == object_id:
            return entry
    raise DevFixtureError(f"the fixture has no object {object_id} in {resource}")


def _secrets_and_exposure(document: Document) -> None:
    """Critical and high: two secrets replaced, client isolation off, a zone gains a network."""
    wifi = _object(document, "unifi-wifi-broadcasts", "fx-wifi-corp")
    wifi["securityConfiguration"]["passphrase"] = _canary("wifi-corp-0002")
    vpn = _object(document, "unifi-vpn-servers", "fx-vpn-1")
    vpn["preSharedKey"] = _canary("vpn-psk-0002")
    guest = _object(document, "unifi-wifi-broadcasts", "fx-wifi-guest")
    guest["clientIsolationEnabled"] = False
    zone = _object(document, "unifi-firewall-zones", "fx-zone-guest")
    zone["networkIds"] = ["fx-net-guest", "fx-net-iot"]


def _routine(document: Document) -> None:
    """Medium and low: a VLAN, a firmware version, a switched off DNS policy and two names."""
    _object(document, "unifi-networks", "fx-net-iot")["vlanId"] = 41
    _object(document, "unifi-devices", "fx-dev-sw1")["firmwareVersion"] = "1.1.0"
    _object(document, "unifi-dns-policies", "fx-dns-2")["enabled"] = False
    _object(document, "unifi-devices", "fx-dev-ap1")["name"] = "FIXTURE Access point lobby"
    _object(document, "unifi-networks", "fx-net-guest")["name"] = "FIXTURE Visitors"


def _lifecycle(document: Document) -> None:
    """Objects added and removed, a device offline and the management mode of a network."""
    document["unifi-networks"].append(
        {
            "id": "fx-net-lab",
            "name": "FIXTURE Lab",
            "enabled": True,
            "management": "GATEWAY",
            "vlanId": 50,
            "internetAccessEnabled": True,
        }
    )
    document["unifi-dns-policies"] = [
        entry for entry in document["unifi-dns-policies"] if entry["id"] != "fx-dns-1"
    ]
    document["unifi-radius-profiles"] = []
    _object(document, "unifi-devices", "fx-dev-ap1")["state"] = "OFFLINE"
    _object(document, "unifi-networks", "fx-net-office")["management"] = "USER"


@dataclass(frozen=True, slots=True)
class Step:
    """One pushed document: ``edit`` changes the previous one; ``age`` is how long ago it was."""

    label: str
    age: timedelta
    edit: Callable[[Document], None] | None


STEPS: Final = (
    Step("baseline", timedelta(hours=6), None),
    Step("secrets and exposure", timedelta(hours=4), _secrets_and_exposure),
    Step("routine changes", timedelta(hours=2), _routine),
    Step("objects added and removed", timedelta(minutes=30), _lifecycle),
)


class _StepClock:
    """UTC timestamps one second apart, starting at the time the current step is dated."""

    def __init__(self) -> None:
        self.start = datetime.now(UTC)
        self._calls = 0

    def begin(self, start: datetime) -> None:
        self.start = start
        self._calls = 0

    def __call__(self) -> str:
        moment = self.start + timedelta(seconds=self._calls)
        self._calls += 1
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _documents() -> list[Document]:
    """The document of every step: each one is the previous one with the step's edit applied."""
    documents: list[Document] = []
    current = _baseline()
    for step in STEPS:
        if step.edit is not None:
            current = copy.deepcopy(current)
            step.edit(current)
        documents.append(copy.deepcopy(current))
    return documents


def _was_deleted(database: Database) -> bool:
    """True when an earlier ``source.delete`` event names the fixture source."""
    query = sa.select(audit_events.c.detail).where(audit_events.c.action == ACTION_DELETE)
    with database.read() as connection:
        details = connection.execute(query).scalars().all()
    return any(
        isinstance(detail, dict) and detail.get("name") == FIXTURE_SOURCE_NAME for detail in details
    )


def _finished_runs(database: Database, source_id: int) -> int:
    """How many runs of the source ended ok, which is how many steps already ran."""
    query = (
        sa.select(sa.func.count())
        .select_from(runs)
        .where(runs.c.source_id == source_id, runs.c.status == "ok")
    )
    with database.read() as connection:
        return int(connection.execute(query).scalar_one())


def seed_fixture(
    database: Database,
    service: SourceService,
    pipeline: RunPipeline,
    clock: _StepClock,
) -> FixtureReport:
    """Make the fixture source when it is missing and run the steps that did not run yet.

    ``pipeline`` must be built with ``clock`` and without a notifier. Raises DevFixtureError when
    a run does not end ok, or when a source of another type has the fixture's name.
    """
    existing = next(
        (view for view in service.list_sources() if view.name == FIXTURE_SOURCE_NAME), None
    )
    created = False
    if existing is None:
        if _was_deleted(database):
            return FixtureReport(created=False, removed=True, pushed=0, events=0)
        try:
            existing = service.create(
                name=FIXTURE_SOURCE_NAME,
                source_type="push",
                actor=ACTOR_SYSTEM,
                options={OPTION_PUSH_FIELDS: PUSH_FIELDS},
            )
        except SourceValidationError as error:
            raise DevFixtureError(f"the fixture source cannot be made: {error}") from error
        created = True
    elif existing.type != "push":
        raise DevFixtureError("a source that is not a push source has the fixture's name")
    documents = _documents()
    done = _finished_runs(database, existing.id)
    now = datetime.now(UTC)
    pushed = 0
    events = 0
    for step, document in list(zip(STEPS, documents, strict=True))[done:]:
        body = json.dumps(document).encode()
        clock.begin(now - step.age)
        collector = PushCollector(document, PUSH_FIELDS, body_bytes=len(body))
        report = pipeline.run(existing.id, collector)
        if report.status != "ok":
            raise DevFixtureError(
                f"the fixture step '{step.label}' ended {report.status}"
                f" ({report.error_class or 'no error class'})"
            )
        pushed += 1
        if report.event_id is not None:
            events += 1
    return FixtureReport(created=created, removed=False, pushed=pushed, events=events)


def seed_fixture_at_startup(
    settings: Settings, database: Database, master_key: MasterKey
) -> FixtureReport | None:
    """Seed the Development fixture when this is a Development address; never raises.

    Returns None without a log line when the address is not a Development one (Stage,
    Production, localhost), and after one error line when the fixture could not be made. The
    database must be migrated. The fixture's pipeline has no notifier, so nothing is sent.
    """
    try:
        check_development_startup(settings)
    except DevSeedRefusedError:
        return None
    clock = _StepClock()
    try:
        pipeline = RunPipeline(
            database,
            RuleEngine(load_rules()),
            Fingerprinter.from_master(master_key),
            overrides=load_overrides(),
            clock=clock,
        )
        service = SourceService(database, CredentialCipher.from_master(master_key))
        report = seed_fixture(database, service, pipeline, clock)
    except (
        DevFixtureError,
        SourceError,
        RuleLoadError,
        OverrideFileError,
        SQLAlchemyError,
    ) as error:
        _LOG.error("development fixture not seeded: %s", error)
        return None
    if report.removed:
        _LOG.info("development fixture was removed earlier, not made again")
    elif report.pushed:
        _LOG.info(
            "development fixture seeded: %s documents run, %s change events",
            report.pushed,
            report.events,
        )
    else:
        _LOG.info("development fixture already present, unchanged")
    return report
