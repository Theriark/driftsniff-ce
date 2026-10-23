"""The collection side of ``serve``: service, run pipeline, scheduler and factory (P10).

``build_collection`` makes what ``driftsniff serve`` hands to the application so that polled
sources are really collected:

* the source service (the one credential key of the installation);
* the run pipeline with the shipped rules and overrides, the fingerprint key derived from the
  master key and the ``notifier`` that tells the notification channel about a change event after
  its run was committed;
* the collector factory, whose ``for_source`` is the factory of the scheduler and whose
  ``for_target`` is the probe factory of the test connection button;
* the scheduler, which ``create_app`` starts and stops with the application and which the source
  pages ask to sync after every create, edit, enable, disable and delete.

Nothing is started here: the scheduler starts in the lifespan of the application.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from driftsniff.db.engine import Database
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import MasterKey
from driftsniff.secrets.scanner import load_overrides
from driftsniff.sources.factory import CollectorFactory
from driftsniff.sources.runs import RunPipeline
from driftsniff.sources.scheduler import Scheduler
from driftsniff.sources.service import SourceService


@dataclass(frozen=True, slots=True)
class Collection:
    """The parts of the collection side that ``create_app`` and the pages are given."""

    service: SourceService
    pipeline: RunPipeline
    factory: CollectorFactory
    scheduler: Scheduler


def build_collection(
    database: Database,
    master_key: MasterKey,
    data_dir: Path | str,
    *,
    notifier: Callable[[int], None] | None = None,
) -> Collection:
    """Build the service, pipeline, factory and scheduler of one installation.

    Raises ``RuleLoadError`` or ``OverrideFileError`` when the shipped rules or overrides cannot
    be loaded; ``serve`` reports that and stops.
    """
    service = SourceService(database, CredentialCipher.from_master(master_key))
    pipeline = RunPipeline(
        database,
        RuleEngine(load_rules()),
        Fingerprinter.from_master(master_key),
        overrides=load_overrides(),
        notifier=notifier,
    )
    factory = CollectorFactory(service, data_dir)
    scheduler = Scheduler(service, pipeline, factory.for_source)
    return Collection(service, pipeline, factory, scheduler)
