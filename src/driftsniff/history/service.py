"""The two read services of the History and Configuration pages, built together."""

from collections.abc import Mapping

from driftsniff.core.normalize import StaticTypeTable
from driftsniff.db.engine import Database
from driftsniff.history.configuration import ConfigurationQueries
from driftsniff.history.queries import HistoryQueries
from driftsniff.secrets.fingerprint import Fingerprinter


class HistoryService:
    """``history`` lists sources and snapshots; ``configuration`` browses the newest snapshot."""

    def __init__(
        self,
        database: Database,
        fingerprinter: Fingerprinter,
        type_tables: Mapping[str, StaticTypeTable] | None = None,
    ) -> None:
        self.history = HistoryQueries(database)
        self.configuration = ConfigurationQueries(database, fingerprinter, type_tables)
