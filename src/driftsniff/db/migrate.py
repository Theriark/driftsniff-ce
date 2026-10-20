"""Schema migrations: upgrade to the newest revision and refuse a database from a newer version."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from driftsniff.db.engine import Database

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


class DatabaseTooNewError(Exception):
    """The database is at a revision this application does not know (a newer version wrote it)."""


def _config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR).replace("%", "%%"))
    return config


def head_revision() -> str:
    """Return the newest revision shipped with this application."""
    head = ScriptDirectory.from_config(_config()).get_current_head()
    if head is None:
        raise RuntimeError("this application contains no migration revisions")
    return head


def current_revisions(database: Database) -> tuple[str, ...]:
    """Return the revision(s) stored in the database; empty for a database never migrated."""
    with database.read() as connection:
        return tuple(MigrationContext.configure(connection).get_current_heads())


def check_not_newer(database: Database) -> None:
    """Raise DatabaseTooNewError when the database revision is not one of ours."""
    known = {rev.revision for rev in ScriptDirectory.from_config(_config()).walk_revisions()}
    unknown = [revision for revision in current_revisions(database) if revision not in known]
    if unknown:
        raise DatabaseTooNewError(
            f"the database is at revision {', '.join(unknown)}, which is newer than this "
            f"version of driftsniff supports (latest known revision {head_revision()}). "
            "Start the newer version again or restore a database backup made by this version."
        )


def upgrade_to_head(database: Database) -> str:
    """Upgrade the database to the newest revision and return that revision.

    The whole upgrade runs in one write transaction: it is applied completely or not at all.
    """
    check_not_newer(database)
    config = _config()
    with database.write() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    return head_revision()
