"""Alembic environment.

Migrations run on the connection that driftsniff.db.migrate passes in, inside its write
transaction. The alembic command line is not used and offline (SQL script) mode is not supported.
"""

from alembic import context

from driftsniff.db.tables import metadata

config = context.config


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("migrations are run through driftsniff.db.migrate")
    context.configure(connection=connection, target_metadata=metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("offline migrations are not supported")
run_migrations_online()
