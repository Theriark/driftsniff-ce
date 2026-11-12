"""More source types: Portainer, TrueNAS, Synology and QNAP are read like UniFi and XO.

SQLite cannot alter a CHECK constraint. Copying the table (alembic batch mode) would drop
``sources`` and, with foreign keys on, cascade-delete every run, snapshot and event of it. So the
constraint text is rewritten in the schema instead, the way the SQLite ALTER TABLE documentation
allows for a change that does not alter the stored data format: a wider CHECK only.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-12
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

OLD = "CHECK (type IN ('unifi', 'xo', 'push'))"
NEW = "CHECK (type IN ('unifi', 'xo', 'push', 'portainer', 'truenas', 'synology', 'qnap'))"


def upgrade() -> None:
    connection = op.get_bind()
    sql = connection.exec_driver_sql(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sources'"
    ).scalar_one()
    if sql.count(OLD) != 1:
        raise RuntimeError("the sources table does not have the expected type constraint")
    version = connection.exec_driver_sql("PRAGMA schema_version").scalar_one()
    connection.exec_driver_sql("PRAGMA writable_schema = ON")
    connection.exec_driver_sql(
        "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = 'sources'",
        (sql.replace(OLD, NEW),),
    )
    connection.exec_driver_sql(f"PRAGMA schema_version = {int(version) + 1}")
    connection.exec_driver_sql("PRAGMA writable_schema = OFF")


def downgrade() -> None:
    raise NotImplementedError("downgrades are refused: restore a database backup instead")
