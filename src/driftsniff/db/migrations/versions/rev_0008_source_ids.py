"""Source ids are never given twice.

``sources.id`` has no AUTOINCREMENT, so SQLite gave the id of the newest source again after it
was deleted, and the audit trail of the deleted source then named the new one. The table
``source_ids`` (AUTOINCREMENT) now hands out every new source id. It starts above the highest id
ever used: the sources that exist and the ``source:<id>`` targets of the audit trail, which
still name sources that were deleted. Its rows are removed right after an id is taken; SQLite
keeps the highest id in ``sqlite_sequence``.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-28
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "source_ids",
        sa.Column("id", sa.Integer, primary_key=True),
        sqlite_autoincrement=True,
    )
    op.execute(
        "INSERT INTO source_ids (id) "
        "SELECT highest FROM ("
        "  SELECT MAX(used) AS highest FROM ("
        "    SELECT MAX(id) AS used FROM sources"
        "    UNION ALL"
        "    SELECT MAX(CAST(substr(target, 8) AS INTEGER)) AS used FROM audit_events"
        "    WHERE target LIKE 'source:%'"
        "  )"
        ") WHERE highest IS NOT NULL AND highest > 0"
    )
    op.execute("DELETE FROM source_ids")


def downgrade() -> None:
    raise NotImplementedError("downgrades are refused: restore a database backup instead")
