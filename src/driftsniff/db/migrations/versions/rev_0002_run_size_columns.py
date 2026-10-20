"""Size columns on runs: the compressed bytes a run added as new states and as a manifest.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def _size_column(name: str) -> sa.Column[int]:
    return sa.Column(name, sa.Integer, nullable=False, server_default=sa.text("0"))


def upgrade() -> None:
    op.add_column("runs", _size_column("new_state_bytes"))
    op.add_column("runs", _size_column("manifest_bytes"))


def downgrade() -> None:
    raise NotImplementedError("downgrades are refused: restore a database backup instead")
