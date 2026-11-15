"""The account of a user: a display name, a picture and a theme.

``display_name`` is what the shell shows instead of the user name (empty shows the user name).
``avatar`` holds the picture's bytes (PNG, JPEG or WebP, at most 512 KB, recognised by its first
bytes), ``avatar_type`` its media type and ``avatar_version`` a counter the picture's address
carries, so a browser may keep a picture until it changes. ``theme`` is light, dark or system.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("display_name", sa.Text))
    op.add_column("users", sa.Column("avatar", sa.LargeBinary))
    op.add_column("users", sa.Column("avatar_type", sa.Text))
    op.add_column(
        "users",
        sa.Column("avatar_version", sa.Integer, nullable=False, server_default=sa.text("0")),
    )
    op.add_column(
        "users",
        sa.Column("theme", sa.Text, nullable=False, server_default=sa.text("'system'")),
    )


def downgrade() -> None:
    raise NotImplementedError("downgrades are refused: restore a database backup instead")
