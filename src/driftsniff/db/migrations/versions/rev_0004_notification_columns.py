"""Notification columns: the key id of a channel configuration and the error class of a delivery.

``notification_channel.key_id`` says which master key sealed ``config_ciphertext`` (the same
role as ``sources.key_id``), so a rekey knows what to re-encrypt. ``notification_deliveries``
gets an ``error_class`` (a class word, never message text) and an index on the event.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-22
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("notification_channel", sa.Column("key_id", sa.Text))
    op.add_column("notification_deliveries", sa.Column("error_class", sa.Text))
    op.create_index(
        "ix_notification_deliveries_event", "notification_deliveries", ["event_id", "channel_id"]
    )


def downgrade() -> None:
    raise NotImplementedError("downgrades are refused: restore a database backup instead")
