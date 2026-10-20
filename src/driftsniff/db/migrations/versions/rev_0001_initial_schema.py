"""Initial schema: every table of the technical report section 10.

Revision ID: 0001
Revises:
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _workspace_id() -> sa.Column[int]:
    return sa.Column(
        "workspace_id",
        sa.Integer,
        sa.ForeignKey("workspaces.id"),
        nullable=False,
        server_default=sa.text("1"),
    )


def upgrade() -> None:
    workspaces = op.create_table(
        "workspaces",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
    )
    # The one workspace of the community edition.
    op.bulk_insert(workspaces, [{"id": 1, "name": "default"}])

    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        _workspace_id(),
        sa.Column("username", sa.Text, nullable=False),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("disabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("failed_logins", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.CheckConstraint("role IN ('viewer', 'operator', 'admin')", name="role"),
    )

    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("token_prefix", sa.Text, nullable=False),
        sa.Column("token_hash", sa.Text, nullable=False),
        sa.Column("scopes", sa.JSON, nullable=False),
        sa.Column("last_used_at", sa.Text),
        sa.Column("expires_at", sa.Text),
        sa.Column("revoked_at", sa.Text),
        sa.UniqueConstraint("token_hash", name="uq_api_tokens_token_hash"),
    )

    op.create_table(
        "sources",
        sa.Column("id", sa.Integer, primary_key=True),
        _workspace_id(),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("type", sa.Text, nullable=False),
        sa.Column("base_url", sa.Text),
        sa.Column("options", sa.JSON, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("credential_ciphertext", sa.Text),
        sa.Column("key_id", sa.Text),
        sa.Column("push_token_hash", sa.Text),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_checked_at", sa.Text),
        sa.Column("last_success_at", sa.Text),
        sa.Column("controller_version", sa.Text),
        sa.Column("state", sa.Text, nullable=False, server_default=sa.text("'new'")),
        sa.UniqueConstraint("workspace_id", "name", name="uq_sources_workspace_id_name"),
        sa.CheckConstraint("type IN ('unifi', 'xo', 'push')", name="type"),
    )

    op.create_table(
        "runs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "source_id", sa.Integer, sa.ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("started_at", sa.Text, nullable=False),
        sa.Column("finished_at", sa.Text),
        sa.Column("status", sa.Text),
        sa.Column("error_class", sa.Text),
        sa.Column("error_summary", sa.Text),
        sa.Column("object_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("bytes_fetched", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("stored_new_snapshot", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.CheckConstraint("status IN ('ok', 'partial', 'failed', 'skipped')", name="status"),
    )

    op.create_table(
        "resource_coverage",
        sa.Column(
            "source_id", sa.Integer, sa.ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("resource", sa.Text, nullable=False),
        sa.Column("last_status", sa.Text, nullable=False),
        sa.Column("last_ok_at", sa.Text),
        sa.Column("stale_since", sa.Text),
        sa.Column("object_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.PrimaryKeyConstraint("source_id", "resource"),
    )

    op.create_table(
        "objects",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "source_id", sa.Integer, sa.ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("resource", sa.Text, nullable=False),
        sa.Column("object_key", sa.Text, nullable=False),
        sa.Column("display_name", sa.Text),
        sa.Column("first_seen_at", sa.Text, nullable=False),
        sa.Column("last_seen_at", sa.Text, nullable=False),
        sa.Column("removed_at", sa.Text),
    )
    op.create_index(
        "uq_objects_source_resource_key",
        "objects",
        ["source_id", "resource", "object_key"],
        unique=True,
    )

    op.create_table(
        "object_states",
        sa.Column("state_hash", sa.Text, primary_key=True),
        sa.Column("body_zstd", sa.LargeBinary, nullable=False),
        sa.Column("normaliser_version", sa.Integer, nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
    )

    op.create_table(
        "snapshots",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "source_id", sa.Integer, sa.ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("taken_at", sa.Text, nullable=False),
        sa.Column("manifest_hash", sa.Text, nullable=False),
        sa.Column("manifest_zstd", sa.LargeBinary, nullable=False),
        sa.Column("controller_version", sa.Text),
        sa.Column("normaliser_version", sa.Integer, nullable=False),
        sa.Column("kind", sa.Text, nullable=False, server_default=sa.text("'normal'")),
        sa.CheckConstraint("kind IN ('normal', 'baseline')", name="kind"),
    )
    op.create_index(
        "ix_snapshots_source_taken", "snapshots", ["source_id", sa.text("taken_at DESC")]
    )

    op.create_table(
        "change_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "source_id", sa.Integer, sa.ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id"), nullable=False),
        sa.Column("previous_snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id")),
        sa.Column("window_start", sa.Text, nullable=False),
        sa.Column("window_end", sa.Text, nullable=False),
        sa.Column("max_severity", sa.Text, nullable=False),
        sa.Column("item_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("rule_pack_version", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default=sa.text("'open'")),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.CheckConstraint(
            "max_severity IN ('low', 'medium', 'high', 'critical')", name="max_severity"
        ),
        sa.CheckConstraint("status IN ('open', 'acknowledged')", name="status"),
    )
    op.create_index(
        "ix_change_events_source_created",
        "change_events",
        ["source_id", sa.text("created_at DESC")],
    )
    op.create_index("ix_change_events_severity_status", "change_events", ["max_severity", "status"])

    op.create_table(
        "change_items",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "event_id",
            sa.Integer,
            sa.ForeignKey("change_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("object_id", sa.Integer, sa.ForeignKey("objects.id")),
        sa.Column("resource", sa.Text, nullable=False),
        sa.Column("object_name_at_time", sa.Text),
        sa.Column("change_kind", sa.Text, nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("field_class", sa.Text, nullable=False),
        sa.Column("before_value", sa.Text),
        sa.Column("after_value", sa.Text),
        sa.Column("before_fp", sa.Text),
        sa.Column("after_fp", sa.Text),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("rule_id", sa.Text),
        sa.Column("rationale", sa.Text),
        sa.Column("order_detail", sa.JSON),
        sa.CheckConstraint(
            "field_class IN ('config', 'secret', 'ignore', 'unclassified')", name="field_class"
        ),
        sa.CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name="severity"),
    )
    op.create_index("ix_change_items_event", "change_items", ["event_id"])
    op.create_index("ix_change_items_object", "change_items", ["object_id"])

    op.create_table(
        "acknowledgements",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "event_id",
            sa.Integer,
            sa.ForeignKey("change_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("comment", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    op.create_table(
        "notes",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "event_id",
            sa.Integer,
            sa.ForeignKey("change_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    op.create_table(
        "enrichments",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "event_id",
            sa.Integer,
            sa.ForeignKey("change_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_id", sa.Integer, sa.ForeignKey("api_tokens.id"), nullable=False),
        sa.Column("provider_label", sa.Text, nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("payload", sa.JSON),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.CheckConstraint("length(summary) <= 2000", name="summary_length"),
    )

    op.create_table(
        "path_mutes",
        sa.Column("id", sa.Integer, primary_key=True),
        _workspace_id(),
        sa.Column("resource", sa.Text, nullable=False),
        sa.Column("path_pattern", sa.Text, nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("reason", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    op.create_table(
        "notification_channel",
        sa.Column("id", sa.Integer, primary_key=True),
        _workspace_id(),
        sa.Column("type", sa.Text, nullable=False),
        sa.Column("config_ciphertext", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("min_severity", sa.Text, nullable=False, server_default=sa.text("'high'")),
        sa.CheckConstraint("type IN ('webhook', 'smtp')", name="type"),
        sa.CheckConstraint(
            "min_severity IN ('low', 'medium', 'high', 'critical')", name="min_severity"
        ),
    )

    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "event_id",
            sa.Integer,
            sa.ForeignKey("change_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "channel_id",
            sa.Integer,
            sa.ForeignKey("notification_channel.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt", sa.Integer, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("http_status", sa.Integer),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer, primary_key=True),
        _workspace_id(),
        sa.Column("at", sa.Text, nullable=False),
        sa.Column("actor", sa.Text, nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("target", sa.Text),
        sa.Column("detail", sa.JSON),
    )

    op.create_table(
        "settings",
        _workspace_id(),
        sa.Column("key", sa.Text, nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.PrimaryKeyConstraint("workspace_id", "key"),
    )


def downgrade() -> None:
    raise NotImplementedError("downgrades are refused: restore a database backup instead")
