"""Table metadata for the whole schema (technical report section 10).

Every top-level table carries workspace_id (default 1) so a later multi-tenant edition needs no
schema rewrite; child tables are scoped through their parent. All timestamps are UTC ISO 8601
text ending in Z. Migrations never import this module for their DDL (they spell the tables out,
so an old migration keeps meaning what it meant); a test compares the migrated database with it.
"""

import sqlalchemy as sa

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

DEFAULT_WORKSPACE_ID = 1
USER_ROLES = ("viewer", "operator", "admin")
SOURCE_TYPES = ("unifi", "xo", "push")
RUN_STATUSES = ("ok", "partial", "failed", "skipped")
SNAPSHOT_KINDS = ("normal", "baseline")
SEVERITIES = ("low", "medium", "high", "critical")
EVENT_STATUSES = ("open", "acknowledged")
FIELD_CLASSES = ("config", "secret", "ignore", "unclassified")
CHANNEL_TYPES = ("webhook", "smtp")
ENRICHMENT_SUMMARY_MAX_CHARS = 2000

metadata = sa.MetaData(naming_convention=NAMING_CONVENTION)


def _in(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({quoted})"


def _workspace_id() -> sa.Column[int]:
    return sa.Column(
        "workspace_id",
        sa.Integer,
        sa.ForeignKey("workspaces.id"),
        nullable=False,
        server_default=sa.text(str(DEFAULT_WORKSPACE_ID)),
    )


def _id() -> sa.Column[int]:
    return sa.Column("id", sa.Integer, primary_key=True)


def _cascade_fk(name: str, target: str) -> sa.Column[int]:
    """A required foreign key whose rows are deleted together with the row they point to."""
    return sa.Column(
        name,
        sa.Integer,
        sa.ForeignKey(target, ondelete="CASCADE"),
        nullable=False,
    )


workspaces = sa.Table(
    "workspaces",
    metadata,
    _id(),
    sa.Column("name", sa.Text, nullable=False),
)

users = sa.Table(
    "users",
    metadata,
    _id(),
    _workspace_id(),
    sa.Column("username", sa.Text, nullable=False),
    sa.Column("password_hash", sa.Text, nullable=False),
    sa.Column("role", sa.Text, nullable=False),
    sa.Column("disabled", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Column("failed_logins", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.Column("locked_until", sa.Text),
    sa.Column("created_at", sa.Text, nullable=False),
    sa.UniqueConstraint("username", name="uq_users_username"),
    sa.CheckConstraint(_in("role", USER_ROLES), name="role"),
)

api_tokens = sa.Table(
    "api_tokens",
    metadata,
    _id(),
    _cascade_fk("user_id", "users.id"),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("token_prefix", sa.Text, nullable=False),
    sa.Column("token_hash", sa.Text, nullable=False),
    sa.Column("scopes", sa.JSON, nullable=False),
    sa.Column("last_used_at", sa.Text),
    sa.Column("expires_at", sa.Text),
    sa.Column("revoked_at", sa.Text),
    sa.UniqueConstraint("token_hash", name="uq_api_tokens_token_hash"),
)

sources = sa.Table(
    "sources",
    metadata,
    _id(),
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
    sa.CheckConstraint(_in("type", SOURCE_TYPES), name="type"),
)

runs = sa.Table(
    "runs",
    metadata,
    _id(),
    _cascade_fk("source_id", "sources.id"),
    sa.Column("started_at", sa.Text, nullable=False),
    sa.Column("finished_at", sa.Text),
    # NULL while the run is still going.
    sa.Column("status", sa.Text),
    sa.Column("error_class", sa.Text),
    sa.Column("error_summary", sa.Text),
    sa.Column("object_count", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.Column("bytes_fetched", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.Column("stored_new_snapshot", sa.Boolean, nullable=False, server_default=sa.false()),
    # Compressed bytes this run added to object_states and to snapshots (migration 0002).
    sa.Column("new_state_bytes", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.Column("manifest_bytes", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.CheckConstraint(_in("status", RUN_STATUSES), name="status"),
)

resource_coverage = sa.Table(
    "resource_coverage",
    metadata,
    _cascade_fk("source_id", "sources.id"),
    sa.Column("resource", sa.Text, nullable=False),
    # 200, 403, 404 or error
    sa.Column("last_status", sa.Text, nullable=False),
    sa.Column("last_ok_at", sa.Text),
    sa.Column("stale_since", sa.Text),
    sa.Column("object_count", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.PrimaryKeyConstraint("source_id", "resource"),
)

objects = sa.Table(
    "objects",
    metadata,
    _id(),
    _cascade_fk("source_id", "sources.id"),
    sa.Column("resource", sa.Text, nullable=False),
    sa.Column("object_key", sa.Text, nullable=False),
    sa.Column("display_name", sa.Text),
    sa.Column("first_seen_at", sa.Text, nullable=False),
    sa.Column("last_seen_at", sa.Text, nullable=False),
    sa.Column("removed_at", sa.Text),
    sa.Index("uq_objects_source_resource_key", "source_id", "resource", "object_key", unique=True),
)

object_states = sa.Table(
    "object_states",
    metadata,
    sa.Column("state_hash", sa.Text, primary_key=True),
    sa.Column("body_zstd", sa.LargeBinary, nullable=False),
    sa.Column("normaliser_version", sa.Integer, nullable=False),
    sa.Column("size_bytes", sa.Integer, nullable=False),
)

snapshots = sa.Table(
    "snapshots",
    metadata,
    _id(),
    _cascade_fk("source_id", "sources.id"),
    sa.Column("taken_at", sa.Text, nullable=False),
    # Not unique per source: a manifest may legitimately return to an older state (A, B, A).
    sa.Column("manifest_hash", sa.Text, nullable=False),
    sa.Column("manifest_zstd", sa.LargeBinary, nullable=False),
    sa.Column("controller_version", sa.Text),
    sa.Column("normaliser_version", sa.Integer, nullable=False),
    sa.Column("kind", sa.Text, nullable=False, server_default=sa.text("'normal'")),
    sa.Index("ix_snapshots_source_taken", "source_id", sa.text("taken_at DESC")),
    sa.CheckConstraint(_in("kind", SNAPSHOT_KINDS), name="kind"),
)

change_events = sa.Table(
    "change_events",
    metadata,
    _id(),
    _cascade_fk("source_id", "sources.id"),
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
    sa.Index("ix_change_events_source_created", "source_id", sa.text("created_at DESC")),
    sa.Index("ix_change_events_severity_status", "max_severity", "status"),
    sa.CheckConstraint(_in("max_severity", SEVERITIES), name="max_severity"),
    sa.CheckConstraint(_in("status", EVENT_STATUSES), name="status"),
)

change_items = sa.Table(
    "change_items",
    metadata,
    _id(),
    _cascade_fk("event_id", "change_events.id"),
    # NULL for items that belong to no single object (for example a schema drift item).
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
    sa.Index("ix_change_items_event", "event_id"),
    sa.Index("ix_change_items_object", "object_id"),
    sa.CheckConstraint(_in("field_class", FIELD_CLASSES), name="field_class"),
    sa.CheckConstraint(_in("severity", SEVERITIES), name="severity"),
)

acknowledgements = sa.Table(
    "acknowledgements",
    metadata,
    _id(),
    _cascade_fk("event_id", "change_events.id"),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
    sa.Column("comment", sa.Text, nullable=False),
    sa.Column("created_at", sa.Text, nullable=False),
)

notes = sa.Table(
    "notes",
    metadata,
    _id(),
    _cascade_fk("event_id", "change_events.id"),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
    sa.Column("body", sa.Text, nullable=False),
    sa.Column("created_at", sa.Text, nullable=False),
)

enrichments = sa.Table(
    "enrichments",
    metadata,
    _id(),
    _cascade_fk("event_id", "change_events.id"),
    sa.Column("token_id", sa.Integer, sa.ForeignKey("api_tokens.id"), nullable=False),
    sa.Column("provider_label", sa.Text, nullable=False),
    sa.Column("summary", sa.Text, nullable=False),
    sa.Column("payload", sa.JSON),
    sa.Column("created_at", sa.Text, nullable=False),
    sa.CheckConstraint(f"length(summary) <= {ENRICHMENT_SUMMARY_MAX_CHARS}", name="summary_length"),
)

path_mutes = sa.Table(
    "path_mutes",
    metadata,
    _id(),
    _workspace_id(),
    sa.Column("resource", sa.Text, nullable=False),
    sa.Column("path_pattern", sa.Text, nullable=False),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
    sa.Column("reason", sa.Text),
    sa.Column("created_at", sa.Text, nullable=False),
)

notification_channel = sa.Table(
    "notification_channel",
    metadata,
    _id(),
    _workspace_id(),
    sa.Column("type", sa.Text, nullable=False),
    sa.Column("config_ciphertext", sa.Text, nullable=False),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("min_severity", sa.Text, nullable=False, server_default=sa.text("'high'")),
    sa.CheckConstraint(_in("type", CHANNEL_TYPES), name="type"),
    sa.CheckConstraint(_in("min_severity", SEVERITIES), name="min_severity"),
)

notification_deliveries = sa.Table(
    "notification_deliveries",
    metadata,
    _id(),
    _cascade_fk("event_id", "change_events.id"),
    _cascade_fk("channel_id", "notification_channel.id"),
    sa.Column("attempt", sa.Integer, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("http_status", sa.Integer),
    sa.Column("created_at", sa.Text, nullable=False),
)

audit_events = sa.Table(
    "audit_events",
    metadata,
    _id(),
    _workspace_id(),
    sa.Column("at", sa.Text, nullable=False),
    # A user name, an API token label or system.
    sa.Column("actor", sa.Text, nullable=False),
    sa.Column("action", sa.Text, nullable=False),
    sa.Column("target", sa.Text),
    # Never holds secrets.
    sa.Column("detail", sa.JSON),
)

settings = sa.Table(
    "settings",
    metadata,
    _workspace_id(),
    sa.Column("key", sa.Text, nullable=False),
    sa.Column("value", sa.Text, nullable=False),
    sa.PrimaryKeyConstraint("workspace_id", "key"),
)
