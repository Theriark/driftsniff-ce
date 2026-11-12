"""More source types: Proxmox, Home Assistant, Redfish, Grafana, Prometheus, Zabbix, Checkmk and
UniFi Protect (UniFi Drive has no documented API: docs/vendor-notes/unifi-drive.md).

The CHECK text is rewritten in place, as in revision 0005 (a table copy would cascade-delete runs).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-12
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

OLD = "CHECK (type IN ('unifi', 'xo', 'push', 'portainer', 'truenas', 'synology', 'qnap'))"
NEW = (
    "CHECK (type IN ('unifi', 'xo', 'push', 'portainer', 'truenas', 'synology', 'qnap', "
    "'proxmox', 'homeassistant', 'redfish', 'grafana', 'prometheus', 'zabbix', 'checkmk', "
    "'unifi_protect'))"
)


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
