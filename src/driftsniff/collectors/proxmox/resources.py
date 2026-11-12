"""The Proxmox VE resources the collector reads and where it reads them.

Paths, permissions and field names were read from the Proxmox VE API schema
(https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js) and the pve-access-control and pve-storage
sources on 2026-11-12 (docs/vendor-notes/proxmox.md). No lab Proxmox VE was used. Every path is
below ``/api2/json`` and every answer is ``{"data": ...}``.
"""

from dataclasses import dataclass
from typing import Final

API_PREFIX: Final = "/api2/json"
AUTH_HEADER: Final = "Authorization"
AUTH_SCHEME: Final = "PVEAPIToken="
VERSION_PATH: Final = "/version"
VERSION_FIELD: Final = "version"

# A guest config read costs one request each. 300 per kind at 150 ms per read is 45 s, so both
# kinds and the rest fit well inside the five minute run. More guests fail the resource.
MAX_GUESTS: Final = 300

RESOURCE_CLUSTER_OPTIONS: Final = "proxmox-cluster-options"
RESOURCE_NODES: Final = "proxmox-nodes"
RESOURCE_VMS: Final = "proxmox-vms"
RESOURCE_CONTAINERS: Final = "proxmox-containers"
RESOURCE_STORAGE: Final = "proxmox-storage"
RESOURCE_FIREWALL_OPTIONS: Final = "proxmox-firewall-options"
RESOURCE_FIREWALL_RULES: Final = "proxmox-firewall-rules"
RESOURCE_FIREWALL_GROUPS: Final = "proxmox-firewall-groups"
RESOURCE_FIREWALL_ALIASES: Final = "proxmox-firewall-aliases"
RESOURCE_FIREWALL_IPSETS: Final = "proxmox-firewall-ipsets"
RESOURCE_USERS: Final = "proxmox-users"
RESOURCE_TOKENS: Final = "proxmox-tokens"
RESOURCE_GROUPS: Final = "proxmox-groups"
RESOURCE_ROLES: Final = "proxmox-roles"
RESOURCE_ACL: Final = "proxmox-acl"
RESOURCE_ADMIN_ACL: Final = "proxmox-admin-acl"
RESOURCE_REALMS: Final = "proxmox-realms"
RESOURCE_BACKUP_JOBS: Final = "proxmox-backup-jobs"
RESOURCE_REPLICATION_JOBS: Final = "proxmox-replication-jobs"
RESOURCE_HA_RESOURCES: Final = "proxmox-ha-resources"
RESOURCE_HA_GROUPS: Final = "proxmox-ha-groups"
RESOURCE_SDN_ZONES: Final = "proxmox-sdn-zones"
RESOURCE_SDN_VNETS: Final = "proxmox-sdn-vnets"
RESOURCE_POOLS: Final = "proxmox-pools"

# The role whose ACL entries go to proxmox-admin-acl (an added one is critical).
ADMIN_ROLE: Final = "Administrator"


@dataclass(frozen=True, slots=True)
class ProxmoxResource:
    """One resource: its name in the type tables, the path it starts from and its key field."""

    name: str
    path: str
    key_field: str


# In reading order. Resources whose path is shared read it again: one GET each, kept simple.
RESOURCES: Final = (
    ProxmoxResource(RESOURCE_CLUSTER_OPTIONS, "/cluster/options", "id"),
    ProxmoxResource(RESOURCE_NODES, "/nodes", "node"),
    ProxmoxResource(RESOURCE_VMS, "/cluster/resources?type=vm", "vmid"),
    ProxmoxResource(RESOURCE_CONTAINERS, "/cluster/resources?type=vm", "vmid"),
    ProxmoxResource(RESOURCE_STORAGE, "/storage", "storage"),
    ProxmoxResource(RESOURCE_FIREWALL_OPTIONS, "/cluster/firewall/options", "id"),
    ProxmoxResource(RESOURCE_FIREWALL_RULES, "/cluster/firewall/rules", "id"),
    ProxmoxResource(RESOURCE_FIREWALL_GROUPS, "/cluster/firewall/groups", "group"),
    ProxmoxResource(RESOURCE_FIREWALL_ALIASES, "/cluster/firewall/aliases", "name"),
    ProxmoxResource(RESOURCE_FIREWALL_IPSETS, "/cluster/firewall/ipset", "name"),
    ProxmoxResource(RESOURCE_USERS, "/access/users?full=1", "userid"),
    ProxmoxResource(RESOURCE_TOKENS, "/access/users?full=1", "id"),
    ProxmoxResource(RESOURCE_GROUPS, "/access/groups", "groupid"),
    ProxmoxResource(RESOURCE_ROLES, "/access/roles", "roleid"),
    ProxmoxResource(RESOURCE_ACL, "/access/acl", "id"),
    ProxmoxResource(RESOURCE_ADMIN_ACL, "/access/acl", "id"),
    ProxmoxResource(RESOURCE_REALMS, "/access/domains", "realm"),
    ProxmoxResource(RESOURCE_BACKUP_JOBS, "/cluster/backup", "id"),
    ProxmoxResource(RESOURCE_REPLICATION_JOBS, "/cluster/replication", "id"),
    ProxmoxResource(RESOURCE_HA_RESOURCES, "/cluster/ha/resources", "sid"),
    ProxmoxResource(RESOURCE_HA_GROUPS, "/cluster/ha/groups", "group"),
    ProxmoxResource(RESOURCE_SDN_ZONES, "/cluster/sdn/zones", "zone"),
    ProxmoxResource(RESOURCE_SDN_VNETS, "/cluster/sdn/vnets", "vnet"),
    ProxmoxResource(RESOURCE_POOLS, "/pools", "poolid"),
)

RESOURCE_PATHS: Final = {resource.name: resource for resource in RESOURCES}

# Indexed config keys (net0, scsi1, ...) that the collector folds into one keyed list per kind,
# named as the API schema names them (``net[n]``). Single keys such as efidisk0 stay as they are.
VM_SLOTS: Final = (
    "net",
    "ide",
    "sata",
    "scsi",
    "virtio",
    "unused",
    "hostpci",
    "usb",
    "serial",
    "parallel",
    "ipconfig",
    "numa",
    "virtiofs",
)
CONTAINER_SLOTS: Final = ("net", "mp", "dev", "unused")
NODE_SLOTS: Final = ("acmedomain",)
