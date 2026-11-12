# Setting up a Proxmox VE source

This guide connects driftsniff to a Proxmox VE cluster (or a single node) so that it records
changes to the datacenter options, nodes, virtual machines and containers, storage, the cluster
firewall, users, API tokens, groups, roles, permissions, realms, backup and replication jobs, HA,
SDN and pools.

## Read this first

- **No lab Proxmox VE has been used.** The API paths and fields come from the official API schema,
  the wiki and the Proxmox source, read on 2026-11-12 (`docs/vendor-notes/proxmox.md`). The
  collector is tested against a fake Proxmox VE on localhost (`tests/contract/fake_proxmox.py`),
  not a real cluster.
- driftsniff **only reads**: it sends `GET` requests and nothing else. The token's role is the
  real limit, so give it a read only role.

## What driftsniff reads

All paths are below `/api2/json`. Any node of a cluster answers for the whole cluster.

| Resource | Proxmox path | Right needed |
|---|---|---|
| `proxmox-cluster-options` | `/cluster/options` | `Sys.Audit` on `/` |
| `proxmox-nodes` | `/nodes`, then `/nodes/{node}/config` | `Sys.Audit` on `/` |
| `proxmox-vms`, `proxmox-containers` | `/cluster/resources?type=vm`, then one config per guest | `VM.Audit` on the guest |
| `proxmox-storage` | `/storage` | `Datastore.Audit` on the storage |
| `proxmox-firewall-options`, `-rules`, `-groups`, `-aliases`, `-ipsets` | `/cluster/firewall/...` | `Sys.Audit` on `/` |
| `proxmox-users`, `proxmox-tokens` | `/access/users?full=1` | `Sys.Audit` on `/access/groups` |
| `proxmox-groups`, `proxmox-roles` | `/access/groups`, `/access/roles` | `Sys.Audit` |
| `proxmox-acl`, `proxmox-admin-acl` | `/access/acl` | `Sys.Audit` on `/access` |
| `proxmox-realms` | `/access/domains`, then `/access/domains/{realm}` | `Sys.Audit` on `/access/realm` |
| `proxmox-backup-jobs`, `proxmox-replication-jobs` | `/cluster/backup`, `/cluster/replication` | `Sys.Audit` on `/` |
| `proxmox-ha-resources`, `proxmox-ha-groups` | `/cluster/ha/resources`, `/cluster/ha/groups` | `Sys.Audit` on `/` |
| `proxmox-sdn-zones`, `proxmox-sdn-vnets` | `/cluster/sdn/zones`, `/cluster/sdn/vnets` | `SDN.Audit` |
| `proxmox-pools` | `/pools` | `Pool.Audit` |

Many Proxmox lists are **filtered** rather than refused: a token without the right sees fewer
objects or an empty list, which driftsniff would report as removals. Give the token its role on
`/` with propagation so that it sees everything. A path that this Proxmox does not have (SDN
without its package, HA groups on a release that replaced them) shows coverage "not available" and
keeps its previous state.

One run reads at most 300 virtual machines and 300 containers (one request per guest config);
a larger cluster fails those two resources and keeps their previous state.

## Least privilege

Use a dedicated user and a privilege separated API token, both with the built-in **PVEAuditor**
role (read only) on `/`. With privilege separation the token has only the rights that both its own
ACL entries and its user have, so both get the role.

## Steps

1. On any node, as root:

   ```
   pveum user add driftsniff@pve --comment "driftsniff reader"
   pveum acl modify / --users driftsniff@pve --roles PVEAuditor
   pveum user token add driftsniff@pve audit --privsep 1
   pveum acl modify / --tokens 'driftsniff@pve!audit' --roles PVEAuditor
   ```

   The third command prints the token secret (`value`) once. The same can be done in the web
   interface under Datacenter, Permissions.
2. In driftsniff, select **Add source**, choose **Proxmox VE**, and enter a name, the `https://`
   address of a node with its port and no path (for example `https://pve1.example.invalid:8006`),
   the whole token `driftsniff@pve!audit=<secret>` in the API token field, the interval, the
   resources and the TLS mode. A node's own certificate is self signed unless you replaced it:
   use your own CA bundle or a pinned certificate rather than switching checks off.
3. Select **Test connection**. It reads the version and each resource once and stores nothing.

The token is sent only in the `Authorization: PVEAPIToken=...` header, stored encrypted and never
shown again.

## What is never stored in clear

The cloud-init password of a VM, the environment of a container, storage passwords and keys,
realm bind passwords and OpenID client keys, the second factor key ids of users and the datacenter
HTTP proxy: driftsniff keeps only a keyed fingerprint of each, so it can tell that one changed but
not what it is. API token secrets are never returned by Proxmox; only their metadata is read.
