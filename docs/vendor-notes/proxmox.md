# Proxmox VE vendor notes

driftsniff's own notes on the Proxmox VE API that the Proxmox collector reads
(`src/driftsniff/collectors/proxmox/`, type table `src/driftsniff/rules/types/proxmox.yaml`).
Nothing here is copied from the vendor; every statement is in our own words, with its source and
the date it was read.

## Status in one paragraph

The statements below were read from the official API schema that the Proxmox VE API viewer
renders (its data file `apidoc.js`, parsed as JSON), from the Proxmox VE wiki and manual, and from
three handlers of the Proxmox source on **2026-11-12**. **No lab Proxmox VE was used**: nothing
here is checked against a running cluster, and the contract tests run against
`tests/contract/fake_proxmox.py`, which follows these notes. Names marked **UNVERIFIED** were not
confirmed by what was read.

## Sources

| Id | Source | Read on |
|---|---|---|
| S1 | https://pve.proxmox.com/pve-docs/api-viewer/ and its data file `apidoc.js` (paths, GET permissions, returned properties, create parameters) | 2026-11-12 |
| S2 | https://pve.proxmox.com/wiki/User_Management (roles, API tokens, privilege separation, the `Authorization: PVEAPIToken=...` header) | 2026-11-12 |
| S3 | https://pve.proxmox.com/pve-docs/pveum.1.html (`pveum user token add`, `pveum acl modify --tokens/--users`) | 2026-11-12 |
| S4 | git.proxmox.com pve-access-control `src/PVE/API2/ACL.pm`, `User.pm`, `Domains.pm` (what the ACL, user and realm reads return) | 2026-11-12 |
| S5 | git.proxmox.com pve-storage `src/PVE/API2/Storage/Config.pm` (what the storage list returns) | 2026-11-12 |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | Every path is below `/api2/json`; every answer is an object whose `data` member holds the result. | S1 | schema |
| 2 | An API token is sent as `Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET`. Its secret is shown once, at creation. With privilege separation (the default) the token has only the rights of its own ACL entries that its user also has. | S2, S3 | vendor doc |
| 3 | `GET /version` is open to any authenticated caller and answers `version`, `release`, `repoid` (and `console`). | S1 | schema |
| 4 | `GET /cluster/options` needs `Sys.Audit` on `/` and answers the datacenter options (keyboard, language, console, `http_proxy`, `email_from`, `mac_prefix`, `migration`, `migration_unsecure`, `ha`, `crs`, `next-id`, `u2f`, `webauthn`, `description`, ...). | S1 | schema; whether property strings come back as text or as objects is **UNVERIFIED** |
| 5 | `GET /nodes` lists nodes with live usage and `ssl_fingerprint`; `GET /nodes/{node}/config` needs `Sys.Audit` on `/` and answers `description`, `location`, `acme`, `acmedomain[n]`, `wakeonlan`, `startall-onboot-delay`, `ballooning-target`, `digest`. | S1 | schema |
| 6 | `GET /cluster/resources?type=vm` lists every guest the caller may audit with `vmid`, `type` (`qemu`/`lxc`), `node` and live usage. | S1 | schema |
| 7 | `GET /nodes/{node}/qemu/{vmid}/config` and `.../lxc/{vmid}/config` need `VM.Audit` on `/vms/{vmid}` and answer the guest config; numbered devices are keys such as `net0`, `scsi1`, `mp0` (the schema writes them `net[n]`). | S1 | schema |
| 8 | Whether the VM config answer masks `cipassword`. | none read | **UNVERIFIED**; classed secret either way |
| 9 | `GET /storage` needs `Datastore.Audit` or `Datastore.AllocateSpace` per storage. Its schema names only `storage`, but the handler returns a copy of each stored storage config plus `storage` and `digest`, without masking. Passwords and keys are extracted to `/etc/pve/priv` at create time, so they are normally absent. `GET /storage/{storage}` needs `Datastore.Allocate` and is not used. | S1, S5 | source; the members of a real answer are **UNVERIFIED** in a lab |
| 10 | `GET /cluster/firewall/options`, `/rules`, `/aliases`, `/ipset`, `/ipset/{name}` and `/groups/{group}` need `Sys.Audit` on `/`; `/groups` is open to any caller. Rules carry `pos`, `type`, `action`, `macro`, `source`, `dest`, `proto`, `dport`, `sport`, `iface`, `log`, `enable`, `comment`, `icmp-type`, `ipversion`; rules have no id other than their position. `enable` of the options is an integer. | S1 | schema |
| 11 | `GET /access/users?full=1` lists the users the caller may audit (`User.Modify` or `Sys.Audit` on `/access/groups`); `full` adds `groups` (comma separated) and `tokens` (`tokenid`, `comment`, `expire`, `privsep`). `keys` (yubico ids) is returned; the password is not. | S1, S4 | source |
| 12 | `GET /access/acl` returns every entry when the caller has `Sys.Audit` on `/access` (otherwise only paths it may change); entries have `path`, `type` (`user`, `group`, `token`), `ugid`, `roleid`, `propagate` (stored as 0 or 1). | S4 | source |
| 13 | `GET /access/domains` is world readable (`realm`, `type`, `comment`, `tfa`). `GET /access/domains/{realm}` needs `Realm.Allocate` or `Sys.Audit` on `/access/realm` and returns the whole stored realm hash plus `digest`, unfiltered. The LDAP bind password is stored in `/etc/pve/priv/realm/<realm>.pw`; an OpenID `client-key` is a realm property. | S1, S4 | source |
| 14 | `GET /access/groups` (`groupid`, `comment`, `users` comma separated), `GET /access/roles` (`roleid`, `privs` comma separated, `special`). | S1 | schema |
| 15 | `GET /cluster/backup` (`Sys.Audit` on `/`): `id`, `enabled`, `schedule`, `storage`, `vmid`, `all`, `exclude`, `pool`, `mode`, `compress`, `comment`, `next-run`, `prune-backups`, `fleecing`, `performance`, ... | S1 | schema; members of the object options **UNVERIFIED** |
| 16 | `GET /cluster/replication`: `id`, `guest`, `jobnum`, `target`, `schedule`, `rate`, `comment`, `disable`, `remove_job`, `source`, `type`; only jobs whose guest the caller may audit. | S1 | schema |
| 17 | `GET /cluster/ha/resources` and `/cluster/ha/groups` need `Sys.Audit` on `/`. Their list schemas name only `sid` and `group`; the members (`state`, `group`, `max_restart`, `max_relocate`, `failback`, `comment`; `nodes`, `restricted`, `nofailback`) come from the read and create schemas. Newer releases add `/cluster/ha/rules`, not read. | S1 | schema; list members **UNVERIFIED** |
| 18 | `GET /cluster/sdn/zones` and `/vnets` list what the caller may audit (`SDN.Audit`). | S1 | schema |
| 19 | `GET /pools` lists pools with `members` (each member an object with `id` and live usage) in the current schema. | S1 | schema; older releases may omit members (**UNVERIFIED**) |
| 20 | Proxmox answers HTTP 501 for a path it does not implement (for example SDN without its package). | experience | **UNVERIFIED** |
| 21 | PVEAuditor is the read only built-in role. | S2 | vendor doc; its privilege list was not read (**UNVERIFIED**) |

## Decisions of driftsniff

- Numbered config keys become one list per kind named like the schema (`net[n]`), members
  `{slot, value}` keyed by `slot` (`collectors/proxmox/normalize.py`).
- The options objects get the key `cluster`. ACL entries get the key `path|type|ugid|roleid`, and
  entries of the `Administrator` role go to their own resource, `proxmox-admin-acl`, whose added
  floor is critical. API tokens get the key `userid!tokenid` and are read from the user list.
- Firewall rules are keyed by position (`cluster/<pos>`, `group/<name>/<pos>`), because Proxmox
  gives them no id. A rule inserted above others shifts the keys below it, so those rules show as
  modified rather than one added rule. Per-guest firewall rules are not read (one more request per
  guest).
- Pool members keep only their ids; usage, uptime, `digest`, `lock`, `next-run`, `meta`,
  `vmgenid` and SDN `state`/`pending` are ignored.
- Guest configs: at most 300 VMs and 300 containers per run (one request each). More fail that
  resource, which keeps its previous state.
- 404 and 501 are coverage "not available" (stored as 404 so the pipeline does not retry a 501).
- Secret: `cipassword`, container `env`, storage `password`, `encryption-key` and `keyring`, realm
  `password` and `client-key`, user `keys`, `http_proxy` (it can carry a user and password).
