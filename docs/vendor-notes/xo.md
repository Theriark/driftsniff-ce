# Xen Orchestra vendor notes (P8-T1)

These are driftsniff's own notes on the Xen Orchestra (XO) interface that the XO collector will
read (P8). They are written for the people who build and review the collector and the type table
`src/driftsniff/rules/types/xo.yaml`. Nothing here is copied or vendored from the vendor; every
statement is in our own words, with its source and the date it was read.

## Status in one paragraph

**Nothing in this file is lab-verified, and the vendor's own reference was not read for this
task.** The reference could not be fetched (this role has no web access), no lab Xen Orchestra
exists yet (Phase 0 tests X1 to X4 are not run) and no other source was available. The founder
waived Gate A for development work (THE-359, comment e8aa0805), which allows the type table to be
written now, with every XO fact labelled below. The only source of the statements is our own plan
(S1). Every field name is therefore **unverified**: it is the name the plan lists, and it must be
checked against the vendor reference or a lab result before it is relied on. No lab result is
claimed anywhere in this repository.

## Sources

All sources were read on **2026-10-22**.

| Id | Source | What it was used for |
|---|---|---|
| S1 | driftsniff dev work plan part B, section 13 (task THE-411, document analysis-1, revision 11) | Every collection, kept field, ignored field, excluded collection and design decision below |
| S2 | `rules/types/xo.yaml` as written in P5-T3 (the skeleton this task completes) | The starting field list and the derived resource `backup-job-settings` |

Neither source is a vendor document. Statements whose status is *plan* are our own design
decisions, not vendor facts.

## Statements

Status values: **plan** (decided by our own plan, not a vendor fact), **unverified** (a name or
behaviour the plan assumes, not checked against the vendor reference or a lab), **unknown** (no
source at all; the table makes a placeholder choice).

| # | Statement | Source | Date read | Status |
|---|---|---|---|---|
| 1 | XO offers a REST interface with one collection per object type, and a collection can be requested with an explicit field list and as newline delimited JSON. | S1 (P8-T2 is written on this) | 2026-10-22 | unverified |
| 2 | The session credential is sent in a cookie named `authenticationToken`. | S1 | 2026-10-22 | unverified |
| 3 | Collections are not paginated, and the returned order is not trusted. | S1 | 2026-10-22 | plan (the collector sorts by id) |
| 4 | The collections the collector requests are: vms, vm-templates, hosts, pools, networks, pifs, pbds, srs, vifs, vbds, vdis, backup-jobs, schedules, backup-repositories, proxies, servers, users, groups, acl-roles and, when reachable, acl-privileges. | S1 | 2026-10-22 | unverified (the collection names) |
| 5 | The collections tasks, alarms, messages, backup-logs, restore-logs, backup-archives, events, vm-snapshots, vdi-snapshots, licenses, sms, pcis, pgpus, vm-controller and xoa are never requested. They have no type table, so the field list built from the tables cannot name them. | S1 | 2026-10-22 | plan |
| 6 | Plugin configuration, legacy ACLs, resource sets, cloud-config templates, custom fields, IP pools and the audit log are reachable only through JSON-RPC and are not in CE v1. | S1 | 2026-10-22 | unverified (that they have no REST collection) |
| 7 | The names of the fields kept for each collection are the ones in the table below. | S1 | 2026-10-22 | unverified |
| 8 | A VM object holds a nested object `boot` with `firmware` and `order`, and nested `CPUs` (`max`, `number`) and `memory` (`static`, `dynamic`, `size`, `usage`). The dotted names are how the table writes them. | S1 (the plan writes "CPUs max and number" and "memory static and dynamic limits"); the nesting is our reading | 2026-10-22 | unverified |
| 9 | `memory.size` and `memory.usage` change with use and are not configuration. | S1 | 2026-10-22 | plan |
| 10 | Power state, start times, current operations, guest reported values, snapshot lists, VDI lists and parent references change without an administrator changing anything, so they are ignore class. | S1 | 2026-10-22 | plan (volatility not measured, test X1 is open) |
| 11 | The server credential (a password or token), the credential part of a remote address and plugin secrets are hidden by XO. | S1 | 2026-10-22 | unverified (test X3 is open); the field names `password` and `token` of a server: no source |
| 12 | Backup job settings are a map keyed by schedule id inside the backup job. | S2 | 2026-10-22 | unverified |
| 13 | A read-only role reaches fewer collections than an admin session; the expected 403 collections are users, groups, servers and remotes. | S1 (P8-T4) | 2026-10-22 | unverified (test X2 is open) |
| 14 | The XO configuration export holds credentials and is never ingested. | S1 | 2026-10-22 | plan |

## The type table

`rules/types/xo.yaml` holds twenty one resources. XO collections keep their plain names (the UniFi
tables carry the prefix `unifi-`). Every kept field has class `config` unless noted. Every name has
status **unverified** (statement 7) unless the "No source" column says there is not even that.

| Resource | Kept fields | Ignored fields | Lists | No source |
|---|---|---|---|---|
| `vms` | `name_label`, `name_description`, `tags`, `notes`, `CPUs.max`, `CPUs.number`, `coresPerSocket`, `cpuCap`, `cpuMask`, `cpuWeight`, `memory.static`, `memory.dynamic`, `auto_poweron`, `high_availability`, `secureBoot`, `virtualizationMode`, `boot.firmware`, `boot.order`, `blockedOperations`, `affinityHost`, `startDelay`, `nicType`, `vga`, `videoram`, `viridian`, `PV_args`, `resourceSet`, `suspendSr` | `uuid`, `type`, `_xapiRef`, `$pool`, `$poolId`, `$container`, `power_state`, `startTime`, `agentStartTime`, `installTime`, `memory.size`, `memory.usage`, `current_operations`, `addresses`, `mainIpAddress`, `os_version`, `xenTools`, `vulnerabilities`, `docker`, `snapshots`, `VDIs`, `parent` | `tags` set; `boot.order` ordered scalar | `$container`, the driver fields |
| `vm-templates` | the same list as `vms` | the identity, back reference, memory, `current_operations`, `snapshots`, `VDIs` and `parent` fields of `vms` | as `vms` | which templates are built in |
| `hosts` | `name_label`, `name_description`, `hostname`, `enabled`, `version`, `build`, `productBrand`, `multipathing`, `powerOnMode`, `supplementalPacks`, `certificates.notAfter`, `license_expiry`, `logging`, `otherConfig` | `uuid`, `type`, `_xapiRef`, `$pool`, `$poolId`, `power_state`, `startTime`, `agentStartTime`, `current_operations`, `rebootRequired`, `residentVms`, `memory.size`, `memory.usage` | `supplementalPacks`, `certificates` sets | |
| `pools` | `name_label`, `name_description`, `HA_enabled`, `haSrs`, `default_SR`, `crashDumpSr`, `suspendSr`, `migrationCompression`, `platform_version`, `otherConfig` | `uuid`, `type`, `_xapiRef`, `current_operations` | `haSrs` set | |
| `networks` | `name_label`, `name_description`, `MTU`, `bridge`, `automatic`, `defaultIsLocked`, `isBonded`, `nbd`, `insecureNbd`, `other_config` | `uuid`, `type`, `_xapiRef`, `$pool`, `$poolId`, `current_operations` | | |
| `pifs` | `device`, `vlan`, `mode`, `ip`, `netmask`, `gateway`, `dns` | `currently_attached`, `attached`, identity fields | | `ip`, `netmask`, `gateway`, `dns`: the plan says only "IP settings" |
| `pbds` | none; `device_config` is **secret** | `currently_attached`, `attached`, identity fields | | `device_config` |
| `srs` | `name_label`, `name_description`, `SR_type`, `content_type`, `shared`, `allocationStrategy`, `inMaintenanceMode`, `is_tools_sr` | `size`, `usage`, `physical_usage`, `current_operations`, `VDIs`, identity fields | | |
| `vifs` | `MAC`, `MTU`, `device`, `lockingMode`, `allowedIpv4Addresses`, `allowedIpv6Addresses`, `rateLimit`, `txChecksumming` | `attached`, `currently_attached`, identity fields | the two address lists are sets | |
| `vbds` | `bootable`, `device`, `is_cd_drive`, `position`, `read_only` | `attached`, `currently_attached`, `parent`, identity fields | | |
| `vdis` | `name_label`, `VDI_type`, `size`, `cbt_enabled`, `image_format` | `usage`, `physical_usage`, `current_operations`, `snapshots`, `parent`, identity fields | | |
| `backup-jobs` | `name`, `type`, `mode`, `compression`, `proxy`, `remotes`, `srs`, `vms` | `settings`, `userId` | `remotes`, `srs`, `vms` sets | the shape of `vms` (list or filter) |
| `backup-job-settings` | `jobId`, `scheduleId`, `exportRetention`, `snapshotRetention`, `copyRetention`, `reportRecipients`, `reportWhen`, `timeout`, `concurrency`, `offlineBackup`, `offlineSnapshot`, `fullInterval`, `checkpointSnapshot` | none | `reportRecipients` set | all names |
| `schedules` | `jobId`, `cron`, `enabled`, `name`, `timezone` | none | | |
| `backup-repositories` (floor high) | `name`, `enabled`, `url`, `options` | none | | |
| `proxies` | `name`, `address`, `version` | none | | |
| `servers` (floor high) | `label`, `host`, `username`, `httpProxy`, `allowUnauthorized`, `readOnly`, `enabled` | `status`, `error` | | |
| `users` (floor high) | `username`, `email`, `permission`, `groups`; `authProviders` is **secret** | `last_uses` | `groups` set | `username` (the skeleton used `email` as the name) |
| `groups` (floor high) | `name`, `provider`, `users`, `aclRoleIds` | none | `users`, `aclRoleIds` sets | |
| `acl-roles` (floor high) | `name` | none | | |
| `acl-privileges` (floor high) | none yet | none | | every field name |

Identity fields are `uuid`, `type` and `_xapiRef`. "Floor high" means the object floor of the plan
(P5-T2): an added, removed, modified or moved object of the type is at least high.

A field that is not in the table is **unclassified** (a change shows as a fingerprint only) until
the Backend Developer classifies it and the Code Reviewer agrees. A credential field that is not
listed (a server password or token, a password hash) is therefore never shown as a value.

### What Xen Orchestra hides (`hidden_by_xo`)

The table marks the values that XO itself does not return in clear, so the interface can say
"hidden by XO, changes not observable" instead of showing a field that never moves (acceptance 2).
The marker is the key `hidden_by_xo` of a type, read by `ResourceTable.is_hidden_by_xo`.

| Resource | Marked | Why | Status |
|---|---|---|---|
| `servers` | `password`, `token` | The server credential is hidden by XO (statement 11) | unverified; the two names have no source |
| `backup-repositories` | `url.credentials` | The user and password part of a remote address. `url.credentials` is a **virtual** path: it stands for that part of `url`, which the collector strips before storage and scans in full (P8-T2) | unverified |
| plugin configuration | not a collection | Plugin secrets are hidden by XO, and plugin configuration is not collected in CE v1 (statement 6) | unverified |

The marker changes no field class. The collector never relies on it to drop a value: a credential
that does arrive is still unclassified or secret.

### Decisions the table makes

1. **Boot order.** The plan says ordered-keyed for the boot order. That mode needs a field that keys
   the members and the shape of `boot.order` is unverified (a string of device letters and a list
   are both possible). The table declares `boot.order` an **ordered scalar** list, which keeps the
   order and is also what an undeclared list gets. Revisit with the vendor reference.
2. **VM selection of a backup job.** `vms` is declared a set. If it is a filter object it holds no
   list and the mode has no effect.
3. **Built in templates.** The table cannot say which templates are built in. P8-T2 drops them
   after the fetch, with a test; the field that tells them apart is not known (open item 3).
4. **Ignore class names that are not listed.** The plan also names "driver fields" and
   "dollar-prefixed back-references". Only the names the plan or the skeleton gives are classified.
   Any other name is unclassified until it is read from a real answer, and a volatile one would then
   raise a fingerprint change. The fixtures of P8-T4 (the simulated backup run) are the test.

## Open items

1. **Vendor reference.** Every name above must be checked against the vendor reference or the lab
   (tests X1 to X4). The most important are the dotted nested names (`CPUs.max`, `memory.static`,
   `boot.order`, `certificates.notAfter`) and `backup-job-settings`.
2. **Test X2.** Which collections a non-admin read-only role reaches decides how the setup guide
   (P8-T5) is worded, not whether the collector is built.
3. **Built in templates.** The name of the field that marks a built in template.
4. **Driver and back reference fields.** The names of the guest driver fields and the other
   dollar-prefixed references of VMs, hosts and VBDs.
5. **ACL privileges.** No field of a privilege is known, so only the key is classified.
6. **Credential names.** The server and remote credential field names, and whether any other
   credential field reaches the collector (test X3).

## Carried over, not settled here

- **`backup-job-settings`.** The derived resource (one object per key of the settings map of a
  backup job) is kept as P5-T3 wrote it. Whether to keep that design must be decided **before
  P8-T2**; this task does not settle it.
- **Collector factory.** `serve` has no scheduler until the collector factory exists. Neither P8-T1
  nor this file builds it.
- **Cloud base address option** of the UniFi collector (P7-T3): off by default; the decision stays
  with the Delivery lead.
- **UniFi setup guide, step 3.** The write probe in step 3 should be run in the lab only.
- **404 handling.** The UniFi pipeline counts a 404 as a partial run, while the plan (P7-T2) says a
  404 is coverage `404` and never a failure. The XO client (P8-T2) follows the plan.
