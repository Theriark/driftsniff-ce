# Lab evidence

What driftsniff was checked against on real systems, and what each check settled. A setup guide or
vendor note may call a statement **VERIFIED** only when this file records the check behind it;
`tests/unit/test_xo_setup_guide.py` enforces that for the Xen Orchestra guide.

Every system below is a lab system run by the maintainers, read by a driftsniff instance from the
`development` branch with read-only intent. Names of the lab systems, their hosts and their data are
not recorded here. The integrations not listed (Synology DSM, QNAP, Proxmox VE, Redfish,
Prometheus, Zabbix, UniFi Protect) are tested only against the simulations of the Mock Platform and
the fakes in `tests/contract`.

## How a system was checked

1. Create the account the setup guide asks for, with the least rights that cover every resource.
2. Add the source and run it; read the coverage panel: every resource must answer, or the reason
   it does not must be understood.
3. Read every stored field in the configuration view and classify each one that showed as
   unclassified (fixes went into the type tables, with a test that holds the real field paths).
4. Run it again with nothing changed: no change may be reported.
5. **Change test:** change one harmless setting on the system, run the source, check the change
   item (path, before, after, rule, severity), revert the setting, run again, check the revert.

## Results (2026-11-13 and 2026-11-14)

| System | Version | Account | Resources | Change test | Fixes that came from it |
|---|---|---|---|---|---|
| UniFi Network (two consoles) | 10.6.109 | API key of an owner account | 14 of 14 | firewall policy description set and cleared: low, rule `unifi.firewall_policies.description` | real field names and ordering of controller-made policies (#138), `index` ignored and normaliser version 2 (#139), `metadata.configurable` (#140) |
| TrueNAS Community Edition | 25.04.2.6 | user with only the Read-Only Administrator privilege, API key | 18 of 18 | SMB share description set and cleared: high (share floor) | child datasets were never read; 25.04 SMB share shape; 56 fields classified (#141) |
| Portainer Business Edition | 2.45.3 | access token of an administrator | 10 of 10 | a stack file changed by an image update: high, rule `portainer.stacks.file` | Edge groups 503 while Edge compute is off; about 80 fields; cloud keys and stack webhooks secret (#143); same value stored in clear and as a fingerprint is no change (#144) |
| Checkmk Community | 2.5.0p14 | automation user, role a copy of `admin` without "Make changes, perform actions" | 9 of 9 | contact group alias set and restored: medium | version text of 2.5; 53 notification rule fields (#145) |
| Home Assistant | 2026.10.4, then 2026.11.1 | long-lived token of an administrator | 8 of 8 | entity name override set and cleared: low | 8 entity fields; identifiers no longer taken for secrets (#146); an object whose key moved between clear and fingerprint is one object (#147) |
| Grafana | 13.3.0 | service account with the Admin role, token | 10 of 10 | folder renamed and renamed back: low on the folder and, after #151, low on its permissions | about 45 fields (#148); subtrees for dashboard panels and labels (#149); a folder rename no longer high on the permissions object (#151) |
| Xen Orchestra (two servers, one pool) | XO 5 (2026 build) | authentication token of an administrator | 20 of 20 | pool description set and cleared, reported by both servers: low after #156 | the REST root redirects, probe reads a collection (#152); 58 fields (#153); the hourly `xo:clientInfo` heartbeat is dropped, normaliser version 3 (#154) |

Between the checks, the lab systems changed on their own (firmware updates, a Home Assistant
update, a new user): driftsniff reported each of those as a change, which is not recorded here.

## Still open

- UniFi: what a View Only account can read (the check used an owner key).
- TrueNAS: NFS, iSCSI, replication, cloud sync and cron jobs (none configured on the lab system).
- Portainer: Edge groups themselves, teams, tags, and filled-in cloud keys or webhooks.
- Checkmk: host and service groups, and notification conditions on labels, tags or levels.
- Xen Orchestra: a non-admin user with a read-only ACL role (mode b of the guide); the expiry of
  the credential in use is not read on these builds (`/users/me` redirects).
- Every integration in the list of the second paragraph above.
