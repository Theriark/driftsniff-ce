# Setting up a Zabbix source

This guide connects driftsniff to a Zabbix server (6.0 or later) so that it records changes to
hosts, host groups, templates, triggers, actions, media types, users, user groups, user roles,
global macros, proxies, maintenance periods and the authentication settings.

## Read this first

- **No lab Zabbix has been used.** The API methods and fields come from the Zabbix manual, read on
  2026-11-12 (`docs/vendor-notes/zabbix.md`). The collector is tested against a fake Zabbix on
  localhost (`tests/contract/fake_zabbix.py`), not a real server.
- driftsniff **only reads**: it calls `apiinfo.version` and `*.get` methods and nothing else. The
  token still has every right of its user, so the role you give that user is the real limit.

## What driftsniff reads

| Resource | Zabbix method | Needs a Super admin type role |
|---|---|---|
| `zabbix-hosts` | `host.get` (plain hosts, with interfaces, groups, linked templates, macros, tags) | no (sees the host groups the user may read) |
| `zabbix-host-groups` | `hostgroup.get` | no |
| `zabbix-templates` | `template.get` | no |
| `zabbix-triggers` | `trigger.get` (plain triggers) | no |
| `zabbix-actions` | `action.get` | UNVERIFIED |
| `zabbix-media-types` | `mediatype.get` | yes (UNVERIFIED for older versions) |
| `zabbix-users` | `user.get` | yes for full details |
| `zabbix-user-groups` | `usergroup.get` | yes for the permissions |
| `zabbix-user-roles` | `role.get` | UNVERIFIED |
| `zabbix-global-macros` | `usermacro.get` with `globalmacro` | no |
| `zabbix-proxies` | `proxy.get` | UNVERIFIED |
| `zabbix-maintenance` | `maintenance.get` | no |
| `zabbix-authentication` | `authentication.get` | yes |

A resource the token may not read shows coverage `403` and keeps its previous state; nothing is
reported as removed.

## Least privilege

Full coverage needs a user whose role has the type **Super admin**, because the authentication
settings, media types and the details of other users are only shown to that type. Limit what the
token can do with the role itself:

1. In Zabbix, **Users > User roles > Create user role**: name `driftsniff-reader`, user type
   **Super admin role**.
2. Under **Access to UI elements**, turn every element off.
3. Under **Access to API**, enable it, choose **Allow list** and enter the method `*.get`
   (`apiinfo.version` needs no right). The manual says wildcards such as `*.get` are accepted; that
   this blocks every write was not tested on a server (UNVERIFIED).
4. Under **Access to actions**, turn every action off.
5. Create a user `driftsniff` with that role, in a user group whose frontend access is
   **Disabled**.

With an Admin or User type role instead, hosts and triggers are limited to the host groups the user
may read, and the resources marked "yes" above answer `403`.

## Steps

1. Sign in as a Super admin, open **Users > API tokens**, select **Create API token** for the user
   `driftsniff`, set an expiry date and copy the token: Zabbix shows it once. (API tokens exist
   since Zabbix 5.4.)
2. In driftsniff, select **Add source**, choose **Zabbix**, and enter a name, the `https://`
   address of the Zabbix frontend **including the path it is served under** (for example
   `https://zabbix.example.invalid/zabbix`, or `https://zabbix.example.invalid` when the frontend
   is at the root; not `/api_jsonrpc.php`), the token, the interval, the resources and the TLS mode.
3. Select **Test connection**. It reads the version and each resource once and stores nothing.

The token is stored encrypted and never shown again. On Zabbix 6.4 and later it is sent in the
`Authorization: Bearer` header; on 6.0 and 6.2, which do not read that header, it is sent in the
`auth` member of the request body. It is never put in a URL.

## What is never stored in clear

IPMI passwords and PSKs of hosts, SNMP communities and passphrases, the value of a secret macro
(Zabbix does not return it anyway), media type passwords, OAuth secrets and tokens, webhook
parameter values and scripts, proxy PSKs and the LDAP bind password of the 6.0 authentication
settings: driftsniff keeps only a keyed fingerprint of each, so it can tell that one changed but
not what it is.

## What is not read

Items, discovery rules, prototypes, scripts, dashboards, maps, services, SLAs, user directories,
template groups, history and events. Hosts and triggers made by low-level discovery are skipped.
Volatile values (trigger state and last change, proxy last access, host maintenance status, user
sign in attempts) are ignored, so polling does not create changes.
