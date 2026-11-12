# Zabbix vendor notes

driftsniff's own notes on the Zabbix API that the Zabbix collector reads
(`src/driftsniff/collectors/zabbix/`, type table `src/driftsniff/rules/types/zabbix.yaml`, packs
`src/driftsniff/rules/packs/zabbix/`). Nothing here is copied from the vendor; every statement is in
our own words, with its source and the date it was read.

## Status in one paragraph

The statements below were read from the Zabbix manual (API section) for versions 8.0 (`current`),
7.0, 6.2 and 6.0, and from the 7.2 upgrade notes, on **2026-11-12**. **No lab Zabbix was used**:
nothing here is checked against a running server, and the contract tests run against
`tests/contract/fake_zabbix.py`, which follows these notes. Supported: Zabbix **6.0 and later**
(the LTS releases 6.0, 7.0 and 8.0 and the releases between them). Names marked **UNVERIFIED**
were not found in what was read or not compared across versions.

## Sources

| Id | Source | Read on |
|---|---|---|
| S1 | https://www.zabbix.com/documentation/current/en/manual/api (8.0: endpoint, request and answer shape, Authorization header, Content-Type) | 2026-11-12 |
| S2 | https://www.zabbix.com/documentation/7.0/en/manual/api (Authorization header, `auth` member deprecated) | 2026-11-12 |
| S3 | https://www.zabbix.com/documentation/6.0/en/manual/api (`auth` member, no header) | 2026-11-12 |
| S4 | Zabbix 7.2 upgrade notes ("auth API property dropped", deprecated since 6.4), found through a web search of zabbix.com | 2026-11-12 |
| S5 | `.../current/en/manual/api/reference/apiinfo/version` | 2026-11-12 |
| S6 | `.../current/en/manual/api/reference_commentary` (common get parameters; values are sent as text) | 2026-11-12 |
| S7 | host object and `host.get`: `current`, 7.0 and 6.0 | 2026-11-12 |
| S8 | `usergroup.get`: `current`, 6.2, 6.0; user group object (`current`) | 2026-11-12 |
| S9 | user object and `user.get`, role object (`current`) | 2026-11-12 |
| S10 | media type object (`current`) | 2026-11-12 |
| S11 | authentication object: `current` and 6.0 | 2026-11-12 |
| S12 | `action.get`, trigger object, `trigger.get`, `template.get`, user macro object and `usermacro.get`, proxy object (`current`) | 2026-11-12 |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | Every call is a JSON-RPC 2.0 POST to `api_jsonrpc.php` in the frontend directory, so the frontend path is part of the URL (`https://example.com/zabbix/api_jsonrpc.php` when the frontend is under `/zabbix`). `Content-Type` must be `application/json-rpc`, `application/json` or `application/jsonrequest`. | S1 | vendor doc |
| 2 | A request is `{jsonrpc, method, params, id}`; a good answer `{jsonrpc, result, id}`, a failed one `{jsonrpc, error: {code, message, data}, id}`. | S1 | vendor doc |
| 3 | From 6.4 the token goes in `Authorization: Bearer <token>`. 6.0 knows only the `auth` member of the request body. 7.0 documents the `auth` member as deprecated; 7.2 removed it (deprecated since 6.4). | S1, S2, S3, S4 | vendor doc |
| 4 | `apiinfo.version` takes an empty array, answers the version as text (equal to the Zabbix version) and is only for unauthenticated callers. | S5 | vendor doc |
| 5 | Common get parameters: `output` (`extend` or a list; the id is always returned), `limit`, `sortfield`, `sortorder`, `filter` (exact match, not for text fields), `preservekeys`, `countOutput`. There is **no offset**. Values are returned as texts or arrays. | S6 | vendor doc |
| 6 | Host: `hostid`, `host`, `name`, `status` (0 enabled, 1 disabled), `description`, `flags` (0 plain, 4 discovered), `inventory_mode`, `ipmi_*` (`ipmi_password` not marked write-only), `tls_connect`, `tls_accept`, `tls_issuer`, `tls_subject`, `tls_psk` and `tls_psk_identity` (write-only), maintenance fields (read-only), `active_available` (read-only). | S7 | vendor doc |
| 7 | `host.get`: `selectInterfaces`, `selectParentTemplates` (`parentTemplates`), `selectMacros`, `selectTags`, sort by `hostid`, `host`, `name`, `status`, filter by `hostids`. | S7 | vendor doc |
| 8 | 6.0 has `proxy_hostid`; 7.0 replaces it with `monitored_by`, `proxyid`, `proxy_groupid` (and read-only `assigned_proxyid`). | S7 | vendor doc |
| 9 | 6.0 `host.get` has `selectGroups` (`groups`); 8.0 documents `selectHostGroups` (`hostgroups`). The change is taken to be 6.2, with template groups. | S7, S8 | vendor doc; the 6.2 threshold for `host.get` and `maintenance.get` is **UNVERIFIED** (only `usergroup.get` was read for 6.2) |
| 10 | `usergroup.get`: 6.0 `selectRights` (`rights`: `{permission, id}`); 6.2 adds `selectHostGroupRights` and `selectTemplateGroupRights` and deprecates `selectRights`; 8.0 no longer lists it. Permission 0 denied, 2 read, 3 read-write. `gui_access` 0 system default, 1 internal, 2 LDAP, 3 disabled; `users_status` 0 enabled, 1 disabled; `debug_mode`; `mfa_status`. `selectTagFilters` (`tag_filters`: `groupid`, `tag`, `value`). | S8 | vendor doc |
| 11 | User: `passwd` is write-only; `attempt_*` are read-only; `username` (since 5.4), `roleid`, `autologin`, `autologout`, `name`, `surname`, `url`. `user.get` has `selectUsrgrps`, `selectRole` (`roleid`, `name`, `type`, `readonly`). Admin and User type users see only themselves in full. Role `type` 1 User, 2 Admin, 3 Super admin; role rules `ui`, `ui.default_access`, `services.*`, `modules`, `api.access`, `api.mode`, `api` (wildcards allowed), `actions`. | S9 | vendor doc |
| 12 | A user macro (`macro`, `value`, `type`, `description`, host macros also `automatic`) has `type` 0 text, 1 secret, 2 vault secret; the value of a secret macro is **write-only**. `usermacro.get` with `globalmacro` reads global macros. | S12 | vendor doc |
| 13 | Media type: `type` 0 email, 1 script, 2 SMS, 4 webhook, 5 push; SMTP fields, `username`, `passwd`, `script`, `parameters` (webhook `{name, value}`, script `{sortorder, value}`), OAuth fields (`client_secret` Super admin only, `access_token`, `refresh_token`, token times). | S10 | vendor doc; whether `passwd` and the OAuth tokens are returned at all is **UNVERIFIED** |
| 14 | Authentication settings (8.0): `authentication_type`, `http_*`, `ldap_auth_enabled`, `ldap_case_sensitive`, `ldap_userdirectoryid`, `saml_auth_enabled`, `saml_case_sensitive`, `passwd_min_length`, `passwd_check_rules`, JIT fields, `disabled_usrgrpid`, `mfa_status`, `mfaid`. 6.0 has the LDAP server (`ldap_host`, `ldap_bind_dn`, `ldap_bind_password`, ...) and SAML fields in the same object. | S11 | vendor doc |
| 15 | `action.get`: `selectFilter` (`evaltype`, `formula`, `eval_formula`, `conditions` with `conditiontype`, `operator`, `value`, `value2`, `formulaid`), `selectOperations`, `selectRecoveryOperations`, `selectUpdateOperations`; status 0 enabled, 1 disabled. | S12 | vendor doc; the members of the operation sub-objects, `notify_if_canceled` and `pause_symptoms` are **UNVERIFIED** |
| 16 | Trigger: `value`, `lastchange`, `state`, `error`, `flags`, `templateid` are read-only; `priority` 0 to 5; `status` 0 enabled, 1 disabled. `trigger.get` has `expandExpression`, `selectHosts`, sort by `triggerid` among others, filter by `triggerids`. | S12 | vendor doc |
| 17 | Proxy (7.0 and later): `name`, `operating_mode` (0 active, 1 passive), `address`, `port`, `allowed_addresses`, `tls_*` (`tls_psk*` write-only), timeouts; read-only `lastaccess`, `version`, `compatibility`, `state`. 6.0 names (`host`, `status` 5/6, `proxy_address`) are listed from memory of the 6.0 schema. | S12 | 7.0+ vendor doc; the 6.0 names are **UNVERIFIED** |
| 18 | `template.get`: `selectParentTemplates` (`parentTemplates`), `selectMacros`; `maintenance.get`: `selectHosts`, `selectTimeperiods`, `selectTags`. | S12 | vendor doc; members of a time period and of SNMP interface `details` are **UNVERIFIED** |
| 19 | The exact JSON-RPC error codes and texts for a refused token and a missing permission. | none read | **UNVERIFIED**; the client treats any error on the token check as a refused token, and any error whose text names a permission as `forbidden` |
| 20 | Zabbix refuses an `output` field it does not know. | none read | **UNVERIFIED** (believed from experience); it is why `extend` is used where the field set differs between versions |

## Decisions of driftsniff

- The address is the frontend address with its path; the client adds `/api_jsonrpc.php` (an
  address that already ends with it is used as is).
- The probe reads `apiinfo.version` with no credential, refuses versions below 6.0, picks where the
  token goes (statement 3) and checks it with a one-row `hostgroup.get`.
- `output` lists only configuration fields where they are the same on 6.0 to 8.0 (hosts, host
  groups, templates, triggers, users, user groups, roles, global macros). Actions, media types,
  proxies, maintenance periods and the authentication settings are read with `extend` (statement
  20); the type table ignores what is volatile and classes credentials as secret.
- `user.get` never asks for `passwd` (it is write-only anyway).
- Hosts and triggers: plain objects only (`filter: {flags: "0"}`): objects made by low-level
  discovery come and go with what they find. There is no offset (statement 5), so they are listed
  by id first (`limit` 100 001) and read 500 ids per request; more than 100 000 fails the resource
  (`too_many_objects`) instead of storing part of it.
- Version renames with the same shape are folded into the newer name (`groups` to `hostgroups`,
  `rights` to `hostgroup_rights`), so an upgrade is not a change.
- The value of a secret macro, if ever returned, moves to `secret_value` (classed secret); text and
  vault macro values stay readable (a vault value is a path, not the secret).
- Webhook parameter values and the webhook script are classed secret: they hold URLs and tokens
  alike, so a change shows as a changed fingerprint, graded high like any media type change.
- Users, user groups, user roles and the authentication settings have the object floor high, so
  low and medium rules there would never apply; none are shipped.
- The fake's Admin type token is refused `authentication.get`, `mediatype.get`, `role.get` and
  `proxy.get`. That set is an assumption of the fake, not a verified list.
