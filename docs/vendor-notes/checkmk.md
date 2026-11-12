# Checkmk vendor notes

driftsniff's own notes on the Checkmk REST API that the Checkmk collector reads
(`src/driftsniff/collectors/checkmk/`, type table `src/driftsniff/rules/types/checkmk.yaml`).
Nothing here is copied from the vendor; every statement is in our own words, with its source and
the date it was read.

## Status in one paragraph

The statements below were read from the Checkmk source code of the REST API (GitHub
`Checkmk/checkmk`, tag `2.4.0`) and from the Checkmk REST API documentation on **2026-11-12**.
**No lab Checkmk site was used**: nothing here is checked against a running site, and the contract
tests run against `tests/contract/fake_checkmk.py`, which follows these notes. The built-in OpenAPI
document of a site (`/check_mk/api/1.0/openapi-swagger-ui.json`) was not read, since no site was
available. Names marked **UNVERIFIED** were not found in the code that builds the answers.

## Sources

| Id | Source | Read on |
|---|---|---|
| S1 | https://docs.checkmk.com/latest/en/rest_api.html (base URL with the site name, Bearer header, problem answers) | 2026-11-12 |
| S2 | `cmk/gui/wsgi/applications/rest_api.py` (URL map `/<site>/check_mk/api/<version>/`, spec and UI routes, error handling) | 2026-11-12 |
| S3 | `cmk/gui/auth.py` (`Bearer <user> <secret>` split at the first space; automation and normal users) and `cmk/gui/exceptions.py` (authentication errors are HTTP 401) | 2026-11-12 |
| S4 | `cmk/gui/openapi/endpoints/version/` (`/version`) | 2026-11-12 |
| S5 | `cmk/gui/openapi/endpoints/host_config/`, `folder_config/`, `cmk/gui/watolib/builtin_attributes.py`, `cmk/gui/fields/attributes.py` | 2026-11-12 |
| S6 | `cmk/gui/openapi/endpoints/host_group_config/`, `service_group_config/`, `contact_group_config/`, `utils.py` | 2026-11-12 |
| S7 | `cmk/gui/openapi/endpoints/user_config/` | 2026-11-12 |
| S8 | `cmk/gui/openapi/endpoints/time_periods/`, `password/`, `notification_rules/` | 2026-11-12 |
| S9 | `cmk/gui/openapi/restful_objects/constructors.py` (collection and domain object shapes, `/domain-types/<type>/collections/all`) | 2026-11-12 |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | The REST API of a site is at `<scheme>://<host>/<site>/check_mk/api/<version>/`. The version segment is free text in the URL map; the documentation uses `1.0` and `v1`. The spec is served at `openapi-swagger-ui.json`/`.yaml` and an interactive UI at `ui/`. | S1, S2 | source and doc |
| 2 | Credentials go in `Authorization: Bearer <user> <secret>`. Checkmk splits the token at the first space, so the user name cannot hold a space. Automation users (secret) and normal users (password) are both accepted. | S1, S3 | source and doc |
| 3 | Every endpoint needs a signed in user; a missing or wrong credential answers 401. A missing permission (`user.need_permission`) raises the same authentication error and also answers **401**, not 403. Errors are problem objects `{title, status, detail}`. | S2, S3 | source |
| 4 | A collection answers `{links, id, domainType, value, extensions}`; each entry of `value` is a domain object `{links, domainType, id, title, members, extensions}` with the configuration in `extensions`. There is no paging. | S9 | source |
| 5 | `GET /version` answers `site`, `group`, `rest_api`, `versions` (`checkmk` such as `2.4.0p2.cre`, plus `apache`, `python`, `mod_wsgi`, `wsgi`), `edition` (short name such as `cre`) and `demo`. | S4 | source |
| 6 | `GET /domain-types/host_config/collections/all` lists every host the user may see; with `effective_attributes=false` (the default) the inherited attributes are left out. Extensions: `folder`, `attributes` (as stored), `effective_attributes`, `is_cluster`, `is_offline`, `cluster_nodes`. The title is the alias, or the host name. | S5 | source |
| 7 | Built-in host attributes: `alias`, `ipaddress`, `ipv6address`, `additional_ipv4addresses`, `additional_ipv6addresses`, `snmp_community`, `parents`, `network_scan`, `network_scan_result`, `management_address`, `management_protocol`, `management_snmp_community`, `management_ipmi_credentials`, `site`, `locked_by`, `locked_attributes`, `meta_data`, `inventory_failed`, `waiting_for_discovery`, `labels`; plus `contactgroups` and one `tag_<group>` per tag group. The list endpoint serves `attributes` without a schema dump, so the SNMP communities (a string, or a v3 tuple with passwords) and the IPMI password are in the answer. | S5 | source |
| 8 | `GET /domain-types/folder_config/collections/all?recursive=true` lists the root folder and all its subfolders (without `recursive`, only the direct subfolders). Id is the folder slug (`~` for the root, `~servers~linux`), title the folder title, extensions `path` and `attributes`. | S5 | source |
| 9 | Host, service and contact group collections: id is the group name, title its alias, extensions everything else of the group (contact groups: `inventory_paths`; `customer` in the managed services edition). Permission `wato.groups` (host and service groups) and `wato.users` (contact groups). Built-in user roles are `admin`, `user`, `guest` and `agent_registration` (the role ids, not checked against a site). | S6 | source; role ids from the documentation of user roles (**UNVERIFIED** against a site) |
| 10 | `GET /domain-types/user_config/collections/all` (permission `wato.users`): `fullname`, `customer`, `disable_login`, `contact_options {email, fallback_contact}`, `idle_timeout {option, duration}`, `roles`, `contactgroups`, `pager_address`, `disable_notifications {disable, timerange}`, `language`, `temperature_unit`, `auth_option {auth_type, store_automation_secret, enforce_password_change}`, `interface_options`, custom user attributes. No password, hash or automation secret. `authorized_sites` is in the response schema but not in the code that builds the answer. | S7 | source; `authorized_sites` **UNVERIFIED** |
| 11 | `GET /domain-types/time_period/collections/all` (permission `wato.timeperiods`): `alias`, `exclude` (not for `24X7`), `active_time_ranges [{day, time_ranges [{start, end}]}]`, `exceptions [{date, time_ranges}]`. | S8 | source |
| 12 | `GET /domain-types/password/collections/all` (permission `wato.passwords`): title, and only `comment`, `docu_url`, `owned_by`, `shared_with`, `customer` in the extensions. The password itself is never returned. The response schema names `documentation_url`, `editable_by` and `shared` instead. | S8 | source; schema names **UNVERIFIED** as served |
| 13 | `GET /domain-types/notification_rule/collections/all` (permission `general.edit_notifications`; Checkmk 2.3 and later): id is the rule id, title the description, extensions `rule_config {rule_properties, notification_method {notify_plugin {option, plugin_params}, notification_bulking}, contact_selection, conditions}`. Most members are `{state, value}`. `plugin_params` holds the method's parameters, including webhook URLs, API keys and passwords (or references to the password store). | S8 | source; members beyond those named in the type table not opened (**UNVERIFIED**) |
| 14 | Creating, changing and deleting objects needs `wato.edit` in addition to the read permission; a role without `wato.edit` can read these collections but not change them. | S6, S7, S8 | source |
| 15 | Rules of rulesets are read per ruleset (`/domain-types/rule/collections/all?ruleset_name=...`) and their value is a Python literal text. | S1 | doc; not read by the collector |
| 16 | Pending changes and activation runs (`/domain-types/activation_run/...`) change with every edit and are not configuration. | S1 | doc; not read by the collector |

## Decisions of driftsniff

- The collector appends `/check_mk/api/1.0` to the site address the admin enters.
- Extensions are lifted to the top of each object; `links`, `members` and `domainType` are
  dropped. Host and folder `labels` and `tag_*` attributes become keyed lists (`attributes.labels`
  by `key`, `attributes.tags` by `group`), so own labels and tag groups are classified.
- A 401 or 403 on a resource after a good probe is coverage `forbidden` (statement 3): the
  previous state stays, nothing is reported as removed. A 404 is `not_available` (an older site
  without notification rules).
- Secret in the type table: host and folder `snmp_community`, `management_snmp_community`,
  `management_ipmi_credentials`, and notification `plugin_params` as a whole (its `plugin_name`
  is copied out to `notify_plugin.plugin_name`). Also secret in case a version serves them: user
  `password` and `automation_secret`, password store `password`.
- Volatile and ignored: `meta_data`, `network_scan_result`, `inventory_failed`,
  `waiting_for_discovery`, `effective_attributes`, `is_offline` (derived from the criticality
  tag), user `interface_options`, and the titles that repeat another field.
- No object floors: a floor would also grade a member removed from a list inside an object (a
  label, a role) as high. A `**` rule per resource grades whole added and removed objects instead.
- **Not read**: rules of rulesets (statement 15; one call per ruleset, values are Python literal
  texts that cannot be compared field by field and can hold credentials of special agents), and
  activation status and pending changes (statement 16; volatile). Global settings, sites, LDAP
  connections, host tag group definitions, roles and agent bakery settings are not read in this
  version.
