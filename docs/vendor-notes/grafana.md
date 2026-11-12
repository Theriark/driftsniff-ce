# Grafana vendor notes

driftsniff's own notes on the Grafana HTTP API that the Grafana collector reads
(`src/driftsniff/collectors/grafana/`, type table `src/driftsniff/rules/types/grafana.yaml`).
Nothing here is copied from the vendor; every statement is in our own words, with its source and
the date it was read.

## Status in one paragraph

The statements below were read from the Grafana HTTP API documentation on **2026-11-12**. **No lab
Grafana was used**: nothing here is checked against a running server, and the contract tests run
against `tests/contract/fake_grafana.py`, which follows these notes. The current documentation
(`latest`) describes the new `/apis` endpoints for folders and dashboards; the legacy `/api`
folder and dashboard pages were read from the Grafana 11.6 archive. Grafana 13 deprecates `/api`
in favour of `/apis` but keeps the legacy endpoints working. Names marked **UNVERIFIED** were not
found in what was read.

## Sources

| Id | Source | Read on |
|---|---|---|
| S1 | https://grafana.com/docs/grafana/latest/developers/http_api/data_source/ | 2026-11-12 |
| S2 | https://grafana.com/docs/grafana/latest/developers/http_api/alerting_provisioning/ (endpoints and the schema tables) | 2026-11-12 |
| S3 | https://archive.grafana.com/docs/grafana/v11.6/developers/http_api/folder/ | 2026-11-12 |
| S4 | https://grafana.com/docs/grafana/latest/developers/http_api/folder_permissions/ | 2026-11-12 |
| S5 | https://archive.grafana.com/docs/grafana/v11.6/developers/http_api/dashboard/ | 2026-11-12 |
| S6 | https://grafana.com/docs/grafana/latest/developers/http_api/folder_dashboard_search/ | 2026-11-12 |
| S7 | https://grafana.com/docs/grafana/latest/developers/http_api/org/ | 2026-11-12 |
| S8 | https://grafana.com/docs/grafana/latest/developers/http_api/team/ | 2026-11-12 |
| S9 | https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/ | 2026-11-12 |
| S10 | https://grafana.com/docs/grafana/latest/developers/http_api/other/ (health) | 2026-11-12 |
| S11 | https://grafana.com/docs/grafana/latest/developers/http_api/admin/ (settings) | 2026-11-12 |
| S12 | https://grafana.com/docs/grafana/latest/administration/provisioning/ (data source jsonData) | 2026-11-12 |
| S13 | https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/ | 2026-11-12 |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | A service account token is sent as `Authorization: Bearer <token>`. | S1 | vendor doc |
| 2 | `GET /api/health` answers `commit`, `database` and `version`; the example sends no token. Whether a server can hide the version there is not stated. | S10 | vendor doc; auth not stated, hidden version **UNVERIFIED** |
| 3 | `GET /api/org` answers the current organisation `{id, name}` (action `orgs:read`). | S7 | vendor doc |
| 4 | `GET /api/datasources` lists data sources, without paging (5000 at most by default). Fields: `id`, `orgId`, `uid`, `name`, `type`, `typeLogoUrl`, `access`, `url`, `password`, `user`, `database`, `basicAuth`, `basicAuthUser`, `withCredentials`, `isDefault`, `jsonData`, `secureJsonFields`, `version`, `readOnly`. Action `datasources:read`. | S1 | vendor doc |
| 5 | Secure values (`secureJsonData`) are stored encrypted and never returned; `secureJsonFields` names them with `true`. `password` and `basicAuthPassword` answer empty. | S1 | vendor doc |
| 6 | Common `jsonData` keys of the core data sources include `tlsAuth`, `tlsAuthWithCACert`, `tlsSkipVerify`, `serverName`, `timeout`. | S12 | vendor doc (provisioning page) |
| 7 | `GET /api/search` takes `type` (`dash-folder`, `dash-db`), `limit` (default 1000, at most 5000) and `page` (from 1), and answers a bare list of `id`, `uid`, `orgId`, `title`, `url`, `type`, `tags`, `isStarred`, `uri` and, inside a folder, `folderId`, `folderUid`, `folderTitle`, `folderUrl`. | S6 | vendor doc |
| 8 | `GET /api/folders` with nested folders lists only the top level (`parentUid` for children). The collector lists folders through search instead. That search with `type=dash-folder` returns nested folders, with their parent in `folderUid`, is not stated. | S3, S6 | **UNVERIFIED** |
| 9 | `GET /api/folders/{uid}/permissions` answers a list of entries: `id`, `folderId`, `created`, `updated`, `userId`, `userLogin`, `userEmail`, `teamId`, `team`, `role`, `permission` (1 View, 2 Edit, 4 Admin), `permissionName`, `uid`, `title`, `slug`, `isFolder`, `url`. Action `folders.permissions:read`. An `inherited` flag for nested folders is not documented. | S4 | vendor doc; `inherited` **UNVERIFIED** |
| 10 | `GET /api/dashboards/uid/{uid}` answers `{dashboard, meta}`; the dashboard has `id`, `uid`, `title`, `tags`, `timezone`, `schemaVersion`, `version`; meta has `isStarred`, `url`, `folderId`, `folderUid`, `slug`. Action `dashboards:read`. Other meta fields (`provisioned`, `created`, `updated`, `canSave`) are not in the example. | S5 | vendor doc; other meta **UNVERIFIED** (not kept) |
| 11 | `GET /api/v1/provisioning/alert-rules` answers a list of `ProvisionedAlertRule`: `id`, `uid`, `orgID`, `folderUID`, `ruleGroup`, `title`, `condition`, `data` (list of `AlertQuery`: `refId`, `queryType`, `relativeTimeRange`, `datasourceUid`, `model`), `updated`, `noDataState`, `execErrState`, `for`, `keepFiringFor`, `annotations`, `labels`, `provenance`, `isPaused`, `notification_settings`, `record`. Marked deprecated in favour of the App Platform APIs. | S2 | vendor doc; members of `notification_settings` and `record` **UNVERIFIED** |
| 12 | `GET /api/v1/provisioning/contact-points` answers a list of `uid`, `name`, `type`, `settings`, `disableResolveMessage`, `provenance`. `settings` depends on the type. The `decrypt` parameter that redacts or decrypts secure settings is documented only for the export endpoint. | S2 | vendor doc; whether a plain GET redacts secure settings (as `[REDACTED]`) is **UNVERIFIED** |
| 13 | `GET /api/v1/provisioning/policies` answers one `Route`: `receiver`, `group_by`, `group_wait`, `group_interval`, `repeat_interval`, `continue`, `match`, `match_re`, `matchers`, `object_matchers`, `mute_time_intervals`, `provenance`, `routes` (child routes of the same shape). | S2 | vendor doc |
| 14 | `GET /api/org/users` lists the members of the current organisation: `orgId`, `userId`, `email`, `avatarUrl`, `login`, `role`, `lastSeenAt`, `lastSeenAtAge`; no paging. Action `org.users:read`, org admins. | S7 | vendor doc; `name`, `isDisabled`, `authLabels` **UNVERIFIED** |
| 15 | `GET /api/teams/search` takes `perpage` (default 1000) and `page` and answers `{totalCount, teams, page, perPage}`; a team has `id`, `orgId`, `name`, `email`, `avatarUrl`, `memberCount`. Action `teams:read`. | S8 | vendor doc; `uid` **UNVERIFIED** |
| 16 | `GET /api/serviceaccounts/search` takes `perpage` and `page` and answers `{totalCount, serviceAccounts, page, perPage}`; an account has `id`, `name`, `login`, `orgId`, `isDisabled`, `role`, `tokens`, `avatarUrl`, `accessControl`. Action `serviceaccounts:read`. | S9 | vendor doc; `uid` **UNVERIFIED** |
| 17 | `GET /api/admin/settings` needs a Grafana server administrator with basic authentication; a service account token cannot use it. | S11 | vendor doc; so driftsniff does not read it |
| 18 | Basic roles: data sources, alerting provisioning, organisation users, teams, service accounts and folder permissions need the organisation Admin role; Viewers and Editors read only the folders and dashboards they were given. | S7, S8, S13 | vendor doc; per role answers not lab checked (**UNVERIFIED**) |

## Decisions of driftsniff

- The probe reads `/api/health` (public) for the version, then `/api/org` with the token, so a
  wrong token fails the probe.
- Folders and dashboards come from search, page by page at 1000; a list stops after 50 pages.
- At most 500 dashboards are read, the lowest uids; with more, the read carries the warning
  `too_many_dashboards` and the run is `partial`. Each dashboard keeps its model with `uid`,
  `title` and `meta.folderUid` lifted to the top; the rest of `meta` is dropped (the token's own
  rights, timestamps). The model's `version`, `id` and `iteration` are ignored.
- Folder permissions are one object per folder with entries keyed `user:<id>`, `team:<id>` or
  `role:<role>`; entry ids and timestamps are dropped.
- The policy tree gets the fixed key `policies`. Child routes keep their order (it decides which
  policy applies first), so a change shows its position, for example `routes.0.receiver`.
- The whole `settings` object of a contact point is secret (a webhook or chat URL can carry its
  token, and the secure field names differ per type): driftsniff can tell that it changed, not how.
- A changed data source password cannot be seen at all: Grafana never returns it and `version`,
  which a save raises, is ignored as volatile. Adding or removing a secure field is seen through
  `secureJsonFields`.
- Mute timings and the admin settings are not read.
