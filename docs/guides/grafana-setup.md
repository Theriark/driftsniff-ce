# Setting up a Grafana source

This guide connects driftsniff to a Grafana server so that it records changes to data sources,
folders and their permissions, dashboards, alert rules, contact points, notification policies,
organisation users, teams and service accounts.

## Read this first

- **No lab Grafana has been used.** The API paths and fields come from the Grafana HTTP API
  documentation, read on 2026-11-12 (`docs/vendor-notes/grafana.md`). The collector is tested
  against a fake Grafana on localhost (`tests/contract/fake_grafana.py`), not a real server.
- driftsniff **only reads**: it sends `GET` requests and nothing else. The token still has every
  right of its service account, so the role you give that account is the real limit.
- One source reads one Grafana organisation, the one the service account belongs to.

## What driftsniff reads

| Resource | Grafana path | Needs the Admin role |
|---|---|---|
| `grafana-datasources` | `/api/datasources` | yes |
| `grafana-folders` | `/api/search?type=dash-folder` | no (sees the folders it may view) |
| `grafana-folder-permissions` | `/api/search?type=dash-folder`, then `/api/folders/{uid}/permissions` per folder | yes |
| `grafana-dashboards` | `/api/search?type=dash-db`, then `/api/dashboards/uid/{uid}` per dashboard (at most 500) | no (sees the dashboards it may view) |
| `grafana-alert-rules` | `/api/v1/provisioning/alert-rules` | yes |
| `grafana-contact-points` | `/api/v1/provisioning/contact-points` | yes |
| `grafana-notification-policies` | `/api/v1/provisioning/policies` | yes |
| `grafana-org-users` | `/api/org/users` | yes |
| `grafana-teams` | `/api/teams/search` | yes |
| `grafana-service-accounts` | `/api/serviceaccounts/search` | yes |

A resource the token may not read shows coverage `403` and keeps its previous state; nothing is
reported as removed. With more than 500 dashboards, only the 500 with the lowest uids are read and
the run is marked partial.

## Least privilege

A service account has one organisation role: None, Viewer, Editor or Admin. It can never be a
Grafana server administrator, so the admin settings are not read.

- **Full coverage** needs the Admin role. If that token leaks, the holder can change data sources,
  users and alerting of the organisation. Use a dedicated service account (for example
  `driftsniff`), give its token an expiry, and keep driftsniff's address list tight.
- **Narrower coverage** with Viewer: folders and dashboards that the account may view; everything
  else answers `403`. Editor sees the same resources as Viewer here. These per role answers come
  from the documentation and were not checked on a server (UNVERIFIED).

## Steps

1. In Grafana, open **Administration**, **Users and access**, **Service accounts**, and select
   **Add service account**. Give it a name and the role, then **Add service account token** and
   copy the token: Grafana shows it once.
2. In driftsniff, select **Add source**, choose **Grafana**, and enter a name, the `https://`
   address of the Grafana server (for example `https://grafana.example.invalid`, with no path),
   the token, the interval, the resources and the TLS mode.
3. Select **Test connection**. It reads the version and each resource once and stores nothing.

The token is sent only in the `Authorization: Bearer` header, stored encrypted and never shown
again.

## What is never stored in clear

Contact point settings (webhook and chat URLs that carry a token, passwords, keys) are kept only
as a keyed fingerprint, so driftsniff can tell that they changed but not what they are. Grafana
never returns data source passwords; driftsniff records only which secure fields a data source
has.
