# Setting up a Checkmk source

This guide connects driftsniff to one Checkmk site so that it records changes to hosts, folders,
host, service and contact groups, users, time periods, the password store and notification rules.

## Read this first

- **Checked on a lab Checkmk 2.5.0p14 Community site (2026-11-13)** with an automation user whose
  only role is a copy of `admin` without **Make changes, perform actions**: all nine collections
  answered, and a change to a contact group and its revert were reported. The API paths and fields
  otherwise come from the Checkmk source and documentation (`docs/vendor-notes/checkmk.md`).
- driftsniff **only reads**: it sends `GET` requests and nothing else. It never activates
  changes. The user still has every right its roles give, so the role is the real limit.
- driftsniff reads the Setup configuration, not monitoring states. Rules of rulesets and pending
  changes are not read (see the vendor notes for why).

## What driftsniff reads

All paths are below `<site address>/check_mk/api/1.0`.

| Resource | Checkmk path | Permission |
|---|---|---|
| `checkmk-hosts` | `/domain-types/host_config/collections/all?effective_attributes=false` | `wato.see_all_folders` (or read access to the folders) |
| `checkmk-folders` | `/domain-types/folder_config/collections/all?recursive=true` | read access to the folders |
| `checkmk-host-groups` | `/domain-types/host_group_config/collections/all` | `wato.groups` |
| `checkmk-service-groups` | `/domain-types/service_group_config/collections/all` | `wato.groups` |
| `checkmk-contact-groups` | `/domain-types/contact_group_config/collections/all` | `wato.users` |
| `checkmk-users` | `/domain-types/user_config/collections/all` | `wato.users` |
| `checkmk-time-periods` | `/domain-types/time_period/collections/all` | `wato.timeperiods` |
| `checkmk-passwords` | `/domain-types/password/collections/all` (names and sharing only, never the password) | `wato.passwords` |
| `checkmk-notification-rules` | `/domain-types/notification_rule/collections/all` (Checkmk 2.3 and later) | `general.edit_notifications` |

A resource the user may not read shows coverage `401` or `403` (Checkmk answers a missing
permission with 401) and keeps its previous state; nothing is reported as removed. A site without
notification rules in its API shows `404`.

## Least privilege

- Use a dedicated **automation user** (for example `driftsniff`), so the secret can be replaced
  without touching people's accounts.
- Give it a role **without** "Make changes, perform actions" (`wato.edit`): the collections above
  can then be read but nothing can be changed through the API. A copy of the `user` role with the
  permissions in the table added, and `wato.edit` left out, is a good start. Check the role in
  your Checkmk version; this was read from the source, not tried on a site.
- `wato.users` and `wato.passwords` show who may sign in and which credentials exist (never the
  passwords themselves). Leave them out if you do not want that coverage.
- Host and folder attributes are served as stored, so the SNMP communities and IPMI credentials
  reach driftsniff; it keeps only their fingerprints.

## Steps

1. In Checkmk, open **Setup > Users > Users**, select **Add user**, give it an id such as
   `driftsniff`, choose **Automation secret for machine accounts**, generate a secret and copy it,
   and give it the role prepared above. The quickest role with full coverage is a copy of
   `admin` (Setup > Users > Roles & permissions > clone) with **Make changes, perform actions** set
   to *no*: it can read everything driftsniff reads and change nothing. On 2.5.0p14 the REST API
   accepted the new automation user as soon as it was saved, before the change was activated.
2. In driftsniff, select **Add source**, choose **Checkmk**, and enter a name, the address of the
   site including the site name (for example `https://checkmk.example.invalid/mysite`, without
   `/check_mk`), the user name, the automation secret, the interval, the resources and the TLS
   mode.
3. Select **Test connection**. It reads the version and each resource once and stores nothing.
   The version shows as Checkmk reports it, with the edition at the end (`2.4.0p2.cre`).

## What is graded how

Shipped rules (`src/driftsniff/rules/packs/checkmk/`):

- **critical**: a user is given the `admin` role.
- **high**: a host, folder, user or stored password added or removed; a user may sign in again
  or changed how they sign in; a role or the sites of a user changed; SNMP or management board
  credentials changed; who a stored password is shared with; how a notification is delivered; a
  notification rule switched off.
- **medium**: host and folder attributes (a folder's attributes are inherited by its hosts), a
  host moved to another folder, contact groups, a user's contact groups or notification settings,
  time periods, other notification rule changes.
- **low**: host and folder labels, aliases, titles, comments and personal preferences.
