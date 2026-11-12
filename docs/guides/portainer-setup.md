# Setting up a Portainer source

This guide connects driftsniff to a Portainer server so that it records changes to environments,
groups, tags, Edge groups, stacks, users, teams, registries and the Portainer settings.

## Read this first

- **No lab Portainer has been used.** The API paths and fields come from the Portainer source and
  documentation, read on 2026-11-12 (`docs/vendor-notes/portainer.md`). The collector is tested
  against a fake Portainer on localhost (`tests/contract/fake_portainer.py`), not a real server.
- driftsniff **only reads**: it sends `GET` requests and nothing else. The token still has every
  right of its user, so the role you give that user is the real limit.

## What driftsniff reads

| Resource | Portainer path | Needs an administrator |
|---|---|---|
| `portainer-environments` | `/api/endpoints?excludeSnapshots=true` | no (sees what the user may see) |
| `portainer-environment-groups` | `/api/endpoint_groups` | no |
| `portainer-tags` | `/api/tags` | no |
| `portainer-edge-groups` | `/api/edge_groups` | yes |
| `portainer-stacks` | `/api/stacks` and `/api/stacks/{id}/file` per stack | no (only visible stacks) |
| `portainer-users` | `/api/users` | no |
| `portainer-teams` | `/api/teams` | no |
| `portainer-team-memberships` | `/api/team_memberships` | yes (or team leader) |
| `portainer-registries` | `/api/registries` | no (only usable registries) |
| `portainer-settings` | `/api/settings` | yes |

A resource the token may not read shows coverage `403` and keeps its previous state; nothing is
reported as removed.

## Least privilege

Portainer CE has two user roles, administrator and standard user, and no read-only role.

- **Full coverage** needs an access token of an administrator. If that token leaks, the holder
  controls every environment. Use a dedicated user (for example `driftsniff-reader`) so the token
  can be revoked without touching people's accounts, and keep driftsniff's address list tight.
- **Narrower coverage** with a standard user: environments, stacks and registries are limited to
  what that user may use, and settings, Edge groups and team memberships answer `403`.
- Portainer Business Edition has a read-only role; it was not checked for this guide (UNVERIFIED).

## Steps

1. In Portainer, sign in as the user driftsniff will use, open **My account**, then **Access
   tokens**, and select **Add access token**. Copy the token: Portainer shows it once.
2. In driftsniff, select **Add source**, choose **Portainer**, and enter a name, the `https://`
   address of the Portainer server (for example `https://portainer.example.invalid:9443`, with no
   path), the access token, the interval, the resources and the TLS mode.
3. Select **Test connection**. It reads the version and each resource once and stores nothing.

The token is sent only in the `X-API-Key` header, stored encrypted and never shown again.

## What is never stored in clear

Stack environment values, stack files, Edge keys, the agent secret, registry passwords and access
tokens, the git password of a stack, LDAP and OAuth secrets: driftsniff keeps only a keyed
fingerprint of each, so it can tell that one changed but not what it is.
