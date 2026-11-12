# Portainer vendor notes

driftsniff's own notes on the Portainer API that the Portainer collector reads
(`src/driftsniff/collectors/portainer/`, type table `src/driftsniff/rules/types/portainer.yaml`).
Nothing here is copied from the vendor; every statement is in our own words, with its source and
the date it was read.

## Status in one paragraph

The statements below were read from the Portainer source code (the Go structs and the swagger
annotations of the HTTP handlers, `develop` branch) and from the Portainer documentation on
**2026-11-12**. **No lab Portainer was used**: nothing here is checked against a running server,
and the contract tests run against `tests/contract/fake_portainer.py`, which follows these notes. The
SwaggerHub page named in older material is marked "no longer maintained" by Portainer; the current
API reference (`api-docs.portainer.io`) renders client side and could not be read as text, so the
handlers' own annotations were used instead. Names marked **UNVERIFIED** were not found in what was
read.

## Sources

| Id | Source | Read on |
|---|---|---|
| S1 | https://docs.portainer.io/api/access (access tokens, header, admin-only example) | 2026-11-12 |
| S2 | https://github.com/portainer/portainer, `api/portainer.go` (structs, json tags, role and type constants) | 2026-11-12 |
| S3 | same repository, `api/http/handler/*/` list handlers: `endpoints/endpoint_list.go`, `endpoints/handler.go`, `endpointgroups/endpointgroup_list.go`, `tags/tag_list.go`, `edgegroups/edgegroup_list.go`, `stacks/stack_list.go`, `stacks/stack_file.go`, `users/user_list.go`, `teams/team_list.go`, `teammemberships/teammembership_list.go`, `registries/registry_list.go`, `registries/handler.go`, `settings/settings_inspect.go`, `settings/handler.go`, `system/version.go` | 2026-11-12 |
| S4 | same repository, `api/git/types/types.go` (git config of a stack) | 2026-11-12 |
| S5 | https://api.swaggerhub.com/apis/portainer/portainer-ce (only says the page moved) | 2026-11-12 |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | An access token is sent in the header `X-API-Key`. It has the rights of the user who made it (My account, Access tokens). | S1 | vendor doc |
| 2 | `GET /api/system/version` needs a token and answers `ServerVersion`, `DatabaseVersion`, `ServerEdition`, `Build` and more. `/api/status` is public. | S3 | source |
| 3 | `GET /api/endpoints` lists environments. Fields include `Id`, `Name`, `Type`, `URL`, `PublicURL`, `GroupId`, `TagIds`, `TLSConfig` (`TLS`, `TLSSkipVerify`, `TLSCACert`, `TLSCert`, `TLSKey`), `UserAccessPolicies` and `TeamAccessPolicies` (maps from id to `{RoleId, Namespaces}`), `EdgeID`, `EdgeKey`, `SecuritySettings`, `Edge`, `Kubernetes`, `Snapshots`, `Status`, `Heartbeat`. | S2, S3 | source |
| 4 | `GET /api/endpoint_groups`: `Id`, `Name`, `Description`, `TagIds`, `UserAccessPolicies`, `TeamAccessPolicies`. | S2, S3 | source |
| 5 | Without `limit` the environment list is not paginated (the handler returns everything when limit is 0); `X-Total-Count` is set. The other lists have no paging. | S3 | source |
| 6 | `excludeSnapshots=true` leaves the snapshots out of the environment list. The handler clears `AzureCredentials` itself but **does not clear `EdgeKey`**. | S3 | source |
| 7 | `GET /api/tags`: `ID` (no json tag, so the Go name), `Name`, `Endpoints` and `EndpointGroups` (maps from id to true). | S2 | source |
| 8 | Roles and types: user role 1 administrator, 2 standard user; team membership role 1 leader, 2 member; authentication method 1 internal, 2 LDAP, 3 OAuth; environment types 1 to 7 (Docker, agent, Azure, Edge agent, local Kubernetes, Kubernetes agent, Edge Kubernetes); registry types 1 to 8 (Quay, Azure, custom, GitLab, ProGet, Docker Hub, ECR, GitHub). | S2 | source |
| 9 | `GET /api/registries`: `Id`, `Type`, `Name`, `URL`, `BaseURL`, `Authentication`, `Username`, `Password`, `AccessToken`, `ManagementConfiguration`, `Gitlab`, `Github`, `Quay`, `Ecr`, `RegistryAccesses` (map from environment id to accesses). The handler clears `Password` and reduces `ManagementConfiguration` to its TLS settings; it does not clear `AccessToken`. Non-admins see only the registries they may use. | S2, S3 | source |
| 10 | `GET /api/stacks` (authenticated, only the stacks the user may see): `Id`, `Name`, `Type`, `EndpointId`, `SwarmId`, `EntryPoint`, `Env` (list of `{name, value}`), `AdditionalFiles`, `AutoUpdate`, `GitConfig` (`URL`, `ReferenceName`, `ConfigFilePath`, `Authentication {Username, Password, ...}`, `ConfigHash`, `TLSSkipVerify`), `Status`, bookkeeping dates. `GET /api/stacks/{id}/file` answers `{StackFileContent}`. | S2, S3, S4 | source |
| 11 | `GET /api/users` answers only `Id`, `Username` and `Role` in the current source (older versions return the stored user). `GET /api/teams`: `Id`, `Name`, `DenyPortainerAccess`. `GET /api/team_memberships` (administrator or team leader): `Id`, `UserID`, `TeamID`, `Role`. | S2, S3 | source |
| 12 | `GET /api/settings` is administrator only. It clears `LDAPSettings.Password`, `OAuthSettings.ClientSecret` and `OAuthSettings.KubeSecretKey` before answering; it does **not** clear `AgentSecret`. `GET /api/edge_groups` is administrator only (`Id`, `Name`, `Dynamic`, `TagIds`, `PartialMatch`, `Endpoints`, plus derived fields). | S1, S3 | source |
| 13 | Members of `Settings.Edge`, `FeatureFlagSettings`, `GlobalDeploymentOptions`, the stack `Option`, and the registry sub-objects `Gitlab`, `Github`, `Quay`, `Ecr`. | none read | **UNVERIFIED**; unclassified in the type table |
| 14 | The exact JSON key casing of the stack `AutoUpdate` members (`Interval`, `Webhook`, `ForceUpdate`, `ForcePullImage`, `JobID`): the struct has no json tags, so the Go names are assumed. | S2 | source, by Go default |
| 15 | Portainer CE has no read-only role: a standard user cannot read the settings, Edge groups or (unless team leader) team memberships. | S1, S3 | source; a read-only role exists only in Business Edition (not read here: **UNVERIFIED**) |

## Decisions of driftsniff

- The access maps (statements 3, 4, 7, 9) are turned into lists of objects with the id as a field
  (`collectors/portainer/normalize.py`), so the type table can classify their members.
- The settings object gets the fixed key `settings`.
- Secret in the type table even though Portainer clears them today (defence in depth): the LDAP
  password, the OAuth client secret and kube secret key, registry passwords. Secret because
  Portainer serves them: `EdgeKey`, `AgentSecret`, registry `AccessToken`, stack `Env` values, the
  git password, the auto update webhook and the whole stack file (it can hold inline credentials).
- A stack file that cannot be read fails the stacks resource for that run; the previous state
  stays, so nothing is reported as changed or removed by mistake.
