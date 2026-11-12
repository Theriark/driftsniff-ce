# TrueNAS vendor notes

driftsniff's own notes on the TrueNAS interface that the TrueNAS collector reads
(`src/driftsniff/collectors/truenas/`). They are written for the people who build and review the
collector and the type table `src/driftsniff/rules/types/truenas.yaml`. Every statement is in our
own words, with its source and the date it was read.

## Status in one paragraph

**Nothing here is lab-verified.** No lab TrueNAS was read. The method names, the query options
and the field names come from the vendor's published API reference (S3 to S5), read on
2026-11-12 through a summarising web reader, so a field the reader left out can be missing. The
collector, the rule pack and the pipeline are tested against a fake TrueNAS on localhost
(`tests/contract/fake_truenas.py`) that serves those names. That shows what driftsniff does with
them; it does not show that a real TrueNAS answers with them. Every field name is therefore
**UNVERIFIED** against a live system, as the header of the type table says.

## Sources

| Id | Source | Read | Used for |
|---|---|---|---|
| S1 | TrueNAS 26 documentation, "Deprecations" (`truenas.com/docs/scale/26/gettingstarted/deprecations/`, page dated 2026-04-01) | 2026-11-12 | REST API deprecated in 25.04 and removed in 26; `auth.login` and `auth.login_with_api_key` deprecated in 26, planned removal in 27; `auth.login_ex` with `API_KEY_PLAIN` stays |
| S2 | TrueNAS 26 documentation, "API" (`truenas.com/docs/scale/26/api/`) | 2026-11-12 | JSON-RPC 2.0 over WebSocket since 25.04; API keys only over HTTPS, a key sent over plain http is revoked |
| S3 | API reference index (`api.truenas.com`) | 2026-11-12 | Versions offered: 25.10 (stable), 27 (early), 28 (preview); docs also on the box at `/api/docs/` |
| S4 | API reference 25.10, `jsonrpc.html` and `api_methods_auth.login_ex.html`; 25.04 `api_methods_auth.login_ex.html` | 2026-11-12 | Request, result and error shape; error codes -32000, -32001; `API_KEY_PLAIN` takes `username` and `api_key`; `response_type` SUCCESS, AUTH_ERR, EXPIRED, OTP_REQUIRED, REDIRECT (same in 25.04) |
| S5 | API reference 25.10, the `*.query` / `*.config` pages of every method in the table below | 2026-11-12 | Field names, which fields are run state, which hold secrets |
| S6 | Search result summaries (TrueNAS forum, 25.10 release notes) | 2026-11-12 | 25.10.1 raises an alert when a deprecated REST endpoint is used; the removal was announced for "26.04" |

## REST or WebSocket: the decision

- The REST API (`/api/v2.0`, `Authorization: Bearer <key>`) was **deprecated in 25.04** and is
  **removed in TrueNAS 26** (S1). It still answers on 25.04 and 25.10, and 25.10.1 raises an alert
  every time a deprecated REST endpoint is used (S6). A collector polling every few minutes would
  keep that alert raised on every supported box and stop working on the next major release.
- The JSON-RPC 2.0 API over one WebSocket is the API of 25.04 and later (S2) and the only one after
  REST is removed. **driftsniff uses it.** TrueNAS 24.10 and older (and TrueNAS CORE) are not
  supported: they have no `/api/current`, and the probe reports `no_api`.
- Sign in: `auth.login_ex` with `mechanism: API_KEY_PLAIN`, `username` and `api_key` (S4). The
  older `auth.login_with_api_key` (key only) is deprecated in 26 and planned for removal in 27
  (S1), so it is not used. `API_KEY_PLAIN` needs the user name, which is why a TrueNAS source has a
  user name field next to the API key.
- No WebSocket library is a dependency of driftsniff. The collector has its own small RFC 6455 client
  (`collectors/truenas/websocket.py`) that opens the connection through the shared HTTP client, so
  the TLS modes, the certificate pin, the pinned address and the refusal of redirects of the other
  collectors apply unchanged.

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | The WebSocket endpoint is `/api/current` (`wss://<host>/api/current`). | S6 (search summary of the deprecation page); the 25.10 reference does not name the path | UNVERIFIED |
| 2 | Requests are `{"jsonrpc": "2.0", "id", "method", "params": [...]}`; answers carry `result` or `error {code, message, data {errname, reason, ...}}`. | S4 | documented |
| 3 | An unknown method answers code `-32601` (JSON-RPC method not found). A refused call answers `-32001` with `errname` `EACCES` / `ENOTAUTHENTICATED`. | JSON-RPC 2.0 standard; S4 names -32001; the errnames are our reading | UNVERIFIED |
| 4 | The methods read: `pool.query`, `pool.dataset.query`, `sharing.smb.query`, `sharing.nfs.query`, `iscsi.target.query`, `iscsi.extent.query`, `user.query`, `group.query`, `ssh.config`, `service.query`, `interface.query`, `network.configuration.config`, `pool.snapshottask.query`, `replication.query`, `cloudsync.query`, `cloudsync.credentials.query`, `cronjob.query`, `certificate.query`, and `system.version` for the probe. | S5 | documented, UNVERIFIED live |
| 5 | `pool.dataset.query` accepts `[[], {"extra": {"flat": true, "retrieve_children": false, "retrieve_user_props": false}}]`. | S5 | UNVERIFIED |
| 6 | ZFS properties of pools and datasets are objects `{parsed, rawvalue, value, source, source_info}`; `value` is the text the UI shows (`LZ4`, `ON`, `STANDARD`). | S5 | documented; the exact `value` texts are UNVERIFIED |
| 7 | `guestok` of an SMB share exists only inside `options` of a legacy share. | S5 | documented |
| 8 | A user that belongs to `builtin_administrators` has `FULL_ADMIN` in `roles`. | Our reading of the role model; S5 lists `roles` but not its values | UNVERIFIED |
| 9 | `user.query` returns `unixhash`, `smbhash` and `password_history`; `ssh.config` returns the host private keys; `certificate.query` returns `privatekey`; `cloudsync.credentials.query` and `cloudsync.query` return provider secrets; `replication.query` returns `encryption_key`. | S5 | documented; whether a read-only user receives them in clear is UNVERIFIED |
| 10 | Run state that changes without a configuration change: pool `status`, `healthy`, `scan`, `expand`, sizes, `topology`; dataset `used*`, `available`, `compressratio`, `key_loaded`, `locked`; share `locked`; service `state`, `pids`; interface `state`; network `state`; task `state` and `job`; user `password_age`, `last_password_change`; certificate `expired`. | S5 (descriptions), our reading | ignore class; volatility not measured on a live system |
| 11 | API keys sent over plain http are revoked. | S2 | documented |
| 12 | TrueNAS CORE (FreeBSD) has no `/api/current`. | Our reading (CORE ended at 13.x with the REST and the legacy WebSocket API) | UNVERIFIED |

## What the collector does to the answers

Dropped before the pipeline: the certificate `privatekey` and the SSH host private keys. Flattened:
pool and dataset properties to their `value`. Derived: `open_to_all` on NFS shares (no network and
no host), `full_admin` on users (`FULL_ADMIN` in `roles`). Reduced: the snapshot tasks embedded in a
replication task to their ids. Everything else is passed raw and classified by the type table.

## Not covered (yet)

The vdev layout of a pool (`topology` carries per-disk state and counters; tracking the layout
needs a derived field), apps, virtual machines, Kubernetes/Docker settings, directory services,
alert settings, UPS, SNMP and other per-service config methods, rsync and scrub tasks, API keys
(`api_key.query`), privileges (`privilege.query`), Kerberos and KMIP. Each is one more entry in
`collectors/truenas/resources.py` and a type table.
