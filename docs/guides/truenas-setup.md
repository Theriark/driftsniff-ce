# Setting up a TrueNAS source

This guide connects driftsniff to a TrueNAS system so it records changes to its pools, datasets,
shares, users and groups, SSH and other services, network settings, snapshot, replication and
cloud sync tasks, cloud credentials, cron jobs and certificates. It is for the person who runs
TrueNAS and the driftsniff admin.

## Read this first

- **Checked on a lab TrueNAS 25.04.2.6 (2026-11-13)** with a user that holds only the Read-Only
  Administrator privilege: all 18 resources answered, and a change to an SMB share and its revert
  were reported. Steps 1 and 2 are **VERIFIED on 25.04.2.6**. Field names of what the lab system
  did not have (NFS, iSCSI, replication, cloud sync, cron) still come from the 25.10 reference
  (`docs/vendor-notes/truenas.md`) and are labelled **NOT VERIFIED** where they matter.
- TrueNAS gives a read-only user a fixed placeholder instead of password hashes, so a password
  change is not visible with such a user.
- The client and the pipeline are tested against a fake TrueNAS on localhost
  (`tests/contract/fake_truenas.py`). That shows how driftsniff behaves for the names it expects,
  not that a real TrueNAS answers with them.

## What driftsniff does with TrueNAS

- **It only reads.** It calls `*.query` and `*.config` methods and `system.version`, nothing else.
  The API key still has the rights of its user, so give that user a read-only role (step 1).
- It uses the JSON-RPC 2.0 API over one WebSocket at `/api/current` (TrueNAS 25.04 and later). The
  REST API is deprecated and is removed in TrueNAS 26, so it is not used. TrueNAS 24.10 and older
  and TrueNAS CORE are not supported: the connection test reports that the API did not answer.
- The source holds the user name and the API key in two fields. The key is sent once per check, inside the sign in call
  (`auth.login_ex`) on the encrypted connection, never in an address, a header, a log line or an
  error. It is **encrypted at rest** and never shown again after you save it.
- Private keys of certificates and SSH host keys are dropped as they arrive and never stored.
  Password hashes, cloud provider secrets and encryption passwords are stored only as keyed
  fingerprints: a change shows that the value changed, not the value.
- Run state is ignored (pool usage and health, scrubs, service state, task and job progress), so an
  unchanged system gives no changes.

## Steps

1. **Create a read-only user on TrueNAS.** Credentials > Users > Add, for example `driftsniff`,
   with **Disable Password** on. Under **Auxiliary Groups** add `truenas_readonly_administrators`,
   the group behind the built-in privilege **Read-Only Administrator** (Credentials > Groups >
   Privileges shows it). Untick **SMB User**, which is on by default, and keep the shell
   `nologin` and no home directory. VERIFIED on 25.04.2.6.
2. **Create an API key for that user.** Credentials > Users > **API Keys** (top right) > Add: a
   name such as `driftsniff`, the user from step 1, and **Non-expiring** or a date. Copy the key:
   TrueNAS shows it once. VERIFIED on 25.04.2.6.
3. **Add the source in driftsniff.** Sources > Add a source > TrueNAS.
   - Address: `https://nas.example.invalid` (no path, no user name).
   - User name: the TrueNAS user, for example `driftsniff`. API key: the key, for example `1-AbC...`.
   - Do **not** use a plain `http://` address with a real key: TrueNAS revokes an API key that is
     used over plain http.
4. **TLS.** TrueNAS ships a self-signed certificate (`truenas_default`). Either install a trusted
   certificate on TrueNAS, upload its CA as a CA bundle (mode *ca_file*) or pin its fingerprint
   (mode *pinned*). See `docs/tls.md`.
5. **Test the connection**, then save. The first check stores the current configuration; changes
   appear from the second check on.

## What a check reads, and what is high or critical

Users, groups, the SSH service, SMB, NFS and iSCSI shares and cloud credentials: every change is
at least **high**. Critical: SSH password login switched on, the cipher NONE allowed, a user
allowed to sign in over SSH with a password (root included), a user becoming a full administrator
(for example by joining `builtin_administrators`), a changed SSH key of a user, password-less sudo
changes, group roles changed, an SMB share admitting guests, an NFS share exported to everyone, or
NFS root mapping to root. High: dataset made read only or writable, encryption off, sync disabled,
ACL type changed, snapshot, replication or cloud sync task turned off, replication target changed,
cron command changed, gateway, first name server or proxy changed, a service set to start. Low:
descriptions and names only. The rule packs are `src/driftsniff/rules/packs/truenas/`.

A resource the user may not read shows **403** in the coverage panel and keeps its last state; a
method your version does not have shows **404**. Neither reports anything as removed.
