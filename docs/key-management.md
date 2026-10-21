# Key management

driftsniff keeps one master key. It protects stored source credentials and is the base of
the secret fingerprints that let the application show that a secret changed without storing it.

## The key file

- Location: the file named by `DRIFTSNIFF_KEY_FILE` (default `/keys/master.key`), on the key
  volume. Keep it on a different volume from `/data`.
- First start with no stored fingerprints: driftsniff creates 32 random bytes from the
  operating system random source with mode `0400`. The key is written to a private temporary
  file next to its final name and published with an atomic hard link, so two processes that
  start together agree on one key and no process can read a half-written file. On a file system
  without hard links the key is created in place with exclusive create, and readers wait a
  moment for a file that is still too short.
- An existing key file is never overwritten, replaced or re-created. A symbolic link, a
  directory, a named pipe or a file that does not hold exactly 32 bytes is refused.
- The mode is checked every time the file is loaded: only `0400` and `0600` are accepted. A
  key file that other users can read (for example `0644` after a careless restore from backup)
  stops the start with exit code 1 and the message tells you to run `chmod 0400` on it.
- The key id is the first 8 hex characters of the SHA-256 of the master key. It is safe to show.

## Start-up

`driftsniff serve` loads or creates the key after the database is migrated and before the
server starts. It stops with:

| Exit code | Meaning |
|---|---|
| 4 | fingerprints are stored but the key file is missing |
| 1 | the key file cannot be used (unreadable, wrong size, wrong mode, a link) or cannot be created |

## When the key file is missing

Once the first fingerprint is stored the database setting `fp_in_use` is set. It is set in the
same transaction that stores the first object state holding a fingerprint, before that state is
inserted, so the flag and the fingerprint commit together or not at all. From then on a
missing key file stops the application at start with **exit code 4** and a message. driftsniff
never creates a replacement, because a new key would make every stored fingerprint and
encrypted credential unverifiable. Restore the file from your backup of the key volume.

The database backup command does not include the key. Back up the key volume separately and
keep it apart from the database backup.

## Derived keys

Four purpose keys are derived with HKDF-SHA256 (no salt, 32 bytes, the label as context):

| Purpose | Label |
|---|---|
| Secret fingerprints | `driftsniff/fingerprint/v1` |
| Source credential encryption | `driftsniff/credential/v1` |
| Sessions | `driftsniff/session/v1` |
| Webhook signing | `driftsniff/webhook/v1` |

The master key and the derived keys are never logged, shown in an error message or returned by
the interface. A test checks the hex, base64 and bytes forms of every key against the
representations, error texts, tracebacks, log output and standard streams of every failure path.

## Credential encryption

A source credential is encrypted with AES-256-GCM under the credential key. The stored value
is the base64 text of a version byte (`1`), a 12 byte random nonce and the ciphertext with its
16 byte tag. The associated data is `driftsniff-credential-v1/source/<source id>/key/<key id>`,
so a value copied to another source, or one whose `key_id` column was edited, does not decrypt.
The key id is stored next to the value in the `key_id` column of the source. A wrong key, a
wrong source and damaged data all fail with one clean error that never contains the credential.
A credential is limited to 64 KiB.

## Rekey

Use it when the master key must change. A secret fingerprint is a keyed hash and the secret is
not stored, so fingerprints cannot be converted; they are re-stamped by one collection cycle.

1. Move the old key file aside, keep it, and run
   `DRIFTSNIFF_OLD_KEY_FILE=<old file> driftsniff rekey`. The new master key is the file named
   by `DRIFTSNIFF_KEY_FILE`; it is created (mode `0400`) when it does not exist. In one
   transaction every stored credential is re-encrypted with the new key and the rekey state is
   saved. A credential made with a third key stops the rekey and nothing changes.
2. For one full collection cycle the old key file stays available through
   `DRIFTSNIFF_OLD_KEY_FILE`. For each stored fingerprint the collector computes it again with
   the key that made it. Equal: the secret did not change, so it is stored again under the new
   key with no change item. Different: a real change, shown as usual.
3. When every enabled source has finished one clean cycle, one system event `fingerprint_rekey`
   is written and the old key file can be removed.

If the old key is lost, run `driftsniff rekey --old-key-lost`. One system event
`baseline_reestablished` is written (secret changes during the gap are unknown), fingerprints
are re-stamped without a comparison, and credentials made with the lost key cannot be recovered:
enter them again.

Limits: only one rekey runs at a time; a source that is disabled when the rekey starts is not
waited for, so its fingerprints are re-stamped without a comparison if it is enabled later. The
collection runs that call the re-stamp check arrive with the collectors (phases 6 to 8).
