# Key management

driftsniff keeps one master key. It protects stored source credentials and is the base of
the secret fingerprints that let the application show that a secret changed without storing it.

## The key file

- Location: the file named by `DRIFTSNIFF_KEY_FILE` (default `/keys/master.key`), on the key
  volume. Keep it on a different volume from `/data`.
- First start with no stored fingerprints: driftsniff creates 32 random bytes from the
  operating system random source, with exclusive create and mode `0400`.
- An existing key file is never overwritten, replaced or re-created. A symbolic link, a
  directory or a file that does not hold exactly 32 bytes is refused.
- The key id is the first 8 hex characters of the SHA-256 of the master key. It is safe to show.

## When the key file is missing

Once the first fingerprint is stored the database setting `fp_in_use` is set. From then on a
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
the interface.
