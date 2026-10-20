# Secret handling: field classes, fingerprints, scanner and redaction

driftsniff stores what a controller reports, but never a credential. This page describes the
rules that keep credentials out of storage, logs and the interface.

## Field classes

Every field of every resource type has one of four classes, set in the type table.

| Class | Stored | Shown |
|---|---|---|
| `config` | yes | yes |
| `secret` | fingerprint only | fingerprint only |
| `ignore` | no (dropped before storage) | no |
| `unclassified` | yes | a change is shown as a fingerprint only |

A new vendor field is `unclassified` until someone classifies it.

## Fingerprints

A fingerprint is HMAC-SHA-256 over `driftsniff-fp-v1`, a slash, the resource type, a slash, the
field path, a zero byte and the canonical JSON of the value, keyed with the fingerprint key
(see [key-management.md](key-management.md)). The first 128 bits are kept as 32 hex characters
with the id of the key that made them. The interface shows the first 8 to 12 characters.

- Two equal secrets in two fields, or two resource types, never share a fingerprint.
- The same secret in the same field always does, while the master key stays the same.
- Fingerprints are compared in constant time.
- Stored form inside an object: `fp1:<key id>:<32 hex>`.

A fingerprint shows that a secret changed, not what it is. It cannot be reversed without the
master key, but it can be confirmed by anyone who holds the key and guesses the value.

## Scanner

The scanner forces the secret class on a value that looks like a credential, whatever its field
class. Rules: a PEM header, a JWT shape, a URL with user and password, a known credential prefix
(`AKIA`, `ASIA`, `AIza`, `ghp_`, `gho_`, `github_pat_`, `xoxb-`, `xoxp-`, `sk_live_`, `glpat-`
with a body of at least 8 characters), a word of 20 or more characters with Shannon entropy above
4.2 bits per character (UUIDs and hex words of length 32, 40 or 64 are exempt) and text shaped
like a stored fingerprint.

The entropy rule judges words, not whole sentences: a plain description has an entropy above 4.2
bits per character, so judging it as a whole would turn every description into a secret.
The consequence is that a passphrase made of short words in a field that is not classified
as a secret is not caught by entropy; classify such fields as `secret` in the type table.

### Reviewed false positives

`src/driftsniff/rules/overrides.yaml` lists paths where a finding is known to be harmless. Each
entry has a resource type (or `*`), a field path, an optional list of rules and a reason. A secret
field is never affected and the fingerprint look-alike rule cannot be overridden.

## Redaction at the collector boundary

`redact_object` runs on the raw object before it is normalised. It drops `ignore` fields,
replaces `secret` values and scanner findings with fingerprints, and scans every other string
(free text and map values included). It reports the paths the scanner forced, never the values.
The collectors of phases 7 and 8 must call it for every object.

Storing the first state that holds a fingerprint sets the `fp_in_use` flag in the same
transaction (see [key-management.md](key-management.md)). Code that stores a fingerprint anywhere
else (for example change items) must call `mark_fingerprints_in_use_in` in the same transaction.

## Logging

Payloads and query strings are never logged on purpose. As a safety net `driftsniff serve`
installs a filter on the log handlers that replaces PEM blocks, JWTs, passwords in URLs,
credential prefixes, long high-entropy words and URL query strings with `***REDACTED***`,
including in exception text. Words containing a slash, a backslash or a dot are not judged by
entropy in logs so that file names and host names stay readable. The filter cannot recognise an
arbitrary password that matches none of these patterns.
