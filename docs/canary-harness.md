# Canary leak harness

The harness answers one question: after driftsniff has read a controller and stored what it saw,
can any credential still be found anywhere? It lives in `tests/security/canary.py`; the tests that
use it are in `tests/security/test_canary_leaks.py`. CI runs them as the job `CI / Canary leak
harness` (see [ci-baseline.md](ci-baseline.md) section 9).

## What a canary is

A canary is a synthetic secret: `CANARY-` followed by 24 random hex characters, new for every run.
It carries no real credential. Every canary is unique,
and its Shannon entropy is kept below 3.9 bits per character so that the scanner's entropy rule
(which fires above 4.2) never decides whether a canary is hidden or found.

The harness remembers where it injected each canary (for example `unifi-wlan/w0/x_passphrase
(secret)`). A leak report names that place and the surface where the canary was found, never the
canary value.

## What is injected

`FakeSource` makes raw controller objects of two resource types (`unifi-wlan` and `xo-server`,
three objects each) and gives every revision fresh canaries:

| Field kind | Examples | What the canary looks like |
|---|---|---|
| Secret-class fields | passphrase, RADIUS secret, API tokens (a list), a nested map value, server password and token | the plain canary |
| Free-text fields | description, comment, a list of notes, nested map values, a server label and address | a credential-shaped value that contains the canary: a URL with a password, a well-known token prefix, a JWT shape, a PEM block |
| The source row | the encrypted credential and the push key | the credential is encrypted with the credential key; of the push key only its SHA-256 is stored |

Free-text canaries are credential-shaped on purpose. Free text is configuration; the scanner turns
a value into a fingerprint only when it looks like a credential. A plain `CANARY-<hex>` sentence in
a description is stored as written, and `test_a_plain_canary_in_a_configuration_text_field_is_not_redacted`
pins that. If a field can hold a secret that has no recognisable shape, classify it as `secret` in
the type table.

## The path that is run

`collect()` takes a fake source's objects through the same steps a collector takes: `redact_object`,
`normalize_object`, `build_manifest`, then `record_collection` in one write transaction, so the
states, the manifest, the objects and the run record are stored exactly as in production. Two
revisions are collected (the second with new canaries), so a later snapshot is covered too.

## Where the harness looks

| Surface | How |
|---|---|
| Database file | the bytes of the database file, its `-wal` and its `-shm` file, before and after the database is closed (closing checkpoints the log into the main file) |
| Database rows | every column of every table; a compressed column (stored states and manifests are zstd frames, which a byte search of the file cannot see into) is searched compressed and decompressed; a text value that is valid base64 is searched decoded as well |
| Logs | every record of every logger, formatted as the application formats it, with the application's log filter installed; the extra attributes of a record are searched too |
| Raised errors | the message, the arguments, the full traceback and every chained cause of the errors that the secret handling code raises when given canaries (wrong key id, another source, damaged data, an oversize credential, a non-text key, a value that is not JSON, NaN, a bad fingerprint path) |
| Output | standard output and standard error while the collection runs |

A search looks for the whole canary and for its random hex part alone, so a leak that lost its
prefix is found.

## Proof that the harness can fail

The tests leak on purpose and require a hit: a canary logged in a message and in a log extra field,
a canary in an error message and in the cause of a chained error, a canary in a plain text column,
a compressed state and a base64 column, and a collection run with redaction switched off. The log
filter is also checked from the other side: a credential-shaped canary in a log line is scrubbed
and gives no hit.

## Limits

- The harness finds a canary only where it is looked for. The surfaces above are the ones that exist
  today. Notifications are covered by `test_notification_canaries.py` (P9-T4); API output, the
  OpenAPI document and the backup file by `test_api_canaries.py` (P9-T6, described below). The real
  collectors have their own canary tests (P7, P8). Add a surface by writing a function that returns
  `Leak` values and call it from the test.
- A secret that is transformed before it leaks (hashed, split, encrypted with another key) is not
  found; base64 is the only encoding the rows scan tries.
- The log filter is a safety net. The harness checks that the code does not log values; it does not
  turn the filter into the only protection.
- The canary job is a required check only when a repository admin adds it to the branch protection
  of `development`.

## Surfaces added in P9 (API output, OpenAPI document, backup file)

`tests/security/test_api_canaries.py` runs the real application (`tests/security/appkit.py`) and
reuses `CanaryFactory`, `CanaryScanner` and `scan_database_rows`.

| Surface | Planted | How it is searched |
|---|---|---|
| API output | values of secret and unclassified items (never written by the pipeline, so the API must hide them even if a row held them); credential-shaped text in an item path, object name, rationale and order detail; the values of the API tokens, the session cookie, the login password; a token sent in a request; the webhook address secrets and the mail login and password | the body and every header of the change list and detail, the enrichment answer, `GET /tokens`, a refused token, the notification channel (webhook and mail) and the deliveries |
| OpenAPI document | all of the above | the body and headers of `GET /api/v1/openapi.json` |
| Backup file | the login password, the session cookie, the token values, the webhook address secrets, the mail login and password | the bytes of the file made by `backup_database`, then every row with compressed columns decompressed |

Text in a path, object name, rationale or order detail is vendor data or free text, so the API
passes it through the log scrubber (`secrets.redact.scrub_text`): credential-shaped text becomes
`***REDACTED***`. A plain `CANARY-<hex>` sentence is not credential-shaped and is not scrubbed; the
test plants the URL, prefixed-token and JWT shapes, like the core harness. Values of `config`
fields are shown on purpose, and the last test of the file reports one to prove the scan can find
something.
