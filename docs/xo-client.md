# The Xen Orchestra client (P8-T2)

`driftsniff.collectors.xo.client.XoClient` reads the REST interface of Xen Orchestra (XO), read
only. It is a `Collector` (docs/collectors.md): `probe()`, `resources()`, `fetch(spec)`, `close()`.

**Nothing in the interface names below is verified.** The vendor reference was not read and no lab
Xen Orchestra exists (docs/vendor-notes/xo.md; Phase 0 tests X1 to X4 are open). The REST prefix
(`/rest/v0`), the cookie name, the collection names, the field names and the credential endpoint
are the plan's or our own reading of how such an interface is laid out. The behaviour (streaming,
coverage, expiry) is the plan's and does not depend on them. When the vendor reference exists,
correct `collectors/xo/resources.py`; the tests use a fake server (`tests/contract/fake_xo.py`) and
change with it.

## The credential

The session credential is sent in one cookie, `authenticationToken`, and nowhere else: never as
basic credentials, never in a query string, a log line or an error text. The client logs nothing and
every error text is fixed, so the text of an answer is never shown. A credential that is blank or
holds characters a cookie cannot carry (a space, a quote, a comma, a semicolon, a backslash, a
control or non ASCII character) is refused when the client is made.

## Probe

1. The host is resolved once and every address is checked (metadata and link-local addresses are
   refused, error class `blocked_address`; `collectors/resolve.py`).
2. The REST root is requested once. A 401 or 403 stops the probe (`unauthorized`, `forbidden`); a
   404, a web page or an answer that is not JSON is `no_api`. XO reports no version through it, so
   `probe()` returns `None`.
3. After a good probe the client tries once to read the expiry of the credential in use (see
   below). No collection is read before a probe has succeeded: `fetch` raises `not_probed`.

## Collections

The client reads these collections, in this order, and no others: `vms`, `vm-templates`, `hosts`,
`pools`, `networks`, `pifs`, `pbds`, `srs`, `vifs`, `vbds`, `vdis`, `backup-jobs`, `schedules`,
`backup-repositories`, `proxies`, `servers`, `users`, `groups`, `acl-roles` and `acl-privileges`
(when the credential can reach it).

- **One request each.** The request carries an explicit field list and asks for newline delimited
  JSON: `?fields=<list>&ndjson=true`. No paging parameter is sent; a collection is treated as
  unpaginated.
- **The field list comes from the type table** of the collection (`rules/types/xo.yaml`): the first
  segment of every field that is not ignore class, sorted, plus the key field. A nested object
  (`memory`, `settings`) is asked for whole; the ignore class fields inside it are dropped by the
  normaliser, and a field the table does not name is unclassified (a fingerprint only).
  `vm-templates` also asks for the marker of a built in template.
- **Excluded collections can never be requested.** `tasks`, `alarms`, `messages`, `backup-logs`,
  `restore-logs`, `backup-archives`, `events`, `vm-snapshots`, `vdi-snapshots`, `licenses`, `sms`,
  `pcis`, `pgpus`, `vm-controller` and `xoa` have no type table and are not in the list above; a
  `fetch` for any name outside the list fails with `unknown_resource` and sends nothing.
- **Streaming.** The body is read in chunks and parsed line by line, so memory stays flat while it
  streams (a test reads 200,000 small objects and asserts growth under 100 MB). The 200 MB limit
  counts bytes while they arrive; one line may be at most 16 MB.
- **Order.** The objects are sorted by id after the fetch; the order the server returned is never
  trusted.
- **A bad line fails that collection only** (`bad_payload`): a line that is not valid JSON, a value
  that is not an object, or an object without a text id. The other collections are read as usual.
  The error text never quotes the line.

## Coverage

As for UniFi (plan P7-T2): a 404 on a collection is coverage `404` (class `not_available`) and a
403 is coverage `403` (class `forbidden`). Neither is a failure of the run and neither is retried;
the previous state of the collection stays, so nothing is reported as removed. A read-only role is
expected to get 403 on `users`, `groups`, `servers` and the repositories (test X2 is open). Any
other failure keeps its error class and its HTTP status; a timeout and a 5xx answer are retried by
the pipeline.

## What is removed before the pipeline

- **Built in templates** are dropped from `vm-templates` (the marker field `isDefaultTemplate` is
  unverified; an object without it stays).
- **The user and password part** of the address of a backup repository (`smb://user:password@host`)
  is removed from `url` before storage; the rest of the address is scanned like every other value.
  XO itself hides some credentials (`hidden_by_xo` in the type table); this covers the one that can
  arrive inside an address.

## Credential expiry

The administrator may enter the expiry date of the credential when saving the source (an entered
date means the end of that day, UTC). After a successful probe the client tries **once** to read the
expiry of the credential in use from the REST interface (`/users/me/authentication_tokens`, the
entry whose id is the credential; epoch milliseconds or an ISO 8601 text; unverified). A 403, a 404
or any other failure of that read is tolerated and the entered date is used. The reported date wins
over the entered one when both exist.

`client.token_expiring()` is true when the date that counts is in the past or within 14 days. The
caller sets the source state `token_expiring` from it (the interface shows it in P10). The clock is
injectable (`clock=`), which is how the tests cover it.

## Not done here

- The factory that builds a client from a stored source (decrypts the credential, reads the TLS
  options and the entered expiry, saves the state `token_expiring`). `serve` has no scheduler until
  it exists.
- The setup guide (P8-T5). The rule pack and golden rows are P8-T3; the volatility, coverage and
  canary tests are P8-T4 (docs/xo-volatility.md).
- No lab result is claimed anywhere in this repository.
