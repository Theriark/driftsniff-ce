# The Xen Orchestra client

`driftsniff.collectors.xo.client.XoClient` reads the REST interface of Xen Orchestra (XO), read
only. It is a `Collector` (docs/collectors.md): `probe()`, `resources()`, `fetch(spec)`, `close()`.

The REST prefix (`/rest/v0`), the cookie name, the collection names and the field names were
checked against two Xen Orchestra 5 servers (2026 builds) in a lab in November 2026 (see
[the 27.0.0 release notes](release-notes/v27.0.0.md#checked-on-real-systems) and
docs/vendor-notes/xo.md). The credential endpoint could not be checked there (see "Credential
expiry"). The behaviour (streaming, coverage, expiry) does not depend on the names. The tests use
a fake server (`tests/contract/fake_xo.py`); if a later XO version changes a name, correct
`collectors/xo/resources.py` and the fake together.

## The credential

The session credential is sent in one cookie, `authenticationToken`, and nowhere else: never as
basic credentials, never in a query string, a log line or an error text. The client logs nothing and
every error text is fixed, so the text of an answer is never shown. A credential that is blank or
holds characters a cookie cannot carry (a space, a quote, a comma, a semicolon, a backslash, a
control or non ASCII character) is refused when the client is made.

## Probe

1. The host is resolved once and every address is checked (metadata and link-local addresses are
   refused, error class `blocked_address`; `collectors/resolve.py`). The first answer is pinned
   for every connection of the run.
2. One small collection is requested once: `/rest/v0/pools?fields=id&ndjson=true`. (The REST
   root itself redirects to the API documentation on XO 5 builds of 2026, and redirects are never
   followed.) A 401 or 403 stops the probe (`unauthorized`, `forbidden`); a
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

As for UniFi: a 404 on a collection is coverage `404` (class `not_available`) and a 403 is
coverage `403` (class `forbidden`). Neither is retried, and the previous state of the collection
stays, so nothing is reported as removed. The shared run pipeline counts the collection as
failed, so the run is `partial`. A read-only role is expected to get 403 on `users`, `groups`,
`servers` and the repositories (not yet checked on a lab system). Any
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

`client.token_expiring()` is true when the date that counts is in the past or within 14 days.
The clock is injectable (`clock=`), which is how the tests cover it. The source pages do not call
it: they mark a source **Credential expiring** from the entered date, with the same 14 days
(`credential_expiring` in `web/source_pages.py`).

## Not done here

- Nothing writes the source state `token_expiring`. The collector factory (`sources/factory.py`)
  builds the client from the stored source (credential, TLS options and the entered expiry, the
  source option `credential_expires_on`), but the state column is not set from the result.
- On the lab XO 5 builds `/users/me` redirects, so the reported expiry is not read there and the
  entered date is the one that counts.
- Related pages: the rule pack and golden rows (docs/rules.md, docs/golden-table.md), the
  volatility, coverage and canary tests (docs/xo-volatility.md) and the setup guide
  (docs/guides/xo-setup.md).
