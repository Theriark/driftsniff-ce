# The UniFi client (P7-T2)

`driftsniff.collectors.unifi.client.UnifiClient` reads the integration API of the UniFi Network
application, read only. It is a `Collector` (docs/collectors.md): `probe()`, `resources()`,
`fetch(spec)`, `close()`.

**Nothing in the interface names below is verified.** Dependency D5 (the vendor reference) is open
and no lab controller was used (docs/vendor-notes/unifi.md). The paths, the key header name and the
envelope names come from third party descriptions. The behaviour (floor, paging, coverage) is the
plan's and does not depend on them. When D5 exists, correct `collectors/unifi/resources.py` and the
header name; the tests use a fake controller (`tests/contract/fake_unifi.py`) and change with them.

## The credential

The API key is sent in one request header, `X-API-KEY`, and nowhere else: never in a query string,
a log line or an error text. The client logs nothing and every error text is fixed, so the text of
an answer (which a misbehaving controller could fill with the key it received) is never shown. A
key that is blank or holds characters a header cannot carry is refused when the client is made.

## Probe and version floor

1. The host is resolved once and every address is checked with `blocked_reason` (metadata and
   link-local addresses are refused, error class `blocked_address`). The connection resolves the
   name again, so a name that changes its answer in between is not caught.
2. The information endpoint is called on the direct integration path (`/integration`), then on the
   console proxy path (`/proxy/network/integration`). A stored base path is tried first. The first
   path that answers with an application version wins and is available as `client.base_path`; the
   caller stores it in the source options. A 404, a web page or an answer without a version moves
   on to the next path; any other failure stops the probe. Neither path answering is `no_api`.
3. A 401 or 403 on the probe stops it (`unauthorized`, `forbidden`).
4. The version is compared as integer tuples with the floor 10.1.84. A lower version, or one that
   cannot be read, raises `UnsupportedVersionError` (error class `unsupported_version`) with a plain
   message that holds only numbers the client parsed itself. No resource is read after that:
   `fetch` raises `not_probed` until a probe has succeeded.

## Paging

Lists are read with `limit=200` and a growing `offset`.

- With a reported `totalCount` the loop runs until that many objects are read. A short page does
  not end it, because a controller may cap its page size below 200 and a silently cut list would
  show up as removed objects. A list that ends (empty page) before the total is `bad_payload` and
  the resource keeps its previous state.
- Without a total, a short page ends the list.
- A page equal to the previous page stops the loop with `paging_loop`; so does a list that is
  still going after 1000 pages.

Resources below a site (everything but `unifi-sites`) are read once per site and joined. The site
list is read once per run. A site id that is not letters, digits, `_` or `-` is refused
(`bad_payload`) before it can reach a path.

## Coverage

| Answer | Result of `fetch` | Status | Retried by the pipeline |
|---|---|---|---|
| 200 | the raw objects | `200` | |
| 404 | failure `not_available` | `404` | no |
| 403 | failure `forbidden` | `403` | no |
| 5xx, timeout | failure `http_error` or `timeout` | `5xx` or `error` | yes |
| invalid JSON | failure `bad_json` | `error` | no |
| JSON that is not a page of objects | failure `bad_payload` | `error` | no |
| body cut short | failure `connection` | `error` | no |
| repeated page | failure `paging_loop` | `error` | no |

A failed resource keeps its previous state in the pipeline, so nothing is reported as removed.
Objects reach the pipeline as raw dictionaries; only the paging envelope and the object key are
read through pydantic (`collectors/unifi/models.py`).

## What is not here

- TLS modes (P7-T3): the client uses the system trust store only.
- The ordering lists of firewall policies and ACL rules and the rule pack (P7-T4).
- The factory that builds a client from a stored source and saves the detected base path and the
  state `unsupported`. The source option for the base path does not exist yet; the factory adds
  it to `ALLOWED_OPTIONS`. `serve` has no scheduler until that factory exists (P7 or P8).
- `unifi-site-settings` is not read: no source names an endpoint for it.
- The run pipeline counts a `404` resource as failed (the run is `partial`). The plan calls it
  "never a failure"; whether the pipeline should treat `not_available` differently is a decision
  for Delivery.
