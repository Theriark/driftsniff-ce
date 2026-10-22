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
| certificate refused (docs/tls.md) | failure `tls_error` or `tls_pin_mismatch` | `error` | no |

A failed resource keeps its previous state in the pipeline, so nothing is reported as removed.

## Ordering and the action field (P7-T4)

Firewall policies and ACL rules are first match lists, so their order is data. The controller gives
the order in separate documents (the paths and names are **unverified**, docs/vendor-notes/
unifi.md, statements 9, 10, 16 and 17):

- Firewall policies are ordered per pair of (source zone, destination zone). For every site the
  client takes the distinct zone pairs of the policies, sorted, and asks for the ordering of each
  pair (`<site>/firewall/policies/ordering?sourceFirewallZoneId=...&destinationFirewallZoneId=...`).
  Each answer holds two lists, the policies that run before the system defined ones and those that
  run after them. The position list is the lists of all pairs one after the other, each pair
  before first, then after. The pair order is sorted so that an unchanged controller gives the same
  list every run.
- ACL rules have one list per site (`<site>/acl-rules/ordering`).
- The objects of a site are returned in that order, and the sites one after the other.

A mismatch between the lists and the objects is repaired and reported, never hidden: an object that
no list names (a policy with no usable pair of zones counts) is appended at the end, and an id that
no object has, or that is listed twice, is dropped. The result then carries the warning class
`ordering_mismatch` with a text of two counts (no ids or names), the run is `partial` and the
coverage of the resource stays `200`. A policy that moves because the controller order changed is
one `moved` item, critical when it jumped over a blocking policy.

If an ordering document cannot be read (`404`, `403`, a bad answer), the whole resource fails with
that coverage status and keeps its previous state; the order of the list answer is never used as a
guess, because it would report moves that did not happen. More than 256 zone pairs on one site is
`bad_payload`.

The nested action of a firewall policy (`action.type`) is copied to the flat field `actionType`
that the type table names as its action field; a value of that name sent by the controller is
replaced. Without the copy a move over a block policy would only be high.

Objects reach the pipeline as raw dictionaries; only the paging envelope and the object key are
read through pydantic (`collectors/unifi/models.py`).

## What is not here

- TLS modes are in `collectors/tls.py` (P7-T3, `docs/tls.md`); the client takes the settings as an
  argument. Nothing builds those settings from a stored source yet (the factory below).
- The factory that builds a client from a stored source and saves the detected base path and the
  state `unsupported`. The source option for the base path does not exist yet; the factory adds
  it to `ALLOWED_OPTIONS`. `serve` has no scheduler until that factory exists (P7 or P8).
- `unifi-site-settings` is not read: no source names an endpoint for it.
- The run pipeline counts a `404` resource as failed (the run is `partial`). The plan calls it
  "never a failure"; whether the pipeline should treat `not_available` differently is a decision
  for Delivery.
