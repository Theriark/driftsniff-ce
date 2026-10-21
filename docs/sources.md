# Sources

A source is one system driftsniff watches: a UniFi Network controller (`unifi`), a Xen
Orchestra server (`xo`), or a sender that pushes its own documents (`push`). The source service
(`driftsniff.sources.service`) creates, updates, enables, disables and deletes them. The
collector and run pipeline (`collectors.md`) and the scheduler (`scheduler.md`) build on it.

## What a source holds

| Field | Rule |
|---|---|
| name | 1 to 100 printable characters, unique |
| type | `unifi`, `xo` or `push`; it cannot change later |
| base address | `unifi` and `xo` only; `https://`, no user name, password, query or fragment, trailing slashes removed |
| credential | `unifi` and `xo` only; required; encrypted before it is stored |
| options | `allow_plain_http` (true or false), `interval_seconds` (whole seconds, 60 to 3600, default 300, polled sources only) and `push_fields` (push sources only, see `push.md`); an unknown option, a wrong type or a value out of range is refused |
| enabled | a disabled source is not collected |

A `push` source has no address and no credential. It has a sender key instead, made with
`set_push_key`; only the SHA-256 of the key is stored and the key itself is returned once.
`push.md` describes the endpoint.

## Credentials

- The credential is encrypted with AES-256-GCM and the credential key (see
  `key-management.md`). The stored value is bound to the source id and the key id, so a value
  copied to another source cannot be decrypted.
- A credential is never part of a return value, an audit event, a log line or an error message.
  The service returns `has_credential` only.
- A new credential replaces the stored one. There is no way to remove one; delete the source.
- `credential_for_collector` is the only way to read it back. It exists for the run pipeline,
  which needs the credential to call the controller, and the result must go to that request and
  nowhere else.

## Addresses

- The address must be `https`. The admin can set the option `allow_plain_http` for one source;
  setting it writes the audit event `source.allow_plain_http`. Switching the option off while
  the address is still `http` is refused.
- These addresses are refused in every case, even with `allow_plain_http`: `169.254.0.0/16`
  (the cloud metadata address `169.254.169.254` is in it), `fe80::/10` and `100.100.100.200`.
  The IPv4-mapped IPv6 form and the old numeric spellings (`2852039166`, `0xa9fea9fe`,
  `169.254.43518`) are recognised too.
- The service can only judge a literal address. A host name is resolved by the collector when it
  connects. The collector must call `driftsniff.sources.addresses.blocked_reason` on every
  address the name resolves to, and must not follow redirects (`FOLLOW_REDIRECTS` is `False`).
  This is not built yet: the UniFi and XO collectors (P7, P8) own it and their tests must cover
  it.

## Audit events

Every change writes one event in the same transaction as the change, with the actor that was
passed in: `source.create`, `source.update` (the detail lists the names of the fields that
changed, never their values), `source.enable`, `source.disable`, `source.allow_plain_http`,
`source.push_key` (a sender key was made; the detail says whether it replaced one) and
`source.delete`. A failed change writes nothing.

## Deleting a source

Delete removes, in one transaction, the source row, its runs, coverage, objects, snapshots,
change events and their items, acknowledgements, notes, enrichments and notification
deliveries, and then the object states that no remaining snapshot refers to. States shared with
another source stay. If any step fails, nothing is deleted. The audit event `source.delete`
records the type, the name and how many states were removed. Users, API tokens and notification
channels belong to no source and are kept.

## Tests

`tests/unit/test_source_addresses.py`, `tests/unit/test_source_service.py` and
`tests/unit/test_push_source_service.py`. Run with
`pytest tests/unit/test_source_addresses.py tests/unit/test_source_service.py tests/unit/test_push_source_service.py`.
