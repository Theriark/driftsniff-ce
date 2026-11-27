# Sources

A source is one system driftsniff watches. There are 15 kinds (`SOURCE_TYPES` in
`driftsniff.db.tables`): 14 polled kinds that driftsniff reads itself, `unifi` (UniFi Network),
`unifi_protect`, `xo` (Xen Orchestra), `proxmox`, `portainer`, `truenas`, `synology`, `qnap`,
`redfish`, `homeassistant`, `grafana`, `prometheus`, `zabbix` and `checkmk`, and `push`, a sender
that pushes its own documents. The source service (`driftsniff.sources.service`) creates,
updates, enables, disables and deletes them. The collector and run pipeline (`collectors.md`) and the scheduler (`scheduler.md`) build on it.

## What a source holds

| Field | Rule |
|---|---|
| name | 1 to 100 printable characters, unique |
| type | one of the 15 kinds above; it cannot change later |
| base address | polled sources only; `https://`, no user name, password, query or fragment, trailing slashes removed |
| credential | polled sources only; required; encrypted before it is stored (a password, an API key or a token, as the setup guide of the kind says) |
| options | `allow_plain_http` (true or false), `interval_seconds` (whole seconds, 60 to 3600, default 300, polled sources only), the TLS options of `tls.md` (`tls_mode`, `tls_ca_file`, `tls_pin`, and `insecure`, which the service sets itself exactly when the mode is `insecure`; polled sources only), `username` (`synology`, `qnap`, `truenas`, `redfish`, `checkmk` and `prometheus` only: the user name that goes with the password; it may stay empty for `prometheus`, which then sends the credential as a bearer token), `resources_off` (polled sources only: a list of at most 100 distinct resource names the admin turned off), `credential_expires_on` (`xo` only: the expiry date of the credential an admin entered, `YYYY-MM-DD`) and `push_fields` (push sources only, see `push.md`); an unknown option, a wrong type, a value out of range or an option of another type is refused |
| enabled | a disabled source is not collected |

A `push` source has no address and no credential. It has a sender key instead, made by an admin
with Make sender key on the source page (`POST /sources/{id}/push-key`, which calls
`set_push_key`); only the SHA-256 of the key is stored and the key itself is returned once.
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
  connects. Every collector calls `pin_address` (`driftsniff.collectors.resolve`): it resolves
  the name once, refuses it when any answer is blocked (`blocked_reason` of
  `driftsniff.sources.addresses`), and pins the first answer for every connection of the run, so a
  name that changes its answer between the check and the request (DNS rebinding) cannot reach a
  blocked address. Collectors do not follow redirects (`FOLLOW_REDIRECTS` is `False`).

## Audit events

Every change writes one event in the same transaction as the change, with the actor that was
passed in: `source.create`, `source.update` (the detail lists the names of the fields that
changed, never their values), `source.enable`, `source.disable`, `source.allow_plain_http`,
`source.tls_insecure_enabled` (the TLS mode `insecure` was set, after the confirmation sentence),
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
`tests/unit/test_push_source_service.py` and `tests/unit/test_source_options.py`. Run with
`pytest tests/unit/test_source_addresses.py tests/unit/test_source_service.py tests/unit/test_push_source_service.py`.
