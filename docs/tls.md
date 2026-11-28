# TLS modes

Every polled source reads its system over HTTPS, and every collector uses the same TLS code. The
mode is stored in the source options and applies to every request of the source. Code: `collectors/tls.py`.

| Mode | Option values | What is trusted | Host name checked |
|---|---|---|---|
| `verify` (default) | none | system trust store plus the certifi bundle | yes |
| `ca_file` | `tls_ca_file`: a file name | only the CA bundle `/data/ca/<name>` | yes |
| `pinned` | `tls_pin`: 64 hex characters | the one certificate whose DER SHA-256 equals the pin | no |
| `insecure` | `insecure` flag, set by the service | nothing | no |

TLS 1.2 is the lowest version in every mode.

## CA file

`tls_ca_file` is a **file name**, not a path (letters, digits, `.`, `_`, `-`, at most 100
characters, starting with a letter or digit), so it cannot leave `/data/ca`. The file must be PEM
text of at most 64 KB that holds only `CERTIFICATE` blocks (a private key in the file is refused),
must not be a symbolic link, and must load in OpenSSL. There is no upload: put the PEM file in
`/data/ca` on the data volume and type its file name in the source form (Certificate checks,
**CA bundle file name**). Saving the form checks the file: one that is not there, is a link, is
too large or holds anything but certificates is refused with a message on that field.

## Pinned

The pin is the SHA-256 of the server certificate in DER form (for example
`openssl x509 -in cert.pem -outform der | sha256sum`). It is compared **during the handshake,
before any request byte is sent**: the HTTP pool uses a network backend whose `start_tls` step
reads the peer certificate and compares the digest in constant time. A mismatch closes the
connection and the read fails with error class `tls_pin_mismatch`; the API key never reaches that
server. There is no check after the response. Chain and host name are not checked in this mode: the
pin is the trust decision. A pinned source is read over `https` only; plain http is refused, and
the options `allow_plain_http` and a TLS mode other than `verify` exclude each other.

A renewed certificate has a new pin, so the admin must update the pin on renewal.

## Insecure

Needs the confirmation text `I understand the risk` (typed by an admin; passed to the source service
as `tls_confirmation`). The service then stores the flag `insecure` (the source pages show
the Insecure TLS badge) and writes the audit event `source.tls_insecure_enabled`. A source that is
already insecure is not asked again; leaving the mode removes the flag.

## Errors

| Class | Meaning |
|---|---|
| `tls_error` | the certificate was not accepted (unknown CA, wrong host name, protocol failure) |
| `tls_pin_mismatch` | the certificate is not the pinned one; nothing was sent |

Both texts are fixed; no fingerprint, path or certificate appears in them.

## Notes

- The source form offers the four modes. The insecure mode asks for a confirmation sentence and
  the source then carries the Insecure TLS badge. The collector factory
  (`sources/factory.py`) builds the settings from the stored options and passes them to the client.
- There is no CA file upload (see "CA file" above).
- The cloud connector base address option is not added: nothing reads a cloud address.
- The audit action is named `source.tls_insecure_enabled`, following the `source.` prefix of the
  other audit actions; the plan calls it `tls_insecure_enabled`.
