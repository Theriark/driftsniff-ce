# Notifications

driftsniff can tell you that something changed: one **channel**, a webhook or an SMTP account,
receives a short message for every change event that is serious enough. The message says that
something changed and where to look. It never carries the changed values: the details stay behind
the sign-in.

Status: built in P9-T4. The settings page arrives with the interface (P10); until then an admin
uses the routes below. The collection scheduler is wired to the notifier in a later task
(`RunPipeline(notifier=service.notify_event)`); the routes, the sender and the stored deliveries
work and are tested now.

## What is sent

| Field | Content |
|---|---|
| `event_id` | The change event |
| `source` | The name of the source (control characters removed, at most 120 characters) |
| `severity` | The highest severity of the event: `low`, `medium`, `high` or `critical` |
| `summary` | The generated summary, for example `3 changes in 2 resource types, highest severity high` |
| `item_count` | The number of change items |
| `link` | `DRIFTSNIFF_BASE_URL` + `/changes/<event id>` |
| `test` | `true` only for the sample of the test button |

Nothing else leaves the application: no before or after value, no object name, no object path, no
rationale, no fingerprint. A canary test (`tests/security/test_notification_canaries.py`) plants
a canary in the before and after values, the object name and the path, and looks for it in the
webhook request, the mail, the stored deliveries, the audit events and the logs.

An event is sent when its highest severity is at least the **minimum severity** of the channel
(default `high`) and the channel is enabled. Once an event is delivered it is not sent again.

## Webhook

The body is the JSON object above (keys sorted, no spaces). Two request fields make it verifiable:

| Request field | Content |
|---|---|
| `X-Driftsniff-Timestamp` | The time of sending, whole seconds since 1970 |
| `X-Driftsniff-Signature` | The hex HMAC-SHA-256 of `<timestamp>.<body>` with the signing key |

A receiver checks that the timestamp is recent (five minutes is a good limit) and that the
signature matches, in constant time:

```python
import hashlib, hmac, time

def verify(key: bytes, timestamp: str, body: bytes, signature: str) -> bool:
    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > 300:
        return False
    expected = hmac.new(key, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

The **signing key** is derived from the master key (label `driftsniff/webhook/v1`, see
[key-management.md](key-management.md)). An admin reads it once with `POST /notifications/signing-key`
and gives it to the receiver; each reading is written to the audit log. It is the same for the whole
installation and it **changes after a rekey**: read it again and update the receiver.

The URL may carry a secret (a token in the path or the query). The whole configuration is encrypted
at rest and the interface shows only the scheme, host and port. The HTTP library's own request log
is switched off (it would print the URL).

`http://` and `https://` are accepted, so a receiver inside your network does not need a
certificate. An `https://` receiver must have a certificate that the system trust store and the
certifi bundle accept and that matches the host name; there is no option to switch the check off.
A receiver with a private CA needs that CA in the trust store of the container.

## Mail (SMTP)

Fields: `host`, `port` (default 587 for `starttls`, 465 for `tls`), `security` (`starttls`, the
default, or `tls` for implicit TLS), optional `username` and `password`, `from_address` and
`to_addresses` (up to 10, separated by commas, semicolons or spaces).

The connection is always encrypted. With `starttls` the session is upgraded before the login and
the message are sent, and a server that does not offer STARTTLS is refused (class
`smtp_no_starttls`), so the password never travels in clear. The certificate and the host name are
checked. The mail carries the same fields as the webhook body, as plain text. The password of an
existing channel is kept when the update leaves it out and the user name is the same.

## Delivery, retries and what is stored

Delivery runs in the background, never inside a collection run. The first attempt is followed by up
to **three retries after 1, 2 and 4 seconds**; then the event is given up. Every attempt is stored
(`notification_deliveries`: attempt number, status, HTTP status, error class, time).

| Status | Meaning |
|---|---|
| `delivered` | The receiver took the message (HTTP 2xx, or the mail was accepted) |
| `failed` | This attempt failed; see the error class |
| `blocked` | The target is never allowed; nothing was sent and there is no retry |

| Error class | Retried | Cause |
|---|---|---|
| `timeout`, `connection`, `server_error` (HTTP 5xx and 429), `smtp_temporary` | yes | The receiver or the network |
| `rejected` (other HTTP 4xx), `redirect` (HTTP 3xx), `tls_error`, `smtp_login`, `smtp_refused`, `smtp_no_starttls`, `unresolved`, `unexpected` | no | Something that waiting does not fix |
| `blocked_address` | no | The target is in a range that is never allowed |
| `config_unreadable` | no | The stored configuration cannot be decrypted (enter it again) |

**Redirects are never followed.** A receiver that answers with a redirect is a failure (class
`redirect`), so an allowed address cannot send the message on to a blocked one.

## Which targets are allowed

Private network targets are allowed: a self-hosted receiver is the normal case. These are **always**
refused: `169.254.0.0/16` (the cloud metadata range, `169.254.169.254` included), `fe80::/10`
(link-local) and `100.100.100.200`, in every spelling (also IPv4 inside IPv6). The check is made
**when the message is sent**, not only when the channel is saved: the host name is resolved, every
answer is checked, and one blocked answer refuses the target. The connection then goes to the
address that was checked and not to the name, so a name that changes its answer between the check
and the connection (DNS rebinding) cannot lead the message to a blocked address. The host name is
still used for the certificate check and the `Host` field.

## Routes (admin session, CSRF value on writes)

| Route | What it does |
|---|---|
| `GET /notifications/channel` | The channel as an admin may see it, or `{"channel": null}` |
| `PUT /notifications/channel` | Set the one channel (replaces the existing one). Fields: `type` (`webhook` or `smtp`), `min_severity`, `enabled` (the text `true` or `false`) and the fields of the type |
| `DELETE /notifications/channel` | Remove the channel and its stored deliveries |
| `POST /notifications/test` | Send a sample marked `"test": true`, once; the answer is `{"ok": ..., "error_class": ..., "http_status": ...}`; the outcome is written to the audit log and no delivery is stored |
| `POST /notifications/signing-key` | The webhook signing key (hex); audited |
| `GET /notifications/deliveries?event_id=&limit=` | Stored attempts, newest first |

The routes answer 503 when the application was built without the service, 401 without a session,
403 for a role below `admin`, 422 for bad input (the message names the field, never a value).

## Storage and keys

The configuration is encrypted with AES-256-GCM under the credential key. The associated data is
`driftsniff-channel-v1/channel/<channel id>/key/<key id>`, a different text from the one of a source
credential, so one can never be opened as the other. The key id is stored in
`notification_channel.key_id` (migration `0004`, which also adds `notification_deliveries.error_class`
and an index on the event). A **rekey** re-encrypts the channel in the same transaction as the source
credentials; a channel made with the lost key becomes unreadable and must be entered again (the
view shows `config_unreadable`).

Audit events: `notification.channel_saved`, `notification.channel_removed`, `notification.test`,
`notification.signing_key_shown`. They hold the type, the minimum severity, the outcome and the error
class, never an address, a password or message text.

## Limits

- One channel at a time (webhook or SMTP), as in the plan.
- There is no per-channel signing key and no option to trust a private CA for a webhook.
- A process that stops during the retry schedule does not resume it after a restart.
- The page `/changes/<id>` that the link points to is built with the interface (P10).
