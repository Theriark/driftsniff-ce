# API tokens

How programs get access to the `/api/v1` routes of driftsniff CE (P9-T3). The code is in
`driftsniff/web/bearer.py` (rules and storage), `driftsniff/web/routes_api.py` (the admin routes)
and `driftsniff/web/deps.py` (`require_token`). The table `api_tokens` already exists since
migration `0001`; this task adds no migration.

## What a token is

- 32 random bytes in URL-safe base64: 43 characters of `A-Z a-z 0-9 - _`.
- **Shown once**, in the answer to the request that makes it. The database keeps only the SHA-256
  of the value and its first 8 characters (the visible prefix, which is how an admin tells tokens
  apart in the list). A copy of the table, a backup or a log cannot be turned back into a token.
- It carries one or both **scopes** and may carry an **expiry**. It can be **revoked**. The time of
  its last use is stored, at most once a minute.
- It belongs to the admin who made it (`created_by` in the list). Tokens are never deleted, only
  revoked, so what a token did (audit events, later enrichments) keeps its meaning.

| Scope | May |
|---|---|
| `read` | read the change lists and details (P9-T5) |
| `enrich` | append an enrichment to a change (P9-T5) |

A scope is never implied by another one: a token with only `enrich` cannot read the lists, and a
token with only `read` cannot enrich. A token has no other power: it cannot manage tokens, users,
sources or settings, and it cannot sign in to the interface.

## Using a token

Send it in the `Authorization` request field with the scheme word `Bearer`:

```
Authorization: Bearer <the 43 characters>
```

| Answer | When |
|---|---|
| 401 with `WWW-Authenticate: Bearer` | no field, another scheme, a value of the wrong shape, an unknown token, an expired token, a revoked token, or a token of a disabled user. The text is always the same, so a caller learns nothing about which case it was. |
| 403 | the token is valid but does not carry the scope the route needs |
| 503 | the application was built without the token service (not possible with `serve`) |

A token is found by the SHA-256 of what the caller sent (an indexed lookup on a value the caller
cannot choose), and the stored hash is then compared once more in constant time. The `/api/v1`
routes refuse a request that carries the session cookie (P9-T2), so a browser session and a token
are never mixed.

The tokens of a **disabled user** stop working at once and work again when the user is enabled
again. (The plan does not say this; it follows the rule that a disabled user loses all access.)

A route of `/api/v1` asks for a scope with `Depends(require_read_token)` or
`Depends(require_enrich_token)` from `driftsniff.web.deps`, which return the `TokenPrincipal`
(id, name, prefix and scopes, never the value).

## Managing tokens (admin only)

These routes are part of the interface, not of `/api/v1`: an admin uses them with a session, and
the writes need the session CSRF value like every other write (`docs/csrf-and-headers.md`). A
viewer or operator gets 403, no session gets 401, and a token cannot manage tokens. The pages that
show them come with P10; until then the routes take a form post or a JSON object and answer with
JSON.

| Route | Does |
|---|---|
| `GET /tokens` | lists every token, newest first: `id`, `name`, `prefix`, `scopes`, `status` (`active`, `expired` or `revoked`), `created_by`, `last_used_at`, `expires_at`, `revoked_at`. Never the value, never the hash. |
| `POST /tokens` | makes a token and answers **201** with the same fields plus `token` (the value) and a note that it is shown once |
| `POST /tokens/{id}/revoke` | revokes a token for good: **200**; an unknown id is **404**; revoking twice changes nothing |

Fields of `POST /tokens` (a form post or a JSON object, at most 16 KB):

| Field | Rule |
|---|---|
| `name` | 1 to 80 printable characters; trimmed |
| `scopes` | `read`, `enrich` or both; in a form separated by commas or spaces, in JSON also a list |
| `expires_in_days` | optional whole number from 1 to 3650; absent or empty means the token does not expire |

A field that is not in the table is refused (**422**), so a misspelt `expires_in_day` cannot
quietly make a token that never expires. In a JSON body a value of the wrong type (a boolean, a
fraction, `null`) is refused with 400 rather than ignored. A rule-breaking name, scope list or
expiry is **422** and nothing is stored.

## Audit events

| Action | Written when | Actor |
|---|---|---|
| `token.created` | a token is made (name, scopes, expiry in the detail) | the admin |
| `token.revoked` | a token is revoked (not again for a second revoke) | the admin |
| `token.rejected` | a token is refused with 401 (reason in the detail: `malformed`, `unknown`, `revoked`, `expired` or `user disabled`) | `token:<prefix>`, or `token:unknown` |
| `token.forbidden` | a valid token lacks the scope (403) | `token:<prefix>` |

No event holds a token value. A request with **no** `Authorization` field writes no event. Refusals
of malformed and unknown tokens come from anyone who can reach the port, so they are written at
most once a minute per kind; the next event says how many were left out (`held_back`). The same
limit applies per token to the other refusals. If the database cannot take an event, the request
is still refused and a warning without any value is logged.

## Logs

A token value is never written to a log. The tests check the log text and the database file for
the value of a token they made.

## Rollback

Remove `tokens=TokenService(database)` from `serve` in `cli.py` (the `/api/v1` token checks then
answer 503) or redeploy the previous approved digest. Nothing is migrated; the table keeps its
rows.

## Limits

- The list has no creation time: the table `api_tokens` has no such column and this task adds no
  migration. The `token.created` audit event holds it.
- A token cannot be edited (name, scopes, expiry); revoke it and make a new one.
- There is no limit on how many tokens exist and no per-token request limit. A token is 256 bits
  of randomness, so guessing is not a practical attack; a leaked token is stopped by revoking it.
- The routes that use the scopes (`/api/v1/changes` and the enrichment route) arrive with P9-T5;
  until then only the checks and the management routes exist. The complete route table test is
  P9-T6.
