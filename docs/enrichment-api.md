# Change and enrichment API

The read-only view of recorded changes and the one write an outside program may make: append an
enrichment. Code: `driftsniff/enrich/api.py` (routes and storage), `driftsniff/enrich/models.py`
(shapes and limits). The `enrichments` table has existed since migration `0001`; this task adds no
migration. Tokens and scopes are in `docs/api-access.md`.

| Route | Scope | Does |
|---|---|---|
| `GET /api/v1/changes` | `read` | one page of changes, newest first, **without** items |
| `GET /api/v1/changes/{id}` | `read` | one change with its items, notes and enrichments |
| `POST /api/v1/changes/{id}/enrichments` | `enrich` | appends one enrichment (**201**) |
| `GET /api/v1/openapi.json` | none | the OpenAPI document of every route under `/api/v1` |

A token with only `enrich` cannot read the lists, and a token with only `read` cannot enrich. No
token or a bad one is 401, a token without the scope is 403 (checked before the body is read).

## Listing

`GET /api/v1/changes` takes these query values; an invalid one is **422**.

| Value | Rule |
|---|---|
| `source` | source id (whole number from 1) |
| `severity` | exactly `low`, `medium`, `high` or `critical`: the highest severity of the change |
| `status` | `open` or `acknowledged` |
| `since` | only changes recorded at or after this UTC time, written `2026-10-01T00:00:00Z` |
| `limit` | 1 to 100, default 50 |
| `cursor` | the `next_cursor` of the previous page; opaque, do not build it |

The answer is `{"changes": [...], "next_cursor": "..." | null}`. `next_cursor` is `null` on the
last page. Paging is by event id, so a change recorded while you page does not shift the pages.
Each entry holds `id`, `source` (`id`, `name`), `severity`, `status`, `summary`, `item_count`,
`window_start`, `window_end`, `created_at` and `rule_pack_version`.

The plan says the list and the detail both "return an event with its items". The list leaves the
items out on purpose: a page of 100 changes could otherwise hold hundreds of thousands of items.
Read the items of one change with `GET /api/v1/changes/{id}`.

## Detail

The same fields plus:

- `items`: `id`, `resource`, `object_name`, `change_kind`, `path`, `field_class`, `before`,
  `after`, `before_fingerprint`, `after_fingerprint`, `severity`, `rule_id`, `rationale`,
  `order_detail`. At most 1000 are returned; `items_truncated` says when there are more.
- `notes`: what people wrote (`author`, `body`, `created_at`).
- `enrichments`: what programs appended (`id`, `provider_label`, `summary`, `payload`,
  `created_at`).

**What is shown of a value.** It is what the interface shows. A field of class `config` has
`before` and `after` (canonical JSON text, already redacted when it was collected). A `secret` or
unclassified field has only a fingerprint: the first 12 characters of the digest, enough to see
that a secret changed and never enough to use it. The API never returns a value for a `secret` or
unclassified item, even if a row held one, and drops a fingerprint that does not have the stored
form. An unknown change is **404**.

## Appending an enrichment

`POST /api/v1/changes/{id}/enrichments` with `Content-Type: application/json`:

| Field | Rule |
|---|---|
| `provider_label` | required; trimmed, 1 to 80 printable characters; says who made it |
| `summary` | required; plain text, 1 to 2000 characters; newlines and tabs are fine, other control characters are not |
| `payload` | optional; a JSON **object**, at most 32 KB written compactly, nested at most 6 levels (`{"a": {"b": 1}}` is 2); no `NaN` or `Infinity` |

Any other field is refused. The answer is **201** with `id`, `provider_label`, `summary`,
`payload` and `created_at`.

| Answer | When |
|---|---|
| 404 | no such change |
| 409 | the change already holds 100 enrichments (a limit this task adds, so a leaked token cannot fill the database) |
| 413 | the request is over 64 KB, or the payload is over 32 KB |
| 415 | the body is not `application/json` |
| 422 | a field breaks its rule, the JSON is invalid, or the payload is too deep |

A refused request stores nothing. An error answer names the field and the kind of problem
(`{"errors": [{"field": "summary", "problem": "string_too_long"}]}`) and never repeats what was
sent.

An enrichment is **append only**: it never changes the severity or the status of the change, and
there is no route to edit or delete one. It is the claim of an outside program, not something the
product verified. The interface (P10) shows it under the heading **External analysis, not verified
by the product**, always as escaped text; the API returns it as data and a client must escape it
too. An `enrichment.added` audit event records the token prefix, the change and the enrichment id
(never the summary or the payload).

## OpenAPI

`GET /api/v1/openapi.json` is public: it describes routes, not data, and holds nothing of this
installation. It lists every route under `/api/v1` of the running application, including the push
endpoint, and the `bearerAuth` scheme. A test compares it with the real route table, so a route
cannot be added without appearing in it. The push route authenticates with its own key header, not
a bearer token, and the document does not model that header.

## Limits and not-verified items

- Pages are at most 100 changes; a detail shows at most 1000 items.
- The change list is not filtered by token: any `read` token sees every source.
- The behaviour of the enrichment route under real traffic has not been measured; the limits above
  are checked by tests with a fake client only.
