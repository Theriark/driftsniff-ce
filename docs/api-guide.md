# API guide

For release candidate v27.0.0-rc.5. driftsniff has a small HTTP API under `/api/v1` for scripts:
read the changes, attach an external analysis to a change, and push a configuration. The full
schema is served by the application at `/api/v1/openapi.json`.

Replace `https://driftsniff.example` with your `DRIFTSNIFF_BASE_URL`. The values in angle brackets
are yours; never put a real token or key in a file that others can read.

## Tokens

An admin makes a token on the Settings page ([admin guide](admin-guide.md#api-tokens)). Send it in
the `Authorization` header:

```
Authorization: Bearer <TOKEN>
```

| Answer | Meaning |
|---|---|
| 401 | no token, a token of the wrong shape, unknown, expired, revoked, or of a disabled user. The text is always the same. |
| 403 | the token is valid but lacks the scope the route needs |

A request that also carries the browser session cookie is refused: the API takes tokens only. The
rules are in [api-access.md](api-access.md).

## Read changes (scope `read`)

```
curl -H 'Authorization: Bearer <TOKEN>' https://driftsniff.example/api/v1/changes
curl -H 'Authorization: Bearer <TOKEN>' https://driftsniff.example/api/v1/changes/<EVENT_ID>
```

The list returns up to 100 changes per page (default 50), newest first, without their items, and
takes `source`, `severity`, `status`, `since`, `limit` and `cursor`. Pass the `next_cursor` of one
page to get the next. The detail holds the items with their rule, severity and rationale, the
before and after values of a configuration field, or only a fingerprint for a secret, plus notes
and enrichments. The fields are in [enrichment-api.md](enrichment-api.md).

## Attach an external analysis (scope `enrich`)

```
curl -X POST https://driftsniff.example/api/v1/changes/<EVENT_ID>/enrichments \
  -H 'Authorization: Bearer <TOKEN>' \
  -H 'Content-Type: application/json' \
  --data '{"provider_label": "ticket-bot", "summary": "Matches planned work NET-123", "payload": {"ticket": "NET-123"}}'
```

`provider_label` (1 to 80 characters) says who wrote it, `summary` (1 to 2000 characters) is the
text, and `payload` is an optional JSON object of at most 32 KB. Any other field is refused. An
enrichment is append only and never changes the severity or the status. It appears on the change
page under "External analysis, not verified by the product", as plain text. The answers and limits
are in [enrichment-api.md](enrichment-api.md).

## Push a configuration

A push source takes the configuration from a sender instead of reading a controller. The sender
uses the source's sender key, not an API token:

```
curl -X POST https://driftsniff.example/api/v1/push/<SOURCE_ID> \
  -H 'X-Driftsniff-Push-Key: <PUSH_KEY>' \
  -H 'Content-Type: application/json' \
  --data @config.json
```

The body maps each declared resource to the complete current list of its objects, at most 10 MB:

```
{"unifi-networks": [{"id": "n1", "name": "Lab", "vlanId": 10}]}
```

This body fits a push source that declares `unifi-networks: id, name, vlanId`. Each object needs
the key field of its resource (`id`), or the post is refused with 422 `bad_object`.

A resource that is not in the post keeps its previous state; an empty list means every object of
it is gone. Fields that the source does not declare are dropped before anything is stored. The
answers are listed in [push.md](push.md).
