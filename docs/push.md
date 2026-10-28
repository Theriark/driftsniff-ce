# Push source

A `push` source has no controller to call. A sender posts a JSON document of its own
configuration, and driftsniff runs it through the same pipeline as a polled source (see
`collectors.md`): redact, normalise, compare with the last stored snapshot, classify, store.
The collector is `driftsniff.collectors.push.PushCollector`, the endpoint is in
`driftsniff.web.routes_push`.

## Setting a push source up

1. Create a source of type `push` (no address, no credential).
2. Declare, per resource, the top-level fields that are configuration, with the source option
   `push_fields`, for example `{"unifi-networks": ["id", "name", "vlanId"]}`. Every other
   field of a pushed object is dropped before anything is stored. Include the key field of the
   resource (the one its type table names; `id` for every UniFi and Xen Orchestra resource) or
   the run fails with `bad_object`.
3. Make a sender key with `SourceService.set_push_key`. It is returned once. Only its SHA-256
   is stored (`push_token_hash`), so it cannot be shown again; make a new one to replace it, and
   the old one stops working at once. The audit event `source.push_key` records that a key was
   made and whether it replaced one, never the key.

Rules for `push_fields`: a resource name is 1 to 100 characters of letters, digits, `_`, `.`,
`:` or `-`, starting with a letter or digit; each resource lists 1 to 200 distinct, printable
field names of at most 100 characters; at most 100 resources. Only a push source has the option.
Each resource must also have a type table in the rule packs, or its run fails with
`unknown_resource` (the other resources of the push still go through).

## The endpoint

`POST /api/v1/push/{source_id}`

```
curl -X POST https://driftsniff.example/api/v1/push/3 \
  -H 'X-Driftsniff-Push-Key: <PUSH_KEY>' \
  -H 'Content-Type: application/json' \
  --data @config.json
```

The body is a JSON object that maps resource names to lists of objects, at most 10 MB:

```
{"unifi-networks": [{"id": "n1", "name": "Lab", "vlanId": 10}]}
```

Each post is the complete current list of every resource it contains. A resource that is not in
the post keeps its previous state and is never reported as removed; a resource that is in the
post with an empty list means every object of it is gone.

| Answer | When |
|---|---|
| 200 | The run finished with status `ok` or `partial`. The body has `run_id`, `status`, `stored_new_snapshot`, `event_id` (set when the post changed something), `object_count` and `ignored_resources` (resources of the body that the source does not declare). |
| 400 | The body is not a JSON object of resource names to lists of objects (also NaN, Infinity, a repeated key, a document nested too deeply). |
| 401 | The key is missing or wrong, the source does not exist, is not a push source, or has no key. All of these give the same answer. |
| 409 | The source declares no fields, is disabled, or a run of it is already going. |
| 413 | The body is larger than 10 MB, by its declared length or while it streams. |
| 422 | None of the declared resources is in the body, the source id is not a positive number, or the run failed (the answer names the error class, for example `bad_object`). |
| 503 | The application was started without a push gateway. |

The key is checked first and the body is not read for a wrong key. Answers and logs never repeat
the body, a field name or a key.

## Limits and notes

- The key is compared by SHA-256 in constant time. There is no rate limit on wrong keys yet.
- Redaction is the pipeline's: a field the type table classes as secret is stored as a
  fingerprint only, and free text is scanned. The allow-list decides what is read at all.
- `driftsniff serve` builds the push gateway with the same run pipeline as the polled sources
  (`driftsniff.sources.wiring`); a run it stores tells the notifier like any other.

## Tests

`tests/unit/test_push_collector.py`, `tests/unit/test_push_source_service.py` and
`tests/unit/test_push_endpoint.py`.
