# Collectors and the run pipeline

A collector reads one kind of system. The run pipeline (`driftsniff.sources.runs`) does
everything else: it locks the source, retries, redacts, normalises, stores, compares, classifies
and records the result. The UniFi and Xen Orchestra collectors (P7, P8) and the push source (P6-T4)
are collectors; the scheduler (P6-T3) starts runs through one shared `RunPipeline`.

## The collector contract

`driftsniff.collectors.base.Collector` has three calls and one optional one.

| Call | Returns |
|---|---|
| `probe()` | the controller version as text, or `None`; raises `CollectorError` when the controller cannot be reached or refuses the credential |
| `resources()` | the resources to read, in order, as `ResourceSpec(name, path)`; names are unique and each needs a type table in the rule packs |
| `fetch(spec)` | a `FetchResult`: `ok`, the raw JSON objects, `status`, and on failure an error class and a short text |
| `close()` | nothing; called once after the run, even a failed one |

`fetch` returns the objects exactly as the controller sent them. The pipeline redacts, normalises
and keys them, so a collector cannot forget to. `status` is `200` for a good read, the HTTP status
as text for a refused one (`403`, `404`, `502`) and `error` when there was no answer.

A collector never puts a payload, a credential or a request URL with a query string into an
error text. `fetch_json` raises `CollectorError` with fixed texts for that reason.

## What a run does

1. **Lock.** One run per source at a time, in this process. A second start writes a run record
   with status `skipped` and error class `already_running`. A disabled source is skipped the same
   way (`disabled`). A run record that was left open by a process that died is closed as
   `failed` with error class `interrupted` before the new run starts.
2. **Probe**, then **read every resource**. No database lock is held while the controller is read.
3. **Redact and normalise** each object, then key it with the key field of the type table of its
   resource. A resource without a type table fails (`unknown_resource`); an object without a usable
   key, or two objects with the same key, fail the resource (`bad_object`, `duplicate_key`).
4. **Store, in one transaction:** carry over every resource that was not read, build the manifest,
   store it if it changed, compare it with the last stored manifest, classify the change items with
   the rule engine, write the change event and its items, update the coverage of every resource and
   close the run record.
5. **Notify**, after the commit, if a notifier is set. A failing notifier is logged and never
   changes the result of the run.

If step 4 raises, the transaction rolls back: no snapshot, no state, no object row and no event
are written. The run record is then closed as `failed` with the class name of the exception.

## Limits

| Limit | Value | Where it is enforced |
|---|---|---|
| time per request | 30 seconds | `make_client` |
| size of a response body | 200 MB, checked while the body streams | `fetch_json` and `read_limited` |
| redirects | never followed; a redirect is the error `redirect_refused` | `make_client`, `fetch_json` |
| retries | three, after 1, 2 and 4 seconds, on HTTP 5xx and timeouts only | the pipeline |
| time per run | 5 minutes, checked between resources against a monotonic clock | the pipeline |

Resources not reached when the time is up fail with error class `run_timeout`. A retry is not
started when it would end after the run's deadline. A `403`, a `404`, a connection problem or a
body that is not JSON is not retried.

## Run status

| Status | Meaning |
|---|---|
| `ok` | every resource was read |
| `partial` | some resources failed, or were read but repaired; the others are stored |
| `failed` | nothing could be read, or the probe failed, or the run stopped unexpectedly; nothing is stored |
| `skipped` | another run of the source was going, or the source is disabled |

A read can also succeed with a warning (`FetchResult.success(..., warning_class=..., warning_text=...)`):
the objects are usable but the collector had to repair something, for example an ordering list
that did not match the objects (UniFi, `ordering_mismatch`). The pipeline stores the objects, keeps
the coverage at `200`, and marks the run `partial` with the warning class and a summary that starts
with `repaired:`. A failed resource still decides the error class when both happen.

A failed resource keeps its previous state: its objects are carried over into the new manifest, so
no object of it is ever reported as removed. Its coverage row shows the last status (`403`, `404`
or `error`) and `stale_since`, the time of its last good read (or of the first failure when it was
never read). A resource that reads again clears `stale_since`. A resource of the previous manifest
that a collector stops listing is carried over the same way.

The error summary of a run record is an error class and a short text of at most 200 characters,
on one line, with credential patterns scrubbed. For a collector that raises something unexpected,
only the name of the exception class is recorded.

## Addresses

- A host that cannot be written as UTF-8 (a lone surrogate) is refused as a base address with the
  message that the character cannot be stored.
- An IPv6 address that carries an IPv4 address is judged by the IPv4 address inside it. Four forms
  are unwrapped: IPv4-mapped (`::ffff:a.b.c.d`), the well-known NAT64 prefix `64:ff9b::/96`, the
  deprecated IPv4-compatible form (`::a.b.c.d`) and 6to4 (`2002::/16`). So `64:ff9b::a9fe:a9fe` is
  refused like `169.254.169.254`.
- Decision: other NAT64 prefixes (an operator can choose its own, and `64:ff9b:1::/48` exists for
  local use) cannot be told from any other IPv6 address and are not unwrapped. A host name that
  resolves into such a prefix is only caught when the resolved IPv6 address is itself blocked.
  `tests/unit/test_source_addresses_embedded.py` pins this either way.
- A host name is still resolved by the collector when it connects; the UniFi and Xen Orchestra
  collectors (P7, P8) must call `blocked_reason` on every address a name resolves to. Redirects
  are refused by the shared client, so a redirect cannot lead from an allowed address to a blocked
  one.
