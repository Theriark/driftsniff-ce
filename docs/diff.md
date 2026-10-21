# Comparing manifests: change items

This page explains how driftsniff turns two stored manifests into change items, what each item
shows, and what it leaves out. It is for people who run, extend or review driftsniff. The code is
`src/driftsniff/core/diff.py`; the manifests come from [snapshots.md](snapshots.md) and the field
classes from [secrets-handling.md](secrets-handling.md).

## The call

```python
compare(
    previous_manifest,
    new_manifest,
    states,
    window_start=...,
    window_end=...,
    fingerprinter=...,
    type_tables=...,
)
```

- `states` is a function from a state hash to the normalised state. It is called only for objects
  that were added or removed (to read their name) and for objects whose state hash differs, so an
  unchanged object costs nothing.
- `type_tables` maps a resource type to its type table. A resource without a table has every field
  `unclassified`, so its changes are shown as fingerprints only.
- `window_start` is the time of the previous successful check and `window_end` the time of this
  one (UTC, ISO 8601 text). Every item carries both: a change was made some time inside that
  window, not at a known instant.
- The result is a list of `ChangeItem`, ordered by resource, then added objects, removed objects
  and modified objects (each by key), then the fields of an object in path order. The same input
  always gives the same list.

## Which objects are compared

| Situation | Result |
|---|---|
| Key only in the new manifest | one `added` item, empty path |
| Key only in the previous manifest | one `removed` item, empty path |
| Key in both, same state hash | nothing (the state is not read) |
| Key in both, different hash | field by field, see below |
| Resource only in the new manifest | all of its objects are `added` |
| Resource only in the previous manifest | nothing: the collection could not read it, so it is not reported as removed |
| Resource present but empty in the new manifest | all of its objects are `removed` |

## Which fields are compared

Fields of the `ignore` class are skipped. Null and a missing field are the same state, so a field
that is null on one side and missing on the other is no change. A list member is a value and keeps
its null.

Paths are dot separated field names, such as `wan.dns.primary`. Lists work as follows:

| List mode | How it is compared | Path |
|---|---|---|
| `set` | by membership; the order never matters | the path of the list |
| every other mode | position by position | the path of the list plus the index, such as `dns.1` |

For a `set` list, a member that is gone is `removed`, a new one is `added`, and a member that has a
declared item key and changed content is one `modified` item whose before and after values are the
whole member. Duplicate members count once. Fields inside a list member are classified by the path
without the index, exactly as the normaliser writes them.

The order of whole collections (the position lists in a manifest) is not read here. It belongs to
`core/order.py`.

## What an item shows

| Field class | Shown |
|---|---|
| `config` | `before_value` and `after_value`, as canonical JSON text |
| `secret` | `before_fp` and `after_fp` only, in the stored form `fp1:<key id>:<32 hex>` |
| `unclassified` | a fingerprint only, until somebody classifies the field |

A stored state already holds the fingerprint of a secret, never the value. Any string of exactly
the fingerprint form is treated as a secret even when the type table calls its field `config`,
because the scanner can force the secret class on a field. If a secret field holds something that
is not a fingerprint, the fingerprint is computed here and the value is still not shown. Nested
secret and unclassified fields inside a value that is shown (a set member) are masked the same way.

Two fingerprints of one field differ only when the value differs, as long as the master key stays
the same. A change of the master key is handled by the rekey flow before the comparison.

`severity`, `rule_id` and `rationale` are empty until the rule engine classifies the item. The one
exception is schema drift, below.

CE never claims to know who made a change. An item has no actor and no author; the window says
only when it happened.

## Schema drift

When a vendor upgrade adds the same new field to every object of a resource type, one item per
object would bury the real changes. A `schema_drift` item replaces them when all of these hold:

1. the controller version differs from the previous manifest, and both versions are known;
2. at least two objects of the resource exist in both manifests;
3. every one of them changed;
4. the same new field path appeared on every one of them.

The result is one item per resource type, severity `low`, rule `builtin.schema_drift`, with no
object key. Its `path` lists the new paths (`a, b` when there are several) and its order detail
holds the two controller versions, the object count and the list of paths. Another change on one
of the objects is still reported for that object. A new field on only some objects, an unchanged
object in the set, or a single object is an ordinary change, reported per object.

## Baselines

The first snapshot of a source, and the first one after a normaliser version change, is a
baseline. Its states cannot be compared with the earlier ones, so `compare` returns no items for
it. The diff starts again from the baseline on the next collection.

## Limits

- A scalar list that gains an entry at the front reports every later position as modified. Moves
  and inserts in ordered collections are reported properly by the order engine of phase 4.
- Values are not truncated. A very long free-text field is shown in full in the item; the stored
  state remains the source of truth.
