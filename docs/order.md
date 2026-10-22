# Order: moved items

This page explains how driftsniff reports that something in an ordered list changed place, such as
a firewall rule that moved above a deny rule. It is for people who run, extend or review
driftsniff. The code is `src/driftsniff/core/order.py`. It works beside [diff.md](diff.md): the
diff reports what was added, removed or changed, this module reports where things moved.

## The call

```python
compare_order(
    previous_manifest,
    new_manifest,
    states,
    window_start=...,
    window_end=...,
    type_tables=...,
    fingerprinter=...,
)
```

The arguments are those of `compare`. The `fingerprinter` is optional and is used only to label
the members of a list that have no declared key (see below); the run pipeline passes its own.
The items are listed with the ones of `compare`. `states` is read only for an object whose state
hash differs, to find the ordered lists inside it, and for the name of a moved object when the
manifests carry none. A first snapshot, or one made with another normaliser version, is a
baseline and gives no items.

`diff_order(old_keys, new_keys)` is the same comparison for two plain lists of keys. Every key must
be listed once on each side. It returns the inserted keys, the deleted keys and the moves.

## Which lists are read

| Mode | Order is read? | Where a change shows |
|---|---|---|
| `set` | no, the list is sorted when it is normalised | nowhere: a reordered set is no change |
| `ordered-keyed` | yes | a `moved` item |
| `ordered-scalar` | no | `compare` reports it position by position (`dns.1`) |
| `vendor-index` | no, the index is a field of the member | `compare` reports a changed index as `modified` |

An `ordered-keyed` list is read in two places:

- the position list of a whole resource, for a collection that the collector marks as ordered
  (`Manifest.positions`). It is read when both manifests hold one for the resource;
- a list of keyed members inside an object, such as `rules` or `acl.entries`, declared in the type
  table of the resource. Both sides must hold the list. A list that is `secret` or `ignore` class
  is never read.

## What counts as a move

Only keys found on both sides are compared. The longest common subsequence of the old and the new
order stays where it is, and every other common key is a move, so the fewest keys are called moved.
When two equally short answers exist the choice is fixed, and the same input always gives the same
items.

A key on one side only is an insert or a delete. `compare` already reports it once, as `added` or
`removed`, so it is never a move here. One rule inserted at the top of a list is one `added` item
from `compare` and no `moved` item. A reordered set gives nothing at all.

| Change | Result |
|---|---|
| insert at the top | one `added` item (diff), no move |
| delete in the middle | one `removed` item (diff), no move |
| swap two neighbours | one `moved` item |
| last key to the first place | one `moved` item |
| first key to the end | one `moved` item |
| reverse a list of n keys | n - 1 `moved` items |

## What a moved item holds

`change_kind` is `moved`. The path is empty for an object of an ordered resource, and the item is
that of the moved object. For a list inside an object the item is that of the owning object and
its path is the path of the list. Values and fingerprints are empty and `severity`, `rule_id` and
`rationale` are empty until the rule engine classifies the item.

The order detail holds:

| Key | Meaning |
|---|---|
| `key` | the moved key |
| `from_after`, `from_before` | the key it followed and the key that followed it before the move; null at an end |
| `to_after`, `to_before` | the same two after the move |
| `summary` | the move in words, `r7 moved from after r2 to before r1` |

### Actions, when the type table names an action field

A type table can name an `action_field` (the field of an object, or of a list member, that says
what it does, such as the verdict of a firewall rule). Only then, and only if that field has the
class `config`, a moved item also holds these three keys. The rule engine reads them to tell a move
across a deny rule from a harmless one (see `docs/rules.md`). Without an `action_field` the detail
is exactly the table above.

| Key | Meaning |
|---|---|
| `moved_actions` | the distinct values of the action field on the moved entry, before and after the change, sorted |
| `jumped_actions` | the same for every entry the moved one passed (its place relative to the moved entry changed), sorted |
| `jumped_count` | how many entries it passed |

An entry whose action is missing or is not text has no action. The actions are read from the stored
states, and only for the moved entries and the entries they passed.

A key that is repeated in a list is told apart by its occurrence: `r1`, then `r1#2`. A member
without a declared key, or whose key field is not `config` class, is shown as `member:` followed by
12 hex characters of a keyed hash (a fingerprint made with the fingerprint key; the field is the
list path, so equal content in two lists differs) and never as its content, because the content
can be a secret. An unkeyed hash of the content would let anyone who sees the detail test guesses
against it. Without a fingerprinter (tests and tools) a key made at the start of the process is
used.

## Limits

- Finding the entries a moved key passed (`jumped_actions`, `jumped_count`) scans the whole new
  list once for every moved key, so reading the actions costs O(n) per move and O(n x m) for m
  moves in a list of n entries. The cost is bounded by the 5,000 entry limit below, and a reversed
  list of that size is the worst case.
- A list of more than 5,000 entries on either side is compared as a set. If the order of the keys
  found on both sides differs, one item of kind `order_changed` says so, with `old_count`,
  `new_count` and the note `order changed, large list, detail not computed`. It does not say
  which keys moved. A list of exactly 5,000 entries still gets its moves.
- Lists inside a member of another list are not examined.
- The keys in a move are object keys or member keys, not names. The name of the owning object is
  on the item.
- Moves are found per list. A rule moved from one list to another is a removal and an addition.
