# Canonical JSON and the normaliser

This page is for people who change driftsniff. It has no effect on what a user sees.

Every object a collector reads is turned into one byte string before it is hashed and stored
(`driftsniff.core.canonical`, `driftsniff.core.normalize`). Two reads of the same logical
configuration give the same bytes, so a change in the bytes is a change in the configuration.

## Canonical JSON

- UTF-8, object keys sorted by code point, no whitespace (`,` and `:` as separators).
- Integers keep every digit, also above 2^53.
- A float with an integer value is written as an integer (`1.0` becomes `1`); `-0.0` becomes `0`.
  Other floats use the shortest representation that reads back to the same number.
- Strings are written as they are. There is no Unicode normalisation: a word written with one
  accented character and the same word written with a combining accent are different values.
- `NaN` and the infinities are refused.

## Normaliser

`normalize_object(type_table, raw)` works on the raw JSON dictionary of one object:

1. Fields whose class is `ignore` are dropped.
2. Keys with a `null` value are dropped, at every depth: null and missing are the same state.
   Empty lists and empty objects are kept. A `null` inside a list is kept.
3. Lists in `set` mode are sorted: by the key field the type table declares, or, for members
   without one, by the SHA-256 of their canonical form. Other modes keep the order received.

Field paths are dot separated (`wan.dns.servers`). A list adds no index to the path, so its
members, and lists nested in them, use the path of the list.

`TypeTable` is the small interface the normaliser reads (`field_class`, `collection_mode`,
`item_key_field`, `object_key_field`, `name_field`). `StaticTypeTable` is a table written in
code; the YAML type tables of the rule engine implement the same interface. Undeclared fields are
`unclassified` and undeclared lists keep their order.

## Changing the output

`NORMALISER_VERSION` (now `1`) must be raised whenever the output for any input changes. A test in
`tests/unit/test_normalize.py` pins the output for a fixed fixture, so a silent change fails the
build. When you change the output on purpose: raise the version, set `PINNED_VERSION` to it, and
replace `PINNED_TEXT` and `PINNED_SHA256` with the new values.
