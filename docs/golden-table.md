# The golden table and the type coverage check

`tests/golden/test_golden_table.py` is the acceptance test of the rule engine (P5-T4). It holds the
23 hand-tested changes of the plan (rows 1 to 23, plus row 20b: a key omitted instead of null is no
change) and runs each through the real chain: two collections of one resource, `compare`,
`compare_order` and the engine. A row passes when it produces one item with the expected severity,
a rule id of the expected family and a rationale that is not empty, or no item at all for the rows
the plan marks `none`. The two secret rows (17 and 18) also check that only fingerprints are stored
and shown; the values in them start with `CANARY-`.

- The rows run against test-only tables and packs in `tests/golden/types` and
  `tests/golden/packs`, in the shipped file format, so the engine is tested apart from the shipped
  rules. They declare only the fields the rows name, and two fields the shipped Xen Orchestra table
  does not collect (`docker.enabled`, `pw_hash`). The UniFi resource names carry the prefix
  `unifi-` because a resource can be defined only once across all type files (see
  [rules.md](rules.md)).
- The rows that the plan marks for the shipped run run again against the shipped packs: the UniFi
  rows (3, 5, 16, 17, 21, 22) in `tests/golden/test_golden_unifi_shipped.py` (P7-T4), the Xen
  Orchestra rows (1, 2, 4, 6, 8, 10 to 15, 18 to 20, 23) in `tests/golden/test_golden_xo_shipped.py`
  (P8-T3). Row 8 (`docker` is ignore class) and row 18 (no password hash is collected; the
  shipped secret field `authProviders` runs in its place, severity critical like the plan row)
  are pinned, not run as written. UniFi rows 7 and 9 need a site settings field that the shipped
  table does not have, so they are not run (the plan says: only if the field exists).
- `tests/golden/test_ordering.py` runs the ordering fixtures through the engine: an insert at the top
  of a first-match list is one insert and HIGH, a swap of neighbours is one move and at least HIGH,
  a move across a `deny` or `drop` policy is CRITICAL, a deleted policy is CRITICAL, and a
  reordered set is no change.
- Rows 6 and 13 name a setting of a backup job. In the test-only tables and in the shipped table
  they are plain nested fields of `backup-jobs` (`settings.reportRecipients`,
  `settings.exportRetention`); there is no derived resource (decision of Core on THE-359).

## The type coverage check

`scripts/check_type_coverage.py` fails when a type table names a field without a class: its
`key_field`, `name_field` or `action_field`, a list under `lists` (a classified field below the
list also counts), or the member key of a keyed list. Run it with
`PYTHONPATH=src python scripts/check_type_coverage.py [RULES_ROOT ...]`; without an argument it
checks the shipped tables. `tests/unit/test_check_type_coverage.py` runs it on the shipped and the
golden tables, so the ordinary test job already enforces it.
