# History and current configuration (services and routes)

This page is for people who build the History and Configuration pages (task P10-T7, slice B) or
call the services from somewhere else. The code is `src/driftsniff/history/` and
`src/driftsniff/web/routes_history.py`. Slice A (this one) holds the queries, the role checks and
the data contract; the templates, the stylesheet and the navigation entries belong to the interface
slice.

| Module | What it holds |
|---|---|
| `history/queries.py` | `HistoryQueries`: `list_sources`, `list_snapshots` (read only) |
| `history/configuration.py` | `ConfigurationQueries.current`: the newest snapshot, one resource at a time |
| `history/service.py` | `HistoryService`: both of the above, built together |
| `history/views.py` | the frozen dataclasses the pages print, and the escaping contract |
| `history/errors.py` | `StoredConfigurationError` |
| `web/routes_history.py` | the four routes |

Nothing here writes. A read writes no audit event (the audit log records changes made by people and
by the system, not what a viewer looked at), and no route needs more than the viewer role.

## The plan's two checks

| Check (plan P10-T7) | Test |
|---|---|
| The view equals `resolve_current_state` for the fixture | `tests/unit/test_history_service.py::test_the_view_equals_resolve_current_state` |
| A baseline marker is visible in the history | `tests/unit/test_history_service.py::test_the_history_marks_the_baselines_and_the_current_snapshot` |

## The history

`HistoryQueries(database).list_snapshots(source_id, page=1)` returns a `SnapshotPageView` (or `None`
for an unknown source): the source, 50 snapshots a page newest first, `total`, `baseline_count`,
`page`, `pages`. A page past the end is the last page. Each `SnapshotRow` has:

| Field | Meaning |
|---|---|
| `taken_at`, `controller_version`, `normaliser_version` | what the `snapshots` row says |
| `kind`, `is_baseline` | `baseline` or `normal`. The first snapshot of a source and the first one after a normaliser version change are baselines: the diff engine starts from them and reports nothing across them. The page marks them. |
| `is_current` | the newest snapshot of the source, the one the configuration page shows |
| `change_count` | change events found at this snapshot |
| `manifest_bytes` | stored (compressed) size of the manifest |

The list never opens a manifest, so a long history costs one query per page.
`list_sources()` returns every source by name with its snapshot count, baseline count and the time of
its newest snapshot; it feeds the picker of both pages.

## The configuration

`ConfigurationQueries(database, fingerprinter).current(source_id, resource=None, search="", page=1)`
returns a `ConfigurationView` (or `None` for an unknown source): the newest snapshot, the resource
types in it (`ResourceSummary`: object count, `ordered`, `hidden_by_xo`), the objects of the selected
resource (50 a page) and `total`, `page`, `pages`.

- **Which resource.** The one asked for, or the first (by name) when none or an unknown one was
  asked for. A source without a snapshot, or a snapshot without objects, gives an empty view
  (`snapshot` is `None` in the first case).
- **Same content as `resolve_current_state`.** The view is built from the manifest of the newest
  snapshot and the stored state of each object, the same inputs `resolve_current_state` uses; it reads
  the states of the shown objects only. Objects come back in the order `resolve_manifest` gives.
- **Order.** An ordered resource (`ordered` is true) is shown in its stored order and each object
  has its 1-based `position` (never page relative). A list inside an object keeps its stored order
  (a set is stored sorted); its members have `[n]` in the path (`rules[2].action`) and `ordered`
  tells whether that order means anything (false for a list the type table calls a set).
- **Fields.** Every object has its fields flattened to `FieldView`s: `path`, `value` (text), `field_class`
  (`config`, `secret` or `unclassified`), `secret`, `fingerprint`, `ordered`, `hidden_by_xo`,
  `truncated` (a value longer than 2,000 characters is cut). A field the type table classes as
  `ignore` is not shown.
- **Search.** `search` keeps the objects whose key, name, field path or shown value contains the
  text (any case, literal, at most 200 characters). A search reads at most 5,000 objects of the
  resource; `search_truncated` says when it stopped there.
- **Errors.** A damaged manifest or a missing or corrupt state raises
  `StoredConfigurationError`, whose text is fixed (`the stored configuration cannot be read`) and
  never quotes stored data.

### Secrets

A stored state holds a secret as a fingerprint marker (`fp1:...`), and an unclassified field in
clear (see [snapshots.md](snapshots.md) and [secrets-handling.md](secrets-handling.md)). The view
masks them the way the change items do:

- a marker shows its first 12 characters as `fingerprint` and no `value`, whatever the table says;
- a field of class `secret`, or one the table does not declare (`unclassified`), or any field of a
  resource without a type table, never shows its `value`; its `fingerprint` is made with the
  installation's fingerprint key for that resource and path, so it equals the one a change item of
  the same value shows;
- a secret container (a whole map declared secret) is one masked field;
- a search never reads a hidden value, only shown text, so it cannot be used to guess one;
- vendor text (keys, names, paths, values, the controller version) passes the log scrubber of
  `driftsniff.secrets.redact` like in the change views, so a value shaped like a credential shows
  as `***REDACTED***`.

A resource whose type table is missing (a push source's own fields, for example) therefore shows
fingerprints only until somebody writes its table; that is the same rule the change list follows.

### Hidden by XO

For a source of type `xo`, `ResourceSummary.hidden_by_xo` lists the paths that Xen Orchestra itself
never returns in clear (from `hidden_by_xo` of the type table), so the page can say "hidden by XO,
changes not observable". A field in the state whose path is one of them, or below one, has
`hidden_by_xo` set. Other source types always have an empty list. UNVERIFIED: the field names of
the XO and UniFi tables are the plan's, not lab verified (open item, see the vendor notes).

### The escaping contract

Every text in a view is plain text, the characters that were stored; nothing is escaped in advance
and nothing is `Markup`. The templates print it through autoescape and never through the `safe`
filter (`tests/security/test_template_scan.py` enforces that).
`test_every_text_is_plain_text_and_prints_escaped` plants markup in names, keys, field values, field
names and the controller version, walks the whole view for `Markup` and renders it through the
application's environment.

## Routes

Until the interface slice adds the HTML answer, every client gets JSON (`wants_html` is not used
yet; add it the way `routes_changes.py` does). The status codes are final.

| Method and path | Access | Answer |
|---|---|---|
| `GET /history` | viewer | `{"sources": [...]}` |
| `GET /history/{source_id}?page=N` | viewer | `{"history": SnapshotPageView}` |
| `GET /configuration` | viewer | `{"sources": [...]}` |
| `GET /configuration/{source_id}?resource=&q=&page=` | viewer | `{"configuration": ConfigurationView}` |

All four are rows of `ROUTE_TABLE` in `tests/security/routekit.py`, called as every kind of caller
by `tests/security/test_route_table.py` (no session: 401; no API token ever works here).
`source_id` is a positive integer below 2^31 (anything else is 422); an unknown source is 404; a
`page` that is not a plain number of at most nine digits is the first page; 503 means the
application was built without the service, 500 a damaged store. `create_app(history=...)` takes
the service; `driftsniff serve` builds it with the fingerprint key derived from the master key.

## Not in this slice

- The templates, the stylesheet, the History and Configuration entries of the navigation and the
  screenshots at 1440, 768 and 390 pixels (task P10-T7, slice B).
- Showing an older snapshot's configuration or comparing two snapshots; the plan asks for the
  latest manifest only.
- Pagination of a search past 5,000 objects of one resource (reported through `search_truncated`).

Rollback: the change adds modules, four read-only routes and one optional `create_app` argument;
redeploying the previous approved digest removes them.
