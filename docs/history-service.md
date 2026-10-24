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

A browser gets the pages of slice B (THE-1043, see "The pages" below); every other client gets
JSON, with the same status codes. An HTMX request of the configuration gets the page too. A
damaged store is a designed 500 page for a browser and the fixed JSON text for everyone else.

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

## The pages (slice B)

Task THE-1043 (Jira DRS-289), Frontend Developer. Slice B adds the HTML answers of the four
routes above (`web/routes_history.py`), the words and links of the pages
(`web/history_pages.py`), the templates (`templates/history/sources.html`, `snapshots.html`,
`configuration.html` and the shared head `_head.html`), their stylesheet
(`static/history.css`), the History and Configuration entries of the navigation
(`NAV_ITEMS` in `web/templating.py`) and two links on the source page (Reading history, Current
configuration). No route was added and none writes.

| Page | What it shows |
|---|---|
| `/history`, `/configuration` | every source with its readings, baselines and newest reading; the name opens that page, the other page is one link away |
| `/history/{source_id}` | the reading ledger, 50 a page, newest first |
| `/configuration/{source_id}` | the newest reading, one resource at a time, searchable, 50 objects a page |

**The reading ledger** is the signature of the history, the companion of the drift line
(docs/design-direction.md section 2): a 2 px `border` rail runs down the first column and joins
the readings. A filled `ink` square marks a baseline (the comparison starts there; nothing is
reported across it), a 3 px `ink` ring the current reading (the one Configuration shows), an
8 px `slate` dot any other. The word (Baseline, Current, Reading) always stands next to the
mark and a key above the table names the shapes, so shape is never the only signal; a baseline
row sits on `paper`. Each row has the time read, the changes found at that reading (a link to
the change list of the source), the controller version and the stored size.

**The configuration browser.** Left the resource rail (readable name, object count, whether
the order matters, whether XO hides fields), right the object sheets: the name (or the key), the
key in the value face, and the fields as a two-column table of path and value. In an ordered
resource (firewall policies) each sheet carries its 1-based place in the gutter at 32 px, the
one large number of the page, because there the order is the configuration; an unordered
resource has no numbers. A secret or unclassified field shows `secret` or `unclassified, not
shown` and its keyed fingerprint in groups of four, never a value. A field hidden by Xen
Orchestra carries a chip, and the resource a warning banner that lists those fields. A value
cut at 2,000 characters says so. The rail links and the search form swap `#config-browser`
through HTMX (`hx-select` on the full page, the address pushed) while the skeleton shows;
without scripting they are plain links and a plain GET form.

**Roles.** Both source pages offer the other page and the source page to everyone; an operator
also gets Run now (a CSRF form posting to `/sources/{id}/run`, shown only for an enabled UniFi
or XO source while a scheduler runs) and an admin Edit source. Both target routes check the role
again.

**States.** Empty: no source (Add a source for an admin, See the sources for others), no
reading yet (with the reason: first check, no scheduler, disabled, or a push source's first
push), a reading without objects, a resource without objects, a search without a match (with
Clear the search). Loading: the skeleton of the HTMX swap. Error: a damaged store is a designed
500 page with Try again; an unknown source is the designed 404.

**Decisions where the plan is silent.** (1) Changes found links to the change list of the
source, not of the reading: the change list has no reading filter. (2) The search keeps the
chosen resource; changing the resource clears the search. (3) The page styles are a second
stylesheet, `static/history.css`, loaded after `app.css` by these three templates only through
the `head` block of `base.html`; it uses the tokens of `app.css` and adds no colour. (4) No
drift line here; the source page carries it.

**Checks.** `tests/unit/test_history_pages.py`: the words and links, and every template in every
state with fixture views (the baseline and current marks with their words, the role controls,
the ordered gutter, secrets and unclassified fields as fingerprints, the XO chip and banner, the
search states, the HTMX attributes, the error page, no style attribute, every field labelled,
markup escaped, the stylesheet loaded). `tests/security/test_history_pages.py`: the same routes
as a browser through the real application (the baseline marker, every shown value of the JSON
view printed, no canary in any page or HTMX swap, XSS payloads inert, Run now and Edit by role,
no Run now without a scheduler or for a push source, empty states, the designed 500 and 404, the
navigation). `tests/security/test_planned_routes.py` pins the four rows to the viewer role and
checks that nothing under `/history` or `/configuration` writes.

## Not in this slice

- The screenshots at 1440, 768 and 390 pixels and the interface critique follow the deployment
  of slice B to Development.
- Showing an older snapshot's configuration or comparing two snapshots; the plan asks for the
  latest manifest only.
- Pagination of a search past 5,000 objects of one resource (reported through `search_truncated`).

Rollback: the change adds modules, four read-only routes and one optional `create_app` argument;
redeploying the previous approved digest removes them.
