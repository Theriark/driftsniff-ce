# Change list, change detail, acknowledge, notes and mutes (services)

This page is for people who build the change pages (task P10-T6) or call the services from
somewhere else. The code is `src/driftsniff/changes/`. It holds the queries and the actions only:
the routes, the templates, the field labels and the one-line summaries belong to the interface
slice and are not here.

| Module | What it holds |
|---|---|
| `queries.py` | `ChangeQueries`: `list_changes`, `get_change`, `list_mutes` (read only) |
| `actions.py` | `ChangeActions`: `acknowledge`, `add_note`, `mute_path`, `remove_mute` (each with its audit event) |
| `filters.py` | `parse_filters`: a query string into `ChangeFilters`; it never raises |
| `views.py` | the frozen dataclasses the pages print, and the escaping contract |
| `paths.py` | which items a mute may name |
| `errors.py` | the refusals (`ActionForbiddenError`, `UnknownChangeError`, `InvalidTextError`, ...) |

## The list

`ChangeQueries(database).list_changes(filters)` returns one page of 50 changes (`ChangePageView`:
`rows`, `total`, `page`, `pages`, `page_size`, `muted_hidden`, `mute_scan_truncated`). A page past
the end is the last page. Every filter is optional and they combine:

| Query name | `ChangeFilters` field | Meaning |
|---|---|---|
| `q` | `search` | text in the summary or in the name of an object of the change, any case, matched literally |
| `source` | `source_id` | one source |
| `severity` (repeatable) | `severities` | the highest severity of the change is any of these |
| `status` | `status` | `open` or `acknowledged` |
| `resource` | `resource` | at least one item is of this resource type |
| `from`, `to` | `created_from`, `created_to` | UTC dates, both days included |
| `sort` | `sort` | `newest` (default), `oldest`, `severity` (critical first) |
| `page` | `page` | 1-based |
| `muted` | `include_muted` | `1` also shows changes whose every item is muted |

Each row also carries the number of acknowledgements, notes and enrichments of the change.

## The detail

`get_change(event_id)` returns a `ChangeDetailView` or `None`: the change, its items grouped by
object (`groups`), the acknowledgements, the notes and the enrichments, each in the order they were
stored. At most 1,000 items are returned (`items_truncated` says so).

Every item (`ItemView`) has a `rule_id` and a `rationale` that are never empty. An item stored
without them (only possible for rows from before rules carried an id) shows `rule_id` `unrated`
and a plain sentence, and `rationale_recorded` is `False`. An item also says whether it is a
`secret`, whether a mute hides it (`muted`) and whether the interface may offer "mute this path"
(`mutable`: never for a critical item). An order move has its parts in `move` (the moved key, the
key it followed and the key it now precedes) next to the stored one-line `summary`.

### The escaping contract

Every text in a view is **plain text**: the characters that were stored, never HTML. Nothing is
escaped in advance and nothing is `markupsafe.Markup`. A note, an acknowledgement comment, an
object name, a rationale, a source name, an enrichment label, summary or payload can hold
`<script>` and the page must print it through Jinja's autoescape (no `safe` filter, no
`autoescape off`; `tests/security/test_template_scan.py` enforces it). The test
`test_every_text_is_plain_text_and_prints_escaped` plants markup in all of those fields, walks the
whole view for `Markup`, and renders it through the application's environment.

Secret values never travel in a view. An item of class `secret` or `unclassified` has `before` and
`after` set to `None` and shows a short fingerprint (12 characters) only. Vendor text (object
names, paths, rationales, order details) passes the log scrubber of `driftsniff.secrets.redact`,
like in the change API; the scrubber also hides a long value that has no space and looks like a
key, so a vendor name of that shape shows as `***REDACTED***`.

## The actions

Every action needs the `operator` role or higher; a viewer gets `ActionForbiddenError` and nothing
is stored. An action and its audit event commit together; a refusal stores nothing.

| Action | Stores | Audit event (`action`, `target`) |
|---|---|---|
| `acknowledge(principal, event_id, comment="")` | one row in `acknowledgements`; the change becomes `acknowledged` | `change.acknowledged`, `event:ID` |
| `add_note(principal, event_id, body)` | one row in `notes` | `change.note_added`, `event:ID` |
| `mute_path(principal, item_id, reason="")` | one row in `path_mutes` (unless the mute exists) | `mute.added`, `mute:ID` |
| `remove_mute(principal, mute_id)` | deletes the row | `mute.removed`, `mute:ID` |

Acknowledgements and notes are append only. Acknowledging again adds a second row; the severity of
the change never changes and the change is never reopened. The audit detail holds ids and the
number of characters, never the text of a comment or a note.

Limits: acknowledgement comment 2,000 characters (may be empty), note 4,000 (must not be empty),
mute reason 500, and at most 500 acknowledgements and 500 notes per change. Text is kept as typed
(markup allowed, see above) but refused when it holds control characters other than a line break
or tab, or cannot be stored as UTF-8. A refusal never quotes the text.

## Mutes

`path_mutes` is read by `driftsniff.rules.engine.is_muted` for the list views only. The rule
engine does not read the table: classification, the stored severity and the notifications do not
depend on a mute. `ChangeQueries` is the first place that applies it.

- A mute stores the resource type and the path of one item. It applies to every source that has
  that resource type. The same path spelled differently (`tlsVerify`, `tls_verify`) is the same
  mute, and muting it twice changes nothing (`MuteResult.created` is `False`).
- A critical item cannot be muted, and a mute never hides one. A schema drift item (its path is a
  list of paths) and a path with a `*` cannot be muted (`NotMutableError`).
- In the list a change is hidden when it has items and every one is muted. In the detail every item
  shows, flagged `muted`. The item stays stored with its real severity.
- Because SQL cannot evaluate a mute pattern, a list with mutes checks the newest 5,000 matching
  changes in Python; `mute_scan_truncated` is `True` when more matched.
- Not covered here: the dashboard counts and the change API (`/api/v1/changes`) do not apply
  mutes yet.

## Planned routes

The routes are added by the interface slice. Their rows wait in `PLANNED_ROUTES` of
`tests/security/routekit.py` (the route table test fails on a row without a route, so they cannot
be in `ROUTE_TABLE` yet); whoever adds a route moves its row into `ROUTE_TABLE`.

| Method and path | Access |
|---|---|
| `GET /changes` | viewer |
| `GET /changes/{event_id}` | viewer |
| `POST /changes/{event_id}/acknowledge` | operator |
| `POST /changes/{event_id}/notes` | operator |
| `POST /changes/items/{item_id}/mute` | operator |
| `POST /mutes/{mute_id}/remove` | operator |
