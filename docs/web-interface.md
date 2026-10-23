# Web interface: app shell, components and states (P10-T2)

Task THE-845 (Jira DRS-228). Owner: Frontend Developer. This document describes the shell every
page of Phase 10 is built on, the components the pages use, the two preferences the shell keeps,
and the rules every template obeys. The design brief is `docs/design-direction.md`; the brand
guide wins over both for typography and logo use.

## 1. Files

| File | Role |
|---|---|
| `src/driftsniff/web/templating.py` | the Jinja environment (escaping on, undefined names refused), the `Shell` object every page receives, and the pure helpers: drift line geometry, sparkline points, relative time, initials |
| `src/driftsniff/web/templates/base.html` | the app shell: head, skip link, icon sprite, header with the logo lockup, navigation, environment badge and user menu, the `main` landmark, the footer with the version |
| `src/driftsniff/web/templates/_icons.html` | the one inline SVG icon set: the four severity shapes and the status icons |
| `src/driftsniff/web/templates/page_header.html` | the page header macro: breadcrumb, title, purpose line, actions |
| `src/driftsniff/web/templates/components/*.html` | the component macros (section 3) |
| `src/driftsniff/web/static/app.css` | the one stylesheet: the design tokens of `docs/design-colours.json` (the contrast test fails when they drift) and the component styles carried over from the P10-T1 mock-ups |
| `src/driftsniff/web/static/htmx.min.js` | htmx 2.0.4, unmodified; `htmx.min.js.LICENSE.txt` holds the version, the source, the file hashes and the Zero-Clause BSD licence text |
| `src/driftsniff/web/static/brand/` | byte-for-byte copies of the brand files (the image copies only `src/`, so the running application never reads `brand/`) |
| `src/driftsniff/web/routes_static.py` | `GET /static/{path}`: one explicit route in the route table, serving only files inside the static folder |
| `src/driftsniff/web/preferences.py` | the row density cookie and the safe return path |

## 2. The shell

A page extends `base.html`, fills the `content` block and receives a `Shell`:

| Field | Meaning |
|---|---|
| `title` | the page title; the browser title is `<title>, driftsniff` |
| `nav_current` | which navigation entry is the current page (`dashboard`, `changes`, `sources`, `history`, `configuration`, `settings`) |
| `user_name`, `user_role` | the signed-in user; empty on the sign-in and setup pages, which then show no navigation and no user menu |
| `csrf_token` | the session's CSRF value: it goes into the hidden `csrf_token` field of every form and into the `X-CSRF-Token` request header of every HTMX request (through `hx-headers` on `body`) |
| `density` | the row density of data tables, from the cookie (section 4) |
| `environment_label` | the badge next to the user menu, from `DRIFTSNIFF_ENVIRONMENT_LABEL` (section 5) |
| `path` | the current path with its query, the place a preference form sends the user back to |

The header shows the guide's horizontal logo file at 48 px (40 px below 768 px) through a
`picture` element whose dark source is the guide's dark lockup (the mark on its light tile), so
the mark is never bare on the dark header. Below 1024 px the navigation folds into a `details`
menu; below 768 px the environment badge and the user name are dropped, the lockup never. The
skip link, the labelled `nav`, the single `main` landmark and the footer are present on every
page. Every form is a normal form post, so the interface works without JavaScript; htmx only
improves swaps where a page asks for them.

htmx is configured by the `htmx-config` meta element: `allowEval` off, `selfRequestsOnly` on,
`includeIndicatorStyles` off (the indicator rules live in `app.css`, so htmx injects no style
element) and `historyCacheSize` 0 (no authenticated page is kept in browser storage). The
content security policy of `docs/csrf-and-headers.md` allows nothing inline; the template tests
fail on a `style` attribute, an inline `script` or an event handler attribute.

## 3. Components

Each macro renders in every state the design direction names (section 7 there). The template
tests render each state and assert the markup.

| Macro (file) | States | Notes |
|---|---|---|
| `severity_badge(severity)` (badges) | low, medium, high, critical | colour, the shape symbol and the word, always together |
| `status_badge(kind, text, icon)` (badges) | ok, failing, partial, stale, unsupported, insecure, warn, open | icon and word; `insecure` is the only filled status badge |
| `stat_card(label, value, href, unit, delta, delta_tone, spark)` (cards) | with or without unit, delta and sparkline | the card is the link to the filtered view; the series is listed for screen readers |
| `data_table(caption, columns, density, foot_text)` with `call` (table) | comfortable or compact; sortable columns with `aria-sort`; columns hidden on narrow screens | sticky header; rows are the caller's markup |
| `density_switch(density, path, csrf_token)` (table) | comfortable or compact pressed | a form post to `/preferences/density` |
| `pager(links, summary)` (table) | current page as text, the others as links | |
| `filter_bar(action, label)` with `call`, `search_box`, `select_field`, `text_field` (forms) | plain, with help, with an error (`aria-invalid`, message next to the field, help kept) | every field has a label |
| `confirm_form(action, expected, csrf_token, button_label, text)` (forms) | | the typed text is checked by the server; the form only names it |
| `empty_state(heading, text, action_href, action_label)` (states) | with or without the action | the ferret mark at 96 px |
| `skeleton(label, rows, indicator)` (states) | plain or as an HTMX indicator | `role="status"`, `aria-live="polite"` |
| `error_state(title, text, retry_href)` (states) | with or without the retry form | `role="alert"`; the text says nothing was changed |
| `banner(kind, title, text, action_href, action_label)`, `success_banner` (states) | success, warn, error | the banner repeats the word of the button |
| `definition_list(items)` (details) | plain or mono values | |
| `disclosure(summary, kind, open)` with `call` (details) | closed or open; quiet or rationale | |
| `time_tag(when, now)` (details) | | relative words, exact UTC time in `title` and `datetime` |
| `drift_line(name, checks, id_prefix, href, meta, short)` (driftline) | full row or short strip; ok, failed and change checks of every severity; no checks | the signature visual; each change mark links to its event and names it in its `title` |
| `page_header(title, purpose, crumbs)` with `call` (page_header) | with or without breadcrumb and actions | |

## 4. The row density preference

`POST /preferences/density` (any signed-in role) takes `density` (`comfortable` or `compact`)
and `next` (where to go back to) from a normal form post, sets the `ds_density` cookie (HttpOnly,
SameSite Lax, Secure over HTTPS, one year) and answers 303 to `next`. `next` is kept only when it
is a path of this site: a scheme, a protocol-relative address, a backslash, whitespace or a
control character sends the user to `/` instead. An unknown density answers 422 and sets nothing.
Pages read the cookie with `density_from_cookie`; an absent or odd value is comfortable.

## 5. Settings

| Variable | Default | Meaning |
|---|---|---|
| `DRIFTSNIFF_ENVIRONMENT_LABEL` | unset (no badge) | the badge in the header, 1 to 24 ASCII letters, digits, spaces or hyphens, for example `Development`. Platform sets it per environment in `deploy/dokploy.json` as a literal. |

## 6. Static files

`GET /static/<path>` serves a file only when the path resolves to a file inside the static
folder: no empty or dot segments, no backslash, no absolute path, no symbolic link that leaves
the folder; anything else is 404. The answer carries `Cache-Control: public, max-age=600` (the
middleware leaves `/static/` out of its `no-store` rule) and the security headers like every
other answer. The route is listed in the route table as public.

## 7. Checks

- `tests/unit/test_templates.py`: the shell (landmarks, skip link, navigation, logo lockup,
  user menu, CSRF header and field, escaping) and every component in every state; the two
  policy rules over every template file; the helper functions.
- `tests/unit/test_web_preferences.py`: the density cookie, the route (sign-in required, CSRF
  required, 422 on an odd value, foreign `next` refused, Secure over HTTPS).
- `tests/unit/test_routes_static.py`: the stylesheet and htmx are served with the right type
  and cache header; escapes and folders are 404.
- `tests/unit/test_check_contrast.py`: `app.css` carries the token values of the JSON.
- `tests/security/test_route_table.py`: the two new routes are in the table and refuse the
  callers their access excludes.
- `tests/security/test_template_scan.py`: no template switches escaping off.

Screenshots at 1440, 768 and 390 px of the shell on Development are taken with the first pages
that use it (P10-T3, section 8); P10-T2 shipped no page route of its own.

## 8. Setup, sign-in, sign-out and the status pages (P10-T3)

Task THE-856 (Jira DRS-231). The first screens of the product, built on the shell. The code is
in `src/driftsniff/web/pages.py` (rendering, content negotiation, the status pages) and the
page routes of `src/driftsniff/web/routes_ui.py`; the templates are `setup.html`, `login.html`,
`dashboard.html` and `status.html`.

**A browser gets a page, everyone else gets JSON.** A request whose `Accept` header names
`text/html` (or `application/xhtml+xml`) is a browser and receives the page, in every state. A
request without it (the test client, curl, scripts, the API) keeps the JSON answers described in
`docs/auth.md`, with the same status codes, cookies and checks. Nothing else differs.

| Route | Who | What |
|---|---|---|
| `GET /` | signed in (any role) | the dashboard; P10-T3 ships the page header and the designed empty state with the one action (`Add source`), P10-T4 adds the data. A browser without a session is sent to `/setup` while no admin exists, else to `/login` (with `next` when it asked for another page); a plain client gets 401. Without a sign-in service: 503. |
| `GET /setup` | anyone, until the first admin exists | the one-time code, the admin user name and the password, each with its rule next to the field (12 characters at least; length is the only rule). 404 like an unknown route once any admin exists. |
| `POST /setup` | as above | a browser gets the page back with the field in error: the code field for a wrong code (403), the user name or the password for a rule the service refused (422), and a banner that names the wait after repeated wrong codes (429, `Retry-After` kept). The code and the password are never filled back in; the user name is. Success is 303 to `/` with the session cookie. |
| `GET /login` | anyone | the sign-in page; a signed-in user goes to `/`; with no admin yet, to `/setup`. `?next=` (a local path only) is carried in a hidden field; `?signed-out=1` shows the success banner "Signed out". |
| `POST /login` | anyone | one generic failure banner whatever the reason (401), the wait banner after five failures (429); success is 303 to `next` (a local path, else `/`). |
| `POST /logout` | signed in, with the CSRF value | ends the session and answers 303 to `/login?signed-out=1`. |

**Status pages.** The application's `HTTPException` handler (`handle_http_exception`) turns,
for a browser and outside `/api/v1`, a 401 into the sign-in redirect above, a 403 into the
"Your role does not allow this" page and a 404 into the "Page not found" page, both with the
shell of whoever is signed in and one action back to the start. Every other status, every API
path and every non-browser client get FastAPI's own JSON answer. The refusals the hardening
middleware writes itself (wrong origin, missing CSRF value, oversized body) stay JSON.

**Composition.** Both pre-session pages are the designed empty state as a screen: the ferret
mark on the guide's light rounded tile (`.mark-tile`, also added to the `empty_state` macro so
the mark is never bare on the dark theme), one heading at 24 px, one sentence, and the card
with the single primary action. The column is 440 px wide and centred; at 390 px the card
padding drops to 24 px. The `text_field` macro gained `required`, `autofocus`, `mono` and
`autocapitalize`, each emitted only when set. The first field has `autofocus`; every field has
a label, `autocomplete` and, where there is a rule, help text that stays when the error appears.

**Checks.** `tests/unit/test_web_pages.py`: the full first run (start page to setup page to a
working admin session on the dashboard, then the setup page is 404 for a browser and for a plain
client), every failure state of both forms, the generic error with the user name escaped and
the password never echoed, the wait banner with `Retry-After`, `next` kept only for a local
path, sign-out confirmation, the 403 and 404 pages, and the JSON answers of plain clients. The
route table lists `GET /`, `GET /setup` and `GET /login`.

## 9. The dashboard (P10-T4)

Task THE-863 (Jira DRS-235). Owner: Frontend Developer. The start page with its data. The
queries live in `src/driftsniff/web/dashboard.py` (`DashboardService.load`, one read
connection, every figure from SQL); `GET /` in `routes_ui.py` calls it in a worker thread and
hands the result to `templates/dashboard.html`, which prints and never computes. The charts are
the macros of `templates/components/charts.html` (posture ring, trend chart, bar list); the
drift line is the macro of P10-T2. `serve` builds the service on the one database; an
application built without it (some tests) shows the empty state.

| Part | What it shows | Where the numbers come from |
|---|---|---|
| Stat cards | open changes (events with status open) with the count of events created in the last 7 UTC days, the difference to the 7 days before and a sparkline of those days; critical and high open events; sources healthy out of all sources; storage used | `change_events` grouped by status and by day; the source health below; the size of `driftsniff.db` plus its `-wal` file |
| Posture ring | open change items by severity, counts only, never a score; each row links to the filtered change list | `change_items` of open events grouped by severity |
| Needs attention | the open critical and high events (critical first, newest first, at most 8), then every source that is failing, partial, stale, unsupported or whose credential is expiring, and every source with certificate checks off | `change_events`; the source health below |
| Drift lines | one strip per source, in name order | `runs` of the last 30 days (status ok, partial or failed; a skipped run is not a check) matched to the event the run wrote (`change_events.created_at` equals `runs.finished_at`, the pipeline writes both from one clock reading) |
| Trend | change items per UTC day for 30 days, stacked by severity, with the table behind a disclosure | `change_items` joined to their event, grouped by day and severity |
| Breakdowns | open items by source and by resource type (at most 8 rows each), bars in tenths | the same join grouped by source and by resource; the labels are our own table `RESOURCE_LABELS` |
| Activity | the 20 newest of: events, acknowledgements, notes, finished runs and audit events | each table, 20 newest, merged and cut; refused token calls and enrichments are left out |

**Source health** (`SourceHealth.kind`), in this order: disabled; `state` is `unsupported`;
the last finished run failed (with the length of the failing streak); never checked; stale,
when `last_checked_at` is older than three times the source's interval; the last run was
partial; `state` is `token_expiring`; else healthy. Certificate checks off (the `insecure`
option) is a flag next to the kind, not a kind, so an insecure source can also be failing.
The `state` words are read as the plan names them; no collector writes them yet (part B,
P7-T2 and P8-T2), so until then those two kinds never appear on a real installation.

**Decisions where the plan is silent.** (1) The drift line is one mark per check up to 31
checks in 30 days; a source checked more often (the default interval is five minutes, so most
polled sources) gets one mark per UTC day that had a check, carrying the worst outcome of that
day: a change mark in the colour and shape of the day's highest event, else a hollow tick for
a day with a failed or partial run, else a thin tick. The strip's `desc` says how many checks
it stands for and the card's hint names the rule. (2) The storage card compares the database
file with a constant warning size of 2 GiB (`STORAGE_WARNING_BYTES`); a setting can replace
it in P10-T8. (3) "New this week" counts events created in the last seven UTC days whatever
their status now, so an acknowledgement does not move the sparkline. (4) The links behind the
numbers point at the filtered views of P10-T5 to P10-T8 (`/changes?status=open&severity=...`,
`/changes?status=open&source=ID`, `/changes?status=open&resource=NAME`, `/sources/ID`,
`/settings#about`); until those pages exist they answer the designed not-found page.
(5) Nothing on the dashboard is a before or after value, a note body, an acknowledgement
comment or a credential: titles are the stored event summaries, run errors are the scrubbed
class word and short line of the run record.

**Checks.** `tests/unit/test_dashboard.py`: the pure helpers (ring arcs sum to the
circumference, chart grid and stacked bars, width classes, day and window words, storage
card); the queries on a seeded database (stat cards, posture, every source health kind, the
failing streak, the drift line per check and per day, the trend table, the breakdowns, the
activity order and exclusions); the page as a browser (every section and chart with its title
and description, one primary action, the hostile source name escaped, the canaries absent, the
empty state without sources); and the plan's timing check: with 1,000 objects, 600 runs, 100
events and 2,000 items the page renders in under 500 ms (measured on the second request, after
the template cache is warm). The route table is unchanged (`GET /` was already listed).

**Not done here.** Screenshots at 1440, 768 and 390 px are taken on Development after the
deployment of this pull request (task THE-862 covers the P10-T3 pages); the Frontend Developer
critique for this page goes into that evidence.

## 10. The sources pages (P10-T5)

Task THE-955 (Jira DRS-255). Files: `web/routes_sources.py` (the routes and the form
handling), `web/source_pages.py` (the queries: list, source page, coverage panel),
`sources/probe.py` (the read-only test connection), `templates/sources/` (`list.html`,
`detail.html`, `form.html`, `_coverage.html`, `_probe.html`) and the P10-T5 part of `app.css`.

**Design direction.** Job of the screens: tell an admin, at a glance, whether each watched
system answered its last check and what driftsniff can see of it, and let them add or fix a
source without guessing. Who repeats it: an admin after every controller change, an operator
when a check failed. Tone: a quiet, precise instrument. Signature visual: the drift line,
short on each row of the list and full width on the source page, beside the coverage panel
(one row per resource with the last answer, the objects and since when it is stale). Type and
palette follow `docs/design-direction.md`; alert red only for failing, critical and the delete
card; the insecure TLS badge is the one filled status badge. The forms are one card per part
(the source, the checks, certificate checks, test connection) so a long XO form reads as four
short steps; the TLS mode is a radio group of four cards, the insecure card outlined in alert
red when chosen.

| Route | Role | What it does |
|---|---|---|
| `GET /sources` | viewer | the list: status (the dashboard's rule), the flags insecure TLS, unsupported version and credential expiring, last check, version, short drift line; JSON for a script |
| `GET /sources/new?type=` | admin | the add form of UniFi Network, Xen Orchestra or a push source |
| `POST /sources/new` | admin | add; a refused form comes back with each field marked |
| `POST /sources/test` | admin | test connection of the add form |
| `GET /sources/{id}` | viewer | the source page: status, flags, drift line, coverage panel, recent runs, facts, and the actions the role allows |
| `GET` and `POST /sources/{id}/edit` | admin | the edit form; the type cannot change |
| `POST /sources/{id}/test` | admin | test connection of the edit form; an empty credential tests with the stored one |
| `POST /sources/{id}/run` | operator | run now; refused within 30 seconds of the last one (429 with `Retry-After` and the wait in words), while a run is going (409), for a disabled or push source (409) and when no scheduler runs (503) |
| `POST /sources/{id}/enable`, `/disable` | admin | enable or disable; the scheduler is told at once |
| `POST /sources/{id}/delete` | admin | delete; the typed name must equal the source name (spaces around it are ignored), else 422 and nothing is deleted |
| `POST /sources/{id}/push-key` | admin | a new sender key for a push source, shown once in that answer |

**The credential is write-only.** It is read from the post and handed to the source service
(which encrypts it) or to the test; no page, JSON answer, redirect or field value carries it.
The edit form shows the field empty, and an empty field keeps the stored credential. The
confirmation sentence of the TLS mode insecure (`I understand the risk`) is never filled back
in. The only secret a page shows is the sender key of a push source, once, in the answer of
the post that made it; the source page afterwards only says that one exists.

**Form fields.** A browser always sends `full_form`, so an unticked box means off. A script
that posts JSON may leave fields out; each one it leaves out keeps its stored value. The
interval is entered in minutes (1 to 60) and stored as `interval_seconds`. The resource tick
boxes are stored as `resources_off` (the resources not ticked; none stored when all are on).
The XO expiry date is stored as `credential_expires_on` (`YYYY-MM-DD`); the list and the source
page show credential expiring when the stored state says so or when that date is 14 days away
or past. A form may hold up to 64 fields (`MAX_FORM_FIELDS`, shared with the CSRF check; the 16
KB bound is unchanged): the XO form has a box for each of its 20 resources.

**Coverage panel.** One row per resource of the type in the collector's order, then any stored
row of another resource. A stored row is printed as stored: `200`; `403, stale` with the time it
became stale; `404, not on this version`; `Error` (or `HTTP 502` for another status) with the
stale time. A resource turned off says Off, one never read says Not read yet. An XO resource
whose type table lists `hidden_by_xo` fields names them: hidden by XO, changes not observable.

**Test connection.** `driftsniff.sources.probe` asks a collector for the version, the
resources and one read of each, keeps the status and the object count per resource and drops
the objects. It writes nothing (no source, run, coverage row, snapshot or audit event); the test
stops reading after 60 seconds. With JavaScript the button replaces only the result panel
(`hx-post`, always answered 200 so htmx swaps it) and the typed credential stays in the form;
without it the form page comes back with the result and the credential field empty.

**Known gaps (no owner yet, not invented here).** The collector factory that builds a
collector from a stored source, and the scheduler wiring of `serve`, do not exist. `serve`
therefore passes no probe factory and no scheduler: test connection answers that it is not
available on this installation yet (503, the panel says so) and run now answers that runs are
not scheduled (503). Both work against the existing interfaces (`ProbeFactory` and
`Scheduler.run_now`) as soon as that wiring is assigned. The collectors do not read
`resources_off` yet either: the factory must pass it on. UniFi and XO field names remain
unverified (docs/vendor-notes/).

**Navigation.** The shell lists only Dashboard and Sources; Changes, History, Configuration and
Settings come back with P10-T6 to P10-T8. The dashboard's empty state offers Add source to an
admin only and tells anyone else that an admin adds sources.

**Checks.** `tests/unit/test_web_sources.py` (the three acceptance checks: the credential canary
over every page and answer, the coverage rows against the stored rows for every status, the
typed-name delete; plus roles, forms, TLS confirmation, test connection storing nothing, run
now and enable or disable), `tests/unit/test_source_probe.py`, `tests/unit/test_source_options.py`
and the route table rows in `tests/security/routekit.py`.

**Not done here.** Screenshots at 1440, 768 and 390 px and the UI critique are taken on
Development after this pull request is deployed, by a later check.
