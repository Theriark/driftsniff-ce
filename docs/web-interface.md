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

Screenshots at 1440, 768 and 390 px of the shell on Development are taken when the first page
that uses it (the sign-in page of P10-T3) is deployed; this task ships no page route of its own.
