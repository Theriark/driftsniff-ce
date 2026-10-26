# Design direction and tokens (P10-T1)

Task THE-816 (Jira DRS-222). Owner: Frontend Developer. This document is the brief that every
page of Phase 10 follows. Where it is silent, P10-T2 to P10-T8 choose the simplest option and
record it here in a later pull request. The brand guide wins over this document for typography
and logo use (dev work plan part B, section 23, row 4; see section 11 on what could and could
not be verified).

## 1. The job of the interface

driftsniff watches UniFi Network and Xen Orchestra configuration and records every change with
its before and after value and an explainable risk label. The person who opens it is an
administrator who checks in once or twice a day, often in a hurry, and asks three questions in
this order: did anything change, how bad is it, and what do I do about it. Every screen is
built for that order: the worst open item first, one primary action, and the evidence (before,
after, rule, rationale) one click away.

Tone: a quiet, precise instrument. Ink on paper, slate rules, no decoration that does not carry
information. Alert red appears only on critical items and failures, so when it appears it means
something. The ferret mark is the companion of the empty state, never a mascot on a busy page.

## 2. Signature visual: the drift line

One horizontal strip per source covering the last 30 days, drawn as inline SVG on the server.

| Element | Drawing | Meaning |
|---|---|---|
| Axis | 1 px line in `border`, full width, at y 30 of a 32 px tall viewBox | time, oldest on the left, today on the right |
| Tick | 1.5 px vertical stroke in `slate`, 12 px tall | a check that found no change |
| Hollow tick | 6 by 14 px rectangle, `slate` stroke, no fill | a failed or partial run |
| Mark | the severity shape (section 5), 12 to 18 px, filled with the severity colour, inside a link | a check that found changes; the shape and colour are those of its highest severity |
| Labels | HTML text under the strip, 14 px `text-2` at both ends: "30 days ago" and "today" (not SVG text, so they never scale below 14 px) | orientation without a full axis |

Rules: one mark per check, placed at the time of the check on the 30 day axis, one day every
20 units with 30 days ago at 10 and today at 610 of a 620 unit viewBox, so the widest mark and its
focus stroke stay inside the strip at both ends (THE-1416; the mock-ups' 616 unit strip cut the
critical mark at today by 1 unit) (THE-1402 F2: spaced evenly by check, the newest check of a
quiet source sat beside "30 days ago"; a strip in per-day mode is still one evenly spaced mark per
day, and checks close in time share a spot with the change marks drawn over the ticks); hover or focus on a mark shows the event summary in the SVG
`title` and the link opens the event; a focused mark gets a 2 px `ink` stroke; the strip
scrolls horizontally below 480 px wide instead of shrinking the marks; every strip carries a
`title` and a `desc` so the content is readable without the picture. It appears on the
dashboard (one per source), on each source page (the same strip, with run counts in the heading)
and on the change detail as the short version (strip only, the event is the last mark).

Later phases keep the same strip; the only data that changes is the list of checks.

## 3. Logo and clear space

Files are the supplied brand assets in `brand/` (byte-for-byte copies of the Nextcloud folder,
listed in `brand/MANIFEST.sha256`). The running application serves copies from
`src/driftsniff/web/static/brand/` (P10-T2), never from `brand/`.

The brand guide assigns the horizontal logo files to the site header and keeps the wordmark
files for text-only placements, and it rules that on a dark background the mark sits on a light
rounded tile. The header follows both: one image per theme, the guide's own file, so the mark
is never placed bare on the dark header.

| Use | File | Size |
|---|---|---|
| Header lockup, light theme (paper `#F5F5F0`) | `logo-horizontal-1200x400.png` (mark and wordmark on paper) | 48 px tall, 144 px wide; the ferret mark inside the file is about 38 px, above the guide's 32 px floor |
| Header lockup, dark theme (`#1E1E24`) | `logo-horizontal-dark-1200x400.png` (the mark on its light rounded tile, light wordmark) | the same |
| Header below 768 px (56 px header) | the same files | 40 px tall, 120 px wide; mark about 32 px, at the floor; the lockup is never dropped, the environment badge and the user name are |
| Empty state companion | `logo-mark-512x512.png` on paper or surface, never on a dark surface without a tile | 96 by 96 px |
| Favicon and tiles | `favicon-32x32.png`, `favicon-180x180.png`, `favicon-512x512.png`, `favicon-tile-180x180.png` | as named |
| Social preview (later) | `social-og-1200x630.png` | as named |
| Text-only placements (none in Phase 10) | `wordmark.svg`, `wordmark-dark.svg` | per the guide; not used in the header |

The image is a single `img` with the word "driftsniff" as its alternative text, swapped by
`prefers-color-scheme`; the CSS sizes (`.brand__logo`, 48 px and 40 px) and this table are the
same numbers. Clear space: the guide's minimum is the height of the ferret's eye on every side
(about six percent of the mark, 2 to 3 px at header size). The header gives more than that:
the horizontal file carries about ten percent of its height as padding on every side, the header
adds 8 px above and below the image inside its 64 px height, and the navigation starts 24 px to
the right. That is an extension of the guide rule, never a replacement of it. The logo is never
recoloured, stretched, outlined, cropped or rebuilt from text, and the mark is never shown
smaller than 32 px.

## 4. Typography

The brand guide sets the pairing and the sizes: Inter (or the system sans) bold at 32, 24 and
20 px for headings, 16 px body, and JetBrains Mono (or the system mono) at 14 px for code and
values. The interface uses exactly those families and sizes. No font file ships and no font
licence is carried: each stack names the guide's face first and falls back to the system face
the guide allows, so the first installed family is used.

```
--font-sans: Inter, "Helvetica Neue", "Liberation Sans", Arial, "Segoe UI", sans-serif;
--font-mono: "JetBrains Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace;
```

| Step | Size | Weight and spacing | Used for |
|---|---|---|---|
| 32 | 2 rem | 700, tracking minus 0.02 em, line height 1.15 (1 for the numbers) | page title, the stat card number, the posture ring number |
| 24 | 1.5 rem | 700, line height 1.15 | empty state heading |
| 20 | 1.25 rem | 700, line height 1.15 | section and card title |
| 16 | 1 rem | 400, line height 1.5 | body, form fields, detail text |
| 14 | 0.875 rem | 400 or 700, line height 1.5 | table cells, metadata, buttons, labels, navigation, badges (700), captions and help text (`text-2` or darker); code and values in the mono stack |

Fourteen pixels is the smallest text anywhere, in HTML and in SVG: the drift line labels are
HTML text under the strip, the posture ring is drawn one to one (160 px column, 160 unit
viewBox) so its 32 and 14 unit text renders at 32 and 14 px, the trend chart's axis labels are
HTML text beside and under its drawing, and the replay map is drawn one unit per pixel with
14 unit labels and counts (THE-1405). Nothing is set at 10, 11, 12 or 13 px.

Numbers use tabular figures (`font-variant-numeric: tabular-nums`) wherever they line up in a
column. Before and after values, paths, ids and fingerprints use the mono stack at 14 px. No
all-caps labels, no letter-spaced eyebrows. Line length stays under 80 characters for running
text (`max-width: 44ch` on the empty state and on help paragraphs). The wordmark file itself is
set in Helvetica Neue bold with a tracking of minus two percent; that is the logo, not the
interface face, and it is only ever used as an image.

## 5. Colour

### 5.1 Roles

`docs/design-colours.json` is the single source of every colour value. `docs/mockups/theme.css`
copies it as CSS custom properties, and `tests/unit/test_check_contrast.py` fails when the two
differ. P10-T2 copies the same block into `src/driftsniff/web/static/app.css`.

| Role | Light | Dark | Use |
|---|---|---|---|
| paper | #F5F5F0 (brand) | #16161A | page background |
| surface | #FFFFFF | #1E1E24 | cards, inputs, menus |
| surface-2 | #EBEBE3 | #27272E | sticky table header, hover rows, bar tracks |
| border | #D3D3CB | #3B3B44 | decorative hairlines only: card edges, table rules, chart grid (no contrast pair; anything that must be seen uses slate) |
| slate | #6B7280 (brand) | #9CA3AF | rules, drift line ticks, input borders, large text only (4.4 to 1 on paper) |
| ink | #1E1E24 (brand) | #F5F5F0 | the brand ink; primary buttons, the navigation indicator, the avatar |
| text | #1E1E24 | #F5F5F0 | body text |
| text-2 | #4B5563 (plan) | #B9BEC7 | secondary text, captions, table headers |
| primary and on-primary | ink on paper | paper on ink | the one primary action of a page |
| alert | #C8342B (brand) | #E8665D | critical severity, failures, destructive actions, and nothing else |
| success | #2B6A3C | #7CC48A | healthy status, success banners, a falling count |
| info | #3F5E8C | #9DB6DC | links on hover, the rationale disclosure |
| focus | ink | paper | the focus ring (2 px, 2 px offset) |

Two elevation levels: `elev-1` for resting cards, `elev-2` for menus, hovered stat cards and the
primary button on hover. Radius: 8 px controls and badges, 10 px cards, 12 px large panels,
999 px pills.

### 5.2 Added colours and their contrast

Every colour beyond the four brand colours is listed in `docs/design-colours.json` with the pair
it must pass, and `scripts/check_contrast.py` computes the WCAG 2 ratio of every pair (4.5 to 1
for text, 3 to 1 for graphics and focus rings). The committed file has 68 pairs across both
themes and every pair passes; the lowest are the medium severity badge (4.63 to 1), the high
severity badge (4.68 to 1) and alert red on paper (4.82 to 1). The script prints the full table
and appends it to the GitHub job summary when `GITHUB_STEP_SUMMARY` is set.

### 5.3 Severity: colour, shape and label, always together

| Severity | Light | Dark | Shape (12 px symbol) | Badge |
|---|---|---|---|---|
| low | #4A6283 | #A3B6D4 | circle | tinted (#E4E9F1 / #262C38), coloured text |
| medium | #8A5F00 | #DDAE45 | triangle | tinted (#F3E8CC / #332B14), coloured text |
| high | #A8441B | #EB9068 | diamond | tinted (#F6DFD3 / #3A251C), coloured text |
| critical | alert red | #E8665D | octagon | the only filled badge: paper text on red |

The word is always present in the markup (visually hidden only in narrow table cells), the shape
is an inline SVG symbol, and the colour never carries the meaning alone. The same four shapes
are the drift line marks, the posture ring segments and the trend chart bars.

Source and run status use a second, square-cornered badge with an icon and a word: healthy
(check), failing (cross, alert), partial (half circle, medium), stale and unsupported (clock or
dash, dashed slate border), insecure TLS (open lock, filled red, the only filled status badge),
credential expiring (key, medium).

## 6. Spacing, layout and motion

Spacing scale: 4, 8, 12, 16, 24, 32, 48 px. Content is centred at most 1280 px wide with 32 px
gutters (16 px below 768 px). The header is 64 px tall (56 px below 768 px) and sticky. Every
page starts with the same header block: breadcrumb when deeper than one level, the title, one
line of purpose, and the actions on the right (stacked below the title under 768 px).

Breakpoints: 1024 px (navigation collapses into a disclosure menu, two-column grids become one),
768 px (gutters, header, page header stack), 480 px (stat cards one per row, tables hide their
secondary columns, badges keep shape and colour with the word for screen readers).

Motion: 120 ms for hover and focus, 180 ms for open and close, `cubic-bezier(0.2, 0.7, 0.2, 1)`,
all zero under `prefers-reduced-motion`. The loading skeleton shimmer is the only ambient motion
and it stops under reduced motion too.

## 7. Designed states and copy

| State | Treatment |
|---|---|
| Empty | the ferret mark at 96 px, one heading, one sentence saying what to do first, one primary action |
| Loading | a skeleton of the rows that will appear, `role="status"` and `aria-live="polite"` |
| Error | a banner with an alert border, a title that says what failed, a sentence that says nothing was changed, and a retry form |
| Success | a banner with a success border that names the action that just happened, in the same word as the button |
| Form error | the field marked `aria-invalid`, the message next to the field, the help text kept |
| Not available | a disabled-looking control with a `title` that says why (for example, a critical item cannot be muted) |

Copy: sentence case, plain verbs, the button names the action and the banner repeats it
("Acknowledge change", "Change acknowledged"). Times are UTC with the label, plus a relative
text; the exact time is in the `title` and `datetime`. Detection windows are written as "between
A and B UTC", never as a claim about who changed something.

## 8. Accessibility floor

Skip link to `main`; one `main` landmark, labelled `nav` and `search` regions; every field has a
visible label; every control works with the keyboard and shows the focus ring; status is never
colour alone; charts carry `title`, `desc` and a table alternative behind a disclosure; no inline
script and no `style` attribute anywhere (the content security policy of P9-T2 blocks both, and
the mock-ups obey the same rule); every action is a normal form so it works without JavaScript.

## 9. Files, checks and how they run

| File | Role |
|---|---|
| `docs/design-colours.json` | the token values and the list of contrast pairs (source of truth) |
| `docs/mockups/theme.css` | the tokens as CSS custom properties, light and dark, breakpoint and reduced-motion overrides |
| `docs/mockups/mockup.css` | the component styles of the mock-ups; P10-T2 turns them into `app.css` |
| `docs/mockups/dashboard.html`, `changes.html`, `change-detail.html`, `source.html` | the four static mock-ups with fixture data |
| `docs/mockups/states.html` | the component sheet: colour roles, type scale, badges, buttons, banners, empty, loading, form error |
| `src/driftsniff/web/static/app.css` | the shipped stylesheet (P10-T2): the same token block, then the component styles; `docs/web-interface.md` describes the shell and the components |
| `scripts/check_contrast.py` | the contrast check (exit 0 pass, 1 a pair below its minimum, 2 token file error) |
| `tests/unit/test_check_contrast.py` | pytest tests of the script, and four tests on the committed files, one of which runs the script as a process |

The contrast check is a pull request check through `CI / Tests`, which runs pytest over
`tests/`: `test_the_contrast_script_passes_as_a_ci_step` executes
`python scripts/check_contrast.py` from the repository root as a separate process (the same
command a workflow step would run), requires exit 0 and reads back the table it wrote to the
step summary file; `test_the_committed_tokens_pass_every_check` runs `main()` in process on the
committed token file; `test_the_stylesheets_copy_the_token_values` fails when `theme.css` or
`app.css` drifts. The test module uses pytest fixtures and markers, so it runs under pytest, not under
unittest. No workflow file changes for this: the job's existing pytest command is the step. A
separate named step in the `lint` job would only add the table to that job's summary; if
Platform wants it, the step is:

```
- name: Design token contrast
  run: .venv/bin/python scripts/check_contrast.py
```

To run it by hand: `python scripts/check_contrast.py` from the repository root. To look at the
mock-ups: open `docs/mockups/dashboard.html` in a browser from a checkout (they load the brand
files from `../../brand/`); switch the system colour scheme to see the dark theme.

## 10. Self-critique of the mock-ups

- One primary action per page: "Add source" on the dashboard, "Acknowledge" on the change,
  "Run now" on the source; the change list has only the quiet export. Good.
- The drift line is the memorable element and everything around it is quiet: cards have a hairline
  border and a 1 px shadow, no gradients, no icon tiles. Good.
- The stat cards are the generic four-in-a-row; they earn their place because each number links
  to the filtered view and the sparkline shows the week. Watch that P10-T4 keeps them to four.
- Risk: the dark theme dilutes the brand red; the dark `alert` (#E8665D) is a lighter red to reach
  5.6 to 1, so the "red means critical" rule holds but the two reds are not identical. Accepted.
- Risk: slate at 4.4 to 1 on paper is used only for rules, ticks and input borders, never for
  text; `text-2` carries every secondary word. The contrast file keeps this honest.
- The user menu and the mobile navigation use `details` so they work without JavaScript; the
  trade-off is no outside-click close. Accepted for CE.

## 11. What was verified and what was not

- The brand guide PDF in `/Theriark/Driftsniff/Brand` cannot be opened by this role (the
  preview action answers `caller_not_allowed` for the Frontend Developer, checked again in
  THE-837). Sections 3 and 4 were first derived from the asset files alone and contradicted the
  guide; they were corrected in THE-837 from the Code Reviewer's reading of the guide (THE-833:
  chapter 2 and the do and do-not table for the header files, the tile on dark and the eye-height
  clear space; chapter 4 for Inter, JetBrains Mono and the 32, 24, 20, 16 and 14 px sizes) and
  from the asset files themselves (`logo-horizontal-dark-1200x400.png` carries the light tile).
  The guide wins over this document wherever the two still differ.
- P10-T2 (THE-845) built the shell and the components from this brief; where this document
  was silent it chose: the header logo is one `picture` element (dark source for the dark
  theme) instead of two images; the user menu names the account in text and has no account
  page link; the environment badge reads `DRIFTSNIFF_ENVIRONMENT_LABEL`; the density switch
  is its own form next to the filter bar (`.toolbar`), not inside it. See
  `docs/web-interface.md`.
- P10-T3 (THE-856) built the setup, sign-in and status pages as the empty state composition
  (mark on its tile, heading at 24 px, one sentence, one action in a 440 px column) and put the
  brand mark on the guide's light rounded tile in the `empty_state` macro too, since the mark
  file is transparent and section 3 forbids it bare on a dark surface. See
  `docs/web-interface.md` section 8.
- P10-T4 (THE-863) built the dashboard from the mock-up with the real queries. Where this
  document and the plan were silent it chose: one mark per check up to 31 checks in 30 days and
  one mark per UTC day beyond that (the worst outcome of the day), a constant 2 GiB storage
  warning size, and the severity badges as the legend swatches. See `docs/web-interface.md`
  section 9.
- Screenshots of the mock-ups at 1440, 768 and 390 px are not produced in P10-T1: the browser
  tool refuses `file:` addresses and reaches only `*.theriark.dev`, where the mock-ups are not
  served. Delivery waived them for P10-T1 and made them an acceptance of P10-T2, which takes
  them on Development after deployment and judges them against the UI standard there.
- The contrast ratios were computed by the script on this branch (68 pairs, all pass); the
  pytest, ruff and mypy runs happen in CI because the sandbox has none of them.
- THE-1405 (PR 123) changed the section 2 rule from "spaced evenly by check" to "placed at the
  time of the check", without the owner's sign-off. Frontend, the owner of this brief,
  acknowledges and keeps it (THE-1416): with even spacing the newest check of a quiet source sat
  beside "30 days ago" (THE-1402 F2). The squeeze the old rule guarded against is handled by
  checks close in time sharing a spot, changes drawn over ticks, and the per-day strip beyond 31
  checks (P10-T4). The mock-ups in `docs/mockups/` keep the old evenly spaced 616 unit drawing
  as a record of P10-T1 and are no longer the reference for the drift line geometry.
- P3 (THE-1306) added `state(kind, ...)` to `components/states.html`, the one entry to the
  empty, error and loading states: `empty` is a `role="status"` (with `inline=true` the one
  quiet sentence of a card that has nothing to list), `error` a `role="alert"` banner whose
  action is the retry, `loading` the polite live skeleton, which now also carries its label
  as hidden text because a live region speaks its content. The dashboard, source detail,
  change detail and configuration pages use it; no style changed.
