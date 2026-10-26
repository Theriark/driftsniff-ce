# User guide

For release candidate v27.0.0-rc.1, build `36f78cc9`. The screenshots show the Development
installation with synthetic data: the source called "DEV-FIXTURE synthetic (removable)" and every
object named FIXTURE are test data, not a real network.

All times in driftsniff are UTC. A relative time ("1 day ago") shows the exact UTC time when you
point at it.

## Roles

| Role | Can |
|---|---|
| Viewer | read every page except Settings |
| Operator | everything a viewer can, plus acknowledge a change, write a note, mute a path and run a source now |
| Admin | everything, plus add and edit sources, users, API tokens, the notification channel and retention |

A page that your role may not open says so and changes nothing. The navigation shows only what
your role can use: the Admin group with Settings is an admin's only.

![The not-allowed page a viewer sees when opening Settings: "Your role does not allow this", with one button back to the dashboard](images/not-allowed-1440-viewer.png)

## Signing in and out

Open the address of your installation and sign in with your user name and password. After five
wrong passwords in a minute the page asks you to wait; ten in a row lock the user for 15 minutes.
A session ends after 8 hours without use or 7 days after sign-in.

To sign out, open the user menu at the bottom of the sidebar (in the header on a narrow screen) and
choose Sign out. The sign-in page then confirms "Signed out".

![The sign-in page after signing out, with the Signed out banner](images/signed-out-1440.png)

## The dashboard

The start page answers two questions: what changed across your sources in the last 30 days, and
what still needs a decision.

![The full dashboard at 1440 px: stat cards, open items by severity, Needs attention, drift lines, change items per day, where the open items are, and the activity timeline](images/dashboard-1440-full.png)

From the top:

- **Stat cards.** Open changes with the number new this week, open critical and high changes,
  sources that are healthy, and the storage used. Each card links to the list behind its number.
- **Open items by severity.** The ring counts the open change items per severity. It is a count,
  not a score. Each row opens the matching filtered change list.
- **Needs attention.** Open critical and high changes first, newest first, then every source that
  is failing, stale, partial, unsupported, has an expiring credential or has certificate checks
  off. Each row has one action: Review or Open source.
- **Drift line, last 30 days.** One strip per source, today at the right end. A thin tick is a check
  with no change, a hollow tick a failed or partial check, and a coloured shape a change in the
  colour and shape of its highest severity. Point at or focus a mark to read the change; select it
  to open it.
- **Change items per day.** Thirty days stacked by severity. "Show the numbers as a table" gives
  the same numbers as text.
- **Where the open items are.** Open items by source and by resource type.
- **Activity.** The 20 newest events: changes, acknowledgements, notes, finished checks and admin
  actions.

Severity is always shown with a shape and a word as well as a colour: a circle for critical, a
diamond for high, a triangle for medium and a dot for low.

## The change list

**Changes** in the sidebar lists every detected change, 50 per page.

![The change list with three open changes: high, medium and critical, each with its source, time and status](images/changes-1440.png)

- Search by text, or filter by source, severity (critical, high and above, and so on), status,
  resource type and a range of UTC days, then select Apply.
- Sort by Severity or Detected with the column heads.
- Comfortable and Compact change the row height; the choice is kept in your browser.
- A muted path is hidden from this list only. The hint line says how many changes mutes hide, and
  the muted paths are listed under the table, with Unmute for an operator.

## A change

Select a change to open it.

![A critical change at 1440 px: the summary head with badges, the four changed items with rule, before and after, and the Acknowledge, Notes and About cards](images/change-detail-1440-full.png)

- The head shows the severity and status, the summary, **when** the change was detected (between
  two check times) and the rule pack. driftsniff never says who made a change.
- **What changed** lists each item, grouped by object: the field, what happened, the rule that
  rated it, then the before and after values with the differing part boxed.
- A **secret** field (a passphrase, a pre-shared key) shows "secret changed" with two short keyed
  fingerprints. The value itself is never stored or shown.
- **Why is this rated ...?** opens the reason the rule gives.
- **Mute this path** (operators and admins) hides that field of that resource type from the change
  list. A critical item cannot be muted.
- **External analysis** shows text that an outside program attached through the API. It is
  labelled as not verified by the product.

### Acknowledge and notes

An operator or admin acknowledges a change with an optional comment; the acknowledgement records
the user name and the time and never changes the severity. Every acknowledgement is kept. A note is
kept with the change and never edited. A viewer sees the acknowledgements and notes but no form.

| Operator | Viewer |
|---|---|
| ![The change detail for an operator, with the Acknowledge and Notes forms](images/change-detail-1440-operator.png) | ![The change detail for a viewer: Acknowledge and Notes say that an operator or an admin writes them](images/change-detail-1440-viewer.png) |

The step-by-step version is the tutorial [Review a change and acknowledge
it](tutorials/02-review-a-change.md).

## Sources

**Sources** lists every watched system with its status, its last attempt, the version it reports
and a short drift line.

![The sources list with two push sources, one stale and one with nothing pushed yet](images/sources-1440.png)

Select a source to open its page.

![A source page at 1440 px: status badges, the drift line, the change replay, coverage by resource, recent runs, About this source and Delete this source](images/source-page-1440-full.png)

- **Drift line** of the last 30 days, full width.
- **Change replay.** Choose 7, 30 or 90 days, then step through the days with Previous day and Next
  day or the slider. The matrix shows how many change items each resource type had per day; a
  ringed cell holds a critical item. The panel under it lists the chosen day by resource type and
  severity, with a link to those changes. With reduced motion on, the replay moves only when you
  step.
- **Coverage by resource.** For each resource: the last answer of the controller, the number of
  objects and the last good read. A resource that the controller refused or does not have says so.
- **Recent runs.** The newest checks or pushes and their outcome.
- **About this source** and the actions your role allows: Run now for an operator or admin (polled
  sources only, at most once every 30 seconds), and Edit, Disable or Enable and Delete for an admin.
  Delete asks you to type the source name.

## History and configuration

The tabs on a source page lead to its **History** and **Configuration**; both are also in the
sidebar.

![The history of a source: four readings, newest first, with the baseline at the bottom](images/history-1440.png)

History lists the stored readings, newest first. A reading is stored only when the configuration
differs from the one before. The baseline is where comparison starts; nothing is compared across
it. "Changes found" links to the change that reading produced.

![The configuration of a source: the resource rail on the left and the two devices of the Devices resource on the right](images/configuration-1440.png)

Configuration shows the newest reading, one resource at a time. Choose a resource in the rail, and
search within it. Secret values are shown as fingerprints only.

## Themes, screens and keyboard

- driftsniff follows the light or dark setting of your system.

| Light | Dark |
|---|---|
| ![The dashboard at 1440 px in the light theme](images/dashboard-1440.png) | ![The dashboard at 1440 px in the dark theme](images/dashboard-1440-dark.png) |
| ![A critical change at 1440 px in the light theme](images/change-detail-1440-full.png) | ![A critical change at 1440 px in the dark theme](images/change-detail-1440-dark.png) |

- Below 1024 px the navigation folds into the menu button in the header. Below 768 px the stat
  cards stack. See [On a tablet or a phone](#on-a-tablet-or-a-phone).
- Every control works with the keyboard. "Skip to content" is the first stop of the Tab key.

## On a tablet or a phone

| Dashboard, 768 px, dark | Change replay, 768 px, dark | Sources, 768 px, viewer |
|---|---|---|
| ![The dashboard on a 768 px tablet, dark theme](images/dashboard-768-dark.png) | ![The change replay of a source on a 768 px tablet, dark theme](images/source-replay-768-dark.png) | ![The sources list on a 768 px tablet for a viewer](images/sources-768-viewer.png) |

| Dashboard, 768 px | Change, 768 px, operator | Dashboard, 390 px, dark |
|---|---|---|
| ![The dashboard on a 768 px tablet, light theme](images/dashboard-768.png) | ![A critical change on a 768 px tablet for an operator, with Acknowledge and Add a note at the top](images/change-detail-768-operator.png) | ![The dashboard on a 390 px phone, dark theme](images/dashboard-390-dark.png) |

| Dashboard, 390 px, operator | Dashboard, 390 px, viewer | Menu, 390 px, dark |
|---|---|---|
| ![The dashboard on a 390 px phone for an operator, with no Add source button](images/dashboard-390-operator.png) | ![The dashboard on a 390 px phone for a viewer](images/dashboard-390-viewer.png) | ![The folded navigation menu open on a 390 px phone](images/menu-390-dark.png) |
