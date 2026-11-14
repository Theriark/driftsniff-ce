"""The Jinja environment of the web interface and the helpers its templates use (P10-T2).

Every page extends ``base.html`` (the app shell: the sidebar with the grouped navigation and the
user menu, the top bar, skip link, main landmark, footer) and builds its content from the macros
in ``templates/components/``. The environment escapes everything (autoescape on, never switched
off by a template: the security suite scans for it) and refuses an undefined name, so a template
mistake fails a test instead of rendering an empty string.

The helpers here are pure: geometry for the drift line and the sparkline, the relative time
text, the user initials. They take values and return values, so the template tests run them
without the application.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any, Final

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from driftsniff import __version__

TEMPLATES_DIR: Final = Path(__file__).parent / "templates"

SEVERITIES: Final = ("low", "medium", "high", "critical")
SEVERITY_LABELS: Final = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
# Source and run status badges: the kind names the colour pair, the icon names the shape.
STATUS_ICONS: Final = {
    "ok": "i-check",
    "failing": "i-cross",
    "partial": "i-half",
    "stale": "i-clock",
    "unsupported": "i-dash",
    "insecure": "i-lock-open",
    "warn": "i-key",
    "open": "i-dash",
}
DENSITIES: Final = ("comfortable", "compact")

# The navigation of the shell: key, label, path. The key marks the current page. Only pages that
# exist are listed (Delivery decision on P10-T5): each P10 task added its own entry back, in this
# order, when its page landed: Changes (/changes, P10-T6), History and Configuration (P10-T7),
# Settings (/settings, P10-T8).
NAV_ITEMS: Final = (
    ("dashboard", "Dashboard", "/"),
    ("changes", "Changes", "/changes"),
    ("sources", "Sources", "/sources"),
    ("history", "History", "/history"),
    ("configuration", "Configuration", "/configuration"),
    ("settings", "Settings", "/settings"),
)

# The sidebar groups of the entries above (UI revision WP1, THE-1101): what happened (Monitor),
# what is watched (Inventory) and, for admins only, the settings (Admin). A group never shows a
# link to a page that answers 404, nor one that answers 403 to the reader.
NAV_GROUPS: Final = (
    ("monitor", "Monitor", ("dashboard", "changes")),
    ("inventory", "Inventory", ("sources", "history", "configuration")),
    ("admin", "Admin", ("settings",)),
)
# The entries only an admin may open; a viewer or an operator does not see them at all.
NAV_ADMIN_ONLY: Final = frozenset({"settings"})

# The icon of each entry, a symbol of _icons.html.
NAV_ICONS: Final = {
    "dashboard": "i-dashboard",
    "changes": "i-changes",
    "sources": "i-sources",
    "history": "i-history",
    "configuration": "i-configuration",
    "settings": "i-settings",
}

# The top bar's one action: adding a source, for admins, on every page outside the dashboard and
# the sources section, whose own headers already lead with it. It is drawn as a secondary button,
# so the primary button of a page (Acknowledge, Run now, an empty state's next step) stays the
# only primary one on the screen.
TOPBAR_ACTION_HIDDEN: Final = ("/", "/sources")
TOPBAR_ACTION: Final = ("Add source", "/sources/new")

# Drift line geometry (docs/design-direction.md section 2): a 32 unit tall strip under the axis
# "30 days ago ... today", one day every 20 units with 30 days ago at 10 and today at 610, so the
# strip is 620 wide. A mark sits at the time of its check, never at its place in the list
# (THE-1402 F2: packed from the left, a change of today read as 30 days old). The pad holds the
# widest mark (9 units each side of its centre) and the 2 unit focus stroke around it: the 8 unit
# pad of the mock-ups cut the critical mark at today by 1 unit, 2 when focused (THE-1416).
DRIFT_STEP: Final = 20
DRIFT_PAD: Final = 10
DRIFT_HEIGHT: Final = 32
DRIFT_SPAN_DAYS: Final = 30
DRIFT_WIDTH: Final = 2 * DRIFT_PAD + DRIFT_STEP * DRIFT_SPAN_DAYS
DRIFT_CHECK_KINDS: Final = ("ok", "failed", "change")


@dataclass(frozen=True, slots=True)
class Shell:
    """What the app shell needs from a request: who is signed in and their preferences.

    ``user_name`` and ``user_role`` are empty when nobody is signed in (the sign-in page). The
    ``csrf_token`` goes into every form and into the HTMX request header; it is the session's
    value, never a new one. ``path`` is where a preference form sends the user back to.
    """

    title: str
    nav_current: str = ""
    user_name: str = ""
    user_role: str = ""
    csrf_token: str = ""  # noqa: S105 (an empty default, not a value)
    density: str = "comfortable"
    environment_label: str = ""
    path: str = "/"


@dataclass(frozen=True, slots=True)
class NavLink:
    """One entry of a sidebar group: its label, path, icon and whether it is the current one."""

    key: str
    label: str
    href: str
    icon: str
    current: bool


@dataclass(frozen=True, slots=True)
class NavGroup:
    """A labelled group of the sidebar navigation."""

    key: str
    label: str
    links: tuple[NavLink, ...]


@dataclass(frozen=True, slots=True)
class Location:
    """The trail of the top bar: the group, the section and whether the page is the section."""

    group: str
    label: str
    href: str
    at_section: bool


@dataclass(frozen=True, slots=True)
class DriftMark:
    """One drawn check of a drift line: its position and, for a change, its shape and link."""

    kind: str
    x: float
    severity: str = ""
    summary: str = ""
    href: str = ""
    d: str = ""


def number(value: int) -> str:
    """A count with thousands separators (the dashboard figures and table cells)."""
    return f"{value:,}"


def sentence(text: str) -> str:
    """A reason as a sentence: a capital first letter and a full stop at the end."""
    cleaned = text[:1].upper() + text[1:]
    return cleaned if cleaned.endswith(".") else cleaned + "."


def initials(name: str) -> str:
    """Up to two letters for the avatar: the first letter of the first two words, else two."""
    words = [part for part in name.replace(".", " ").replace("_", " ").split() if part]
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].upper()
    return (words[0][0] + words[1][0]).upper()


def relative_time(when: datetime, now: datetime) -> str:
    """Plain words for how long ago (or ahead) ``when`` is, to the largest whole unit."""
    seconds = (now - when).total_seconds()
    ahead = seconds < 0
    seconds = abs(seconds)
    if seconds < 60:
        return "in under a minute" if ahead else "just now"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        count = int(seconds // size)
        if count >= 1:
            noun = unit if count == 1 else unit + "s"
            return f"in {count} {noun}" if ahead else f"{count} {noun} ago"
    return "just now"


def utc_label(when: datetime) -> str:
    """The exact time as the title of a ``time`` element, always in UTC."""
    return when.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def iso_utc(when: datetime) -> str:
    """The ``datetime`` attribute value of a ``time`` element."""
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sparkline_points(values: Sequence[float], width: int = 96, height: int = 36) -> str:
    """The ``points`` of a polyline through ``values`` inside a ``width`` by ``height`` box.

    Five units of padding keep the stroke inside the box; a flat series is drawn through the
    middle; one value is a flat line too. The result has one decimal per number.
    """
    pad = 5.0
    if not values:
        return ""
    low, high = min(values), max(values)
    span = high - low
    count = len(values)
    usable_h = height - 2 * pad
    points: list[str] = []
    for index, value in enumerate(values):
        x = 0.0 if count == 1 else width * index / (count - 1)
        if span == 0:
            y = height / 2
        else:
            y = pad + usable_h * (1 - (value - low) / span)
        points.append(f"{x:.1f},{y:.1f}")
    if count == 1:
        points.append(f"{width:.1f},{height / 2:.1f}")
    return " ".join(points)


def _mark_path(severity: str, x: float) -> str:
    """The path of a drift line mark centred at ``x``, 18 (the shapes of section 5.3)."""
    if severity == "medium":
        return f"M{x:g} 10 L{x + 8:g} 25 H{x - 8:g} Z"
    if severity == "high":
        return f"M{x:g} 9 L{x + 9:g} 18 L{x:g} 27 L{x - 9:g} 18 Z"
    if severity == "critical":
        return (
            f"M{x - 3.7:g} 9 H{x + 3.7:g} L{x + 9:g} 14.3 V21.7 L{x + 3.7:g} 27 "
            f"H{x - 3.7:g} L{x - 9:g} 21.7 V14.3 Z"
        )
    return ""


def drift_x(age: float) -> float:
    """Where a check ``age`` days before now sits on the strip: today at the right end.

    An age outside the window (a clock step, a run that started inside it and ended a moment
    later) is held at the nearer end rather than drawn off the strip.
    """
    days = min(max(age, 0.0), float(DRIFT_SPAN_DAYS))
    return round(DRIFT_PAD + DRIFT_STEP * (DRIFT_SPAN_DAYS - days), 1)


def drift_marks(checks: Iterable[Mapping[str, Any]]) -> list[DriftMark]:
    """Where and how to draw each check of a drift line, placed by the time of the check.

    A check is a mapping with ``kind`` (ok, failed or change), ``age`` (days before now, a
    fraction allowed) and, for a change, ``severity``, ``summary`` and ``href``. The low mark is
    a circle (drawn by the template from ``x``); the other three severities carry a path. Checks
    close in time can share a spot, so the changes come last and are drawn over the ticks; among
    themselves every kind keeps the order given (oldest first), which is the tab order.
    """
    marks: list[DriftMark] = []
    for check in checks:
        kind = str(check.get("kind", "ok"))
        if kind not in DRIFT_CHECK_KINDS:
            raise ValueError(f"unknown drift line check kind {kind!r}")
        if "age" not in check:
            raise ValueError("a drift line check needs its age in days")
        x = drift_x(float(check["age"]))
        if kind != "change":
            marks.append(DriftMark(kind, x))
            continue
        severity = str(check.get("severity", "low"))
        if severity not in SEVERITIES:
            raise ValueError(f"unknown severity {severity!r}")
        marks.append(
            DriftMark(
                kind,
                x,
                severity=severity,
                summary=str(check.get("summary", "")),
                href=str(check.get("href", "")),
                d=_mark_path(severity, x),
            )
        )
    return sorted(marks, key=lambda mark: mark.kind == "change")


def nav_groups(shell: Shell) -> tuple[NavGroup, ...]:
    """The sidebar groups the reader may open, the shell's current entry marked.

    An admin-only entry is left out for anyone else, and a group left empty is not drawn.
    """
    items = {key: (label, href) for key, label, href in NAV_ITEMS}
    admin = shell.user_role == "admin"
    groups = (
        NavGroup(
            key,
            label,
            tuple(
                NavLink(
                    item,
                    items[item][0],
                    items[item][1],
                    NAV_ICONS[item],
                    item == shell.nav_current,
                )
                for item in members
                if admin or item not in NAV_ADMIN_ONLY
            ),
        )
        for key, label, members in NAV_GROUPS
    )
    return tuple(group for group in groups if group.links)


def _bare_path(path: str) -> str:
    """The path without its query string or fragment."""
    return path.split("?", 1)[0].split("#", 1)[0]


def nav_location(shell: Shell) -> Location | None:
    """Where the page sits in the navigation, or None for a page outside it (an error page).

    ``at_section`` is true on the section's own page (``/changes``) and false below it
    (``/changes/12``), where the section name becomes a link back up.
    """
    for _group_key, group_label, members in NAV_GROUPS:
        if shell.nav_current not in members:
            continue
        label, href = next((lb, hr) for k, lb, hr in NAV_ITEMS if k == shell.nav_current)
        return Location(group_label, label, href, _bare_path(shell.path) == href)
    return None


def topbar_action(shell: Shell) -> tuple[str, str] | None:
    """The action of the top bar, or None for a non-admin and where the page already offers it."""
    if shell.user_role != "admin":
        return None
    path = _bare_path(shell.path)
    if path in TOPBAR_ACTION_HIDDEN or path.startswith("/sources/"):
        return None
    return TOPBAR_ACTION


def make_environment() -> Environment:
    """The configured Jinja environment: escaping on, strict names, the helpers as globals."""
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.globals.update(
        app_version=__version__,
        nav_items=NAV_ITEMS,
        nav_groups=nav_groups,
        nav_location=nav_location,
        topbar_action=topbar_action,
        severities=SEVERITIES,
        severity_labels=SEVERITY_LABELS,
        status_icons=STATUS_ICONS,
        densities=DENSITIES,
        number=number,
        sentence=sentence,
        initials=initials,
        relative_time=relative_time,
        utc_label=utc_label,
        iso_utc=iso_utc,
        sparkline_points=sparkline_points,
        drift_marks=drift_marks,
        drift_width=DRIFT_WIDTH,
        drift_height=DRIFT_HEIGHT,
    )
    return environment


@cache
def environment() -> Environment:
    """The shared environment of the process (templates are cached after the first render)."""
    return make_environment()


def render(template_name: str, shell: Shell, **context: Any) -> str:
    """Render a page template with the shell and the page's own context."""
    return environment().get_template(template_name).render(shell=shell, **context)
