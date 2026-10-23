"""The Jinja environment of the web interface and the helpers its templates use (P10-T2).

Every page extends ``base.html`` (the app shell: header, navigation, user menu, skip link, main
landmark, footer) and builds its content from the macros in ``templates/components/``. The
environment escapes everything (autoescape on, never switched off by a template: the security
suite scans for it) and refuses an undefined name, so a template mistake fails a test instead of
rendering an empty string.

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
# exist are listed (Delivery decision on P10-T5): each P10 task adds its own entry back, in this
# order, when its page lands: Changes (/changes, P10-T6) after Dashboard; History (/history) and
# Configuration (/configuration, P10-T7) and Settings (/settings, P10-T8) after Sources.
NAV_ITEMS: Final = (
    ("dashboard", "Dashboard", "/"),
    ("sources", "Sources", "/sources"),
)

# Drift line geometry (docs/design-direction.md section 2): a 32 unit tall strip, one position
# every 20 units, the first at 8, so 31 checks give the 616 wide strip of the mock-ups.
DRIFT_STEP: Final = 20
DRIFT_PAD: Final = 8
DRIFT_HEIGHT: Final = 32
DRIFT_MIN_WIDTH: Final = 616
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


def drift_marks(checks: Iterable[Mapping[str, Any]]) -> list[DriftMark]:
    """Where and how to draw each check of a drift line, in the order given (oldest first).

    A check is a mapping with ``kind`` (ok, failed or change) and, for a change, ``severity``,
    ``summary`` and ``href``. The low mark is a circle (drawn by the template from ``x``); the
    other three severities carry a path.
    """
    marks: list[DriftMark] = []
    for index, check in enumerate(checks):
        kind = str(check.get("kind", "ok"))
        if kind not in DRIFT_CHECK_KINDS:
            raise ValueError(f"unknown drift line check kind {kind!r}")
        x = float(DRIFT_PAD + DRIFT_STEP * index)
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
    return marks


def drift_width(count: int) -> int:
    """The viewBox width of a strip of ``count`` checks; never narrower than the mock-ups."""
    if count <= 0:
        return DRIFT_MIN_WIDTH
    return max(DRIFT_MIN_WIDTH, 2 * DRIFT_PAD + DRIFT_STEP * (count - 1))


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
        drift_width=drift_width,
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
