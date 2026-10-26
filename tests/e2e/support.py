"""Shared helpers of the journeys: the three viewports, the page audit and the console watch.

An audit runs on the page as it is, in any state (also after a refused form), at 1440, 768 and
390 pixels in the light and the dark colour scheme. It collects every problem instead of
stopping at the first, so one CI run names them all: a serious or critical axe violation, an
inline script (the content security policy forbids it), a page that is wider than its viewport.
Each state is saved as a screenshot in the artifact folder (never committed).
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import ConsoleMessage, Page

Scheme = Literal["light", "dark"]

VIEWPORTS = {"desktop": (1440, 900), "tablet": (768, 1024), "mobile": (390, 844)}
SCHEMES: tuple[Scheme, ...] = ("light", "dark")
BLOCKING_IMPACTS = {"serious", "critical"}
STATUS_NOISE = re.compile(r"the server responded with a status of 4\d\d")


@dataclass(frozen=True)
class Accounts:
    """The admin the setup journey creates and the viewer the role journey adds."""

    admin: str
    admin_password: str
    viewer: str
    viewer_password: str


@dataclass
class Watch:
    """Console errors and uncaught page errors of one page since the last drain."""

    errors: list[str] = field(default_factory=list)
    # a refused form answers 4xx on purpose; the browser may log that as a console error
    allow_refusals: bool = False

    def attach(self, page: Page) -> None:
        page.on("console", self._console)
        page.on("pageerror", lambda error: self.errors.append(f"page error: {error}"))

    def _console(self, message: ConsoleMessage) -> None:
        if message.type != "error":
            return
        if self.allow_refusals and STATUS_NOISE.search(message.text):
            return
        self.errors.append(f"console error: {message.text}")

    def drain(self) -> list[str]:
        found, self.errors = list(self.errors), []
        return found


@dataclass
class Audit:
    """Collects the problems of the audits of one test; ``finish`` fails when there are any."""

    artifact_dir: Path
    problems: list[str] = field(default_factory=list)

    def current(self, page: Page, label: str) -> None:
        """Audit the page as it is now, at every viewport and colour scheme."""
        for scheme in SCHEMES:
            page.emulate_media(color_scheme=scheme)
            for name, (width, height) in VIEWPORTS.items():
                page.set_viewport_size({"width": width, "height": height})
                self._one(page, f"{label} {scheme} {name}", f"{label}-{scheme}-{name}")
        desktop_width, desktop_height = VIEWPORTS["desktop"]
        page.emulate_media(color_scheme="light")
        page.set_viewport_size({"width": desktop_width, "height": desktop_height})

    def _one(self, page: Page, title: str, stem: str) -> None:
        results = Axe().run(page)
        for violation in results.response.get("violations", []):
            if violation.get("impact") in BLOCKING_IMPACTS:
                nodes = violation.get("nodes", [])
                target = nodes[0].get("target") if nodes else ""
                self.problems.append(
                    f"{title}: axe {violation['id']} ({violation['impact']}) on {len(nodes)} "
                    f"node(s), first {target}"
                )
        inline = page.eval_on_selector_all("script:not([src])", "els => els.length")
        if inline:
            self.problems.append(f"{title}: {inline} inline script(s)")
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        if overflow > 1:
            self.problems.append(f"{title}: the page is {overflow}px wider than the viewport")
        page.screenshot(path=self.artifact_dir / f"{stem}.png", full_page=True)

    def finish(self) -> None:
        assert not self.problems, "\n".join(self.problems)
