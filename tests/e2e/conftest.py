"""Shared fixtures of the browser tests: one Chromium for the session, the artifact folder, the
live application and the accounts the journeys create."""

import os
import secrets
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

from tests.e2e.server import LiveApp, start_app
from tests.e2e.support import VIEWPORTS, Audit, Watch


@dataclass(frozen=True)
class Accounts:
    """The admin the setup journey creates and the viewer the role journey adds."""

    admin: str
    admin_password: str
    viewer: str
    viewer_password: str


@pytest.fixture(scope="session")
def artifact_dir() -> Path:
    """Folder for screenshots. CI sets E2E_ARTIFACT_DIR and uploads it; nothing is committed."""
    configured = os.environ.get("E2E_ARTIFACT_DIR")
    path = Path(configured) if configured else Path(tempfile.mkdtemp(prefix="e2e-artifacts-"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def browser() -> Iterator[Browser]:
    """One headless Chromium shared by every journey; each test makes its own context."""
    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch()
        yield chromium
        chromium.close()


@pytest.fixture(scope="session")
def live_app(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveApp]:
    """The real application with the Development fixture, started once for all journeys."""
    app = start_app(tmp_path_factory.mktemp("driftsniff-e2e"))
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture(scope="session")
def accounts() -> Accounts:
    """Throwaway accounts with random passwords, made new on every run."""
    return Accounts(
        admin="journey-admin",
        admin_password=f"journey admin phrase {secrets.token_hex(6)}",
        viewer="journey-viewer",
        viewer_password=f"journey viewer phrase {secrets.token_hex(6)}",
    )


@pytest.fixture(scope="session")
def admin_context(browser: Browser) -> Iterator[BrowserContext]:
    """The browser profile of the admin: the setup journey signs it in, the others reuse it."""
    width, height = VIEWPORTS["desktop"]
    context = browser.new_context(viewport={"width": width, "height": height})
    try:
        yield context
    finally:
        context.close()


@pytest.fixture(scope="session")
def watch() -> Watch:
    return Watch()


@pytest.fixture(scope="session")
def page(admin_context: BrowserContext, watch: Watch) -> Page:
    """The one tab of the admin that the ordered journeys share."""
    tab = admin_context.new_page()
    watch.attach(tab)
    return tab


@pytest.fixture
def audit(artifact_dir: Path) -> Iterator[Audit]:
    """The audits of one test; the test fails at the end when any of them found a problem."""
    collected = Audit(artifact_dir=artifact_dir)
    yield collected
    collected.finish()


@pytest.fixture(autouse=True)
def console_stays_clean(request: pytest.FixtureRequest, watch: Watch) -> Iterator[None]:
    """No console error and no uncaught page error in any journey (refused forms excepted)."""
    watch.drain()
    watch.allow_refusals = False
    yield
    if "page" in request.fixturenames:
        errors = watch.drain()
        assert not errors, "\n".join(errors)
