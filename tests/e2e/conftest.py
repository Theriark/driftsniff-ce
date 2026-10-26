"""Shared fixtures of the browser tests: one Chromium for the session and the artifact folder."""

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Browser, sync_playwright


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
