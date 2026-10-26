"""PLACEHOLDER: proves the browser harness works. It is not a product journey.

It opens a static page in Chromium at the three viewports, runs axe on it and writes a screenshot
to the artifact folder. It never starts the application and never uses the network. The Test
Engineer replaces or extends it with the real journeys of the plan (P10-T9).
"""

from pathlib import Path

import pytest
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Browser

VIEWPORTS = {"desktop": (1440, 900), "tablet": (768, 1024), "mobile": (390, 844)}

PAGE = (
    "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
    "<title>Harness smoke</title></head><body><main><h1>Harness smoke</h1>"
    "<p>Placeholder page for the browser test harness.</p></main></body></html>"
)


@pytest.mark.parametrize("name", sorted(VIEWPORTS))
def test_harness_smoke(browser: Browser, artifact_dir: Path, name: str) -> None:
    width, height = VIEWPORTS[name]
    context = browser.new_context(viewport={"width": width, "height": height})
    try:
        page = context.new_page()
        page.set_content(PAGE)
        results = Axe().run(page)
        page.screenshot(path=artifact_dir / f"harness-smoke-{name}.png")
    finally:
        context.close()
    assert results.violations_count == 0, results.generate_report()
