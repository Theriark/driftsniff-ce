"""The browser journeys of P10-T9 (THE-1315): a person using the real application.

The tests run in file order and share one signed-in tab, as one person's session does; a failure
early on makes the later journeys fail too, so read the first red one. The data is the Development
fixture (three synthetic changes of several severities) plus what the journeys make themselves.
Nothing leaves 127.0.0.1 and no real source or credential is involved.

Every page and every refused state is audited with axe at 1440, 768 and 390 pixels in the light
and dark scheme (tests/e2e/support.py); the screenshots land in E2E_ARTIFACT_DIR.
"""

import re

import pytest
from playwright.sync_api import Browser, Page, expect

from tests.e2e.conftest import Accounts
from tests.e2e.server import LiveApp
from tests.e2e.support import Audit, Watch

FIXTURE_SOURCE = "DEV-FIXTURE synthetic (removable)"
FAKE_SOURCE = "E2E fake source"
PUSH_FIELDS = "networks: _id, name, vlan"
TOKEN_NAME = "e2e-token"
STATE: dict[str, list[int]] = {}


def open_page(page: Page, app: LiveApp, path: str) -> None:
    page.goto(f"{app.base_url}{path}")
    expect(page.locator("main")).to_be_visible()


def sign_in(page: Page, app: LiveApp, user: str, password: str) -> None:
    open_page(page, app, "/login")
    page.fill("#username", user)
    page.fill("#password", password)
    page.get_by_role("button", name="Sign in").click()
    expect(page).to_have_url(f"{app.base_url}/")


def change_ids(page: Page) -> list[int]:
    hrefs = page.eval_on_selector_all(
        "a[href^='/changes/']", "els => els.map(e => e.getAttribute('href'))"
    )
    found = {int(m.group(1)) for m in map(re.compile(r"/changes/(\d+)$").search, hrefs) if m}
    return sorted(found)


def test_01_setup_creates_the_first_admin(
    page: Page, app: LiveApp, accounts: Accounts, audit: Audit, watch: Watch
) -> None:
    open_page(page, app, "/setup")
    expect(page.get_by_role("heading", name="Create the first admin")).to_be_visible()
    audit.current(page, "setup")
    # a wrong code is refused, the page stays and the password is never filled back in
    watch.allow_refusals = True
    page.fill("#code", "WRONG-WRONG-WRONG-0")
    page.fill("#username", accounts.admin)
    page.fill("#password", accounts.admin_password)
    page.get_by_role("button", name="Create admin and sign in").click()
    expect(page.get_by_role("heading", name="Create the first admin")).to_be_visible()
    expect(page.locator("#username")).to_have_value(accounts.admin)
    expect(page.locator("#password")).to_have_value("")
    audit.current(page, "setup-wrong-code")
    watch.allow_refusals = False
    page.fill("#code", app.setup_code)
    page.fill("#password", accounts.admin_password)
    page.get_by_role("button", name="Create admin and sign in").click()
    expect(page).to_have_url(f"{app.base_url}/")
    expect(page.locator(".user-name")).to_have_text(accounts.admin)
    # setup is gone once an admin exists
    response = page.goto(f"{app.base_url}/setup")
    assert response is not None and response.status == 404


def test_02_sign_out_and_sign_in(
    page: Page, app: LiveApp, accounts: Accounts, audit: Audit, watch: Watch
) -> None:
    open_page(page, app, "/")
    page.locator(".user-menu summary").click()
    page.get_by_role("button", name="Sign out").click()
    expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
    expect(page.get_by_text("Signed out").first).to_be_visible()
    audit.current(page, "login")
    watch.allow_refusals = True
    page.fill("#username", accounts.admin)
    page.fill("#password", "not the password at all")
    page.get_by_role("button", name="Sign in").click()
    expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
    expect(page.locator("#password")).to_have_value("")
    audit.current(page, "login-failed")
    watch.allow_refusals = False
    sign_in(page, app, accounts.admin, accounts.admin_password)
    # a page that needs a session sends a signed-out visitor to the sign-in page
    expect(page.locator(".user-name")).to_have_text(accounts.admin)


def test_03_dashboard_and_the_change_list(page: Page, app: LiveApp, audit: Audit) -> None:
    open_page(page, app, "/")
    expect(page).to_have_title(re.compile("Dashboard"))
    audit.current(page, "dashboard")
    open_page(page, app, "/changes")
    ids = change_ids(page)
    assert len(ids) >= 3, f"the fixture makes three changes, the list links {ids}"
    STATE["changes"] = ids
    audit.current(page, "changes-list")
    page.fill("#q", "zzzz-nothing-matches-this")
    page.get_by_role("button", name="Apply").click()
    expect(page.get_by_text("No change matches these filters")).to_be_visible()
    audit.current(page, "changes-list-no-match")


def test_04_add_a_fake_push_source(
    page: Page, app: LiveApp, audit: Audit, watch: Watch
) -> None:
    open_page(page, app, "/sources")
    expect(page.get_by_text(FIXTURE_SOURCE).first).to_be_visible()
    audit.current(page, "sources-list")
    open_page(page, app, "/sources/new?type=push")
    audit.current(page, "source-form")
    # an empty name is refused with the field marked
    watch.allow_refusals = True
    page.fill("#push_fields", PUSH_FIELDS)
    page.get_by_role("button", name="Add source").click()
    expect(page.get_by_text("Check the marked fields")).to_be_visible()
    audit.current(page, "source-form-refused")
    watch.allow_refusals = False
    page.fill("#name", FAKE_SOURCE)
    page.fill("#push_fields", PUSH_FIELDS)
    page.get_by_role("button", name="Add source").click()
    expect(page).to_have_url(re.compile(r"/sources/\d+$"))
    expect(page.get_by_text(FAKE_SOURCE).first).to_be_visible()
    audit.current(page, "source-detail")


def test_05_note_and_acknowledge_a_change(
    page: Page, app: LiveApp, audit: Audit, watch: Watch
) -> None:
    change = STATE["changes"][0]
    open_page(page, app, f"/changes/{change}")
    expect(page.get_by_role("heading", level=1)).to_be_visible()
    audit.current(page, "change-detail")
    # an empty note is refused, nothing is stored
    watch.allow_refusals = True
    page.get_by_role("button", name="Save note").click()
    expect(page.get_by_text("Write the note first.")).to_be_visible()
    audit.current(page, "change-detail-note-refused")
    watch.allow_refusals = False
    page.fill("#note", "e2e note: checked the VLAN with the site owner")
    page.get_by_role("button", name="Save note").click()
    expect(page.get_by_text("Note saved")).to_be_visible()
    expect(page.get_by_text("e2e note: checked the VLAN")).to_be_visible()
    page.fill("#ack-comment", "e2e acknowledgement: expected change")
    page.get_by_role("button", name="Acknowledge change").click()
    expect(page.get_by_text("Change acknowledged")).to_be_visible()
    expect(page.get_by_text("e2e acknowledgement: expected change")).to_be_visible()
    expect(page.get_by_role("button", name="Acknowledge again")).to_be_visible()
    audit.current(page, "change-detail-acknowledged")


def test_06_mute_and_unmute_a_path(page: Page, app: LiveApp, audit: Audit) -> None:
    for change in STATE["changes"]:
        open_page(page, app, f"/changes/{change}")
        if page.locator("summary", has_text="Mute this path").count():
            break
    else:
        pytest.fail("no change of the fixture offers a mutable path")
    page.locator("summary", has_text="Mute this path").first.click()
    page.locator("input[name=reason]").first.fill("e2e mute: noisy field")
    audit.current(page, "change-detail-mute-open")
    page.get_by_role("button", name="Mute path").first.click()
    expect(page.get_by_text("Path muted").first).to_be_visible()
    open_page(page, app, "/changes")
    expect(page.get_by_role("heading", name=re.compile("Muted paths"))).to_be_visible()
    page.locator("summary", has_text="Muted paths").click()
    expect(page.get_by_text("e2e mute: noisy field")).to_be_visible()
    audit.current(page, "changes-list-with-mute")
    page.get_by_role("button", name="Unmute").click()
    expect(page.get_by_text("Mute removed")).to_be_visible()
    expect(page.get_by_role("heading", name=re.compile("Muted paths"))).to_have_count(0)


def test_07_history_and_current_configuration(page: Page, app: LiveApp, audit: Audit) -> None:
    open_page(page, app, "/history")
    audit.current(page, "history-sources")
    page.get_by_role("link", name=re.compile("DEV-FIXTURE")).first.click()
    expect(page).to_have_url(re.compile(r"/history/\d+$"))
    expect(page).to_have_title(re.compile("History of DEV-FIXTURE"))
    audit.current(page, "history-snapshots")
    open_page(page, app, "/configuration")
    audit.current(page, "configuration-sources")
    page.get_by_role("link", name=re.compile("DEV-FIXTURE")).first.click()
    expect(page).to_have_url(re.compile(r"/configuration/\d+$"))
    expect(page).to_have_title(re.compile("Configuration of DEV-FIXTURE"))
    expect(page.get_by_text(re.compile("FIXTURE")).first).to_be_visible()
    audit.current(page, "configuration-current")


def test_08_create_and_revoke_an_api_token(page: Page, app: LiveApp, audit: Audit) -> None:
    open_page(page, app, "/settings")
    audit.current(page, "settings")
    page.fill("#token-name", TOKEN_NAME)
    page.get_by_role("button", name="Make token").click()
    expect(page.get_by_role("heading", name=f"New token {TOKEN_NAME}, shown once")).to_be_visible()
    expect(page.locator("#new-token")).not_to_have_value("")
    audit.current(page, "settings-token-created")
    # shown once: a fresh visit lists the token by its prefix, never the value
    open_page(page, app, "/settings")
    expect(page.locator("#new-token")).to_have_count(0)
    row = page.locator("tr", has_text=TOKEN_NAME)
    expect(row.get_by_text("Active")).to_be_visible()
    page.get_by_role("button", name=f"Revoke {TOKEN_NAME}").click()
    row = page.locator("tr", has_text=TOKEN_NAME)
    expect(row.get_by_text("Revoked")).to_be_visible()
    expect(page.get_by_role("button", name=f"Revoke {TOKEN_NAME}")).to_have_count(0)
    audit.current(page, "settings-token-revoked")


def test_09_a_viewer_reads_and_never_changes(
    page: Page,
    browser: Browser,
    app: LiveApp,
    accounts: Accounts,
    audit: Audit,
    watch: Watch,
) -> None:
    open_page(page, app, "/settings")
    page.fill("#user-username", accounts.viewer)
    page.fill("#user-password", accounts.viewer_password)
    page.select_option("#user-role", "viewer")
    page.get_by_role("button", name="Add user").click()
    expect(page.get_by_text(accounts.viewer).first).to_be_visible()
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    try:
        viewer = context.new_page()
        viewer_watch = Watch()
        viewer_watch.attach(viewer)
        sign_in(viewer, app, accounts.viewer, accounts.viewer_password)
        open_page(viewer, app, f"/changes/{STATE['changes'][0]}")
        expect(viewer.get_by_role("button", name="Acknowledge again")).to_have_count(0)
        expect(viewer.get_by_role("button", name="Save note")).to_have_count(0)
        expect(viewer.get_by_role("button", name="Mute path")).to_have_count(0)
        expect(viewer.get_by_text("Your role reads only")).to_be_visible()
        audit.current(viewer, "change-detail-viewer")
        response = viewer.goto(f"{app.base_url}/settings")
        assert response is not None and response.status == 403
        viewer_watch.allow_refusals = True
        audit.current(viewer, "settings-not-allowed")
        assert not [e for e in viewer_watch.drain() if "status of 403" not in e]
    finally:
        context.close()


def test_10_the_pages_work_without_javascript(
    browser: Browser, app: LiveApp, accounts: Accounts
) -> None:
    context = browser.new_context(
        viewport={"width": 390, "height": 844}, java_script_enabled=False
    )
    try:
        plain = context.new_page()
        sign_in(plain, app, accounts.admin, accounts.admin_password)
        open_page(plain, app, "/changes")
        assert change_ids(plain) == STATE["changes"]
        # the folded navigation opens with a details toggle, no script involved
        plain.locator(".menu-toggle summary").click()
        expect(plain.get_by_role("link", name="Changes").first).to_be_visible()
        open_page(plain, app, f"/changes/{STATE['changes'][0]}")
        plain.fill("#note", "e2e note without JavaScript")
        plain.get_by_role("button", name="Save note").click()
        expect(plain.get_by_text("Note saved")).to_be_visible()
        expect(plain.get_by_text("e2e note without JavaScript")).to_be_visible()
    finally:
        context.close()


def test_99_the_server_log_has_no_traceback(app: LiveApp) -> None:
    assert app.process.poll() is None, "the application stopped during the journeys"
    assert "Traceback" not in app.log_text(), app.log_text()[-2000:]
