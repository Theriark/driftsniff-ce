"""The settings page through the real application (P10-T8 slice B, frontend).

Slice A's tests (``test_settings_routes.py``, ``test_settings_canaries.py``) ask the routes for
JSON. These ask them the way a browser does, with ``Accept: text/html`` and plain form posts that
carry the CSRF value as a field, and check what a person sees. The acceptance checks of P10-T8
(THE-1262), each with its tests here:

1. the page is the admin's; operator and viewer get the not-allowed page, nobody is sent to sign
   in, and no link on the page answers 404: ``test_an_admin_gets_the_page_with_its_five_parts``,
   ``test_an_operator_and_a_viewer_get_the_not_allowed_page``,
   ``test_a_browser_without_a_session_is_sent_to_sign_in``, ``test_no_link_of_the_page_is_a_404``;
2. a token is shown once, the list shows its prefix only, revoke works and no value or hash is
   on the page afterwards: ``test_a_new_token_is_shown_once_and_then_only_its_prefix``,
   ``test_revoking_a_token_comes_back_with_a_notice``;
3. the channel never shows its path, query or password, a blocked address is refused with the
   field marked, every write is audited:
   ``test_a_saved_webhook_shows_its_host_only_and_never_the_path_or_query``,
   ``test_a_blocked_address_is_refused_with_the_field_marked_and_not_filled_back``,
   ``test_an_smtp_password_is_never_filled_back_or_shown``,
   ``test_test_message_signing_key_and_removal_are_audited``;
4. retention 29, 366 and text are refused with the field marked and nothing stored; 30 and 365
   are kept: ``test_retention_outside_its_rule_is_refused_with_the_field_marked``,
   ``test_retention_30_and_365_are_saved``, ``test_the_storage_warning_follows_its_rule_too``;
5. users are added, disabled and enabled; a disabled user's sessions end:
   ``test_an_admin_adds_disables_and_enables_a_user_from_the_page``,
   ``test_a_taken_name_is_refused_with_the_name_marked``;
6. every write needs the CSRF value, hostile names are escaped, the page has no inline style or
   script: ``test_every_form_of_the_page_posts_the_csrf_value_and_fails_without_it``,
   ``test_a_hostile_user_name_is_escaped``, ``test_the_page_has_no_inline_style_or_script``;
7. the browser check at 1440, 768 and 390 in both themes is evidence of the task, not a test; the
   stylesheet the page loads is checked in ``test_the_page_loads_its_stylesheet_after_the_shell``.

Carry-overs of the PR 107 verdicts (THE-1269, THE-1270): the last-admin guard through the HTTP
route (``test_the_last_enabled_admin_cannot_be_disabled_through_the_route`` and
``test_an_admin_cannot_disable_their_own_account_from_the_page``; there is no route that changes
a role, see ``test_no_route_changes_a_role``) and the generic text for an unknown field
(``test_an_unknown_field_is_refused_without_repeating_its_name``).
Everything is synthetic; text that must never be shown starts with CANARY-.
"""

import re
from html.parser import HTMLParser
from typing import Any

import pytest
import sqlalchemy as sa
from httpx import Response

from driftsniff.db.tables import audit_events, settings, users
from driftsniff.web.bearer import hash_token
from driftsniff.web.settings_page import UNKNOWN_FIELD_TEXT

from .appkit import CORRECT, Kit, Session
from .routekit import real_routes

BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
NEW_PASSWORD = "CANARY-a new user password"  # noqa: S105
SMTP_PASSWORD = "CANARY-smtp-password"  # noqa: S105
SHORT_PASSWORD = "x"  # noqa: S105
HOSTILE = "<script>alert('CANARY-xss')</script>"
SECTIONS = ("users", "tokens", "notifications", "retention", "about")


class Tags(HTMLParser):
    """The start tags of a page with their attributes, and its text."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.words: list[str] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        self.words.append(data)

    def attrs(self, name: str) -> list[dict[str, str | None]]:
        return [attrs for tag, attrs in self.tags if tag == name]

    def by_id(self, element_id: str) -> dict[str, str | None]:
        found = [attrs for _tag, attrs in self.tags if attrs.get("id") == element_id]
        assert len(found) == 1, element_id
        return found[0]

    def text(self) -> str:
        return " ".join(" ".join(self.words).split())


def browser(session: Session) -> dict[str, str]:
    """The headers of a browser of the session: the cookie and the origin, the CSRF value is
    a field of each form, like the page sends it."""
    return {**session.headers(csrf=False), **BROWSER}


def show(kit: Kit, session: Session) -> Response:
    return kit.client.get("/settings", headers=browser(session))


def submit(kit: Kit, session: Session, path: str, fields: dict[str, Any]) -> Response:
    """A form of the page posted by the browser, with the CSRF value as its field."""
    data = {"csrf_token": session.csrf, **fields}
    return kit.client.post(path, headers=browser(session), data=data)


def html(response: Response, status: int = 200) -> Tags:
    assert response.status_code == status, response.text[:600]
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-store"
    return Tags(response.text)


def saved(response: Response, notice: str, section: str) -> None:
    assert response.status_code == 303, response.text[:600]
    assert response.headers["location"] == f"/settings?notice={notice}#{section}"


def stored(kit: Kit) -> dict[str, str]:
    with kit.store.read() as connection:
        rows = connection.execute(sa.select(settings.c.key, settings.c.value))
        return {str(row.key): str(row.value) for row in rows}


def actions(kit: Kit) -> list[str]:
    with kit.store.read() as connection:
        rows = connection.execute(sa.select(audit_events.c.action).order_by(audit_events.c.id))
        return [str(row.action) for row in rows]


def disabled_users(kit: Kit) -> list[str]:
    with kit.store.read() as connection:
        rows = connection.execute(sa.select(users.c.username).where(users.c.disabled.is_(True)))
        return sorted(str(row.username) for row in rows)


def marked(page: Tags, field_id: str) -> None:
    """The field is marked invalid and points at its message."""
    attrs = page.by_id(field_id)
    assert attrs.get("aria-invalid") == "true", field_id
    assert f"{field_id}-error" in str(attrs.get("aria-describedby")), field_id


# ---- 1. who gets the page ---------------------------------------------------------------------


def test_an_admin_gets_the_page_with_its_five_parts(kit: Kit) -> None:
    response = show(kit, kit.new_session("admin"))
    page = html(response)
    for section in SECTIONS:
        assert page.by_id(section)
    links = [str(attrs.get("href")) for attrs in page.attrs("a")]
    jumps = [link for link in links if link.startswith("#") and link != "#main"]  # skip link
    assert jumps == [f"#{name}" for name in SECTIONS]
    assert "<h1>Settings</h1>" in response.text
    text = page.text()
    for words in ("Add a user", "Make a token", "Set a channel", "Save retention", "Save warning"):
        assert words in text, words
    # the three users of the kit, the admin's own row marked and without a disable form
    actions_of_forms = {attrs.get("action") for attrs in page.attrs("form")}
    assert f"/settings/users/{kit.user_ids['viewer']}/disable" in actions_of_forms
    assert f"/settings/users/{kit.user_ids['admin']}/disable" not in actions_of_forms
    assert "You" in text and "Signed in" in text


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_an_operator_and_a_viewer_get_the_not_allowed_page(kit: Kit, role: str) -> None:
    session = kit.new_session(role)
    page = html(show(kit, session), 403)
    assert "Your role does not allow this" in page.text()
    # the shell's own forms only: sign out and the change search of the top bar
    assert {attrs.get("action") for attrs in page.attrs("form")} <= {"/logout", "/changes"}
    for path, fields in (
        ("/settings/retention", {"retention_days": "90"}),
        ("/settings/users", {"username": "ada", "password": NEW_PASSWORD, "role": "admin"}),
        ("/tokens", {"name": "x", "scopes": "read"}),
        ("/notifications/channel", {"type": "webhook", "url": "https://hooks.example/a"}),
    ):
        assert submit(kit, session, path, fields).status_code == 403, path
    assert "retention_days" not in stored(kit)


def test_a_browser_without_a_session_is_sent_to_sign_in(kit: Kit) -> None:
    response = kit.client.get("/settings", headers=BROWSER)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/settings"


def test_no_link_of_the_page_is_a_404(kit: Kit) -> None:
    admin = kit.new_session("admin")
    page = html(show(kit, admin))
    links = {str(attrs.get("href")) for attrs in page.attrs("a")}
    paths = {link.split("#", 1)[0] for link in links if link.startswith("/")}
    assert paths, "the page links to the rest of the interface"
    for path in sorted(paths):
        answer = kit.client.get(path, headers=browser(admin))
        assert answer.status_code != 404, path


# ---- 2. API tokens ----------------------------------------------------------------------------


def test_a_new_token_is_shown_once_and_then_only_its_prefix(kit: Kit) -> None:
    admin = kit.new_session("admin")
    made = submit(kit, admin, "/tokens", {"name": "backup-report", "scopes": ["read", "enrich"]})
    page = html(made, 201)
    value = str(page.by_id("new-token").get("value"))
    assert value and "readonly" in page.by_id("new-token")
    assert "shown once" in page.text()
    listed = [info for info in kit.tokens.list_tokens() if info.name == "backup-report"]
    assert len(listed) == 1
    assert set(listed[0].scopes) == {"read", "enrich"}
    again = show(kit, admin).text
    assert value not in again
    assert hash_token(value) not in again and hash_token(value) not in made.text
    assert listed[0].prefix in again


def test_a_refused_token_marks_its_field(kit: Kit) -> None:
    admin = kit.new_session("admin")
    page = html(submit(kit, admin, "/tokens", {"name": "", "scopes": "read"}), 422)
    marked(page, "token-name")
    assert "The token was not made" in page.text()
    page = html(submit(kit, admin, "/tokens", {"name": "no-scope"}), 422)
    assert "The scopes must be one or both of: read, enrich." in page.text()
    assert page.by_id("token-scopes-error")


def test_revoking_a_token_comes_back_with_a_notice(kit: Kit) -> None:
    admin = kit.new_session("admin")
    token_id = next(info.token_id for info in kit.tokens.list_tokens() if info.name == "read")
    saved(submit(kit, admin, f"/tokens/{token_id}/revoke", {}), "token-revoked", "tokens")
    page = html(kit.client.get("/settings?notice=token-revoked", headers=browser(admin)))
    assert "Token revoked" in page.text()
    assert f"/tokens/{token_id}/revoke" not in {a.get("action") for a in page.attrs("form")}
    assert "token.revoked" in actions(kit)


# ---- 3. the notification channel --------------------------------------------------------------


def test_a_saved_webhook_shows_its_host_only_and_never_the_path_or_query(kit: Kit) -> None:
    admin = kit.new_session("admin")
    url = "https://hooks.example:8443/CANARY-path/x?CANARY-query=CANARY-value"
    response = submit(
        kit,
        admin,
        "/notifications/channel",
        {"type": "webhook", "url": url, "min_severity": "medium", "enabled": ["true", "false"]},
    )
    saved(response, "channel-saved", "notifications")
    page = html(show(kit, admin))
    assert "CANARY" not in page.text() and "CANARY" not in show(kit, admin).text
    assert "https://hooks.example:8443" in page.text()
    assert "Medium and above" in page.text()
    assert page.by_id("ch-url").get("value") is None
    assert "notification.channel_saved" in actions(kit)


def test_an_unticked_box_turns_the_channel_off(kit: Kit) -> None:
    admin = kit.new_session("admin")
    fields = {"type": "webhook", "url": "https://hooks.example/a", "enabled": "false"}
    saved(submit(kit, admin, "/notifications/channel", fields), "channel-saved", "notifications")
    channel = kit.client.get("/notifications/channel", headers=admin.headers()).json()["channel"]
    assert channel["enabled"] is False


def test_a_blocked_address_is_refused_with_the_field_marked_and_not_filled_back(kit: Kit) -> None:
    admin = kit.new_session("admin")
    url = "http://127.0.0.1/CANARY-blocked-path"
    response = submit(kit, admin, "/notifications/channel", {"type": "webhook", "url": url})
    page = html(response, 422)
    marked(page, "ch-url")
    assert "The address names an address that is never allowed." in page.text()
    assert "CANARY" not in response.text and page.by_id("ch-url").get("value") is None
    assert "notification.channel_saved" not in actions(kit)


def test_an_smtp_password_is_never_filled_back_or_shown(kit: Kit) -> None:
    admin = kit.new_session("admin")
    fields = {
        "type": "smtp",
        "host": "mail.example",
        "security": "starttls",
        "from_address": "driftsniff@example.org",
        "to_addresses": "CANARY-not-an-address",
        "username": "bot",
        "password": SMTP_PASSWORD,
    }
    refused = submit(kit, admin, "/notifications/channel", fields)
    page = html(refused, 422)
    marked(page, "ch-to")
    assert SMTP_PASSWORD not in refused.text
    assert page.by_id("ch-password").get("value") is None
    assert page.by_id("ch-host").get("value") == "mail.example"
    fields["to_addresses"] = "ops@example.org"
    saved(submit(kit, admin, "/notifications/channel", fields), "channel-saved", "notifications")
    again = show(kit, admin)
    assert SMTP_PASSWORD not in again.text
    assert "mail.example:587" in Tags(again.text).text()


def test_test_message_signing_key_and_removal_are_audited(kit: Kit) -> None:
    admin = kit.new_session("admin")
    fields = {"type": "webhook", "url": "https://hooks.example/a"}
    saved(submit(kit, admin, "/notifications/channel", fields), "channel-saved", "notifications")
    # the kit resolves every name to the loopback address, so the test is refused before sending
    tested = html(submit(kit, admin, "/notifications/test", {}))
    assert "The test message was not taken" in tested.text()
    keyed = html(submit(kit, admin, "/notifications/signing-key", {}))
    key = str(keyed.by_id("signing-key").get("value"))
    assert re.fullmatch(r"[0-9a-f]{32,}", key)
    assert key not in show(kit, admin).text
    removed = submit(kit, admin, "/notifications/channel/remove", {})
    saved(removed, "channel-removed", "notifications")
    channel = kit.client.get("/notifications/channel", headers=admin.headers()).json()
    assert channel == {"channel": None}
    done = actions(kit)
    for action in (
        "notification.channel_saved",
        "notification.test",
        "notification.signing_key_shown",
        "notification.channel_removed",
    ):
        assert action in done, action
    no_channel = html(submit(kit, admin, "/notifications/test", {}), 404)
    assert "There is no channel yet" in no_channel.text()


def test_the_post_twins_answer_json_like_put_and_delete(kit: Kit) -> None:
    admin = kit.new_session("admin")
    body = {"type": "webhook", "url": "https://hooks.example/a"}
    posted = kit.client.post("/notifications/channel", headers=admin.headers(), json=body)
    assert posted.status_code == 200 and posted.json()["channel"]["type"] == "webhook"
    removed = kit.client.post("/notifications/channel/remove", headers=admin.headers(), json={})
    assert removed.json() == {"removed": True}
    again = kit.client.post("/notifications/channel/remove", headers=admin.headers(), json={})
    assert again.status_code == 404


# ---- 4. retention and storage -----------------------------------------------------------------


@pytest.mark.parametrize("value", ["29", "366", "ninety", "", "-30", "90.5"])
def test_retention_outside_its_rule_is_refused_with_the_field_marked(kit: Kit, value: str) -> None:
    admin = kit.new_session("admin")
    page = html(submit(kit, admin, "/settings/retention", {"retention_days": value}), 422)
    marked(page, "retention-days")
    assert "Retention was not saved" in page.text()
    assert "must be a whole number from 30 to 365" in page.text()
    assert "retention_days" not in stored(kit)
    assert "settings.retention_days_changed" not in actions(kit)


@pytest.mark.parametrize("value", ["30", "365"])
def test_retention_30_and_365_are_saved(kit: Kit, value: str) -> None:
    admin = kit.new_session("admin")
    saved(
        submit(kit, admin, "/settings/retention", {"retention_days": value}),
        "retention-saved",
        "retention",
    )
    assert stored(kit)["retention_days"] == value
    page = html(kit.client.get("/settings?notice=retention-saved", headers=browser(admin)))
    assert page.by_id("retention-days").get("value") == value
    assert "Retention saved" in page.text()


def test_the_storage_warning_follows_its_rule_too(kit: Kit) -> None:
    admin = kit.new_session("admin")
    for value in ("0", "1001", "x"):
        response = submit(kit, admin, "/settings/storage-warning", {"storage_warning_gb": value})
        marked(html(response, 422), "storage-gb")
    assert "storage_warning_gb" not in stored(kit)
    saved(
        submit(kit, admin, "/settings/storage-warning", {"storage_warning_gb": "7"}),
        "storage-saved",
        "retention",
    )
    assert stored(kit)["storage_warning_gb"] == "7"
    assert html(show(kit, admin)).by_id("storage-gb").get("value") == "7"


def test_an_unknown_field_is_refused_without_repeating_its_name(kit: Kit) -> None:
    admin = kit.new_session("admin")
    odd = "CANARY-odd-field-name"
    for path, fields in (
        ("/settings/retention", {"retention_days": "90", odd: "1"}),
        ("/settings/users", {"username": "ada", "password": NEW_PASSWORD, odd: "1"}),
        ("/tokens", {"name": "x", "scopes": "read", odd: "1"}),
        ("/notifications/channel", {"type": "webhook", "url": "https://hooks.example/b", odd: "1"}),
    ):
        response = submit(kit, admin, path, fields)
        page = html(response, 422)
        assert UNKNOWN_FIELD_TEXT in page.text(), path
        assert odd not in response.text and NEW_PASSWORD not in response.text, path
    assert "retention_days" not in stored(kit)


# ---- 5. users ---------------------------------------------------------------------------------


def test_an_admin_adds_disables_and_enables_a_user_from_the_page(kit: Kit) -> None:
    admin = kit.new_session("admin")
    fields = {"username": "ada", "password": NEW_PASSWORD, "role": "operator"}
    saved(submit(kit, admin, "/settings/users", fields), "user-added", "users")
    page = html(kit.client.get("/settings?notice=user-added", headers=browser(admin)))
    assert "User added" in page.text() and "ada" in page.text()
    assert NEW_PASSWORD not in kit.client.get("/settings", headers=browser(admin)).text

    ada = kit.auth.login("ada", NEW_PASSWORD, "127.0.0.1")
    ada_id = ada.principal.user_id
    saved(submit(kit, admin, f"/settings/users/{ada_id}/disable", {}), "user-disabled", "users")
    assert kit.auth.authenticate(ada.cookie_value) is None
    assert disabled_users(kit) == ["ada"]
    after = html(show(kit, admin))
    assert f"/settings/users/{ada_id}/enable" in {a.get("action") for a in after.attrs("form")}
    saved(submit(kit, admin, f"/settings/users/{ada_id}/enable", {}), "user-enabled", "users")
    assert disabled_users(kit) == []


def test_a_taken_name_is_refused_with_the_name_marked(kit: Kit) -> None:
    admin = kit.new_session("admin")
    fields = {"username": "viewer", "password": NEW_PASSWORD, "role": "viewer"}
    response = submit(kit, admin, "/settings/users", fields)
    page = html(response, 409)
    marked(page, "user-username")
    assert page.by_id("user-username").get("value") == "viewer"
    assert NEW_PASSWORD not in response.text
    assert page.by_id("user-password").get("value") is None
    fields.update(username="ada", password=SHORT_PASSWORD)
    short = submit(kit, admin, "/settings/users", fields)
    marked(html(short, 422), "user-password")


def test_an_admin_cannot_disable_their_own_account_from_the_page(kit: Kit) -> None:
    admin = kit.new_session("admin")
    response = submit(kit, admin, f"/settings/users/{kit.user_ids['admin']}/disable", {})
    page = html(response, 409)
    assert "The user was not disabled" in page.text()
    assert "You cannot disable your own account." in page.text()
    assert disabled_users(kit) == []
    assert kit.auth.authenticate(admin.cookie) is not None


def test_the_last_enabled_admin_cannot_be_disabled_through_the_route(
    kit: Kit, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard runs inside the write. A second admin disables the first while the first's own
    request to disable the second is on its way: that request must find the second admin the
    last one enabled, refuse with 409 and change nothing, for JSON and for the page."""
    admin = kit.new_session("admin")
    fields = {"username": "boss", "password": NEW_PASSWORD, "role": "admin"}
    saved(submit(kit, admin, "/settings/users", fields), "user-added", "users")
    boss_id = next(user.user_id for user in kit.auth.list_users() if user.username == "boss")
    service = kit.app.state.admin_settings
    real = service.set_user_disabled

    def raced(user_id: int, **kwargs: Any) -> bool:
        # the other admin's disabling lands first (and ends the first admin's sessions later)
        with kit.store.write() as connection:
            connection.execute(
                sa.update(users).where(users.c.id == kit.user_ids["admin"]).values(disabled=True)
            )
        return bool(real(user_id, **kwargs))

    monkeypatch.setattr(service, "set_user_disabled", raced)
    path = f"/settings/users/{boss_id}/disable"
    as_json = kit.client.post(path, headers=admin.headers(), json={})
    assert as_json.status_code == 409
    assert as_json.json() == {"detail": "at least one admin must stay enabled"}
    with kit.store.write() as connection:
        connection.execute(
            sa.update(users).where(users.c.id == kit.user_ids["admin"]).values(disabled=False)
        )
    page = html(submit(kit, admin, path, {}), 409)
    assert "At least one admin must stay enabled." in page.text()
    assert "boss" not in disabled_users(kit)
    assert "user.disabled" not in actions(kit)


def test_no_route_changes_a_role(kit: Kit) -> None:
    # Slice A has no role change or demotion; the page offers none, so the last-admin rule has
    # only the disable route to guard. A new route here must bring its own last-admin test.
    for method, path in real_routes(kit.app):
        if path.startswith("/settings/users"):
            assert path.endswith(("/disable", "/enable")) or path == "/settings/users", path
            assert method == "POST", path
    text = show(kit, kit.new_session("admin")).text
    assert "/role" not in text and "demote" not in text.lower()


# ---- 6. CSRF, escaping, policy ----------------------------------------------------------------


def test_every_form_of_the_page_posts_the_csrf_value_and_fails_without_it(kit: Kit) -> None:
    admin = kit.new_session("admin")
    kit.client.post(
        "/notifications/channel",
        headers=admin.headers(),
        json={"type": "webhook", "url": "https://hooks.example/a"},
    )
    page = html(show(kit, admin))
    forms = page.tags
    posts = 0
    for index, (tag, attrs) in enumerate(forms):
        if tag != "form" or attrs.get("method") != "post":
            continue
        posts += 1
        following = forms[index + 1]
        assert following == ("input", {"type": "hidden", "name": "csrf_token", "value": admin.csrf})
    assert posts >= 10  # sign out, two users, two tokens, three channel actions, the channel, ...
    for path, fields in (
        ("/settings/retention", {"retention_days": "90"}),
        ("/settings/users", {"username": "ada", "password": NEW_PASSWORD, "role": "viewer"}),
        ("/tokens", {"name": "x", "scopes": "read"}),
        ("/notifications/channel/remove", {}),
    ):
        response = kit.client.post(path, headers=browser(admin), data=fields)
        assert response.status_code == 403, path
    assert "retention_days" not in stored(kit)


def test_a_hostile_user_name_is_escaped(kit: Kit) -> None:
    admin = kit.new_session("admin")
    fields = {"username": HOSTILE, "password": NEW_PASSWORD, "role": "viewer"}
    response = submit(kit, admin, "/settings/users", fields)
    # the name rule refuses it; the refused page fills it back in, escaped
    page_text = response.text
    assert response.status_code == 422
    assert HOSTILE not in page_text
    assert "&lt;script&gt;" in page_text
    token = submit(kit, admin, "/tokens", {"name": HOSTILE, "scopes": "read"})
    assert token.status_code == 201
    assert HOSTILE not in token.text and HOSTILE not in show(kit, admin).text


def test_the_page_has_no_inline_style_or_script(kit: Kit) -> None:
    text = show(kit, kit.new_session("admin")).text
    assert "style=" not in text and "<style" not in text
    scripts = re.findall(r"<script\b[^>]*>", text)
    assert scripts and all("src=" in script for script in scripts)
    assert not re.search(r"\son[a-z]+=", text)  # no event handler attribute


def test_every_field_of_the_page_has_a_label(kit: Kit) -> None:
    page = Tags(show(kit, kit.new_session("admin")).text)
    labelled = {attrs.get("for") for attrs in page.attrs("label")}
    for tag in ("input", "select", "textarea"):
        for attrs in page.attrs(tag):
            if attrs.get("type") == "hidden":
                continue
            assert attrs.get("id") in labelled, f"unlabelled {tag} {attrs.get('name')}"


def test_the_page_loads_its_stylesheet_after_the_shell(kit: Kit) -> None:
    text = show(kit, kit.new_session("admin")).text
    sheets = re.findall(r'<link rel="stylesheet" href="([^"]+)">', text)
    assert sheets == ["/static/app.css", "/static/summary-head.css", "/static/settings.css"]
    css = kit.client.get("/static/settings.css")
    assert css.status_code == 200
    for rule in (".settings-pair", ".meter__fill", ".settings-form__fields", ".settings-sub"):
        assert rule in css.text, rule


def test_a_user_who_signs_in_after_a_disable_is_refused(kit: Kit) -> None:
    admin = kit.new_session("admin")
    viewer = kit.user_ids["viewer"]
    saved(submit(kit, admin, f"/settings/users/{viewer}/disable", {}), "user-disabled", "users")
    login = kit.client.post("/login", data={"username": "viewer", "password": CORRECT})
    assert login.status_code == 401
    kit.client.cookies.clear()
