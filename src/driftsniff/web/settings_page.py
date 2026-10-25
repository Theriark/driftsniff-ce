"""The settings page (P10-T8 slice B, docs/settings.md): what an admin sees at ``GET /settings``.

The routes of slice A (``routes_settings``), of the API tokens (``routes_api``) and of the
notification channel (``routes_notifications``) answer JSON to every client that does not ask for
a page. A browser asks for ``text/html`` and gets this page instead, in one of these states:

* plain, or with a notice after a change was saved (``?notice=<word>``, then a 303 back here);
* refused: the form that failed is marked field by field and a banner names what was not saved
  (422 or 409); nothing typed into a password or a webhook address is ever filled back in;
* once after a token was made, or after the signing key was asked for: the value in a card that
  says it is not shown again (the page is ``no-store`` like every page);
* after a test message, with whether it was taken.

A section whose service the application was built without says so instead of failing. The page
builds its view here (pure data), so the template only prints.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from starlette.requests import Request

from driftsniff.db.tables import CHANNEL_TYPES, SEVERITIES
from driftsniff.notify.config import DEFAULT_PORTS, SMTP_SECURITIES
from driftsniff.notify.deliveries import ChannelView, NotificationService
from driftsniff.sources.retention import MAX_RETENTION_DAYS, MIN_RETENTION_DAYS
from driftsniff.web.auth import Principal, UserSummary
from driftsniff.web.bearer import MAX_EXPIRY_DAYS, TOKEN_SCOPES, TokenInfo, TokenService
from driftsniff.web.dashboard import parse_stamp
from driftsniff.web.history_pages import size_text
from driftsniff.web.pages import PageError, page, shell_for
from driftsniff.web.routes_ui import build_commit
from driftsniff.web.settings_service import Overview, SettingsService

SETTINGS_PATH: Final = "/settings"
TEMPLATE: Final = "settings/page.html"
GIGABYTE: Final = 1024**3

# The sections of the page, in order: the id of each card and the label of its tab.
SECTIONS: Final = (
    ("users", "Users"),
    ("tokens", "API tokens"),
    ("notifications", "Notifications"),
    ("retention", "Retention and storage"),
    ("about", "About"),
)

# The words a 303 back to the page carries, and what the banner then says.
NOTICES: Final = {
    "user-added": ("User added", "They can sign in now with the password you set."),
    "user-disabled": (
        "User disabled",
        "Their sessions ended. They cannot sign in until you enable them again.",
    ),
    "user-enabled": ("User enabled", "They can sign in again."),
    "token-revoked": ("Token revoked", "Programs that send it are refused from now on."),
    "channel-saved": (
        "Notification channel saved",
        "Send a test message to check that it arrives.",
    ),
    "channel-removed": (
        "Notification channel removed",
        "No alert is sent until you set a channel again.",
    ),
    "retention-saved": (
        "Retention saved",
        "The next nightly clean-up keeps changes for the new number of days.",
    ),
    "storage-saved": (
        "Storage warning saved",
        "The storage card of the dashboard warns from the new size.",
    ),
}
# Where each notice sends the reader: the section the change belongs to.
NOTICE_SECTIONS: Final = {
    "user-added": "users",
    "user-disabled": "users",
    "user-enabled": "users",
    "token-revoked": "tokens",
    "channel-saved": "notifications",
    "channel-removed": "notifications",
    "retention-saved": "retention",
    "storage-saved": "retention",
}

# The one text for a field the page does not send: the route's answer names the field, which a
# person did not type and should not see repeated (THE-1269/THE-1270 carry-over).
UNKNOWN_FIELD_TEXT: Final = (
    "The form sent a field driftsniff does not know. Reload the page and try again."
)

# How a notification rule names its field (the first word of the message) and how the page says it.
CHANNEL_FIELD_LABELS: Final = {
    "type": "The channel type",
    "min_severity": "The lowest severity",
    "enabled": "On or off",
    "url": "The address",
    "host": "The host",
    "port": "The port",
    "security": "The security",
    "username": "The user name",
    "password": "The password",
    "from_address": "The sender address",
    "to_addresses": "The recipients",
}
TOKEN_FIELD_PREFIXES: Final = (
    ("the token name", "name"),
    ("the scopes", "scopes"),
    ("the expiry", "expires_in_days"),
)
SEVERITY_WORDS: Final = {
    "low": "Low and above (every change)",
    "medium": "Medium and above",
    "high": "High and above",
    "critical": "Critical only",
}
SECURITY_WORDS: Final = {"starttls": "STARTTLS", "tls": "TLS"}
ROLE_WORDS: Final = {
    "viewer": "Viewer: reads every page",
    "operator": "Operator: also runs checks and acknowledges changes",
    "admin": "Admin: also changes sources, users and settings",
}


@dataclass(frozen=True, slots=True)
class Failure:
    """A refused form: which one, the banner and the message of each marked field."""

    form: str
    title: str
    text: str
    fields: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UserRow:
    """One user of the table: the name, the role, the state and the one action the admin has."""

    user_id: int
    username: str
    role: str
    disabled: bool
    locked: bool
    created: datetime | None
    is_you: bool


@dataclass(frozen=True, slots=True)
class TokenRow:
    """One token of the table: never the value and never the hash, only the visible prefix."""

    token_id: int
    name: str
    prefix: str
    scopes: tuple[str, ...]
    status: str
    created_by: str
    last_used: datetime | None
    expires: datetime | None


@dataclass(frozen=True, slots=True)
class Meter:
    """A bar of the page: how full, as a width of 0 to 100 units, and the words for it."""

    width: int
    text: str
    over: bool = False


def _stamp(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return parse_stamp(text)
    except ValueError:
        return None


def user_rows(users: tuple[UserSummary, ...], you: int) -> list[UserRow]:
    """The users as the table shows them: admins first, then by name."""
    rank = {"admin": 0, "operator": 1, "viewer": 2}
    ordered = sorted(users, key=lambda user: (rank.get(user.role, 3), user.username))
    return [
        UserRow(
            user.user_id,
            user.username,
            user.role,
            user.disabled,
            user.locked,
            _stamp(user.created_at),
            user.user_id == you,
        )
        for user in ordered
    ]


def token_rows(tokens: list[TokenInfo] | tuple[TokenInfo, ...], now: datetime) -> list[TokenRow]:
    """The tokens as the table shows them: active ones first, newest first within a status."""
    order = {"active": 0, "expired": 1, "revoked": 2}
    rows = [
        TokenRow(
            info.token_id,
            info.name,
            info.prefix,
            tuple(info.scopes),
            info.status(now),
            info.created_by,
            _stamp(info.last_used_at),
            _stamp(info.expires_at),
        )
        for info in tokens
    ]
    return sorted(rows, key=lambda row: (order.get(row.status, 3), -row.token_id))


def storage_meter(used: int, warning_gb: int) -> Meter:
    """How much of the warning size the database uses."""
    limit = max(warning_gb, 1) * GIGABYTE
    share = used / limit
    width = 0 if used <= 0 else max(1, min(100, round(share * 100)))
    percent = share * 100
    shown = "under 1" if 0 < percent < 1 else f"{percent:.0f}"
    text = f"{size_text(used)} of {warning_gb} GB used, {shown} percent of the warning size"
    return Meter(width, text, over=used >= limit)


def retention_meter(days: int) -> Meter:
    """Where the retention window sits between the shortest and the longest allowed."""
    span = MAX_RETENTION_DAYS - MIN_RETENTION_DAYS
    width = round((days - MIN_RETENTION_DAYS) * 100 / span)
    return Meter(max(0, min(100, width)), f"{days} days kept, of {MAX_RETENTION_DAYS} at most")


def channel_failure(message: str) -> Failure:
    """A refused channel: the field the rule names is marked, the rule is the message."""
    head, _, rest = message.partition(" ")
    if head in CHANNEL_FIELD_LABELS and rest:
        text = f"{CHANNEL_FIELD_LABELS[head]} {rest}"
        fields = {head: _sentence(text)}
    else:
        fields = {}
        text = message
    return Failure(
        "channel",
        "The notification channel was not saved",
        "Fix the marked field, then save again." if fields else _sentence(text),
        fields,
    )


def token_failure(message: str) -> Failure:
    """A refused token: the field the rule names is marked."""
    for prefix, name in TOKEN_FIELD_PREFIXES:
        if message.startswith(prefix):
            return Failure(
                "token",
                "The token was not made",
                "Fix the marked field, then try again.",
                {name: _sentence(message)},
            )
    return Failure("token", "The token was not made", _sentence(message))


def field_failure(form: str, title: str, name: str, message: str) -> Failure:
    """A refused form with one marked field."""
    return Failure(form, title, "Fix the marked field, then try again.", {name: _sentence(message)})


def unknown_field_failure(form: str, title: str) -> Failure:
    """A form that sent a field the route does not know; the field name is not repeated."""
    return Failure(form, title, UNKNOWN_FIELD_TEXT)


def _sentence(text: str) -> str:
    cleaned = text[:1].upper() + text[1:]
    return cleaned if cleaned.endswith(".") else cleaned + "."


def notice_of(request: Request) -> tuple[str, str] | None:
    """The banner of a ``?notice=`` word, or None for an unknown or missing word."""
    return NOTICES.get(request.query_params.get("notice", ""))


def redirect_target(notice: str) -> str:
    """Where a saved form sends the browser: the page with the notice, at the section."""
    return f"{SETTINGS_PATH}?notice={notice}#{NOTICE_SECTIONS[notice]}"


async def _overview(request: Request) -> Overview | None:
    service: SettingsService | None = request.app.state.admin_settings
    if service is None:
        return None
    return await run_in_threadpool(service.overview)


async def _tokens(request: Request) -> list[TokenRow] | None:
    service: TokenService | None = request.app.state.tokens
    if service is None:
        return None
    tokens = await run_in_threadpool(service.list_tokens)
    return token_rows(tokens, service.now())


async def _channel(request: Request) -> tuple[bool, ChannelView | None]:
    service: NotificationService | None = request.app.state.notifications
    if service is None:
        return False, None
    return True, await run_in_threadpool(service.channel)


async def render_settings(
    request: Request,
    admin: Principal,
    *,
    status: int = 200,
    failure: Failure | None = None,
    values: dict[str, str] | None = None,
    created_token: dict[str, Any] | None = None,
    signing_key: str = "",
    test_result: PageError | None = None,
    test_ok: bool = False,
) -> HTMLResponse:
    """The settings page in the state the arguments describe.

    ``values`` are the fields of the refused form to fill back in; the caller leaves out every
    password and the webhook address, so they are never repeated.
    """
    overview = await _overview(request)
    tokens = await _tokens(request)
    notifications_on, channel = await _channel(request)
    now = datetime.now(UTC)
    shell = shell_for(request, admin, "Settings", "settings")
    context: dict[str, Any] = {
        "now": now,
        "sections": SECTIONS,
        "notice": notice_of(request) if failure is None else None,
        "failure": failure,
        "values": values or {},
        "overview": overview,
        "users": None if overview is None else user_rows(overview.users, admin.user_id),
        "tokens": tokens,
        "created_token": created_token,
        "notifications_on": notifications_on,
        "channel": channel,
        "signing_key": signing_key,
        "test_result": test_result,
        "test_ok": test_ok,
        "commit": build_commit(),
        "retention_min": MIN_RETENTION_DAYS,
        "retention_max": MAX_RETENTION_DAYS,
        "token_scopes": TOKEN_SCOPES,
        "max_expiry_days": MAX_EXPIRY_DAYS,
        "channel_types": CHANNEL_TYPES,
        "severities_order": SEVERITIES,
        "severity_words": SEVERITY_WORDS,
        "securities": SMTP_SECURITIES,
        "security_words": SECURITY_WORDS,
        "default_ports": DEFAULT_PORTS,
        "role_words": ROLE_WORDS,
        "size_text": size_text,
        "stamp_of": _stamp,
    }
    if overview is not None:
        about = overview.about
        context["storage"] = storage_meter(about.database_bytes, overview.storage_warning_gb)
        context["retention"] = retention_meter(overview.retention_days)
    return page(TEMPLATE, shell, status=status, **context)
