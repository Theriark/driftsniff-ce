"""Admin routes for the notification channel (P9-T4, docs/notifications.md).

Like the token routes these are routes of the interface, not of ``/api/v1``: an admin uses them
with a session, so a write needs the session CSRF value. They take a form post or a JSON object
and answer with JSON. A browser that asks for ``text/html`` gets the settings page instead (P10-T8,
``driftsniff.web.settings_page``). A form can only post, so the page saves the channel with
``POST /notifications/channel`` (the same as ``PUT``) and removes it with
``POST /notifications/channel/remove`` (the same as ``DELETE``).

The channel is never returned in full. The answer holds the type, the minimum severity, whether the
channel is enabled and the host and port of the target; the URL path, a query, the SMTP login and
the password stay behind (they are encrypted at rest and only the sender reads them).
"""

from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse, Response

from driftsniff.notify.deliveries import (
    ChannelUnreadableError,
    NoChannelError,
    NotificationInputError,
    NotificationService,
)
from driftsniff.web.auth import Principal
from driftsniff.web.deps import get_notification_service, require_admin
from driftsniff.web.pages import PageError, wants_html
from driftsniff.web.routes_ui import read_fields
from driftsniff.web.settings_page import (
    channel_failure,
    redirect_target,
    render_settings,
    unknown_field_failure,
)

router = APIRouter()

_CONFIG_FIELDS: Final = frozenset(
    {
        "url",
        "host",
        "port",
        "security",
        "username",
        "password",
        "from_address",
        "to_addresses",
    }
)
_CONTROL_FIELDS: Final = frozenset({"type", "min_severity", "enabled", "csrf_token"})
_MAX_EVENT_ID: Final = 2**31 - 1
# What a refused settings page fills back in: never the webhook address and never the password.
_KEPT_FIELDS: Final = _CONFIG_FIELDS - {"url", "password"} | {"type", "min_severity", "enabled"}

Admin = Annotated[Principal, Depends(require_admin)]
Service = Annotated[NotificationService, Depends(get_notification_service)]


def _flag(raw: str | None) -> bool:
    """The ``enabled`` field: absent means on; else the text true or false."""
    if raw is None:
        return True
    lowered = raw.strip().lower()
    if lowered not in ("true", "false"):
        raise NotificationInputError("enabled must be true or false")
    return lowered == "true"


@router.get("/notifications/channel")
async def get_channel(
    _admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[NotificationService, Depends(get_notification_service)],
) -> JSONResponse:
    """The channel as an admin may see it, or ``null`` when none is set."""
    view = await run_in_threadpool(service.channel)
    return JSONResponse({"channel": None if view is None else view.as_dict()})


@router.put("/notifications/channel")
@router.post("/notifications/channel")
async def put_channel(request: Request, admin: Admin, service: Service) -> Response:
    """Set the one channel. Fields: ``type`` (webhook or smtp), ``min_severity`` (default high),
    ``enabled`` (true or false) and the fields of the type: ``url`` for a webhook; ``host``,
    ``port``, ``security`` (starttls or tls), ``username``, ``password``, ``from_address`` and
    ``to_addresses`` for SMTP.
    """
    html = wants_html(request)
    fields = await read_fields(request, structured=True)
    kept = {key: value for key, value in fields.items() if key in _KEPT_FIELDS}
    unknown = sorted(set(fields) - _CONFIG_FIELDS - _CONTROL_FIELDS)
    if unknown:
        if html:
            failure = unknown_field_failure("channel", "The notification channel was not saved")
            return await render_settings(request, admin, status=422, failure=failure, values=kept)
        return JSONResponse({"detail": f"unknown field: {unknown[0][:40]}"}, status_code=422)
    try:
        view = await run_in_threadpool(
            service.configure,
            actor=admin.username,
            channel_type=fields.get("type", "").strip().lower(),
            fields={key: value for key, value in fields.items() if key in _CONFIG_FIELDS},
            min_severity=fields.get("min_severity"),
            enabled=_flag(fields.get("enabled")),
        )
    except NotificationInputError as error:
        if html:
            failure = channel_failure(str(error))
            return await render_settings(request, admin, status=422, failure=failure, values=kept)
        return JSONResponse({"detail": str(error)}, status_code=422)
    if html:
        return RedirectResponse(redirect_target("channel-saved"), status_code=303)
    return JSONResponse({"channel": view.as_dict()})


async def _remove(request: Request, admin: Principal, service: NotificationService) -> Response:
    found = await run_in_threadpool(service.remove, actor=admin.username)
    if not found:
        raise HTTPException(status_code=404, detail="there is no notification channel")
    if wants_html(request):
        return RedirectResponse(redirect_target("channel-removed"), status_code=303)
    return JSONResponse({"removed": True})


@router.delete("/notifications/channel")
async def delete_channel(request: Request, admin: Admin, service: Service) -> Response:
    """Remove the channel and its stored deliveries."""
    return await _remove(request, admin, service)


@router.post("/notifications/channel/remove")
async def remove_channel(request: Request, admin: Admin, service: Service) -> Response:
    """The settings page's form for ``DELETE /notifications/channel``: the same removal."""
    return await _remove(request, admin, service)


def _test_words(ok: bool, error_class: str | None, http_status: int | None) -> PageError:
    """What the settings page says after a test message."""
    if ok:
        return PageError(
            "Test message sent", "The channel took it. Check that it arrived where you expect."
        )
    answer = error_class or "an error"
    if http_status is not None:
        answer = f"{answer} (HTTP {http_status})"
    return PageError(
        "The test message was not taken",
        f"The channel answered with {answer}. Check the channel, then send another test.",
    )


@router.post("/notifications/test")
async def send_test(request: Request, admin: Admin, service: Service) -> Response:
    """Send a sample message, marked as a test, once. The answer says whether it was taken."""
    html = wants_html(request)
    try:
        result = await run_in_threadpool(service.send_test, actor=admin.username)
    except NoChannelError as error:
        if html:
            words = PageError("No test was sent", "There is no channel yet. Set one first.")
            return await render_settings(request, admin, status=404, test_result=words)
        raise HTTPException(status_code=404, detail=str(error)) from None
    except ChannelUnreadableError as error:
        if html:
            words = PageError(
                "No test was sent",
                "The stored channel cannot be read. Enter the channel again, then test it.",
            )
            return await render_settings(request, admin, status=409, test_result=words)
        raise HTTPException(status_code=409, detail=str(error)) from None
    if html:
        words = _test_words(result.ok, result.error_class, result.http_status)
        return await render_settings(request, admin, test_result=words, test_ok=result.ok)
    body: dict[str, Any] = {"ok": result.ok}
    if result.error_class is not None:
        body["error_class"] = result.error_class
    if result.http_status is not None:
        body["http_status"] = result.http_status
    return JSONResponse(body)


@router.post("/notifications/signing-key")
async def show_signing_key(request: Request, admin: Admin, service: Service) -> Response:
    """The key a receiver checks the webhook signature with (hex). Each use is audited."""
    key = await run_in_threadpool(service.signing_key_hex, actor=admin.username)
    if wants_html(request):
        return await render_settings(request, admin, signing_key=key)
    return JSONResponse(
        {
            "algorithm": "HMAC-SHA-256",
            "key_hex": key,
            "signed": "the timestamp, a full stop and the request body",
            "note": "keep it secret; it changes after a rekey",
        }
    )


@router.get("/notifications/deliveries")
async def list_deliveries(
    _admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[NotificationService, Depends(get_notification_service)],
    event_id: Annotated[int | None, Query(ge=1, le=_MAX_EVENT_ID)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> JSONResponse:
    """The stored delivery attempts, newest first, optionally of one event."""
    records = await run_in_threadpool(service.deliveries, event_id, limit)
    return JSONResponse({"deliveries": [record.as_dict() for record in records]})
