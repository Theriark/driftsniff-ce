"""Admin routes for the notification channel (P9-T4, docs/notifications.md).

Like the token routes these are routes of the interface, not of ``/api/v1``: an admin uses them
with a session, so a write needs the session CSRF value. They take a form post or a JSON object
and answer with JSON; the pages that show them are built in P10.

The channel is never returned in full. The answer holds the type, the minimum severity, whether the
channel is enabled and the host and port of the target; the URL path, a query, the SMTP login and
the password stay behind (they are encrypted at rest and only the sender reads them).
"""

from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from driftsniff.notify.deliveries import (
    ChannelUnreadableError,
    NoChannelError,
    NotificationInputError,
    NotificationService,
)
from driftsniff.web.auth import Principal
from driftsniff.web.deps import get_notification_service, require_admin
from driftsniff.web.routes_ui import read_fields

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
async def put_channel(
    request: Request,
    admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[NotificationService, Depends(get_notification_service)],
) -> JSONResponse:
    """Set the one channel. Fields: ``type`` (webhook or smtp), ``min_severity`` (default high),
    ``enabled`` (true or false) and the fields of the type: ``url`` for a webhook; ``host``,
    ``port``, ``security`` (starttls or tls), ``username``, ``password``, ``from_address`` and
    ``to_addresses`` for SMTP.
    """
    fields = await read_fields(request, structured=True)
    unknown = sorted(set(fields) - _CONFIG_FIELDS - _CONTROL_FIELDS)
    if unknown:
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
        return JSONResponse({"detail": str(error)}, status_code=422)
    return JSONResponse({"channel": view.as_dict()})


@router.delete("/notifications/channel")
async def delete_channel(
    admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[NotificationService, Depends(get_notification_service)],
) -> JSONResponse:
    """Remove the channel and its stored deliveries."""
    found = await run_in_threadpool(service.remove, actor=admin.username)
    if not found:
        raise HTTPException(status_code=404, detail="there is no notification channel")
    return JSONResponse({"removed": True})


@router.post("/notifications/test")
async def send_test(
    admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[NotificationService, Depends(get_notification_service)],
) -> JSONResponse:
    """Send a sample message, marked as a test, once. The answer says whether it was taken."""
    try:
        result = await run_in_threadpool(service.send_test, actor=admin.username)
    except NoChannelError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    except ChannelUnreadableError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None
    body: dict[str, Any] = {"ok": result.ok}
    if result.error_class is not None:
        body["error_class"] = result.error_class
    if result.http_status is not None:
        body["http_status"] = result.http_status
    return JSONResponse(body)


@router.post("/notifications/signing-key")
async def show_signing_key(
    admin: Annotated[Principal, Depends(require_admin)],
    service: Annotated[NotificationService, Depends(get_notification_service)],
) -> JSONResponse:
    """The key a receiver checks the webhook signature with (hex). Each use is audited."""
    key = await run_in_threadpool(service.signing_key_hex, actor=admin.username)
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
