"""Admin routes of the settings (P10-T8, docs/settings.md): the data and the settings page.

Every route needs the admin role; a write also needs the session CSRF value and the configured
origin (``driftsniff.web.csrf``). The routes take a form post or a JSON object and answer with
JSON, like the token and notification routes. A browser (one that asks for ``text/html``, slice B)
gets the settings page instead (``driftsniff.web.settings_page``): ``GET /settings`` draws it, a
saved write sends it back there with a notice (303), and a refused write draws it again with the
form marked, under the same status code the JSON answer has.

* ``GET /settings``: the retention window, the storage warning size, the users and the About data.
* ``POST /settings/retention``: field ``retention_days``, a whole number from 30 to 365.
* ``POST /settings/storage-warning``: field ``storage_warning_gb``, from 1 to 1000.
* ``POST /settings/users``: fields ``username``, ``password`` and ``role``; 201 with the new user.
* ``POST /settings/users/{user_id}/disable`` and ``/enable``.

A value that breaks its rule answers 422 with the rule and the name of the field (``field``) and
stores nothing; the answer never repeats the value. A name that is taken, your own account and the
last enabled admin answer 409. No answer holds a password, a hash or a session value.
"""

from collections.abc import Callable
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse, Response

from driftsniff.sources.retention import MAX_RETENTION_DAYS, MIN_RETENTION_DAYS
from driftsniff.web.auth import Principal, UserSummary
from driftsniff.web.deps import require_admin
from driftsniff.web.pages import wants_html
from driftsniff.web.routes_ui import build_commit, read_fields
from driftsniff.web.settings_page import (
    Failure,
    field_failure,
    redirect_target,
    render_settings,
    unknown_field_failure,
)
from driftsniff.web.settings_service import (
    Overview,
    RetentionRun,
    SettingConflictError,
    SettingsService,
)
from driftsniff.web.settings_store import FIELD_RETENTION, FIELD_STORAGE, SettingInputError

router = APIRouter()

_MAX_USER_ID: Final = 2**31 - 1
_CSRF_FIELD: Final = "csrf_token"
_USER_FIELDS: Final = frozenset({"username", "password", "role", _CSRF_FIELD})


def get_settings_service(request: Request) -> SettingsService:
    """The settings service; 503 when the application was built without one."""
    service: SettingsService | None = request.app.state.admin_settings
    if service is None:
        raise HTTPException(status_code=503, detail="settings are not available")
    return service


Service = Annotated[SettingsService, Depends(get_settings_service)]
Admin = Annotated[Principal, Depends(require_admin)]


def _user(user: UserSummary) -> dict[str, Any]:
    return {
        "id": user.user_id,
        "username": user.username,
        "role": user.role,
        "disabled": user.disabled,
        "locked": user.locked,
        "created_at": user.created_at,
    }


def _last_run(last: RetentionRun | None) -> dict[str, Any] | None:
    if last is None:
        return None
    return {
        "at": last.at,
        "retention_days": last.retention_days,
        "events_deleted": last.events_deleted,
        "snapshots_thinned": last.snapshots_thinned,
        "states_removed": last.states_removed,
        "freed_bytes": last.freed_bytes,
    }


def _body(view: Overview) -> dict[str, Any]:
    about = view.about
    return {
        "retention": {
            "days": view.retention_days,
            "default": view.default_retention_days,
            "min": MIN_RETENTION_DAYS,
            "max": MAX_RETENTION_DAYS,
            "runs_at_utc": view.retention_run_utc,
        },
        "storage_warning": {
            "gb": view.storage_warning_gb,
            "default": view.default_storage_warning_gb,
            "min": view.min_storage_warning_gb,
            "max": view.max_storage_warning_gb,
            "used_bytes": about.database_bytes,
        },
        "users": [_user(user) for user in view.users],
        "about": {
            "version": about.version,
            "commit": build_commit(),
            "schema_revision": about.schema_revision,
            "database_bytes": about.database_bytes,
            "sources": about.sources,
            "users": about.users,
            "last_retention_run": _last_run(about.last_retention_run),
        },
    }


def _unknown_field(fields: dict[str, str], allowed: frozenset[str]) -> JSONResponse | None:
    unknown = sorted(set(fields) - allowed)
    if unknown:
        return JSONResponse({"detail": f"unknown field: {unknown[0][:40]}"}, status_code=422)
    return None


def _invalid(error: SettingInputError) -> JSONResponse:
    return JSONResponse({"detail": str(error), "field": error.field}, status_code=422)


def _conflict(error: SettingConflictError) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=409)


def _saved(notice: str) -> RedirectResponse:
    return RedirectResponse(redirect_target(notice), status_code=303)


async def _refused_page(
    request: Request,
    admin: Principal,
    failure: Failure,
    status: int,
    values: dict[str, str] | None = None,
) -> Response:
    return await render_settings(request, admin, status=status, failure=failure, values=values)


@router.get("/settings")
async def show_settings(request: Request, admin: Admin, service: Service) -> Response:
    """The settings, the users and the About data; a browser gets the settings page."""
    if wants_html(request):
        return await render_settings(request, admin)
    view = await run_in_threadpool(service.overview)
    return JSONResponse(_body(view))


async def _set_number(
    request: Request,
    admin: Principal,
    *,
    form: str,
    title: str,
    field_name: str,
    notice: str,
    store: Callable[[str | None], int],
) -> Response:
    """The retention and the storage warning: one number, its rule, the same answers."""
    html = wants_html(request)
    fields = await read_fields(request, structured=True)
    refused = _unknown_field(fields, frozenset({field_name, _CSRF_FIELD}))
    if refused is not None:
        if html:
            return await _refused_page(request, admin, unknown_field_failure(form, title), 422)
        return refused
    try:
        number = await run_in_threadpool(store, fields.get(field_name))
    except SettingInputError as error:
        if html:
            failure = field_failure(form, title, error.field, str(error))
            return await _refused_page(request, admin, failure, 422)
        return _invalid(error)
    if html:
        return _saved(notice)
    return JSONResponse({field_name: number})


@router.post("/settings/retention")
async def set_retention(request: Request, admin: Admin, service: Service) -> Response:
    """Set the retention window in days (30 to 365); the nightly job reads it."""

    def store(raw: str | None) -> int:
        return service.set_retention_days(raw, actor=admin.username)

    return await _set_number(
        request,
        admin,
        form="retention",
        title="Retention was not saved",
        field_name=FIELD_RETENTION,
        notice="retention-saved",
        store=store,
    )


@router.post("/settings/storage-warning")
async def set_storage_warning(request: Request, admin: Admin, service: Service) -> Response:
    """Set the storage warning size in gigabytes (1 to 1000); the start page card reads it."""

    def store(raw: str | None) -> int:
        return service.set_storage_warning_gb(raw, actor=admin.username)

    return await _set_number(
        request,
        admin,
        form="storage",
        title="The storage warning was not saved",
        field_name=FIELD_STORAGE,
        notice="storage-saved",
        store=store,
    )


@router.post("/settings/users")
async def add_user(request: Request, admin: Admin, service: Service) -> Response:
    """Add a user. The answer holds the user as listed; the password is never returned."""
    html = wants_html(request)
    title = "The user was not added"
    fields = await read_fields(request, structured=True)
    # what a refused page fills back in: never the password
    kept = {key: fields.get(key, "") for key in ("username", "role")}
    refused = _unknown_field(fields, _USER_FIELDS)
    if refused is not None:
        if html:
            failure = unknown_field_failure("user", title)
            return await _refused_page(request, admin, failure, 422, kept)
        return refused
    try:
        created = await run_in_threadpool(
            service.add_user,
            fields.get("username", ""),
            fields.get("password", ""),
            fields.get("role", ""),
            actor=admin.username,
        )
    except SettingInputError as error:
        if html:
            failure = field_failure("user", title, error.field, str(error))
            return await _refused_page(request, admin, failure, 422, kept)
        return _invalid(error)
    except SettingConflictError as error:
        if html:
            failure = field_failure("user", title, "username", str(error))
            return await _refused_page(request, admin, failure, 409, kept)
        return _conflict(error)
    if html:
        return _saved("user-added")
    return JSONResponse({"user": _user(created)}, status_code=201)


async def _set_disabled(
    request: Request, user_id: int, admin: Principal, service: SettingsService, *, disabled: bool
) -> Response:
    try:
        found = await run_in_threadpool(
            service.set_user_disabled,
            user_id,
            disabled=disabled,
            actor_id=admin.user_id,
            actor=admin.username,
        )
    except SettingConflictError as error:
        if wants_html(request):
            title = "The user was not disabled" if disabled else "The user was not enabled"
            text = str(error)
            failure = Failure("users", title, text[:1].upper() + text[1:] + ".")
            return await _refused_page(request, admin, failure, 409)
        return _conflict(error)
    if not found:
        raise HTTPException(status_code=404, detail="no such user")
    if wants_html(request):
        return _saved("user-disabled" if disabled else "user-enabled")
    return JSONResponse({"id": user_id, "disabled": disabled})


@router.post("/settings/users/{user_id}/disable")
async def disable_user(
    request: Request,
    user_id: Annotated[int, Path(ge=1, le=_MAX_USER_ID)],
    admin: Admin,
    service: Service,
) -> Response:
    """Disable a user and end their sessions; not yourself, not the last enabled admin."""
    return await _set_disabled(request, user_id, admin, service, disabled=True)


@router.post("/settings/users/{user_id}/enable")
async def enable_user(
    request: Request,
    user_id: Annotated[int, Path(ge=1, le=_MAX_USER_ID)],
    admin: Admin,
    service: Service,
) -> Response:
    """Enable a disabled user again."""
    return await _set_disabled(request, user_id, admin, service, disabled=False)
