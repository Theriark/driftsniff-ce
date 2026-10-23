"""The sources pages (P10-T5, docs/web-interface.md section 10): list, add, edit, test, run, delete.

Roles (P9-T1): a viewer reads the source list and the source page; an operator may also start a
run now; an admin adds, edits, tests, enables, disables and deletes sources and makes the sender
key of a push source. The role check is a dependency of each route, so it runs before anything
else, and the security suite lists every route here in its route table.

Every page works without JavaScript: the forms are plain posts and every answer is a page or a
redirect (post, redirect, get). The test connection button also carries ``hx-post``: with
JavaScript only its result panel is replaced, so the typed credential stays in the form.
Content negotiation is the one of ``driftsniff.web.pages``: a browser gets pages, every other
client gets JSON with the same status codes.

The credential is write-only. It is read from the post, handed to the source service (which
encrypts it) or to the test, and never put into a page, a JSON answer, a redirect or a field
value; the edit form leaves it empty and keeps the stored one unless a new one is typed. The
confirmation text of the TLS mode insecure is not filled back in either: it is typed each time.
The one value shown is the sender key of a push source, once, in the answer of the post that
made it (``source.push_key``); the source page only says whether one exists.

Test connection and run now use interfaces that exist (``driftsniff.sources.probe`` and the
scheduler's ``run_now``) and say plainly when the installation has neither: the collector factory
that builds a collector from a stored source is not built yet, so ``serve`` passes no probe
factory and no scheduler.
"""

import dataclasses
from dataclasses import dataclass, field
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from driftsniff.collectors.tls import (
    INSECURE_CONFIRMATION,
    MODE_CA_FILE,
    MODE_INSECURE,
    MODE_PINNED,
    MODE_VERIFY,
    MODES,
    OPTION_INSECURE,
    OPTION_TLS_CA_FILE,
    OPTION_TLS_MODE,
    OPTION_TLS_PIN,
)
from driftsniff.db.tables import SOURCE_TYPES
from driftsniff.sources.probe import ProbeResult, ProbeTarget, start_probe
from driftsniff.sources.scheduler import RunNowStatus, Scheduler
from driftsniff.sources.service import (
    MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    OPTION_ALLOW_PLAIN_HTTP,
    OPTION_CREDENTIAL_EXPIRES_ON,
    OPTION_INTERVAL_SECONDS,
    OPTION_PUSH_FIELDS,
    OPTION_RESOURCES_OFF,
    POLLED_TYPES,
    SourceNameTakenError,
    SourceNotFoundError,
    SourceValidationError,
    SourceView,
    interval_of,
)
from driftsniff.web.auth import ROLE_RANK, Principal
from driftsniff.web.dashboard import resource_label, source_type_label
from driftsniff.web.deps import require_admin, require_operator, require_viewer
from driftsniff.web.pages import page, shell_for, wants_html
from driftsniff.web.routes_ui import read_fields
from driftsniff.web.source_pages import (
    CREDENTIAL_LABELS,
    TLS_MODE_LABELS,
    SourceDetail,
    SourcePages,
    expiry_date,
    probe_rows,
    resources_of,
    resources_off,
)
from driftsniff.web.templating import Shell, render

router = APIRouter()

_MAX_ID: Final = 2**31 - 1
SourceId = Annotated[int, Path(ge=1, le=_MAX_ID)]

# Fields of the add and edit forms. A browser always sends FULL_FORM, so an unticked box or a
# resource left out means off; a JSON client that omits a field keeps the stored value.
FULL_FORM: Final = "full_form"
RESOURCE_FIELD: Final = "resource"
CONFIRM_FIELD: Final = "confirm"
DEFAULT_INTERVAL_MINUTES: Final = 5
_TRUE: Final = frozenset({"on", "true", "1", "yes"})
# The options the forms set; every other stored option is kept as it is.
_MANAGED_OPTIONS: Final = frozenset(
    {
        OPTION_INTERVAL_SECONDS,
        OPTION_ALLOW_PLAIN_HTTP,
        OPTION_TLS_MODE,
        OPTION_TLS_CA_FILE,
        OPTION_TLS_PIN,
        OPTION_INSECURE,
        OPTION_RESOURCES_OFF,
        OPTION_CREDENTIAL_EXPIRES_ON,
        OPTION_PUSH_FIELDS,
    }
)

# The messages a redirect may ask the next page to show; any other word shows nothing.
NOTICES: Final = {
    "created": ("Source added", "Its first check runs within one interval; coverage fills in."),
    "saved": ("Changes saved", "The next check of this source uses them."),
    "enabled": ("Source enabled", "It is checked again on its interval."),
    "disabled": ("Source disabled", "No check runs until you enable it again. History is kept."),
    "run-started": ("Run started", "Its result appears under Recent runs when it ends."),
    "deleted": ("Source deleted", "Its snapshots, change events and coverage were removed."),
}

PROBE_UNAVAILABLE: Final = (
    "Test connection is not available on this installation yet",
    "The collector that the test needs is not installed. Save the source: its first check "
    "fills in the same coverage rows.",
)
RUN_NOT_SCHEDULED: Final = (
    "Runs are not scheduled on this installation yet",
    "The scheduler is not running, so a run cannot start now. Nothing was changed.",
)


def get_source_pages(request: Request) -> SourcePages:
    """The sources pages service; 503 when the application was built without one."""
    pages: SourcePages | None = request.app.state.sources
    if pages is None:
        raise HTTPException(status_code=503, detail="sources are not available")
    return pages


Pages = Annotated[SourcePages, Depends(get_source_pages)]


def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def _sentence(message: str) -> str:
    text = message[:1].upper() + message[1:]
    return text if text.endswith(".") else text + "."


def _view_json(view: SourceView) -> dict[str, Any]:
    """A source as JSON: the service view, which has no credential, only ``has_credential``."""
    return dataclasses.asdict(view)


def _roles(user: Principal) -> dict[str, bool]:
    return {
        "can_operate": ROLE_RANK[user.role] >= ROLE_RANK["operator"],
        "can_admin": ROLE_RANK[user.role] >= ROLE_RANK["admin"],
    }


def _notice(request: Request) -> tuple[str, str] | None:
    return NOTICES.get(request.query_params.get("notice", ""))


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _form_errors(errors: dict[str, str]) -> JSONResponse:
    return JSONResponse({"detail": "the form has errors", "fields": errors}, status_code=422)


async def _find(pages: SourcePages, source_id: int) -> SourceView:
    try:
        return await run_in_threadpool(pages.service.get, source_id)
    except SourceNotFoundError as error:
        raise HTTPException(status_code=404, detail="there is no such source") from error


# ---- the forms ------------------------------------------------------------------------------


@dataclass
class FormValues:
    """What the add or edit form shows again. Never the credential or the confirmation text."""

    source_type: str
    name: str = ""
    base_url: str = ""
    interval_minutes: str = str(DEFAULT_INTERVAL_MINUTES)
    allow_plain_http: bool = False
    tls_mode: str = MODE_VERIFY
    tls_ca_file: str = ""
    tls_pin: str = ""
    credential_expires_on: str = ""
    push_fields: str = ""
    resources_on: frozenset[str] | None = None

    @classmethod
    def of_view(cls, view: SourceView) -> "FormValues":
        options = view.options
        expires = expiry_date(options)
        declared = options.get(OPTION_PUSH_FIELDS)
        lines: list[str] = []
        if isinstance(declared, dict):
            lines = [f"{name}: {', '.join(map(str, names))}" for name, names in declared.items()]
        every = resources_of(view.type, options)
        return cls(
            source_type=view.type,
            name=view.name,
            base_url=view.base_url or "",
            interval_minutes=str(max(1, round(interval_of(options) / 60))),
            allow_plain_http=options.get(OPTION_ALLOW_PLAIN_HTTP) is True,
            tls_mode=str(options.get(OPTION_TLS_MODE, MODE_VERIFY)),
            tls_ca_file=str(options.get(OPTION_TLS_CA_FILE, "")),
            tls_pin=str(options.get(OPTION_TLS_PIN, "")),
            credential_expires_on="" if expires is None else expires.isoformat(),
            push_fields="\n".join(lines),
            resources_on=frozenset(every) - resources_off(options),
        )


@dataclass
class ParsedForm:
    """A posted form: the values to show again, the service arguments and the field errors."""

    values: FormValues
    credential: str | None = field(default=None, repr=False)
    tls_confirmation: str | None = field(default=None, repr=False)
    name: str | None = None
    base_url: str | None = None
    options: dict[str, object] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def _text(fields: dict[str, str], name: str) -> str | None:
    value = fields.get(name)
    return None if value is None else value.strip()


def _parse_push_fields(text: str) -> dict[str, list[str]] | str:
    """``resource: field, field`` per line; the error sentence when a line is not that."""
    declared: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        resource, colon, names = line.partition(":")
        listed = [name.strip() for name in names.split(",") if name.strip()]
        if not colon or not resource.strip() or not listed:
            return "Write each line as a resource, a colon and its fields: networks: _id, name."
        if resource.strip() in declared:
            return f"The resource {resource.strip()[:40]} is declared twice."
        declared[resource.strip()] = listed
    if not declared:
        return "Declare at least one resource and the fields the sender may send."
    return declared


def _parse_interval(parsed: ParsedForm, raw: str | None, current: SourceView | None) -> None:
    if raw is None:
        if current is not None and OPTION_INTERVAL_SECONDS in current.options:
            parsed.options[OPTION_INTERVAL_SECONDS] = interval_of(current.options)
        return
    parsed.values.interval_minutes = raw
    low, high = MIN_INTERVAL_SECONDS // 60, MAX_INTERVAL_SECONDS // 60
    if not raw.isdigit() or not low <= int(raw) <= high:
        parsed.errors["interval_minutes"] = f"Enter a whole number of minutes from {low} to {high}."
        return
    parsed.options[OPTION_INTERVAL_SECONDS] = int(raw) * 60


def _parse_tls(
    parsed: ParsedForm, fields: dict[str, str], current: SourceView | None, full: bool
) -> None:
    options = parsed.options
    values = parsed.values
    mode = _text(fields, OPTION_TLS_MODE)
    if mode is None and not full and current is not None:
        for key in (OPTION_TLS_MODE, OPTION_TLS_CA_FILE, OPTION_TLS_PIN):
            if key in current.options:
                options[key] = current.options[key]
        return
    mode = mode or MODE_VERIFY
    values.tls_mode = mode
    values.tls_ca_file = _text(fields, OPTION_TLS_CA_FILE) or ""
    values.tls_pin = _text(fields, OPTION_TLS_PIN) or ""
    if mode not in MODES:
        parsed.errors[OPTION_TLS_MODE] = "Choose one of the four TLS modes."
        return
    if mode != MODE_VERIFY:
        options[OPTION_TLS_MODE] = mode
    if mode == MODE_CA_FILE:
        if not values.tls_ca_file:
            parsed.errors[OPTION_TLS_CA_FILE] = "Enter the file name of the CA bundle."
        options[OPTION_TLS_CA_FILE] = values.tls_ca_file
    elif mode == MODE_PINNED:
        if not values.tls_pin:
            parsed.errors[OPTION_TLS_PIN] = "Enter the SHA-256 of the certificate."
        options[OPTION_TLS_PIN] = values.tls_pin
    elif mode == MODE_INSECURE:
        already = current is not None and current.options.get(OPTION_TLS_MODE) == MODE_INSECURE
        confirmation = fields.get("tls_confirmation", "")
        parsed.tls_confirmation = confirmation
        if not already and confirmation.strip() != INSECURE_CONFIRMATION:
            parsed.errors["tls_confirmation"] = (
                f"Type {INSECURE_CONFIRMATION} to switch certificate checks off."
            )


def _parse_resources(
    parsed: ParsedForm, fields: dict[str, str], current: SourceView | None, full: bool
) -> None:
    source_type = parsed.values.source_type
    every = resources_of(source_type, {})
    if not full:
        if current is not None and OPTION_RESOURCES_OFF in current.options:
            parsed.options[OPTION_RESOURCES_OFF] = current.options[OPTION_RESOURCES_OFF]
        return
    raw = fields.get(RESOURCE_FIELD, "")
    chosen = frozenset(name.strip() for name in raw.split(",") if name.strip())
    parsed.values.resources_on = chosen & frozenset(every)
    if chosen - frozenset(every):
        parsed.errors["resources"] = "One of the resources is not one this type reads."
        return
    if not chosen:
        parsed.errors["resources"] = "Turn on at least one resource."
        return
    off = [name for name in every if name not in chosen]
    if off:
        parsed.options[OPTION_RESOURCES_OFF] = off


def _parse_expiry(parsed: ParsedForm, fields: dict[str, str], current: SourceView | None) -> None:
    key = OPTION_CREDENTIAL_EXPIRES_ON
    raw = _text(fields, key)
    if raw is None:
        if current is not None and key in current.options:
            parsed.options[key] = current.options[key]
        return
    parsed.values.credential_expires_on = raw
    if not raw:
        return
    if expiry_date({key: raw}) is None or len(raw) != 10:
        parsed.errors[key] = "Enter the date as YYYY-MM-DD."
        return
    parsed.options[key] = raw


def parse_form(
    fields: dict[str, str], source_type: str, current: SourceView | None = None
) -> ParsedForm:
    """Read an add form (``current`` None) or the edit form of ``current``."""
    full = fields.get(FULL_FORM) is not None
    parsed = ParsedForm(FormValues(source_type))
    values = parsed.values
    if current is not None:
        kept = {k: v for k, v in current.options.items() if k not in _MANAGED_OPTIONS}
        parsed.options.update(kept)
    name = _text(fields, "name")
    if name is not None:
        values.name = name
        parsed.name = name
        if not name:
            parsed.errors["name"] = "Give the source a name."
    elif current is None:
        parsed.errors["name"] = "Give the source a name."
    else:
        values.name = current.name
    if source_type in POLLED_TYPES:
        _parse_polled(parsed, fields, current, full)
    else:
        raw = fields.get(OPTION_PUSH_FIELDS)
        if raw is None and current is not None:
            if OPTION_PUSH_FIELDS in current.options:
                parsed.options[OPTION_PUSH_FIELDS] = current.options[OPTION_PUSH_FIELDS]
        else:
            values.push_fields = raw or ""
            declared = _parse_push_fields(values.push_fields)
            if isinstance(declared, str):
                parsed.errors[OPTION_PUSH_FIELDS] = declared
            else:
                parsed.options[OPTION_PUSH_FIELDS] = declared
    return parsed


def _parse_polled(
    parsed: ParsedForm, fields: dict[str, str], current: SourceView | None, full: bool
) -> None:
    values = parsed.values
    base_url = _text(fields, "base_url")
    if base_url:
        values.base_url = base_url
        parsed.base_url = base_url
    elif current is None:
        parsed.errors["base_url"] = "Enter the address of the controller, starting with https://."
    else:
        values.base_url = current.base_url or ""
    credential = fields.get("credential", "")
    if credential.strip():
        parsed.credential = credential
    elif current is None:
        label = CREDENTIAL_LABELS[values.source_type]
        parsed.errors["credential"] = f"Enter the {label}. It is stored encrypted."
    _parse_interval(parsed, _text(fields, "interval_minutes"), current)
    plain = fields.get(OPTION_ALLOW_PLAIN_HTTP)
    if plain is None and not full:
        if current is not None and current.options.get(OPTION_ALLOW_PLAIN_HTTP) is True:
            parsed.options[OPTION_ALLOW_PLAIN_HTTP] = True
    elif plain is not None and plain.strip().lower() in _TRUE:
        values.allow_plain_http = True
        parsed.options[OPTION_ALLOW_PLAIN_HTTP] = True
    _parse_tls(parsed, fields, current, full)
    _parse_resources(parsed, fields, current, full)
    if values.source_type == "xo":
        _parse_expiry(parsed, fields, current)


def _resource_choices(values: FormValues) -> list[dict[str, Any]]:
    on = values.resources_on
    return [
        {"name": name, "label": resource_label(name), "checked": on is None or name in on}
        for name in resources_of(values.source_type, {})
    ]


def _form_page(
    request: Request,
    user: Principal,
    pages: SourcePages,
    values: FormValues,
    *,
    source: SourceView | None = None,
    errors: dict[str, str] | None = None,
    form_error: str = "",
    probe: ProbeResult | None = None,
    probe_unavailable: bool = False,
    status: int = 200,
) -> Response:
    editing = source is not None
    title = f"Edit {source.name}" if source is not None else "Add a source"
    shell = shell_for(request, user, title, "sources")
    return page(
        "sources/form.html",
        shell,
        status=status,
        editing=editing,
        source=source,
        values=values,
        errors=errors or {},
        form_error=form_error,
        source_types=[(kind, source_type_label(kind)) for kind in SOURCE_TYPES],
        resources=_resource_choices(values),
        tls_modes=[(mode, TLS_MODE_LABELS[mode]) for mode in MODES],
        credential_label=CREDENTIAL_LABELS.get(values.source_type, ""),
        insecure_now=source is not None and source.options.get(OPTION_TLS_MODE) == MODE_INSECURE,
        confirmation_text=INSECURE_CONFIRMATION,
        probe=probe,
        probe_rows=probe_rows(values.source_type, probe),
        probe_unavailable=probe_unavailable,
        probe_available=pages.probe_factory is not None,
        problems=[],
        unavailable_text=PROBE_UNAVAILABLE,
        now=pages.now(),
        test_action=f"/sources/{source.id}/test" if source is not None else "/sources/test",
    )


def _type_of(raw: str | None) -> str:
    """The source type a form names; UniFi Network for none or an unknown one."""
    return raw if raw is not None and raw in SOURCE_TYPES else "unifi"


# ---- the list and the source page ------------------------------------------------------------


@router.get("/sources")
async def list_sources(
    request: Request, user: Annotated[Principal, Depends(require_viewer)], pages: Pages
) -> Response:
    """Every source with its status, flags, last check, version and drift line."""
    if not wants_html(request):
        views = await run_in_threadpool(pages.service.list_sources)
        return JSONResponse({"sources": [_view_json(view) for view in views]})
    listing = await run_in_threadpool(pages.listing)
    shell = shell_for(request, user, "Sources", "sources")
    roles = _roles(user)
    return page(
        "sources/list.html",
        shell,
        listing=listing,
        notice=_notice(request),
        can_operate=roles["can_operate"],
        can_admin=roles["can_admin"],
    )


@router.get("/sources/new")
async def new_source(
    request: Request, user: Annotated[Principal, Depends(require_admin)], pages: Pages
) -> Response:
    """The add form of the type in ``?type=`` (UniFi Network when none or an unknown one)."""
    values = FormValues(_type_of(request.query_params.get("type")))
    return _form_page(request, user, pages, values)


@router.post("/sources/new")
async def create_source(
    request: Request, user: Annotated[Principal, Depends(require_admin)], pages: Pages
) -> Response:
    """Add a source from the form; the credential is encrypted by the service."""
    fields = await read_fields(request, structured=True, multi=frozenset({RESOURCE_FIELD}))
    source_type = fields.get("type", "")
    html = wants_html(request)
    if source_type not in SOURCE_TYPES:
        if html:
            values = FormValues("unifi")
            errors = {"type": "Choose UniFi Network, Xen Orchestra or a push source."}
            return _form_page(request, user, pages, values, errors=errors, status=422)
        return JSONResponse({"detail": "type must be unifi, xo or push"}, status_code=422)
    parsed = parse_form(fields, source_type)
    if parsed.errors:
        if html:
            return _form_page(request, user, pages, parsed.values, errors=parsed.errors, status=422)
        return _form_errors(parsed.errors)
    try:
        view = await run_in_threadpool(
            pages.service.create,
            name=parsed.name or "",
            source_type=source_type,
            actor=user.username,
            base_url=parsed.base_url,
            credential=parsed.credential,
            options=parsed.options,
            tls_confirmation=parsed.tls_confirmation,
        )
    except SourceNameTakenError:
        return _refused(request, user, pages, parsed, 409, name_taken=True)
    except SourceValidationError as error:
        return _refused(request, user, pages, parsed, 422, message=str(error))
    await _sync(request)
    if html:
        return _redirect(f"/sources/{view.id}?notice=created")
    return JSONResponse({"source": _view_json(view)}, status_code=201)


def _refused(
    request: Request,
    user: Principal,
    pages: SourcePages,
    parsed: ParsedForm,
    status: int,
    *,
    source: SourceView | None = None,
    name_taken: bool = False,
    message: str = "",
) -> Response:
    """The form again after the service refused it, or the JSON refusal."""
    if not wants_html(request):
        detail = "another source already has that name" if name_taken else message
        return JSONResponse({"detail": detail}, status_code=status)
    errors = dict(parsed.errors)
    form_error = ""
    if name_taken:
        errors["name"] = "Another source already has this name."
    else:
        form_error = _sentence(message)
    return _form_page(
        request,
        user,
        pages,
        parsed.values,
        source=source,
        errors=errors,
        form_error=form_error,
        status=status,
    )


@router.post("/sources/test")
async def test_new_source(
    request: Request, user: Annotated[Principal, Depends(require_admin)], pages: Pages
) -> Response:
    """Test the connection of an add form: version and coverage rows, nothing stored."""
    fields = await read_fields(request, structured=True, multi=frozenset({RESOURCE_FIELD}))
    source_type = _type_of(fields.get("type"))
    parsed = parse_form(fields, source_type)
    return await _test(request, user, pages, parsed, None)


async def _test(
    request: Request,
    user: Principal,
    pages: SourcePages,
    parsed: ParsedForm,
    source: SourceView | None,
) -> Response:
    """Run the read-only probe for a form and show its result (or why it could not run)."""
    html = wants_html(request) or _is_htmx(request)
    values = parsed.values
    needed = ("base_url", "credential", OPTION_TLS_MODE, OPTION_TLS_CA_FILE, OPTION_TLS_PIN)
    blocking = {key: text for key, text in parsed.errors.items() if key in needed}
    if values.source_type not in POLLED_TYPES:
        blocking = {"type": "A push source is not read by driftsniff, so there is nothing to test."}
    if blocking:
        if _is_htmx(request):
            return _probe_panel(pages, values, None, problems=list(blocking.values()))
        if html:
            return _form_page(
                request, user, pages, values, source=source, errors=parsed.errors, status=422
            )
        return _form_errors(blocking)
    factory = pages.probe_factory
    if factory is None:
        if _is_htmx(request):
            return _probe_panel(pages, values, None, unavailable=True)
        if html:
            return _form_page(
                request, user, pages, values, source=source, probe_unavailable=True, status=503
            )
        return JSONResponse({"detail": PROBE_UNAVAILABLE[0]}, status_code=503)
    credential = parsed.credential.encode("utf-8") if parsed.credential else None
    if credential is None and source is not None:
        credential = await run_in_threadpool(pages.service.credential_for_collector, source.id)
    target = ProbeTarget(
        source_type=values.source_type,
        base_url=parsed.base_url or values.base_url,
        credential=credential or b"",
        options=parsed.options,
    )
    result = await run_in_threadpool(start_probe, factory, target)
    if _is_htmx(request):
        return _probe_panel(pages, values, result)
    if html:
        return _form_page(
            request, user, pages, values, source=source, errors=parsed.errors, probe=result
        )
    return JSONResponse({"probe": dataclasses.asdict(result)})


def _probe_panel(
    pages: SourcePages,
    values: FormValues,
    result: ProbeResult | None,
    *,
    problems: list[str] | None = None,
    unavailable: bool = False,
) -> Response:
    """The result panel alone, for the HTMX swap (always 200, or HTMX would not swap it)."""
    body = render(
        "sources/_probe.html",
        Shell(title=""),
        probe=result,
        probe_rows=probe_rows(values.source_type, result),
        problems=problems or [],
        probe_unavailable=unavailable,
        unavailable_text=PROBE_UNAVAILABLE,
        now=pages.now(),
    )
    return HTMLResponse(body)


@router.get("/sources/{source_id}")
async def source_page(
    request: Request,
    user: Annotated[Principal, Depends(require_viewer)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """The source page: status, drift line, coverage panel, recent runs and the actions."""
    detail = await _detail(pages, source_id)
    if not wants_html(request):
        return JSONResponse({"source": _view_json(detail.view)})
    return _detail_page(request, user, detail, notice=_notice(request))


async def _detail(pages: SourcePages, source_id: int) -> SourceDetail:
    try:
        return await run_in_threadpool(pages.detail, source_id)
    except SourceNotFoundError as error:
        raise HTTPException(status_code=404, detail="there is no such source") from error


def _detail_page(
    request: Request,
    user: Principal,
    detail: SourceDetail,
    *,
    notice: tuple[str, str] | None = None,
    problem: tuple[str, str] | None = None,
    delete_error: str = "",
    push_key: str = "",
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    shell = shell_for(request, user, detail.view.name, "sources")
    return page(
        "sources/detail.html",
        shell,
        status=status,
        headers=headers,
        detail=detail,
        notice=notice,
        problem=problem,
        delete_error=delete_error,
        push_key=push_key,
        **_roles(user),
    )


# ---- edit ------------------------------------------------------------------------------------


@router.get("/sources/{source_id}/edit")
async def edit_source(
    request: Request,
    user: Annotated[Principal, Depends(require_admin)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """The edit form; the credential field is empty and keeps the stored one when left so."""
    view = await _find(pages, source_id)
    return _form_page(request, user, pages, FormValues.of_view(view), source=view)


@router.post("/sources/{source_id}/edit")
async def update_source(
    request: Request,
    user: Annotated[Principal, Depends(require_admin)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """Save the edit form. A field a JSON client leaves out keeps its stored value."""
    view = await _find(pages, source_id)
    fields = await read_fields(request, structured=True, multi=frozenset({RESOURCE_FIELD}))
    parsed = parse_form(fields, view.type, view)
    html = wants_html(request)
    if parsed.errors:
        if html:
            return _form_page(
                request, user, pages, parsed.values, source=view, errors=parsed.errors, status=422
            )
        return _form_errors(parsed.errors)
    try:
        updated = await run_in_threadpool(
            pages.service.update,
            source_id,
            actor=user.username,
            name=parsed.name,
            base_url=parsed.base_url,
            credential=parsed.credential,
            options=parsed.options,
            tls_confirmation=parsed.tls_confirmation,
        )
    except SourceNotFoundError as error:
        raise HTTPException(status_code=404, detail="there is no such source") from error
    except SourceNameTakenError:
        return _refused(request, user, pages, parsed, 409, source=view, name_taken=True)
    except SourceValidationError as error:
        return _refused(request, user, pages, parsed, 422, source=view, message=str(error))
    await _sync(request)
    if html:
        return _redirect(f"/sources/{updated.id}?notice=saved")
    return JSONResponse({"source": _view_json(updated)})


@router.post("/sources/{source_id}/test")
async def test_source(
    request: Request,
    user: Annotated[Principal, Depends(require_admin)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """Test the edit form; an empty credential field tests with the stored credential."""
    view = await _find(pages, source_id)
    fields = await read_fields(request, structured=True, multi=frozenset({RESOURCE_FIELD}))
    return await _test(request, user, pages, parse_form(fields, view.type, view), view)


# ---- run now, enable, disable, delete, sender key ------------------------------------------


async def _sync(request: Request) -> None:
    """Let the scheduler pick up a created, changed, enabled, disabled or deleted source."""
    scheduler: Scheduler | None = request.app.state.scheduler
    if scheduler is not None:
        await scheduler.sync()


_RUN_REFUSALS: Final = {
    RunNowStatus.ALREADY_RUNNING: (
        409,
        "A run of this source is going on now",
        "Its result appears under Recent runs when it ends.",
    ),
    RunNowStatus.NOT_SCHEDULED: (
        409,
        "This source is not scheduled yet",
        "The scheduler picks a source up after it is saved or enabled. Try again in a minute.",
    ),
}


@router.post("/sources/{source_id}/run")
async def run_source_now(
    request: Request,
    user: Annotated[Principal, Depends(require_operator)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """Start a run at once; refused within 30 seconds of the last one, with the wait named."""
    detail = await _detail(pages, source_id)
    html = wants_html(request)
    problem: tuple[int, str, str]
    headers: dict[str, str] | None = None
    scheduler: Scheduler | None = request.app.state.scheduler
    if detail.view.type not in POLLED_TYPES:
        problem = (409, "A push source is not run", "Its sender pushes; there is nothing to run.")
    elif not detail.view.enabled:
        problem = (409, "This source is disabled", "Enable it first, then run it.")
    elif scheduler is None:
        problem = (503, RUN_NOT_SCHEDULED[0], RUN_NOT_SCHEDULED[1])
    else:
        result = scheduler.run_now(source_id)
        if result.status is RunNowStatus.STARTED:
            if html:
                return _redirect(f"/sources/{source_id}?notice=run-started")
            return JSONResponse({"status": result.status.value}, status_code=202)
        if result.status is RunNowStatus.TOO_SOON:
            wait = max(1, int(result.retry_after_seconds + 0.999))
            unit = "second" if wait == 1 else "seconds"
            problem = (
                429,
                "A run was started less than 30 seconds ago",
                f"Wait {wait} {unit}, then run this source again. Nothing was changed.",
            )
            headers = {"Retry-After": str(wait)}
        else:
            problem = _RUN_REFUSALS[result.status]
    status, title, text = problem
    if html:
        return _detail_page(
            request, user, detail, problem=(title, text), status=status, headers=headers
        )
    return JSONResponse({"detail": f"{title}. {text}"}, status_code=status, headers=headers)


async def _set_enabled(
    request: Request, user: Principal, pages: SourcePages, source_id: int, enabled: bool
) -> Response:
    await _find(pages, source_id)
    try:
        view = await run_in_threadpool(
            pages.service.set_enabled, source_id, enabled, actor=user.username
        )
    except SourceNotFoundError as error:
        raise HTTPException(status_code=404, detail="there is no such source") from error
    await _sync(request)
    if wants_html(request):
        return _redirect(f"/sources/{source_id}?notice={'enabled' if enabled else 'disabled'}")
    return JSONResponse({"source": _view_json(view)})


@router.post("/sources/{source_id}/enable")
async def enable_source(
    request: Request,
    user: Annotated[Principal, Depends(require_admin)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """Enable a source; the scheduler checks it again on its interval."""
    return await _set_enabled(request, user, pages, source_id, True)


@router.post("/sources/{source_id}/disable")
async def disable_source(
    request: Request,
    user: Annotated[Principal, Depends(require_admin)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """Disable a source; no check runs until it is enabled again, history is kept."""
    return await _set_enabled(request, user, pages, source_id, False)


@router.post("/sources/{source_id}/delete")
async def delete_source(
    request: Request,
    user: Annotated[Principal, Depends(require_admin)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """Delete a source and everything recorded for it; the name must be typed to confirm."""
    view = await _find(pages, source_id)
    fields = await read_fields(request)
    typed = fields.get(CONFIRM_FIELD, "").strip()
    if typed != view.name:
        message = "Type the name of the source exactly as it is shown to delete it."
        if wants_html(request):
            detail = await _detail(pages, source_id)
            return _detail_page(request, user, detail, delete_error=message, status=422)
        return JSONResponse({"detail": message}, status_code=422)
    try:
        result = await run_in_threadpool(pages.service.delete, source_id, actor=user.username)
    except SourceNotFoundError as error:
        raise HTTPException(status_code=404, detail="there is no such source") from error
    await _sync(request)
    if wants_html(request):
        return _redirect("/sources?notice=deleted")
    return JSONResponse({"deleted": True, "removed_states": result.removed_states})


@router.post("/sources/{source_id}/push-key")
async def make_push_key(
    request: Request,
    user: Annotated[Principal, Depends(require_admin)],
    pages: Pages,
    source_id: SourceId,
) -> Response:
    """Make a new sender key for a push source and show it this once; an older key stops."""
    view = await _find(pages, source_id)
    if view.type != "push":
        raise HTTPException(status_code=409, detail="only a push source has a sender key")
    key = await run_in_threadpool(pages.service.set_push_key, source_id, actor=user.username)
    if not wants_html(request):
        return JSONResponse({"push_key": key})
    detail = await _detail(pages, source_id)
    return _detail_page(request, user, detail, push_key=key)
