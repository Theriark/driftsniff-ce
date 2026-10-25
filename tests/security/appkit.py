"""A complete application for the security suite (P9-T6).

``running_kit`` builds the real application with every service it has (sign-in, API tokens,
notifications, the change API, a push gateway with no sources, the sources pages with a test
connection that refuses every target, the change pages, the history service and the admin
settings), a migrated database, one user per role and one API token per scope set. The tests of
this folder use it to ask the same question of every route: who may do this, and what happens to
everyone else.

Everything is synthetic. The user password and every token are made at test time; text that must
never travel starts with ``CANARY-``.
"""

import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import sqlalchemy as sa
from contract.fake_notify import make_store
from fastapi import FastAPI
from fastapi.testclient import TestClient

from driftsniff.collectors.base import Collector, CollectorError
from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import change_events, change_items, notes, snapshots
from driftsniff.enrich.api import ChangeService
from driftsniff.history.service import HistoryService
from driftsniff.main import create_app
from driftsniff.notify.deliveries import NotificationService
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.probe import ProbeTarget
from driftsniff.sources.service import SourceService
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.bearer import TokenService
from driftsniff.web.change_pages import ChangePages
from driftsniff.web.replay import ReplayService
from driftsniff.web.routes_push import PushGateway
from driftsniff.web.settings_service import SettingsService
from driftsniff.web.source_pages import SourcePages

ORIGIN = "http://testserver"
MASTER = MasterKey(bytes(range(32)))
CORRECT = "CANARY-correct horse battery"
ROLES = ("viewer", "operator", "admin")
TOKEN_KINDS = {"read": ["read"], "enrich": ["enrich"], "both": ["read", "enrich"]}
A_TOKEN_THAT_IS_NOT_ONE = "x" * 43
STAMP = "2026-10-22T08:00:00Z"


@dataclass(frozen=True, slots=True)
class Session:
    """A signed-in session: the cookie value and the CSRF value of the session."""

    cookie: str
    csrf: str

    def headers(self, *, csrf: bool = True, origin: str | None = ORIGIN) -> dict[str, str]:
        headers = {"Cookie": f"{SESSION_COOKIE}={self.cookie}"}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        if origin is not None:
            headers["Origin"] = origin
        return headers


class _NoSources:
    """A push gateway service that knows no source: every push key is wrong."""

    def push_target(self, source_id: int) -> None:
        return None


def _no_collector(_target: ProbeTarget) -> Collector:
    """The probe factory of the kit: no target is ever reachable."""
    raise CollectorError("connection", "the controller could not be reached")


class _GatewayStub:
    """What the push route reads from its gateway when no source exists."""

    service = _NoSources()
    pipeline = None


@dataclass
class Kit:
    """The application and the means to act on it as each kind of caller."""

    app: FastAPI
    client: TestClient
    store: Database
    auth: AuthService
    tokens: TokenService
    user_ids: dict[str, int]
    token_values: dict[str, str] = field(default_factory=dict)

    def new_session(self, role: str) -> Session:
        """Sign in as the user of ``role`` and return the session; each call is a new session."""
        response = self.client.post("/login", data={"username": role, "password": CORRECT})
        assert response.status_code == 303, response.text
        match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
        assert match is not None
        self.client.cookies.clear()
        principal = self.auth.authenticate(match.group(1))
        assert principal is not None
        return Session(match.group(1), principal.csrf_token)

    def bearer(self, kind: str) -> dict[str, str]:
        """The Authorization header of the token of ``kind`` (read, enrich or both)."""
        return {"Authorization": f"Bearer {self.token_values[kind]}"}


@contextmanager
def running_kit(folder: Path) -> Iterator[Kit]:
    """The application with all its services; the database is closed when the block ends."""
    store = make_store(folder)
    try:
        auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
        user_ids = {role: auth.create_user(role, CORRECT, role) for role in ROLES}
        tokens = TokenService(store)
        notifications = NotificationService(
            store,
            MASTER,
            base_url=ORIGIN,
            resolver=lambda _host: ["127.0.0.1"],
            sleep=lambda _seconds: None,
        )
        gateway = cast(PushGateway, _GatewayStub())
        app = create_app(
            Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN}),
            master_key=MASTER,
            push_gateway=gateway,
            auth=auth,
            tokens=tokens,
            notifications=notifications,
            changes=ChangeService(store),
            sources=SourcePages(
                store,
                SourceService(store, CredentialCipher.from_master(MASTER)),
                probe_factory=_no_collector,
            ),
            change_pages=ChangePages(store),
            history=HistoryService(store, Fingerprinter.from_master(MASTER)),
            replay=ReplayService(store),
            admin_settings=SettingsService(store, auth),
        )
        with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
            kit = Kit(app, client, store, auth, tokens, user_ids)
            for kind, scopes in TOKEN_KINDS.items():
                created = tokens.create(
                    user_id=user_ids["admin"], actor="admin", name=kind, scopes=scopes
                )
                kit.token_values[kind] = created.value
            yield kit
    finally:
        store.close()


def add_change(
    store: Database, items: tuple[dict[str, Any], ...] = (), *, severity: str = "high"
) -> int:
    """Write a change event of source 1 and its items the way the run pipeline would.

    Each item is a dict of ``change_items`` columns; what it leaves out gets a plain default.
    """
    with store.write() as connection:
        snapshot_id = connection.execute(
            sa.insert(snapshots)
            .values(
                source_id=1,
                taken_at=STAMP,
                manifest_hash="m",
                manifest_zstd=b"x",
                normaliser_version=1,
            )
            .returning(snapshots.c.id)
        ).scalar_one()
        event_id: int = connection.execute(
            sa.insert(change_events)
            .values(
                source_id=1,
                snapshot_id=snapshot_id,
                window_start=STAMP,
                window_end=STAMP,
                max_severity=severity,
                item_count=len(items),
                summary=f"{len(items)} changes",
                rule_pack_version="pack-1",
                status="open",
                created_at=STAMP,
            )
            .returning(change_events.c.id)
        ).scalar_one()
        for item in items:
            row = {
                "event_id": event_id,
                "resource": "networks",
                "change_kind": "changed",
                "path": "name",
                "field_class": "config",
                "severity": "low",
                **item,
            }
            connection.execute(sa.insert(change_items).values(**row))
    return event_id


def add_note(store: Database, event_id: int, user_id: int, body: str) -> None:
    """Write a note of a user on a change event."""
    with store.write() as connection:
        connection.execute(
            sa.insert(notes).values(event_id=event_id, user_id=user_id, body=body, created_at=STAMP)
        )
