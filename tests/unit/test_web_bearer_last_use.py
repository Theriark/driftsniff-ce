"""A failing write of the last-use time does not refuse a valid token (P9-T6, THE-810)."""

import logging

import pytest
import sqlalchemy as sa

from driftsniff.db.engine import Database
from driftsniff.web.auth import AuthService, make_password_hasher
from driftsniff.web.bearer import TokenService


def test_a_failing_last_use_write_does_not_refuse_a_valid_token(
    store: Database, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    user_id = auth.create_user("admin", "CANARY-correct horse battery", "admin")
    service = TokenService(store)
    created = service.create(user_id=user_id, actor="admin", name="t", scopes=["read"])

    def broken() -> None:
        raise sa.exc.OperationalError("UPDATE api_tokens", {}, Exception("database is locked"))

    monkeypatch.setattr(store, "write", broken)
    caplog.set_level(logging.WARNING)
    principal = service.authenticate(f"Bearer {created.value}", "read")
    assert principal.name == "t"
    assert "last use of an API token" in caplog.text
    assert created.value not in caplog.text
    monkeypatch.undo()
    assert service.list_tokens()[0].last_used_at is None
    # Once the database takes writes again the time is stored.
    service.authenticate(f"Bearer {created.value}", "read")
    assert service.list_tokens()[0].last_used_at is not None
