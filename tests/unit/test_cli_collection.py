"""``driftsniff serve`` gives the application the collection side (P10, THE-978).

``tests/contract/test_collection_wiring.py`` runs the wired pieces against fake controllers; this
file only checks that ``serve`` builds and passes them.
"""

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI

from driftsniff.cli import main
from driftsniff.secrets.redact import RedactingFilter
from driftsniff.sources.scheduler import Scheduler
from driftsniff.web.routes_push import PushGateway


@pytest.fixture(autouse=True)
def clean_root_log_filters() -> Iterator[None]:
    """serve installs the log filter on the root handlers; do not leave it for other tests."""
    yield
    for handler in logging.getLogger().handlers:
        for item in list(handler.filters):
            if isinstance(item, RedactingFilter):
                handler.removeFilter(item)


def test_serve_wires_the_collection_side(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    apps: list[FastAPI] = []

    def fake_run(app: FastAPI, **kwargs: object) -> None:
        apps.append(app)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    assert main(["serve"]) == 0
    (app,) = apps
    # The scheduler (run now, scheduled runs), the probe factory (test connection) and the push
    # gateway exist, and the run pipeline tells the notification service about a change event.
    assert isinstance(app.state.scheduler, Scheduler)
    assert app.state.sources.probe_factory is not None
    gateway = app.state.push_gateway
    assert isinstance(gateway, PushGateway)
    assert gateway.service is app.state.sources.service
    assert gateway.pipeline._notifier == app.state.notifications.notify_event
