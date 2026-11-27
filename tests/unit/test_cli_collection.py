"""``driftsniff serve`` gives the application the collection side.

``tests/contract/test_collection_wiring.py`` runs the wired pieces against fake controllers; this
file only checks that ``serve`` builds and passes them.
"""

import logging
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI

from driftsniff.cli import main
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.secrets.keys import MasterKey
from driftsniff.secrets.redact import RedactingFilter
from driftsniff.secrets.rekey import MODE_OLD_KEY, begin_rekey
from driftsniff.sources.runs import RunPipeline
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


OLD_MATERIAL = bytes([4]) * 32
NEW_MATERIAL = bytes([5]) * 32


def rekey_in_progress(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, new_key_id: str | None = None
) -> Path:
    """A migrated database with an active rekey from OLD to NEW; returns the old key file."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database = Database(database_path(data_dir))
    try:
        upgrade_to_head(database)
        with database.write() as connection:
            begin_rekey(
                connection,
                old_key_id=MasterKey(OLD_MATERIAL).key_id,
                new_key_id=new_key_id or MasterKey(NEW_MATERIAL).key_id,
                mode=MODE_OLD_KEY,
                source_ids=(7,),
                at="2026-11-27T10:00:00Z",
            )
    finally:
        database.close()
    paths: dict[str, Path] = {}
    for name, material in (("master.key", NEW_MATERIAL), ("old.key", OLD_MATERIAL)):
        path = tmp_path / "keys" / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(material)
        path.chmod(0o400)
        paths[name] = path
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(paths["master.key"]))
    monkeypatch.delenv("DRIFTSNIFF_OLD_KEY_FILE", raising=False)
    return paths["old.key"]


def serve_pipeline(monkeypatch: pytest.MonkeyPatch) -> RunPipeline:
    apps: list[FastAPI] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: apps.append(app))
    assert main(["serve"]) == 0
    (app,) = apps
    pipeline = app.state.push_gateway.pipeline
    assert isinstance(pipeline, RunPipeline)
    return pipeline


def test_serve_passes_the_old_key_while_a_rekey_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    old_key = rekey_in_progress(monkeypatch, tmp_path)
    monkeypatch.setenv("DRIFTSNIFF_OLD_KEY_FILE", str(old_key))
    old = serve_pipeline(monkeypatch)._old_fingerprinter
    assert old is not None
    assert old.key_id == MasterKey(OLD_MATERIAL).key_id


def test_serve_without_the_old_key_file_still_starts_and_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rekey_in_progress(monkeypatch, tmp_path)
    assert serve_pipeline(monkeypatch)._old_fingerprinter is None
    assert "without a comparison" in capsys.readouterr().err


def test_serve_refuses_an_old_key_file_that_is_not_the_old_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rekey_in_progress(monkeypatch, tmp_path)
    monkeypatch.setenv("DRIFTSNIFF_OLD_KEY_FILE", os.environ["DRIFTSNIFF_KEY_FILE"])
    assert main(["serve"]) == 1
    assert "not the old key" in capsys.readouterr().err


def test_serve_refuses_a_rekey_to_a_key_it_does_not_hold(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rekey_in_progress(monkeypatch, tmp_path, new_key_id="0badc0de")
    assert main(["serve"]) == 1
    assert "DRIFTSNIFF_KEY_FILE holds key" in capsys.readouterr().err


def test_serve_ignores_the_old_key_file_when_no_rekey_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    monkeypatch.setenv("DRIFTSNIFF_OLD_KEY_FILE", str(tmp_path / "missing.key"))
    assert serve_pipeline(monkeypatch)._old_fingerprinter is None
    assert "can be removed" in capsys.readouterr().err
