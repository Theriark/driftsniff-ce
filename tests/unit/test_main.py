"""Tests for the application factory and the /healthz route."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from driftsniff import __version__
from driftsniff.config import Settings
from driftsniff.main import create_app


def make_client() -> TestClient:
    return TestClient(create_app(Settings.from_env({})))


def test_version_is_the_first_development_release() -> None:
    assert __version__ == "0.1.0.dev0"


def test_factory_builds_the_app_with_the_given_settings() -> None:
    settings = Settings.from_env({"DRIFTSNIFF_PORT": "9300"})
    app = create_app(settings)
    assert isinstance(app, FastAPI)
    assert app.title == "driftsniff"
    assert app.version == __version__
    assert app.state.settings is settings


def test_factory_reads_the_environment_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DRIFTSNIFF_PORT", "9400")
    assert create_app().state.settings.port == 9400


def test_healthz_returns_status_and_version_only() -> None:
    response = make_client().get("/healthz")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert set(body) == {"status", "version"}
    assert body == {"status": "ok", "version": __version__}


@pytest.mark.parametrize("path", ["/", "/docs", "/redoc", "/openapi.json"])
def test_scaffold_exposes_nothing_besides_healthz(path: str) -> None:
    assert make_client().get(path).status_code == 404
