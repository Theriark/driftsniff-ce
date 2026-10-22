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


COMMIT = "0123456789abcdef0123456789abcdef01234567"


def test_healthz_reports_the_build_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DRIFTSNIFF_COMMIT", COMMIT)
    response = make_client().get("/healthz")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert set(body) == {"status", "version", "commit"}
    assert body == {"status": "ok", "version": __version__, "commit": COMMIT}


def test_healthz_commit_is_unknown_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DRIFTSNIFF_COMMIT", raising=False)
    response = make_client().get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__, "commit": "unknown"}


@pytest.mark.parametrize("value", ["", "   ", "has space", "semi;colon", "x" * 65, "unknown"])
def test_healthz_commit_is_unknown_when_blank_or_malformed(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_COMMIT", value)
    assert make_client().get("/healthz").json()["commit"] == "unknown"


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_scaffold_exposes_nothing_besides_healthz(path: str) -> None:
    assert make_client().get(path).status_code == 404


def test_the_start_page_needs_the_sign_in_service() -> None:
    # P10-T3: "/" is the dashboard; without a sign-in service it answers 503 like every page.
    assert make_client().get("/").status_code == 503
