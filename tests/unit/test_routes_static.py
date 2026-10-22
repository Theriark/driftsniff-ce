"""The static file route (P10-T2): the stylesheet, htmx and the brand copies, nothing else."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from driftsniff.config import Settings
from driftsniff.main import create_app
from driftsniff.web.routes_static import STATIC_DIR, resolve_static


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(Settings.from_env({})))


def test_the_stylesheet_is_served_as_css_with_a_short_public_cache(client: TestClient) -> None:
    response = client.get("/static/app.css")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert response.headers["cache-control"] == "public, max-age=600"
    assert "--paper: #F5F5F0;" in response.text
    assert response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_htmx_and_its_licence_are_served(client: TestClient) -> None:
    script = client.get("/static/htmx.min.js")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]
    assert 'version:"2.0.4"' in script.text
    licence = client.get("/static/htmx.min.js.LICENSE.txt")
    assert licence.status_code == 200
    assert "Zero-Clause BSD" in licence.text


@pytest.mark.parametrize(
    "path",
    [
        "/static/missing.css",
        "/static/",
        "/static/../pyproject.toml",
        "/static/..%2F..%2Fpyproject.toml",
        "/static/%2e%2e/templating.py",
        "/static/brand/../../templating.py",
        "/static/app.css/",
        "/static/{path:path}",
    ],
)
def test_anything_outside_the_folder_or_missing_is_404(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 404
    assert "templating" not in response.text and "[project]" not in response.text


def test_resolve_static_refuses_escapes_and_accepts_files() -> None:
    assert resolve_static("app.css") == STATIC_DIR / "app.css"
    assert resolve_static("htmx.min.js.LICENSE.txt") == STATIC_DIR / "htmx.min.js.LICENSE.txt"
    for bad in ("", "../templating.py", "/etc/hostname", "a\\b", "a\x00", "./app.css", "x//y"):
        assert resolve_static(bad) is None, bad
    assert resolve_static("no-such-folder/file.css") is None


def test_a_folder_is_not_served(client: TestClient) -> None:
    assert client.get("/static/brand").status_code == 404
    assert client.get("/static/brand/").status_code == 404


def test_the_static_folder_holds_the_shipped_files() -> None:
    names = {path.name for path in Path(STATIC_DIR).iterdir()}
    assert {"app.css", "htmx.min.js", "htmx.min.js.LICENSE.txt"} <= names
