"""Unit tests for the Dokploy release helper (.github/scripts/dokploy_release.py)."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "dokploy_release.py"
IMAGE = "ghcr.io/theriark/driftsniff-ce@sha256:" + "a" * 64
OTHER_IMAGE = "ghcr.io/theriark/driftsniff-ce@sha256:" + "b" * 64
COMMIT = "c" * 40
APP = "app-1"

EMPTY_IMAGE_RESPONSES: list[dict[str, Any]] = [
    {"dockerImage": ""},
    {"dockerImage": "   "},
    {"dockerImage": None},
    {},
    {"data": {"name": "app"}},
]


def load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dokploy_release", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeDokploy:
    """Stands in for request_json: serves application.one answers in order, records POSTs."""

    def __init__(self, one_responses: list[dict[str, Any]]) -> None:
        self.one_responses = list(one_responses)
        self.posts: list[str] = []

    def __call__(self, method: str, path: str, **_kwargs: Any) -> Any:
        if method == "GET" and path == "application.one":
            return self.one_responses.pop(0)
        self.posts.append(path)
        return {}


def make_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "application_id": APP,
        "image": IMAGE,
        "health_url": "https://example.invalid/healthz",
        "expected_commit": COMMIT,
        "title": "title",
        "description": "description",
        "timeout": 1,
        "noop_ok": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def install_fake(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType, responses: list[dict[str, Any]]
) -> FakeDokploy:
    fake = FakeDokploy(responses)
    monkeypatch.setattr(module, "request_json", fake)
    monkeypatch.setattr(module, "wait_health", lambda *_args, **_kwargs: None)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    return fake


@pytest.mark.parametrize("noop_ok", [False, True])
@pytest.mark.parametrize("previous", EMPTY_IMAGE_RESPONSES)
def test_empty_previous_image_updates_and_deploys(
    monkeypatch: pytest.MonkeyPatch, previous: dict[str, Any], noop_ok: bool
) -> None:
    module = load_module()
    fake = install_fake(monkeypatch, module, [previous, {"dockerImage": IMAGE}])
    module.deploy(make_args(noop_ok=noop_ok))
    assert fake.posts == ["application.update", "application.deploy"]


def test_same_image_with_noop_ok_skips_update_and_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake = install_fake(monkeypatch, module, [{"dockerImage": IMAGE}, {"dockerImage": IMAGE}])
    module.deploy(make_args(noop_ok=True))
    assert fake.posts == []


def test_same_image_without_noop_ok_still_deploys(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake = install_fake(monkeypatch, module, [{"dockerImage": IMAGE}, {"dockerImage": IMAGE}])
    module.deploy(make_args())
    assert fake.posts == ["application.update", "application.deploy"]


def test_image_mismatch_after_deploy_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [{"dockerImage": ""}, {"dockerImage": OTHER_IMAGE}])
    with pytest.raises(module.DokployError, match="reports"):
        module.deploy(make_args())


@pytest.mark.parametrize("after", EMPTY_IMAGE_RESPONSES)
def test_missing_image_after_deploy_fails(
    monkeypatch: pytest.MonkeyPatch, after: dict[str, Any]
) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [{"dockerImage": ""}, after])
    with pytest.raises(module.DokployError, match="Could not read dockerImage"):
        module.deploy(make_args())


@pytest.mark.parametrize("response", EMPTY_IMAGE_RESPONSES)
def test_assert_image_is_strict_about_a_missing_image(
    monkeypatch: pytest.MonkeyPatch, response: dict[str, Any]
) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [response])
    with pytest.raises(module.DokployError, match="Could not read dockerImage"):
        module.assert_image(make_args())


def test_current_image_is_strict_unless_allow_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [{}, {}, {"dockerImage": f" {IMAGE} "}])
    with pytest.raises(module.DokployError):
        module.current_image(APP)
    assert module.current_image(APP, allow_missing=True) == ""
    assert module.current_image(APP) == IMAGE


def test_current_image_rejects_a_non_string_even_when_lenient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [{"dockerImage": 5}])
    with pytest.raises(module.DokployError):
        module.current_image(APP, allow_missing=True)
