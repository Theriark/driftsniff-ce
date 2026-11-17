"""Tests for the read-only show-image subcommand of .github/scripts/dokploy_release.py."""

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "dokploy_release.py"
IMAGE = "ghcr.io/theriark/driftsniff-ce@sha256:" + "a" * 64


def load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dokploy_release", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_show_image_reads_only_and_writes_the_image_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_module()
    answers = [{"dockerImage": IMAGE}, {"dockerImage": "nginx:latest"}]
    calls: list[str] = []

    def fake_request(method: str, path: str, **_kwargs: Any) -> Any:
        calls.append(f"{method} {path}")
        return answers.pop(0)

    monkeypatch.setattr(module, "request_json", fake_request)
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    args = module.build_parser().parse_args(["show-image", "--application-id", "app-1"])
    args.func(args)
    assert output.read_text(encoding="utf-8") == f"image={IMAGE}\n"
    with pytest.raises(module.DokployError, match="Image must be"):
        args.func(args)
    assert calls == ["GET application.one", "GET application.one"]
