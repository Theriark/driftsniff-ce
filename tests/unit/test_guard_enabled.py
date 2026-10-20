"""Tests for scripts/guard_enabled.py and the shape of the two promotion workflows."""

import json
import re
from pathlib import Path

import pytest

from guard_enabled import is_enabled, main

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PROMOTIONS = (
    ("promote-stage.yml", "PROMOTE_STAGE_ENABLED"),
    ("promote-production.yml", "PROMOTE_PRODUCTION_ENABLED"),
)


def read_workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_guard_fails_when_the_variable_is_unset(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["PROMOTE_STAGE_ENABLED"], {}) == 1
    assert "stopping before any deploy step" in capsys.readouterr().err


def test_guard_succeeds_when_the_variable_is_true(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["PROMOTE_STAGE_ENABLED"], {"PROMOTE_STAGE_ENABLED": "true"}) == 0
    assert "may continue" in capsys.readouterr().out


@pytest.mark.parametrize(
    "value",
    [None, "", "false", "True", "TRUE", "1", "yes", " true", "true ", "true\n"],
)
def test_only_the_exact_text_true_enables(value: str | None) -> None:
    environ: dict[str, str] = {} if value is None else {"SWITCH": value}
    assert is_enabled(value) is False
    assert main(["SWITCH"], environ) == 1


def test_guard_reads_only_the_named_variable() -> None:
    assert main(["SWITCH"], {"OTHER": "true"}) == 1
    assert main(["SWITCH"], {"SWITCH": "true", "OTHER": "false"}) == 0


def test_is_enabled_accepts_true() -> None:
    assert is_enabled("true") is True


def test_guard_needs_exactly_one_variable_name(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([], {"SWITCH": "true"}) == 2
    assert main([""], {"SWITCH": "true"}) == 2
    assert main(["A", "B"], {"A": "true", "B": "true"}) == 2
    assert "usage:" in capsys.readouterr().err


@pytest.mark.parametrize(("name", "variable"), PROMOTIONS)
def test_workflow_is_dispatch_only(name: str, variable: str) -> None:
    text = read_workflow(name)
    on_block = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert re.findall(r"^  ([a-z_]+):", on_block, re.MULTILINE) == ["workflow_dispatch"]
    assert variable.startswith("PROMOTE_")


@pytest.mark.parametrize(("name", "variable"), PROMOTIONS)
def test_guard_job_comes_first_and_the_deploy_job_waits_for_it(name: str, variable: str) -> None:
    text = read_workflow(name)
    assert f"python3 scripts/guard_enabled.py {variable}" in text
    assert variable + ": ${{ vars." + variable + " }}" in text
    jobs = text.split("\njobs:\n", 1)[1]
    start = jobs.index("\n  promote:")
    guard_part = jobs[:start]
    promote_part = jobs[start:]
    assert "\n  guard:" in guard_part
    assert "dokploy_release.py" not in guard_part
    header = promote_part.split("    steps:", 1)[0]
    assert "needs: guard" in header
    assert "\n    if:" not in header


@pytest.mark.parametrize(("name", "variable"), PROMOTIONS)
def test_workflow_shares_the_pipeline_group_and_never_cancels(name: str, variable: str) -> None:
    text = read_workflow(name)
    assert "  group: driftsniff-ce-pipeline\n  cancel-in-progress: false" in text
    assert variable in text


@pytest.mark.parametrize(("name", "variable"), PROMOTIONS)
def test_actions_are_pinned_to_a_full_commit_sha(name: str, variable: str) -> None:
    uses = re.findall(r"^\s+uses:\s+(\S+)", read_workflow(name), re.MULTILINE)
    assert uses
    for reference in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", reference), (variable, reference)


def test_deployment_notes_list_every_runtime_setting_and_the_smoke_check() -> None:
    notes = (REPO_ROOT / "docs" / "deploy-development.md").read_text(encoding="utf-8")
    manifest = json.loads((REPO_ROOT / "deploy" / "dokploy.json").read_text(encoding="utf-8"))
    for entry in manifest["env"]:
        assert entry["name"] in notes
    for volume in manifest["volumes"]:
        assert volume in notes
    for expected in (
        "https://ce-dev-driftsniff.theriark.dev",
        "512 MB",
        "GET /healthz",
        "previous approved digest",
    ):
        assert expected in notes
