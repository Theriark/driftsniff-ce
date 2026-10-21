"""Contract tests for the two workflows the private publisher dispatches.

promote-stage.yml and finalize-release.yml are started by workflow_dispatch with fixed input
names and the fixed run name publishing:<request_id>. Neither may rebuild an image, and the
stable tag carries a fixed JSON message. The tests read the workflow files as YAML and as text,
so a renamed input, a lost run name, a build step or a dropped tag key fails the checks.
"""

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PUBLISHING = ("promote-stage.yml", "finalize-release.yml")
RUN_NAME = "publishing:${{ inputs.request_id }}"
STAGE_INPUTS = [
    "request_id",
    "version",
    "source_commit",
    "image",
    "development_run_id",
    "documentation_manifest_sha256",
    "rc_tag",
]
FINALIZE_INPUTS = [*STAGE_INPUTS, "stage_promotion_run_id"]
TAG_KEYS = [
    "sourceCommit",
    "imageDigest",
    "developmentRunId",
    "workflowRunId",
    "documentationManifestSha256",
    "stagePromotionRunId",
    "rcTag",
]
RC_KEYS = [
    "sourceCommit",
    "imageDigest",
    "developmentRunId",
    "documentationManifestSha256",
]
REBUILD_PATTERNS = (
    r"docker\s+(buildx\s+)?build\b",
    r"docker\s+push\b",
    r"docker\s+tag\b",
    r"docker\s+commit\b",
)


def read_text(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def load(name: str) -> dict[Any, Any]:
    document = yaml.safe_load(read_text(name))
    assert isinstance(document, dict)
    return document


def dispatch_inputs(name: str) -> dict[str, Any]:
    document = load(name)
    triggers = document.get("on", document.get(True))
    assert list(triggers) == ["workflow_dispatch"]
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert isinstance(inputs, dict)
    return inputs


def steps_of(name: str) -> list[dict[str, Any]]:
    jobs = load(name)["jobs"]
    return [step for job in jobs.values() for step in job["steps"]]


def scripts_of(name: str) -> str:
    return "\n".join(step.get("run", "") for step in steps_of(name))


def test_stage_inputs_are_the_registered_string_inputs() -> None:
    inputs = dispatch_inputs("promote-stage.yml")
    assert list(inputs) == STAGE_INPUTS
    for key, spec in inputs.items():
        assert spec["type"] == "string", key
        assert spec["required"] is True, key


def test_finalize_inputs_add_the_stage_promotion_run() -> None:
    inputs = dispatch_inputs("finalize-release.yml")
    assert list(inputs) == FINALIZE_INPUTS
    for key, spec in inputs.items():
        assert spec["type"] == "string", key
        assert spec["required"] is True, key


def test_run_name_is_publishing_and_the_request_id() -> None:
    for name in PUBLISHING:
        assert load(name)["run-name"] == RUN_NAME, name


def test_workflows_share_the_pipeline_group_and_never_cancel() -> None:
    for name in PUBLISHING:
        concurrency = load(name)["concurrency"]
        assert concurrency == {"group": "driftsniff-ce-pipeline", "cancel-in-progress": False}, name


def test_no_step_rebuilds_or_republishes_an_image() -> None:
    for name in PUBLISHING:
        scripts = scripts_of(name)
        for pattern in REBUILD_PATTERNS:
            assert re.search(pattern, scripts) is None, (name, pattern)
        for step in steps_of(name):
            assert "build-push-action" not in step.get("uses", ""), name
        assert ":latest" not in read_text(name), name


def test_stage_consumes_the_existing_rc_and_never_writes_one() -> None:
    scripts = scripts_of("promote-stage.yml")
    assert '"cat-file", "-t"' in scripts
    assert "%(contents)" in scripts
    for key in RC_KEYS:
        assert f'"{key}"' in scripts, key
    for phrase in ('"tag", "-a"', '"push"', "git push", "git tag -f", "--force", "release create"):
        assert phrase not in scripts, phrase


def test_stage_deploys_the_same_digest_to_the_existing_stage_application() -> None:
    text = read_text("promote-stage.yml")
    scripts = scripts_of("promote-stage.yml")
    assert "DOKPLOY_STAGE_APPLICATION_ID: lhB_AOqk4FTEaHhEQcPKj" in text
    assert "dokploy_release.py deploy" in scripts
    assert '--image "${IMAGE_REF}"' in scripts
    assert '--title "Stage ${SOURCE_COMMIT}"' in scripts
    assert '--description "${GITHUB_REPOSITORY#*/} GitHub Actions run ${GITHUB_RUN_ID}"' in scripts
    assert "--noop-ok" in scripts
    assert "refs/heads/development" in scripts
    assert "refs/heads/stage" in scripts
    promote = load("promote-stage.yml")["jobs"]["promote"]
    assert promote["environment"] == "stage"
    assert promote["needs"] == "guard"


def test_finalize_writes_the_stable_tag_message_with_every_key() -> None:
    scripts = scripts_of("finalize-release.yml")
    for key in TAG_KEYS:
        assert f'"{key}"' in scripts, key
    assert '"gateCycle"' in scripts
    assert '"tag", "-a"' in scripts


def test_finalize_reconciles_before_writing_and_publishes_a_plain_release() -> None:
    scripts = scripts_of("finalize-release.yml")
    for phrase in ("ls-remote", "gh release view", "release not found", "imagetools inspect"):
        assert phrase in scripts, phrase
    assert "gh release create" in scripts
    assert "--verify-tag" in scripts
    assert "--latest=false" in scripts
    assert "--draft" not in scripts
    assert "--prerelease" not in scripts


def test_finalize_needs_no_deployment_environment() -> None:
    jobs = load("finalize-release.yml")["jobs"]
    assert list(jobs) == ["finalize"]
    assert "environment" not in jobs["finalize"]
