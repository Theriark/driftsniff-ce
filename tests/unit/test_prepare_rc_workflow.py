"""Contract tests for the workflow that creates the release candidate (RC).

prepare-rc.yml is started by workflow_dispatch with fixed input names. It validates its inputs,
writes one annotated RC tag with a fixed JSON message and one published prerelease, and never
builds, deploys or publishes a stable release. The tests read the workflow file as YAML and as
text, so a renamed input, a widened permission, a shell-interpolated input, a dropped tag key or
a build step fails the checks.
"""

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "prepare-rc.yml"
INPUTS = [
    "request_id",
    "rc_tag",
    "source_commit",
    "image_digest",
    "development_run_id",
    "documentation_manifest_sha256",
    "gate_cycle",
]
RC_PATTERN = r"^v27\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.[1-9][0-9]*$"
TAG_KEYS = [
    "sourceCommit",
    "imageDigest",
    "developmentRunId",
    "documentationManifestSha256",
    "gateCycle",
    "workflowRunId",
]
INTEGER_KEYS = {
    "developmentRunId": 'int(os.environ["DEVELOPMENT_RUN_ID"])',
    "gateCycle": 'int(os.environ["GATE_CYCLE"])',
    "workflowRunId": 'int(os.environ["GITHUB_RUN_ID"])',
}
DEPLOY_AND_BUILD_PATTERNS = (
    r"docker\s+(buildx\s+)?build\b",
    r"docker\s+push\b",
    r"docker\s+tag\b",
    r"docker\s+commit\b",
    r"imagetools\s+create\b",
    r"dokploy",
    r"--latest",
    r"--force",
    r"git\s+tag\s+-f\b",
)


def read_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def load() -> dict[Any, Any]:
    document = yaml.safe_load(read_text())
    assert isinstance(document, dict)
    return document


def steps_of() -> list[dict[str, Any]]:
    jobs = load()["jobs"]
    return [step for job in jobs.values() for step in job["steps"]]


def scripts_of() -> str:
    return "\n".join(step.get("run", "") for step in steps_of())


def test_only_workflow_dispatch_triggers_the_workflow() -> None:
    document = load()
    triggers = document["on"] if "on" in document else document[True]
    assert list(triggers) == ["workflow_dispatch"]


def test_inputs_are_the_registered_required_string_inputs() -> None:
    document = load()
    triggers = document["on"] if "on" in document else document[True]
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert list(inputs) == INPUTS
    for key, spec in inputs.items():
        assert spec["type"] == "string", key
        assert spec["required"] is True, key


def test_run_name_is_publishing_and_the_request_id() -> None:
    assert load()["run-name"] == "publishing:${{ inputs.request_id }}"


def test_workflow_shares_the_pipeline_group_and_never_cancels() -> None:
    concurrency = load()["concurrency"]
    assert concurrency == {"group": "driftsniff-ce-pipeline", "cancel-in-progress": False}
    for name in ("promote-stage.yml", "finalize-release.yml"):
        text = (WORKFLOW.parent / name).read_text(encoding="utf-8")
        assert "group: driftsniff-ce-pipeline" in text, name


def test_permissions_are_the_smallest_that_work() -> None:
    document = load()
    assert document["permissions"] == {"contents": "read"}
    jobs = document["jobs"]
    assert list(jobs) == ["prepare"]
    permissions = jobs["prepare"]["permissions"]
    assert permissions == {"actions": "read", "contents": "write", "packages": "read"}


def test_the_job_has_no_deployment_environment_and_no_secrets() -> None:
    job = load()["jobs"]["prepare"]
    assert "environment" not in job
    text = read_text()
    assert "secrets.GITHUB_TOKEN" in text
    assert len(re.findall(r"secrets\.", text)) == 1


def test_inputs_reach_scripts_only_through_env() -> None:
    for step in steps_of():
        assert "${{" not in step.get("run", ""), step["name"]
    env = load()["jobs"]["prepare"]["env"]
    for key in INPUTS:
        assert f"${{{{ inputs.{key} }}}}" in env.values(), key


def test_rc_tag_pattern_is_the_registered_one() -> None:
    assert RC_PATTERN in read_text()
    pattern = re.compile(RC_PATTERN)
    for good in ("v27.0.0-rc.1", "v27.12.3-rc.10", "v27.0.10-rc.2"):
        assert pattern.match(good), good
    bad = (
        "v27.0.0",
        "v26.0.0-rc.1",
        "v27.01.0-rc.1",
        "v27.0.00-rc.1",
        "v27.0.0-rc.0",
        "v27.0.0-rc.01",
        "v27.0.0-rc.1x",
        "27.0.0-rc.1",
    )
    for value in bad:
        assert pattern.match(value) is None, value


def test_inputs_are_validated_before_anything_is_written() -> None:
    scripts = scripts_of()
    for phrase in (
        "^[0-9a-f]{40}$",
        "^sha256:[0-9a-f]{64}$",
        "merge-base --is-ancestor",
        "ls-remote --exit-code --tags",
        "gh release view",
    ):
        assert phrase in scripts, phrase
    names = [step["name"] for step in steps_of()]
    assert names.index("Validate inputs, execution ref, source commit and tag") == 1


def test_the_development_run_and_the_image_are_verified() -> None:
    scripts = scripts_of()
    assert "actions/runs/" in scripts
    for phrase in (
        '"conclusion") != "success"',
        ".github/workflows/ci.yml",
        '"head_branch") != "development"',
        '"head_sha") != source',
    ):
        assert phrase in scripts, phrase
    assert 'imagetools inspect "${IMAGE}@${IMAGE_DIGEST}"' in scripts
    assert '[[ "${found}" == "${IMAGE_DIGEST}" ]]' in scripts
    assert "sha-${SOURCE_COMMIT::12}" in scripts


def test_the_rc_tag_is_annotated_on_the_commit_with_the_json_message() -> None:
    scripts = scripts_of()
    for key in TAG_KEYS:
        assert f'"{key}"' in scripts, key
    for key, expression in INTEGER_KEYS.items():
        assert f'"{key}": {expression}' in scripts, key
    assert 'run("git", "tag", "-a", tag, source, "-F", path)' in scripts
    assert '"cat-file", "-t", ref + "^{}") != "commit"' in scripts
    assert 'run("git", "push", "origin", ref)' in scripts
    assert scripts.count("git push") + scripts.count('"push"') == 1


def test_the_release_is_a_published_prerelease_for_the_existing_tag() -> None:
    scripts = scripts_of()
    assert scripts.count("gh release create") == 1
    assert "--verify-tag" in scripts
    assert "--prerelease" in scripts
    assert "--draft" not in scripts
    assert '"false,true"' in scripts


def test_no_step_builds_deploys_or_publishes_a_stable_release() -> None:
    text = read_text()
    scripts = scripts_of()
    for pattern in DEPLOY_AND_BUILD_PATTERNS:
        assert re.search(pattern, scripts) is None, pattern
    for step in steps_of():
        assert "build-push-action" not in step.get("uses", "")
    for phrase in (":latest", "refs/heads/stage", "refs/heads/production"):
        assert phrase not in text, phrase
    assert "PROMOTE_STAGE_ENABLED" not in text
