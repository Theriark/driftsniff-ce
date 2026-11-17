"""Contract tests for the two one-button workflows the gates dispatch.

Gate 2 runs promote-stage.yml and Gate 3 runs release.yml, both from development with no
required input and an optional dry_run. Neither may rebuild an image, every write step must be
skipped by dry_run, and release.yml must never deploy or touch development. The tests read the
workflow files as YAML and as text, so a typed input, a lost dry_run condition, a build step or
a merge of main into development fails the checks.
"""

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
BUTTONS = ("promote-stage.yml", "release.yml")
REBUILD_PATTERNS = (
    r"docker\s+(buildx\s+)?build\b",
    r"docker\s+push\b",
    r"docker\s+tag\b",
    r"docker\s+commit\b",
)
# A step that runs one of these writes something, so dry_run must skip it.
WRITE_PATTERNS = (
    r"git push",
    r"git tag -a",
    r"imagetools create",
    r"dokploy_release\.py deploy",
    r"gh release create",
    r"--method (PATCH|POST|PUT|DELETE)",
)


def read_text(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def load(name: str) -> dict[Any, Any]:
    document = yaml.safe_load(read_text(name))
    assert isinstance(document, dict)
    return document


def steps_of(name: str) -> list[dict[str, Any]]:
    return [step for job in load(name)["jobs"].values() for step in job["steps"]]


def scripts_of(name: str) -> str:
    return "\n".join(step.get("run", "") for step in steps_of(name))


def test_the_retired_typed_input_workflows_are_gone() -> None:
    names = sorted(path.name for path in WORKFLOWS.glob("*.yml"))
    assert names == ["ci.yml", "promote-production.yml", "promote-stage.yml", "release.yml"]


def test_each_button_has_only_an_optional_dry_run() -> None:
    for name in BUTTONS:
        document = load(name)
        triggers = document["on"] if "on" in document else document[True]
        assert list(triggers) == ["workflow_dispatch"], name
        inputs = triggers["workflow_dispatch"]["inputs"]
        assert inputs == {
            "dry_run": {
                "description": "Check everything and change nothing",
                "required": False,
                "default": False,
                "type": "boolean",
            }
        }, name


def test_each_button_runs_only_from_development() -> None:
    for name in BUTTONS:
        assert 'refs/heads/development" ]] || fail' in scripts_of(name), name


def test_buttons_share_the_pipeline_group_and_never_cancel() -> None:
    for name in BUTTONS:
        concurrency = load(name)["concurrency"]
        assert concurrency == {"group": "driftsniff-ce-pipeline", "cancel-in-progress": False}, name


def test_no_step_rebuilds_an_image() -> None:
    for name in BUTTONS:
        scripts = scripts_of(name)
        for pattern in REBUILD_PATTERNS:
            assert re.search(pattern, scripts) is None, (name, pattern)
        for step in steps_of(name):
            assert "build-push-action" not in step.get("uses", ""), name
        assert ":latest" not in read_text(name), name


def test_dry_run_skips_every_write_step() -> None:
    for name in BUTTONS:
        writes = 0
        for step in steps_of(name):
            script = step.get("run", "")
            if any(re.search(pattern, script) for pattern in WRITE_PATTERNS):
                writes += 1
                assert str(step.get("if", "")).startswith("${{ !inputs.dry_run"), step["name"]
        assert writes >= 4, name


def test_every_image_alias_is_a_carbon_copy_of_the_approved_digest() -> None:
    """Without --prefer-index=false, buildx wraps a single-platform image in a new index, so the
    alias gets another digest and the check after it refuses the run (Stage, 15 November 2026)."""
    for name in ("promote-stage.yml", "promote-production.yml", "release.yml"):
        creates = re.findall(r"docker buildx imagetools create[^\n]*", read_text(name))
        assert creates, name
        for line in creates:
            assert "--prefer-index=false" in line, (name, line)


def test_promote_computes_the_candidate_and_tests_the_commit_development_runs() -> None:
    jobs = load("promote-stage.yml")["jobs"]
    assert list(jobs) == ["guard", "resolve", "tests", "promote"]
    scripts = scripts_of("promote-stage.yml")
    assert "https://${DEVELOPMENT_HOST}/healthz" in scripts
    assert "scripts/release_version.py candidate" in scripts
    assert "actions/workflows/ci.yml/runs?branch=development&event=push&status=success" in scripts
    assert jobs["tests"]["steps"][0]["with"]["ref"] == "${{ needs.resolve.outputs.commit }}"
    assert "pytest" in scripts
    assert "dokploy_release.py assert-image" in scripts
    assert jobs["promote"]["environment"] == "stage"


def test_promote_deploys_the_same_digest_to_the_existing_stage_application() -> None:
    text = read_text("promote-stage.yml")
    scripts = scripts_of("promote-stage.yml")
    assert "DOKPLOY_STAGE_APPLICATION_ID: lhB_AOqk4FTEaHhEQcPKj" in text
    assert '--image "${IMAGE_REF}"' in scripts
    assert '--expected-commit "${SOURCE_COMMIT}"' in scripts
    assert "--noop-ok" in scripts
    assert "git/refs/heads/stage" in scripts
    assert "-F force=false" in scripts
    assert "--force" not in scripts


def test_release_reads_stage_and_never_deploys() -> None:
    jobs = load("release.yml")["jobs"]
    assert list(jobs) == ["release"]
    scripts = scripts_of("release.yml")
    assert "refs/remotes/origin/stage" in scripts
    assert "dokploy_release.py show-image" in scripts
    assert "scripts/release_version.py release" in scripts
    assert "scripts/release_notes.py" in scripts
    assert "dokploy_release.py deploy" not in scripts
    assert "promote-production" not in scripts
    assert "PRODUCTION" not in read_text("release.yml")


def test_release_reconciles_before_writing() -> None:
    scripts = scripts_of("release.yml")
    for phrase in ("ls-remote", "gh release view", "release not found", "imagetools inspect"):
        assert phrase in scripts, phrase
    assert "gh release create" in scripts and "--verify-tag" in scripts
    assert "--draft" not in scripts and "--prerelease" not in scripts
    for state in ("TAG_STATE", "IMAGE_STATE", "RELEASE_STATE", "MAIN_STATE"):
        assert f"env.{state} == 'create'" in read_text("release.yml"), state


def test_release_merges_stage_into_main_and_never_main_into_development() -> None:
    scripts = scripts_of("release.yml")
    assert "git/refs/heads/main" in scripts
    assert '"parents[]=${main_sha}"' in scripts and '"parents[]=${STAGE_SHA}"' in scripts
    assert "-F force=false" in scripts
    reads = (
        "+refs/heads/development:refs/remotes/origin/development",
        '[[ "${GITHUB_REF}" == "refs/heads/development" ]]',
        "git merge-base",
    )
    for read in reads:
        scripts = scripts.replace(read, "")
    assert "refs/heads/development" not in scripts
    assert "git merge" not in scripts
