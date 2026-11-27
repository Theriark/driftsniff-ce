"""Contract tests for the two one-button workflows the gates dispatch.

Gate 2 runs promote-stage.yml and Gate 3 runs release.yml, both from development with no
required input and an optional dry_run. Neither may rebuild an image, every write step must be
skipped by dry_run, and release.yml must never deploy or touch development. Neither workflow,
nor a script it calls, may move a branch: the gate script fast-forwards stage after a Stage run
and merges stage into main before release.yml, because the Actions token may not move a branch
to a commit that changes workflow files. The tests read the workflow files as YAML and as text,
so a typed input, a lost dry_run condition, a build step or a branch write fails the checks.
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
# Anything that can write a branch (refs/heads/stage, refs/heads/main or another one) from a
# workflow step or from a script the workflow calls. Tags are pushed with git push to
# refs/tags/ only, so every git push must name a tag ref.
BRANCH_WRITE_PATTERNS = (
    r"\bgit\s+merge(?!-base)\b",
    r"\bgit\s+update-ref\b",
    r"\bgit\s+branch\s+(-f|--force|-m|-M)\b",
    r"\bgh\s+pr\s+merge\b",
    r"\bgh\s+api\b[^\n]*\bbranches/",
    r"\bgit/refs?\b",
    r"\bgit/commits\b",
    r"/merges\b",
    r"[\"'](merge|update-ref|push)[\"']",
)
TAG_PUSH = re.compile(r"\bgit\s+push\s+origin\s+\"refs/tags/\$\{[A-Z_]+\}\"\s*$")
CALLED_SCRIPT = re.compile(r"(?:\.github/)?scripts/[A-Za-z0-9_-]+\.(?:py|sh)")


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


def branch_writes(text: str) -> list[str]:
    """The lines of a step script or a called script that could write a branch."""
    found = []
    for line in text.replace("\\\n", " ").splitlines():
        command = line.strip()
        if any(re.search(pattern, command) for pattern in BRANCH_WRITE_PATTERNS):
            found.append(command)
        elif re.search(r"\bgit\s+push\b", command) and not TAG_PUSH.fullmatch(command):
            found.append(command)
    return found


def called_scripts(name: str) -> set[Path]:
    return {REPO_ROOT / match for match in CALLED_SCRIPT.findall(read_text(name))}


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
        assert writes >= 3, name


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
    assert "DOKPLOY_STAGE_APPLICATION_ID: ${{ vars.DOKPLOY_STAGE_APPLICATION_ID }}" in text
    assert '--image "${IMAGE_REF}"' in scripts
    assert '--expected-commit "${SOURCE_COMMIT}"' in scripts
    assert "--noop-ok" in scripts
    assert "--force" not in scripts


def test_the_stage_branch_position_never_stops_a_promotion() -> None:
    """The gate script moves stage after the run, so where stage is now (behind, ahead or
    diverged) is reported and never checked."""
    scripts = scripts_of("promote-stage.yml")
    assert "ADVANCE" not in read_text("promote-stage.yml")
    assert "diverged" not in scripts
    for line in scripts.splitlines():
        if "stage_sha" in line:
            assert "fail" not in line and "exit" not in line, line
    report = 'stage_sha="$(git ls-remote origin refs/heads/stage | cut -f1)" || stage_sha=""'
    assert report in scripts


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
    for state in ("TAG_STATE", "IMAGE_STATE", "RELEASE_STATE"):
        assert f"env.{state} == 'create'" in read_text("release.yml"), state


def test_release_neither_reads_nor_checks_main() -> None:
    """main is merged by the gate script before the run; whether it is merged or protected is
    not this workflow's business, so nothing about main may stop a release."""
    text = read_text("release.yml")
    assert "MAIN_STATE" not in text
    assert "origin/main" not in text
    assert "heads/main" not in text
    assert "protected" not in text


def test_neither_button_nor_a_script_it_calls_writes_a_branch() -> None:
    for name in BUTTONS:
        assert branch_writes(scripts_of(name)) == [], name
        scripts = called_scripts(name)
        assert scripts, name
        for script in sorted(scripts):
            assert script.is_file(), script
            assert branch_writes(script.read_text(encoding="utf-8")) == [], script


def test_the_buttons_call_the_scripts_the_branch_check_covers() -> None:
    covered = {
        path.relative_to(REPO_ROOT).as_posix() for name in BUTTONS for path in called_scripts(name)
    }
    assert covered == {
        ".github/scripts/dokploy_release.py",
        "scripts/guard_enabled.py",
        "scripts/release_notes.py",
        "scripts/release_version.py",
    }


def test_the_branch_check_catches_every_way_to_move_a_branch() -> None:
    """The steps removed on 17 November 2026 and other ways to move a branch must be caught;
    the reads and tag pushes the buttons keep must not."""
    moves = (
        'gh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/stage" \\\n'
        '  -f sha="${SOURCE_COMMIT}" -F force=false > /dev/null',
        'merge="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" -f tree=x)"',
        'gh api --method POST "repos/${GITHUB_REPOSITORY}/merges" -f base=main -f head=stage',
        'gh api -X PUT "repos/${GITHUB_REPOSITORY}/branches/main/protection"',
        'git push origin "${SOURCE_COMMIT}:refs/heads/stage"',
        "git push origin HEAD:main",
        'git push --force origin "refs/tags/${RC_TAG}"',
        'git push origin "refs/tags/${RC_TAG}" "${STAGE_SHA}:refs/heads/main"',
        "git push",
        "git merge --no-ff refs/remotes/origin/stage",
        "git update-ref refs/heads/main HEAD",
        "git branch -f stage HEAD",
        "gh pr merge 12 --merge",
        'subprocess.run(["git", "push", "origin", "stage"], check=True)',
        '_git("merge", "stage")',
    )
    for move in moves:
        assert branch_writes(move), move
    kept = (
        'git push origin "refs/tags/${RC_TAG}"',
        'git merge-base --is-ancestor "${stage_sha}" refs/remotes/origin/development',
        "git fetch --force --tags origin +refs/heads/stage:refs/remotes/origin/stage",
        'stage_sha="$(git ls-remote origin refs/heads/stage | cut -f1)" || stage_sha=""',
        'gh release create "${STABLE_TAG}" --verify-tag --notes-file "${notes}"',
    )
    for read in kept:
        assert branch_writes(read) == [], read


def test_the_buttons_have_only_the_permissions_they_use() -> None:
    allowed = {"actions": {"read"}, "contents": {"read", "write"}, "packages": {"read", "write"}}
    for name in BUTTONS:
        document = load(name)
        assert document["permissions"] == {"contents": "read"}, name
        for job_name, job in document["jobs"].items():
            for scope, level in job["permissions"].items():
                assert level in allowed.get(scope, set()), (name, job_name, scope, level)
            writes_tags = "git push" in "\n".join(step.get("run", "") for step in job["steps"])
            assert (job["permissions"].get("contents") == "write") == writes_tags, (name, job_name)


def test_release_never_merges_main_into_development() -> None:
    scripts = scripts_of("release.yml")
    reads = (
        "+refs/heads/development:refs/remotes/origin/development",
        '[[ "${GITHUB_REF}" == "refs/heads/development" ]]',
        "git merge-base",
    )
    for read in reads:
        scripts = scripts.replace(read, "")
    assert "refs/heads/development" not in scripts
    assert "git merge" not in scripts


DEPLOYMENT_TARGETS = (
    "DOKPLOY_DEVELOPMENT_APPLICATION_ID",
    "DOKPLOY_STAGE_APPLICATION_ID",
    "DOKPLOY_PRODUCTION_APPLICATION_ID",
    "DEVELOPMENT_HOST",
    "STAGE_HOST",
    "PRODUCTION_HOST",
)


def test_deployment_targets_come_from_github_variables() -> None:
    """The Dokploy application ids and the site host names are GitHub variables, never literals
    in a public workflow file, and every job that uses one fails when it is missing."""
    seen: set[str] = set()
    for path in sorted(WORKFLOWS.glob("*.yml")):
        jobs = load(path.name)["jobs"]
        for job_name, job in jobs.items():
            env = job.get("env") or {}
            for name in DEPLOYMENT_TARGETS:
                if name in env:
                    assert env[name] == f"${{{{ vars.{name} }}}}", (path.name, job_name, name)
                    seen.add(name)
            for step in job["steps"]:
                for name in DEPLOYMENT_TARGETS:
                    assert name not in (step.get("env") or {}), (path.name, step["name"], name)
    assert seen == set(DEPLOYMENT_TARGETS)
    expected = {
        "ci.yml": ("DOKPLOY_DEVELOPMENT_APPLICATION_ID", "DEVELOPMENT_HOST"),
        "promote-stage.yml": (
            "DOKPLOY_DEVELOPMENT_APPLICATION_ID",
            "DOKPLOY_STAGE_APPLICATION_ID",
            "STAGE_HOST",
        ),
        "release.yml": ("DOKPLOY_STAGE_APPLICATION_ID", "STAGE_HOST"),
        "promote-production.yml": (
            "DOKPLOY_STAGE_APPLICATION_ID",
            "STAGE_HOST",
            "DOKPLOY_PRODUCTION_APPLICATION_ID",
            "PRODUCTION_HOST",
        ),
    }
    for name, names in expected.items():
        checked = (
            " ".join(line for line in scripts_of(name).splitlines() if "for required in" in line)
            .replace(";", " ")
            .split()
        )
        for variable in names:
            assert variable in checked, (name, variable)
    assert '[[ -n "${DEVELOPMENT_HOST}" ]] || fail' in scripts_of("promote-stage.yml")
