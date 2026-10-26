"""Tests for scripts/classify_changes.py, the fail-closed documentation-only classifier."""

import io
import json
import re
import subprocess
import urllib.error
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import classify_changes
from classify_changes import (
    blocking_paths,
    changed_paths,
    classify,
    deployed_commit,
    is_documentation_only,
    is_documentation_path,
    main,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SHA_A = "a" * 40
HEALTH_URL = "https://ce-dev-driftsniff.theriark.dev/healthz"


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/README.md",
        "docs/user-guide.md",
        "docs/images/dashboard-1440.png",
        "docs/images/a.jpg",
        "docs/release-notes/v27.0.0-rc.1.md",
        "docs/documentation-manifest.json",
        "docs/tutorials/01-first-sign-in.md",
    ],
)
def test_documentation_paths_are_allowed(path: str) -> None:
    assert is_documentation_path(path)


@pytest.mark.parametrize(
    "path",
    [
        # application, dependency, static, config, build and workflow files
        "src/driftsniff/web/app.py",
        "src/driftsniff/web/templates/base.html",
        "src/driftsniff/web/static/app.css",
        "src/driftsniff/web/static/brand/logo.png",
        "src/driftsniff/README.md",
        "src/driftsniff/rules/types/notes.md",
        "requirements.txt",
        "requirements.in",
        "requirements-dev.txt",
        "pyproject.toml",
        "Dockerfile",
        ".dockerignore",
        "compose.yaml",
        "LICENSE",
        "deploy/dokploy.json",
        "brand/logo.svg",
        "brand/MANIFEST.sha256",
        "scripts/classify_changes.py",
        "tests/unit/test_classify_changes.py",
        "tests/fixtures/notes.md",
        ".github/workflows/ci.yml",
        ".github/scripts/dokploy_release.py",
        ".github/pull_request_template.md",
        ".github/dependabot.yml",
        ".gitleaksignore",
        # other Markdown or look-alike names are not documentation
        "NOTES.md",
        "readme.md",
        "README.md.py",
        "sub/README.md",
        "docs",
        "docs/",
        "docs/.hidden.md",
        "docs/guide.py",
        "docs/script.sh",
        "docs/diagram.svg",
        "docs/images/a.PNG",
        "docs/images/",
        "docs/md",
        "docs/.md",
        "Docs/guide.md",
        "docs2/guide.md",
        "docs/../src/app.py",
        "docs/../README.md",
        "../README.md",
        "/docs/guide.md",
        "docs//guide.md",
        "docs/guide.md/",
        "docs/gu ide.md",
        "docs/guide.md\n",
        "docs/guïde.md",
        'docs/"guide".md',
        "",
    ],
)
def test_everything_else_is_not_documentation(path: str) -> None:
    assert not is_documentation_path(path)


def test_one_application_path_blocks_a_documentation_push() -> None:
    paths = ["docs/user-guide.md", "README.md", "src/driftsniff/__init__.py"]
    assert blocking_paths(paths) == ["src/driftsniff/__init__.py"]
    assert not is_documentation_only(paths)


def test_an_empty_difference_is_not_documentation_only() -> None:
    assert not is_documentation_only([])


def test_only_documentation_paths_are_documentation_only() -> None:
    assert is_documentation_only(["README.md", "docs/images/a.png", "docs/a.md"])


def test_the_dockerfile_copies_nothing_the_allow_list_accepts() -> None:
    copies = re.findall(
        r"^COPY\s+(?!--from)(?:--\S+\s+)*(.+?)\s+\S+\s*$",
        (REPO_ROOT / "Dockerfile").read_text(),
        flags=re.MULTILINE,
    )
    assert copies
    for source_list in copies:
        for source in source_list.split():
            source = source.rstrip("/")
            assert not is_documentation_path(source)
            assert not is_documentation_path(f"{source}/example.md")
            assert not is_documentation_path(f"{source}/example.png")


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commit_files(repo: Path, files: dict[str, str | None]) -> str:
    for name, content in files.items():
        target = repo / name
        if content is None:
            target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    git(repo, "add", "--all")
    git(repo, "commit", "--quiet", "--allow-empty", "-m", "change")
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    git(tmp_path, "init", "--quiet", "--initial-branch=development")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def base_commit(repo: Path) -> str:
    return commit_files(
        repo,
        {
            "README.md": "readme " * 40,
            "docs/guide.md": "guide " * 40,
            "src/driftsniff/app.py": "print('application')\n" * 20,
            "src/driftsniff/note.md": "note " * 40,
            "requirements.txt": "requirement\n" * 20,
        },
    )


def test_changed_paths_lists_added_modified_and_deleted_files(repo: Path) -> None:
    base = base_commit(repo)
    head = commit_files(
        repo, {"README.md": "changed", "docs/new.md": "new", "requirements.txt": None}
    )
    assert sorted(changed_paths(base, head) or []) == [
        "README.md",
        "docs/new.md",
        "requirements.txt",
    ]


def test_a_rename_from_documentation_into_the_application_lists_both_paths(repo: Path) -> None:
    base = base_commit(repo)
    git(repo, "mv", "docs/guide.md", "src/driftsniff/guide.md")
    git(repo, "commit", "--quiet", "-m", "rename")
    head = git(repo, "rev-parse", "HEAD")
    paths = changed_paths(base, head) or []
    assert sorted(paths) == ["docs/guide.md", "src/driftsniff/guide.md"]
    assert not is_documentation_only(paths)


def test_a_rename_from_the_application_into_documentation_lists_the_previous_path(
    repo: Path,
) -> None:
    base = base_commit(repo)
    git(repo, "mv", "src/driftsniff/note.md", "docs/note.md")
    git(repo, "commit", "--quiet", "-m", "rename")
    head = git(repo, "rev-parse", "HEAD")
    paths = changed_paths(base, head) or []
    # Every new path is documentation, but the previous path was application source.
    assert sorted(paths) == ["docs/note.md", "src/driftsniff/note.md"]
    assert not is_documentation_only(paths)


def test_a_pure_documentation_rename_stays_documentation_only(repo: Path) -> None:
    base = base_commit(repo)
    git(repo, "mv", "docs/guide.md", "docs/manual.md")
    git(repo, "commit", "--quiet", "-m", "rename")
    head = git(repo, "rev-parse", "HEAD")
    paths = changed_paths(base, head) or []
    assert sorted(paths) == ["docs/guide.md", "docs/manual.md"]
    assert is_documentation_only(paths)


def test_changed_paths_fails_for_an_unknown_commit(repo: Path) -> None:
    base_commit(repo)
    assert changed_paths(SHA_A, "b" * 40) is None


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200) -> None:
        super().__init__(body)
        self.status = status

    def __enter__(self) -> "FakeResponse":
        return self


def opener_returning(*answers: Any) -> Callable[..., Any]:
    queue = list(answers)

    def opener(request: Any, timeout: float = 0) -> Any:
        answer = queue.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    return opener


def health(payload: Any, status: int = 200) -> FakeResponse:
    return FakeResponse(json.dumps(payload).encode(), status)


def test_the_deployed_commit_is_read_from_a_healthy_answer() -> None:
    opener = opener_returning(health({"status": "ok", "commit": SHA_A}))
    assert deployed_commit(HEALTH_URL, opener=opener, sleep=lambda _: None) == SHA_A


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "degraded", "commit": SHA_A},
        {"status": "ok"},
        {"status": "ok", "commit": None},
        {"status": "ok", "commit": "unknown"},
        {"status": "ok", "commit": SHA_A[:12]},
        {"status": "ok", "commit": SHA_A.upper()},
        {"status": "ok", "commit": SHA_A + "0"},
        ["ok"],
        "ok",
    ],
)
def test_an_unhealthy_or_malformed_answer_proves_nothing(payload: Any) -> None:
    opener = opener_returning(health(payload))
    assert deployed_commit(HEALTH_URL, opener=opener, sleep=lambda _: None) is None


def test_a_non_200_answer_proves_nothing() -> None:
    opener = opener_returning(health({"status": "ok", "commit": SHA_A}, status=204))
    assert deployed_commit(HEALTH_URL, opener=opener, sleep=lambda _: None) is None


def test_an_unreachable_runtime_proves_nothing_after_the_bounded_retries() -> None:
    sleeps: list[float] = []
    opener = opener_returning(
        urllib.error.URLError("down"), TimeoutError(), FakeResponse(b"not json")
    )
    assert deployed_commit(HEALTH_URL, opener=opener, sleep=sleeps.append) is None
    assert len(sleeps) == 2


def test_a_transient_failure_is_retried() -> None:
    opener = opener_returning(
        urllib.error.URLError("down"), health({"status": "ok", "commit": SHA_A})
    )
    assert deployed_commit(HEALTH_URL, opener=opener, sleep=lambda _: None) == SHA_A


@pytest.mark.parametrize("url", ["http://ce-dev-driftsniff.theriark.dev/healthz", "file:///x", ""])
def test_only_an_https_health_url_is_used(url: str) -> None:
    def forbidden(*_: Any, **__: Any) -> Any:
        raise AssertionError("no request must be made")

    assert deployed_commit(url, opener=forbidden, sleep=lambda _: None) is None


def serve(monkeypatch: pytest.MonkeyPatch, commit: str | None) -> None:
    monkeypatch.setattr(classify_changes, "deployed_commit", lambda url: commit)


def test_documentation_only_push_is_classified_against_the_deployed_commit(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = base_commit(repo)
    head = commit_files(repo, {"docs/user-guide.md": "new", "README.md": "changed"})
    serve(monkeypatch, base)
    docs_only, used_base, reason = classify(head, HEALTH_URL)
    assert docs_only
    assert used_base == base
    assert "2 changed paths" in reason


def test_an_application_change_after_the_deployed_commit_is_never_hidden(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The application change was pushed earlier but never deployed; this push is documentation.
    deployed = base_commit(repo)
    commit_files(repo, {"src/driftsniff/app.py": "changed"})
    head = commit_files(repo, {"docs/user-guide.md": "new"})
    serve(monkeypatch, deployed)
    docs_only, _, reason = classify(head, HEALTH_URL)
    assert not docs_only
    assert "src/driftsniff/app.py" in reason


@pytest.mark.parametrize(
    "files",
    [
        {"src/driftsniff/app.py": "changed"},
        {"requirements.txt": "changed"},
        {"Dockerfile": "FROM scratch"},
        {".github/workflows/ci.yml": "name: CI"},
        {"src/driftsniff/web/static/app.css": "body {}"},
        {"deploy/dokploy.json": "{}"},
        {"README.md": "changed", "src/driftsniff/note.md": "changed"},
        {"docs/user-guide.md": "new", "LICENSE": "changed"},
    ],
)
def test_any_non_documentation_change_runs_the_full_deployment(
    repo: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, str | None]
) -> None:
    base = base_commit(repo)
    head = commit_files(repo, files)
    serve(monkeypatch, base)
    docs_only, used_base, _ = classify(head, HEALTH_URL)
    assert not docs_only
    assert used_base == base


def test_a_push_with_no_difference_is_not_classified(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = base_commit(repo)
    head = commit_files(repo, {})
    serve(monkeypatch, base)
    docs_only, _, reason = classify(head, HEALTH_URL)
    assert not docs_only
    assert "no changed paths" in reason


def test_an_unreachable_runtime_runs_the_full_deployment(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_commit(repo)
    head = commit_files(repo, {"docs/user-guide.md": "new"})
    serve(monkeypatch, None)
    docs_only, used_base, reason = classify(head, HEALTH_URL)
    assert not docs_only
    assert used_base == ""
    assert "/healthz" in reason


def test_a_deployed_commit_missing_from_history_runs_the_full_deployment(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_commit(repo)
    head = commit_files(repo, {"docs/user-guide.md": "new"})
    serve(monkeypatch, SHA_A)
    docs_only, _, reason = classify(head, HEALTH_URL)
    assert not docs_only
    assert "not in the fetched history" in reason


def test_a_deployed_commit_that_is_not_an_ancestor_runs_the_full_deployment(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = base_commit(repo)
    git(repo, "checkout", "--quiet", "-b", "other")
    other = commit_files(repo, {"docs/other.md": "other"})
    git(repo, "checkout", "--quiet", "development")
    head = commit_files(repo, {"docs/user-guide.md": "new"})
    assert base != other
    serve(monkeypatch, other)
    docs_only, _, reason = classify(head, HEALTH_URL)
    assert not docs_only
    assert "not an ancestor" in reason


@pytest.mark.parametrize("head", ["", "abc", "A" * 40, SHA_A + "0", "HEAD", "--help"])
def test_a_head_that_is_not_a_full_sha_is_refused(
    head: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    serve(monkeypatch, SHA_A)
    docs_only, _, reason = classify(head, HEALTH_URL)
    assert not docs_only
    assert "full lowercase SHA" in reason


def test_main_writes_the_outputs_and_always_succeeds(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
    capsys: pytest.CaptureFixture[str],
) -> None:
    base = base_commit(repo)
    head = commit_files(repo, {"docs/user-guide.md": "new"})
    output = tmp_path_factory.mktemp("out") / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    serve(monkeypatch, base)
    assert main(["--head", head, "--health-url", HEALTH_URL]) == 0
    assert output.read_text().splitlines() == ["docs_only=true", f"base={base}"]
    assert capsys.readouterr().out.startswith("documentation-only:")


def test_main_falls_back_to_the_full_deployment_when_the_classifier_crashes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def crash(*_: Any) -> Any:
        raise RuntimeError("boom")

    output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(classify_changes, "classify", crash)
    assert main(["--head", SHA_A, "--health-url", HEALTH_URL]) == 0
    assert output.read_text().splitlines() == ["docs_only=false", "base="]
    assert "not documentation-only" in capsys.readouterr().out
