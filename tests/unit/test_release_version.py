"""Tests for scripts/release_version.py and scripts/release_notes.py (one-button release path)."""

import subprocess
from pathlib import Path

import pytest

import release_notes
import release_version
from release_notes import previous_stable, pull_requests, render
from release_version import candidate, line, release

# The tags of Theriark/driftsniff-ce on 17 November 2026: v27.1.0-rc.1 was created by mistake.
CURRENT = ["v27.0.0-rc.5", "v27.1.0-rc.1"]
RELEASED = [*CURRENT, "v27.0.0"]


def test_current_tags_give_rc_6_of_27_0_0() -> None:
    assert candidate(CURRENT, []) == ("v27.0.0-rc.6", True)


def test_no_tags_give_the_first_candidate() -> None:
    assert candidate([], []) == ("v27.0.0-rc.1", True)


def test_after_27_0_0_the_feature_line_continues_its_candidates() -> None:
    assert line(RELEASED) == (27, 1, 0)
    assert candidate(RELEASED, []) == ("v27.1.0-rc.2", True)
    assert candidate(["v27.0.0-rc.5", "v27.0.0"], []) == ("v27.1.0-rc.1", True)


def test_a_candidate_above_the_newest_release_is_the_open_line() -> None:
    tags = ["v27.0.0", "v27.1.0", "v27.1.1-rc.1", "v27.2.0-rc.3"]
    assert candidate(tags, []) == ("v27.1.1-rc.2", True)


def test_any_other_line_is_ignored_until_27_0_0_is_released() -> None:
    tags = ["v27.0.0-rc.2", "v27.1.0-rc.9", "v27.0.1-rc.4"]
    assert line(tags) == (27, 0, 0)
    assert candidate(tags, []) == ("v27.0.0-rc.3", True)


@pytest.mark.parametrize(
    "tag",
    ["v28.0.0", "v26.9.9-rc.1", "v27.0.0-rc.0", "v27.01.0", "27.0.0", "v27.0.0-beta.1", "latest"],
)
def test_tags_outside_the_format_are_ignored(tag: str) -> None:
    assert release_version.parse(tag) is None
    assert candidate([*CURRENT, tag], []) == ("v27.0.0-rc.6", True)


def test_a_commit_that_already_has_a_candidate_keeps_it() -> None:
    tags = [*CURRENT, "v27.0.0-rc.6"]
    assert candidate(tags, ["v27.0.0-rc.6"]) == ("v27.0.0-rc.6", False)
    # A candidate of an ignored line on the commit is not reused.
    assert candidate(CURRENT, ["v27.1.0-rc.1"]) == ("v27.0.0-rc.6", True)


def test_release_of_a_candidate_of_the_line() -> None:
    tags = [*CURRENT, "v27.0.0-rc.6"]
    assert release(tags, ["v27.0.0-rc.6"]) == ("v27.0.0", "v27.0.0-rc.6")


def test_release_of_the_commit_stage_runs_today_is_27_0_0() -> None:
    assert release(CURRENT, ["v27.1.0-rc.1"]) == ("v27.0.0", "v27.1.0-rc.1")


def test_release_rerun_after_the_stable_tag_reports_the_same_version() -> None:
    assert release(RELEASED, ["v27.0.0-rc.6", "v27.0.0"]) == ("v27.0.0", "v27.0.0-rc.6")
    assert release(RELEASED, ["v27.1.0-rc.1", "v27.0.0"]) == ("v27.0.0", "v27.1.0-rc.1")


def test_release_refuses_a_commit_without_a_candidate_of_the_line() -> None:
    with pytest.raises(ValueError, match="no release candidate of v27.0.0"):
        release(CURRENT, [])
    with pytest.raises(ValueError, match="no release candidate of v27.1.0"):
        release(RELEASED, ["v27.0.0-rc.5"])
    with pytest.raises(ValueError, match="no release candidate is"):
        release(RELEASED, ["v27.0.0"])


def test_previous_stable_is_the_newest_release_below() -> None:
    tags = ["v27.0.0", "v27.1.0", "v27.1.0-rc.2", "v27.2.0"]
    assert previous_stable(tags, "v27.2.0") == "v27.1.0"
    assert previous_stable(tags, "v27.0.0") is None
    with pytest.raises(ValueError):
        previous_stable(tags, "v27.2.0-rc.1")


def test_pull_requests_come_from_squash_and_merge_commits() -> None:
    commits = [
        ("Tag promoted images as exact copies (#183)", ""),
        ("Merge pull request #133 from Theriark/feat/x", "\nAdd the first-run check\n"),
        ("ci: register ci.yml on the default branch", ""),
        ("Again (#183)", ""),
    ]
    items = pull_requests(commits)
    assert items == [(183, "Tag promoted images as exact copies"), (133, "Add the first-run check")]
    notes = render("v27.0.0", None, items)
    assert notes.startswith("## Pull requests merged in the first release\n")
    assert "- Add the first-run check (#133)" in notes
    assert render("v27.1.0", "v27.0.0", []).endswith("since v27.0.0\n\n- none\n")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def commit(cwd: Path, message: str) -> str:
    git(cwd, "commit", "--allow-empty", "-q", "-m", message)
    return git(cwd, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "ci@example.invalid")
    git(tmp_path, "config", "user.name", "ci")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_command_line_on_a_real_repository(
    repository: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = commit(repository, "First (#1)")
    git(repository, "tag", "-a", "v27.0.0-rc.5", "-m", "{}")
    second = commit(repository, "Second (#2)")
    git(repository, "tag", "-a", "v27.1.0-rc.1", "-m", "{}")
    head = commit(repository, "Third (#3)")

    assert release_version.main(["candidate", head]) == 0
    assert capsys.readouterr().out == "v27.0.0-rc.6 new\n"
    assert release_version.main(["candidate", first]) == 0
    assert capsys.readouterr().out == "v27.0.0-rc.5 existing\n"
    assert release_version.main(["release", second]) == 0
    assert capsys.readouterr().out == "v27.0.0 v27.1.0-rc.1\n"
    assert release_version.main(["release", head]) == 1
    assert "no release candidate" in capsys.readouterr().err
    assert release_version.main(["release", "HEAD"]) == 2
    assert release_version.main(["other", head]) == 2

    assert release_notes.main(["v27.0.0", second]) == 0
    out = capsys.readouterr().out
    assert "- Second (#2)" in out and "- First (#1)" in out and "Third" not in out
    git(repository, "tag", "-a", "v27.0.0", second, "-m", "{}")
    assert release_notes.main(["v27.1.0", head]) == 0
    out = capsys.readouterr().out
    assert out.startswith("## Pull requests merged since v27.0.0")
    assert "- Third (#3)" in out and "Second" not in out
    assert release_notes.main(["v27.1.0-rc.1", head]) == 2
