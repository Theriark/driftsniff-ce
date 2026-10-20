"""Tests for scripts/check_licenses.py."""

from pathlib import Path

import pytest

from check_licenses import find_problems, licence_allowed, licence_candidates, main


@pytest.mark.parametrize(
    "text",
    [
        "MIT",
        "MIT License",
        "BSD-3-Clause",
        "BSD License",
        "Apache-2.0",
        "Apache License, Version 2.0",
        "Apache-2.0 OR BSD-3-Clause",
        "(MIT AND Python-2.0)",
        "ISC",
        "PSF-2.0",
        "0BSD",
        "Unlicense",
        "Zlib",
        "HPND",
    ],
)
def test_allowed_licences(text: str) -> None:
    assert licence_allowed(text)


@pytest.mark.parametrize(
    "text",
    [
        "GPL-3.0-only",
        "GNU General Public License v3 (GPLv3)",
        "AGPL-3.0-or-later",
        "MIT AND GPL-2.0-only",
        "MPL-2.0",
        "Proprietary",
        "MIT WITH Classpath-exception-2.0",
        "MIT OR",
        "(MIT",
        "",
    ],
)
def test_blocked_or_unrecognised_licences(text: str) -> None:
    assert not licence_allowed(text)


def test_a_gpl_package_in_the_runtime_lock_is_reported() -> None:
    gpl = "GNU General Public License v3 (GPLv3)"
    problems = find_problems({"fine": ["MIT"], "copyleft": [gpl]})
    assert len(problems) == 1
    assert problems[0].startswith("copyleft:")


def test_a_package_without_any_licence_text_is_reported() -> None:
    assert find_problems({"mystery": []}) == [
        "mystery: licence not allowed or not recognised (none declared)"
    ]


def test_certifi_is_the_only_mpl_exception() -> None:
    assert find_problems({"certifi": ["MPL-2.0"]}) == []
    assert find_problems({"other": ["MPL-2.0"]}) != []


def test_real_metadata_of_an_installed_package_is_read() -> None:
    texts = licence_candidates("pytest")
    assert texts
    assert find_problems({"pytest": texts}) == []


def test_main_reports_a_package_that_is_not_installed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = tmp_path / "requirements.txt"
    lock.write_text("definitely-not-installed-xyz==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    assert main([str(lock)]) == 1
    assert "not installed" in capsys.readouterr().err


def test_main_passes_for_an_installed_allowed_package(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.txt"
    lock.write_text("pytest==0.0.0 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    assert main([str(lock)]) == 0


def test_main_fails_for_a_missing_file(tmp_path: Path) -> None:
    assert main([str(tmp_path / "missing.txt")]) == 1
