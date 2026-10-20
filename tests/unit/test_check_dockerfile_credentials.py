"""Tests for scripts/check_dockerfile_credentials.py and the shipped Dockerfile contract."""

from pathlib import Path

import pytest

from check_dockerfile_credentials import check_text, main

REPO_ROOT = Path(__file__).resolve().parents[2]

BAD_DOCKERFILE = """\
FROM python:3.12-slim
ARG SOURCE_SHA=unknown
ARG GITHUB_TOKEN
ENV APP_SECRET=abc \\
    DB_PASSWORD=abc \\
    PORT=8080
ENV api_key legacy value
"""

GOOD_DOCKERFILE = """\
FROM python:3.12-slim
# ARG GITHUB_TOKEN in a comment is ignored
ARG SOURCE_SHA=unknown
ENV PYTHONUNBUFFERED=1 \\
    GREETING="my secret value"
"""


def test_seeded_bad_dockerfile_reports_every_credential_name() -> None:
    problems = check_text(BAD_DOCKERFILE)
    assert len(problems) == 4
    assert "line 3: ARG GITHUB_TOKEN" in problems[0]
    assert "line 4: ENV APP_SECRET" in problems[1]
    assert "line 4: ENV DB_PASSWORD" in problems[2]
    assert "line 7: ENV api_key" in problems[3]


def test_clean_dockerfile_passes_and_values_are_not_names() -> None:
    assert check_text(GOOD_DOCKERFILE) == []


def test_unparsable_instruction_is_reported() -> None:
    problems = check_text('ENV BROKEN="unterminated\n')
    assert problems == ["line 1: cannot parse ENV instruction"]


def test_main_fails_on_the_seeded_bad_dockerfile(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "Dockerfile"
    bad.write_text(BAD_DOCKERFILE, encoding="utf-8")
    assert main([str(bad)]) == 1
    assert "GITHUB_TOKEN" in capsys.readouterr().err


def test_main_passes_a_clean_dockerfile_and_fails_on_a_missing_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = tmp_path / "Dockerfile"
    good.write_text(GOOD_DOCKERFILE, encoding="utf-8")
    assert main([str(good)]) == 0
    assert "no credential-like" in capsys.readouterr().out
    assert main([str(tmp_path / "missing")]) == 1


def test_shipped_dockerfile_has_no_credential_names() -> None:
    assert main([str(REPO_ROOT / "Dockerfile")]) == 0


def test_shipped_dockerfile_declares_the_runtime_contract() -> None:
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    for expected in (
        "USER 10001:10001",
        "EXPOSE 8080",
        "--require-hashes",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONUNBUFFERED=1",
        'ENTRYPOINT ["python", "-m", "driftsniff", "serve"]',
        '"python", "-m", "driftsniff", "healthcheck"',
        "org.opencontainers.image.licenses=\"MIT\"",
    ):
        assert expected in text
