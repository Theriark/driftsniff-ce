"""Tests for scripts/check_migrations.py: upgrade from earlier schemas, refuse every downgrade."""

import textwrap
from pathlib import Path

import pytest
from alembic.config import Config

import check_migrations
from check_migrations import Report, main, run_checks
from driftsniff.db.migrate import MIGRATIONS_DIR, head_revision


def revision_source(revision: str, down: str | None, downgrade_body: str) -> str:
    return textwrap.dedent(
        f'''\
        """Test revision {revision}."""

        import sqlalchemy as sa
        from alembic import op

        revision = "{revision}"
        down_revision = {down!r}
        branch_labels = None
        depends_on = None


        def upgrade() -> None:
            op.create_table("t_{revision}", sa.Column("id", sa.Integer, primary_key=True))


        def downgrade() -> None:
            {downgrade_body}
        '''
    )


def make_config(tmp_path: Path, revisions: dict[str, tuple[str | None, str]]) -> Config:
    """An alembic setup with the given revisions: id -> (down revision, downgrade body)."""
    scripts = tmp_path / "scripts"
    versions = scripts / "versions"
    versions.mkdir(parents=True)
    (scripts / "env.py").write_text(
        (MIGRATIONS_DIR / "env.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    for revision, (down, body) in revisions.items():
        (versions / f"rev_{revision}.py").write_text(
            revision_source(revision, down, body), encoding="utf-8"
        )
    config = Config()
    config.set_main_option("script_location", str(scripts).replace("%", "%%"))
    return config


REFUSED = 'raise NotImplementedError("refused")'


def names(items: list[tuple[str, str]]) -> list[str]:
    return [name for name, _ in items]


def test_the_real_migrations_pass_every_check(tmp_path: Path) -> None:
    report = run_checks(tmp_path)
    assert report.failed == []
    head = head_revision()
    assert "upgrade from an empty database" in names(report.passed)
    assert f"upgrade a copy from 0001 to {head}" in names(report.passed)
    assert "downgrade from 0001 is refused" in names(report.passed)
    assert f"downgrade from {head} is refused" in names(report.passed)


def test_a_chain_that_refuses_downgrades_passes(tmp_path: Path) -> None:
    config = make_config(
        tmp_path, {"a1": (None, REFUSED), "b2": ("a1", REFUSED), "c3": ("b2", REFUSED)}
    )
    work = tmp_path / "work"
    work.mkdir()
    report = run_checks(work, config)
    assert report.failed == []
    assert names(report.passed) == [
        "migrations form one line",
        "upgrade from an empty database",
        "upgrade a copy from a1 to c3",
        "upgrade a copy from b2 to c3",
        "downgrade from a1 is refused",
        "downgrade from b2 is refused",
        "downgrade from c3 is refused",
    ]


def test_a_working_downgrade_is_reported(tmp_path: Path) -> None:
    config = make_config(
        tmp_path,
        {"a1": (None, REFUSED), "b2": ("a1", 'op.drop_table("t_b2")')},
    )
    work = tmp_path / "work"
    work.mkdir()
    report = run_checks(work, config)
    assert names(report.failed) == ["downgrade from b2 is refused"]
    assert "was not refused" in report.failed[0][1]
    assert "downgrade from a1 is refused" in names(report.passed)


def test_two_heads_are_reported_and_stop_the_run(tmp_path: Path) -> None:
    config = make_config(tmp_path, {"a1": (None, REFUSED), "b2": (None, REFUSED)})
    work = tmp_path / "work"
    work.mkdir()
    report = run_checks(work, config)
    assert names(report.failed) == ["migrations form one line"]
    assert "exactly one head" in report.failed[0][1]
    assert report.passed == []


def test_a_migration_that_crashes_is_a_failed_check(tmp_path: Path) -> None:
    config = make_config(tmp_path, {"a1": (None, REFUSED)})
    broken = tmp_path / "scripts" / "versions" / "rev_b2.py"
    broken.write_text(
        revision_source("b2", "a1", REFUSED).replace(
            'op.create_table("t_b2", sa.Column("id", sa.Integer, primary_key=True))',
            'op.drop_table("does_not_exist")',
        ),
        encoding="utf-8",
    )
    work = tmp_path / "work"
    work.mkdir()
    report = run_checks(work, config)
    assert "upgrade from an empty database" in names(report.failed)
    assert report.passed == [("migrations form one line", "one head: b2")]


def test_main_exits_0_and_writes_the_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "summary.md"
    code = main(["--work-dir", str(tmp_path / "work")], {"GITHUB_STEP_SUMMARY": str(summary)})
    assert code == 0
    written = summary.read_text(encoding="utf-8")
    assert written.startswith("## Migrations")
    assert "| upgrade from an empty database | pass |" in written
    assert "FAIL" not in written
    assert "pass  downgrade from 0001 is refused" in capsys.readouterr().out


def test_main_exits_1_when_a_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing(work_dir: Path, config: Config | None = None) -> Report:
        return Report(passed=[("a", "fine")], failed=[("downgrade from 0002 is refused", "x")])

    monkeypatch.setattr(check_migrations, "run_checks", failing)
    summary = tmp_path / "summary.md"
    assert main([], {"GITHUB_STEP_SUMMARY": str(summary)}) == 1
    error = capsys.readouterr().err
    assert "::error::migration check failed: downgrade from 0002 is refused" in error
    assert "**FAIL**" in summary.read_text(encoding="utf-8")


def test_main_rejects_an_unknown_option() -> None:
    assert main(["--bogus"], {}) == 2
