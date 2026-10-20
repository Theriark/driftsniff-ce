"""Migration checks for the pull request: upgrade from every earlier schema and refuse downgrades.

Everything runs on throw-away database files in a work directory, never on real data:

1. The migrations form one line (exactly one head).
2. An empty database upgrades to head. Its schema is the reference.
3. For every earlier revision (0001 and later ones that are not head): build a database at that
   revision, copy the file, upgrade the copy to head and require that the copy ends at head with
   the reference schema, passes the SQLite integrity and foreign key checks, and that the
   original file is untouched (still at its own revision).
4. For every revision: a downgrade of a copy at that revision must fail and leave the copy at the
   same revision with the same schema. Downgrades are refused, a backup is restored instead.

Usage: PYTHONPATH=src python scripts/check_migrations.py [--work-dir DIR]
Exit code: 0 all checks passed, 1 a check failed. The result is also appended to the job summary
file named by GITHUB_STEP_SUMMARY.
"""

import argparse
import os
import shutil
import sqlite3
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from driftsniff.db import migrate
from driftsniff.db.engine import Database

Schema = list[tuple[str, str, str | None]]


class CheckFailed(Exception):
    """One migration check failed; the message says what was found."""


@dataclass
class Report:
    """Outcome per check: (name, detail) pairs."""

    passed: list[tuple[str, str]] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)

    def run(self, name: str, check: Callable[[], str]) -> None:
        try:
            detail = check()
        except CheckFailed as error:
            self.failed.append((name, str(error)))
        except Exception as error:  # a migration that crashes is a failed check, not a crash here
            self.failed.append((name, f"{type(error).__name__}: {error}"))
        else:
            self.passed.append((name, detail))


def _migrate(database: Database, config: Config, action: Callable[[Config], None]) -> None:
    """Run an alembic command on the writer connection, the way driftsniff.db.migrate does."""
    with database.write() as connection:
        config.attributes["connection"] = connection
        action(config)


def _build_at(path: Path, config: Config, revision: str | None) -> None:
    """Create a database file at the given revision (None leaves it empty)."""
    database = Database(path)
    try:
        if revision is not None:
            target: str = revision
            _migrate(database, config, lambda cfg: command.upgrade(cfg, target))
    finally:
        database.close()


def _revisions(path: Path) -> tuple[str, ...]:
    database = Database(path)
    try:
        return migrate.current_revisions(database)
    finally:
        database.close()


def _schema(path: Path) -> Schema:
    """Tables, indexes and their SQL, without the alembic bookkeeping table."""
    with closing(sqlite3.connect(path)) as raw:
        rows = raw.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' AND name <> 'alembic_version' ORDER BY type, name"
        ).fetchall()
    return [(str(kind), str(name), None if sql is None else str(sql)) for kind, name, sql in rows]


def _integrity_problems(path: Path) -> list[str]:
    with closing(sqlite3.connect(path)) as raw:
        integrity = [str(row[0]) for row in raw.execute("PRAGMA integrity_check").fetchall()]
        foreign = [str(row) for row in raw.execute("PRAGMA foreign_key_check").fetchall()]
    problems = [f"integrity_check: {line}" for line in integrity if line != "ok"]
    return problems + [f"foreign_key_check: {line}" for line in foreign]


def _copy(source: Path, target: Path) -> None:
    """Copy a closed database file; Database.close() has already checkpointed the WAL."""
    shutil.copy2(source, target)


def _schema_difference(expected: Schema, actual: Schema) -> str:
    expected_sql = {(kind, name): sql for kind, name, sql in expected}
    actual_sql = {(kind, name): sql for kind, name, sql in actual}
    changes = (
        ("missing", sorted(expected_sql.keys() - actual_sql.keys())),
        ("unexpected", sorted(actual_sql.keys() - expected_sql.keys())),
        (
            "different SQL",
            sorted(
                key
                for key in expected_sql.keys() & actual_sql.keys()
                if expected_sql[key] != actual_sql[key]
            ),
        ),
    )
    parts = [
        f"{label}: " + ", ".join(f"{kind} {name}" for kind, name in keys)
        for label, keys in changes
        if keys
    ]
    return "; ".join(parts) or "same objects, different order"


def run_checks(work_dir: Path, config: Config | None = None) -> Report:
    """Run every check in work_dir (which must exist) and return the report."""
    active = config if config is not None else migrate._config()
    report = Report()
    script = ScriptDirectory.from_config(active)
    heads = script.get_heads()

    def single_line() -> str:
        if len(heads) != 1:
            raise CheckFailed(f"expected exactly one head revision, found {sorted(heads)}")
        return f"one head: {heads[0]}"

    report.run("migrations form one line", single_line)
    if report.failed:
        return report
    head = heads[0]
    order = [revision.revision for revision in reversed(list(script.walk_revisions()))]
    reference_path = work_dir / "empty-to-head.db"
    reference: Schema = []

    def from_empty() -> str:
        nonlocal reference
        _build_at(reference_path, active, "head")
        found = _revisions(reference_path)
        if found != (head,):
            raise CheckFailed(f"ended at {found}, expected ({head!r},)")
        problems = _integrity_problems(reference_path)
        if problems:
            raise CheckFailed("; ".join(problems))
        reference = _schema(reference_path)
        return f"empty -> {head}: {len(reference)} schema objects, integrity ok"

    report.run("upgrade from an empty database", from_empty)
    if report.failed:
        return report

    for start in order[:-1]:
        upgrade_check = _upgrade_copy(work_dir, active, start, head, reference)
        report.run(f"upgrade a copy from {start} to {head}", upgrade_check)
    for revision in order:
        downgrade_check = _refuse_downgrade(work_dir, active, revision)
        report.run(f"downgrade from {revision} is refused", downgrade_check)
    return report


def _upgrade_copy(
    work_dir: Path, config: Config, start: str, head: str, reference: Schema
) -> Callable[[], str]:
    def check() -> str:
        original = work_dir / f"from-{start}.db"
        copy = work_dir / f"from-{start}-copy.db"
        _build_at(original, config, start)
        if _revisions(original) != (start,):
            raise CheckFailed(f"could not build a database at {start}")
        _copy(original, copy)
        _build_at(copy, config, "head")
        found = _revisions(copy)
        if found != (head,):
            raise CheckFailed(f"the copy ended at {found}, expected ({head!r},)")
        if _revisions(original) != (start,):
            raise CheckFailed("the original database changed while its copy was upgraded")
        problems = _integrity_problems(copy)
        if problems:
            raise CheckFailed("; ".join(problems))
        actual = _schema(copy)
        if actual != reference:
            raise CheckFailed(
                "schema differs from the empty-to-head schema: "
                + _schema_difference(reference, actual)
            )
        return f"{start} -> {head} on a copy: same schema as empty -> {head}, integrity ok"

    return check


def _refuse_downgrade(work_dir: Path, config: Config, revision: str) -> Callable[[], str]:
    def check() -> str:
        original = work_dir / f"down-{revision}.db"
        copy = work_dir / f"down-{revision}-copy.db"
        _build_at(original, config, revision)
        _copy(original, copy)
        before = _schema(copy)
        database = Database(copy)
        try:
            try:
                _migrate(database, config, lambda cfg: command.downgrade(cfg, "-1"))
            except Exception as error:  # any refusal counts; what matters is that nothing changed
                refusal = type(error).__name__
            else:
                raise CheckFailed(f"the downgrade from {revision} was not refused")
        finally:
            database.close()
        if _revisions(copy) != (revision,):
            raise CheckFailed(f"the refused downgrade left the database at {_revisions(copy)}")
        if _schema(copy) != before:
            raise CheckFailed("the refused downgrade changed the schema")
        return f"refused with {refusal}; revision and schema unchanged"

    return check


def render_markdown(report: Report) -> str:
    lines = [
        "## Migrations",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    lines += [f"| {name} | pass | {detail} |" for name, detail in report.passed]
    lines += [f"| {name} | **FAIL** | {detail} |" for name, detail in report.failed]
    lines.append("")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migration checks on throw-away databases.")
    parser.add_argument("--work-dir", type=Path, help="directory for the database files")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    env = os.environ if environ is None else environ
    if args.work_dir is not None:
        args.work_dir.mkdir(parents=True, exist_ok=True)
        report = run_checks(args.work_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="driftsniff-migrations-") as directory:
            report = run_checks(Path(directory))
    for name, detail in report.passed:
        print(f"pass  {name}: {detail}")
    for name, detail in report.failed:
        print(f"FAIL  {name}: {detail}", file=sys.stderr)
        print(f"::error::migration check failed: {name}: {detail}", file=sys.stderr)
    if env.get("GITHUB_STEP_SUMMARY"):
        with Path(env["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as handle:
            handle.write(render_markdown(report))
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
