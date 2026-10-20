"""Per-package coverage gate and job summary for the pull request checks.

Reads the JSON report of coverage.py (pytest --cov-report=json:coverage.json), fails when a gated
package is below the minimum and writes the TOTAL, the per-package and the per-module lines as
Markdown to the job summary, so a reviewer can read them without opening the log.

Coverage counts statements and branches together (the project measures branch coverage). A gated
package without any statement passes and is shown as such: an empty package has nothing to cover.

Usage: python scripts/check_coverage.py coverage.json [--min 90] [--package core ...]
       [--summary FILE]   (the summary defaults to the file named by GITHUB_STEP_SUMMARY)
Exit code: 0 gate passed, 1 a gated package is below the minimum, 2 report or usage error.
"""

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

PACKAGE_ROOT = "driftsniff"
GATED_PACKAGES = ("core", "secrets", "rules")
MINIMUM_PERCENT = 90.0
TOP_LEVEL = "(top level)"
OUTSIDE = "(outside driftsniff)"


class ReportError(Exception):
    """The coverage report is missing, unreadable or not a coverage.py JSON report."""


@dataclass(frozen=True)
class Counts:
    """Statements and branches of a file or a package; hit is covered statements plus branches."""

    statements: int = 0
    branches: int = 0
    hit: int = 0

    @property
    def total(self) -> int:
        return self.statements + self.branches

    @property
    def missed(self) -> int:
        return self.total - self.hit

    @property
    def percent(self) -> float:
        return 100.0 if self.total == 0 else 100.0 * self.hit / self.total

    def plus(self, other: Self) -> Self:
        return type(self)(
            self.statements + other.statements,
            self.branches + other.branches,
            self.hit + other.hit,
        )


@dataclass(frozen=True)
class Module:
    path: str
    package: str
    counts: Counts


@dataclass(frozen=True)
class PackageResult:
    name: str
    counts: Counts
    gated: bool
    passed: bool


def split_path(name: str) -> tuple[str, str]:
    """Return (package, module path) for a measured file; the package is the first folder
    below driftsniff, or (top level) for a module directly in driftsniff."""
    parts = [part for part in name.replace("\\", "/").split("/") if part and part != "."]
    if PACKAGE_ROOT not in parts:
        return OUTSIDE, "/".join(parts)
    inside = parts[parts.index(PACKAGE_ROOT) + 1 :]
    if not inside:
        return OUTSIDE, "/".join(parts)
    package = inside[0] if len(inside) > 1 else TOP_LEVEL
    return package, "/".join([PACKAGE_ROOT, *inside])


def _count(summary: Mapping[str, Any], key: str) -> int:
    value = summary.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{key} is not a count: {value!r}")
    return value


def load_modules(path: Path) -> list[Module]:
    """Read every measured file of a coverage.py JSON report."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReportError(f"cannot read the coverage report {path}: {error}") from error
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        raise ReportError(f"{path} is not a coverage.py JSON report (no files object)")
    modules: list[Module] = []
    for name, entry in files.items():
        summary = entry.get("summary") if isinstance(entry, dict) else None
        if not isinstance(summary, dict):
            raise ReportError(f"{path}: {name} has no summary")
        try:
            counts = Counts(
                statements=_count(summary, "num_statements"),
                branches=_count(summary, "num_branches"),
                hit=_count(summary, "covered_lines") + _count(summary, "covered_branches"),
            )
        except ValueError as error:
            raise ReportError(f"{path}: {name}: {error}") from error
        package, module_path = split_path(str(name))
        modules.append(Module(module_path, package, counts))
    return sorted(modules, key=lambda module: module.path)


def evaluate(
    modules: Sequence[Module], gated: Sequence[str], minimum: float
) -> tuple[list[PackageResult], Counts]:
    """Return one result per package (gated ones always present) and the grand total."""
    per_package: dict[str, Counts] = {name: Counts() for name in gated}
    total = Counts()
    for module in modules:
        per_package[module.package] = per_package.get(module.package, Counts()).plus(module.counts)
        total = total.plus(module.counts)
    results = [
        PackageResult(
            name=name,
            counts=counts,
            gated=name in gated,
            passed=name not in gated or counts.percent >= minimum,
        )
        for name, counts in sorted(per_package.items())
    ]
    return results, total


def _percent(counts: Counts) -> str:
    return "no statements" if counts.total == 0 else f"{counts.percent:.2f}%"


def _gate_text(result: PackageResult, minimum: float) -> str:
    if not result.gated:
        return "not gated"
    verdict = "pass" if result.passed else "FAIL"
    return f"{verdict} (minimum {minimum:g}%)"


def render_markdown(
    results: Sequence[PackageResult],
    total: Counts,
    modules: Sequence[Module],
    minimum: float,
) -> str:
    """The job summary: the gate verdict, the per-package table and the per-module table."""
    failed = [result for result in results if not result.passed]
    if failed:
        verdict = "FAIL: " + ", ".join(f"{PACKAGE_ROOT}.{result.name}" for result in failed)
    else:
        verdict = "pass"
    lines = [
        "## Coverage",
        "",
        f"Gate (minimum {minimum:g}% on {', '.join(r.name for r in results if r.gated)}): "
        f"**{verdict}**",
        "",
        "| Package | Statements | Branches | Missed | Coverage | Gate |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for result in results:
        c = result.counts
        lines.append(
            f"| {PACKAGE_ROOT}.{result.name} | {c.statements} | {c.branches} | {c.missed} "
            f"| {_percent(c)} | {_gate_text(result, minimum)} |"
        )
    lines.append(
        f"| **TOTAL** | {total.statements} | {total.branches} | {total.missed} "
        f"| {_percent(total)} | not gated |"
    )
    lines += [
        "",
        "<details><summary>Per module</summary>",
        "",
        "| Module | Statements | Branches | Missed | Coverage |",
        "|---|---:|---:|---:|---:|",
    ]
    for module in modules:
        c = module.counts
        lines.append(
            f"| {module.path} | {c.statements} | {c.branches} | {c.missed} | {_percent(c)} |"
        )
    lines += ["", "</details>", ""]
    return "\n".join(lines)


def render_text(results: Sequence[PackageResult], total: Counts, minimum: float) -> str:
    """The same package lines for the log."""
    lines = [
        f"{PACKAGE_ROOT}.{result.name:<10} {_percent(result.counts):>14}  "
        f"{result.counts.hit}/{result.counts.total}  {_gate_text(result, minimum)}"
        for result in results
    ]
    lines.append(f"TOTAL{'':<16} {_percent(total):>14}  {total.hit}/{total.total}  not gated")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Per-package coverage gate.")
    parser.add_argument("report", type=Path, help="coverage.py JSON report")
    parser.add_argument("--min", dest="minimum", type=float, default=MINIMUM_PERCENT)
    parser.add_argument(
        "--package",
        dest="packages",
        action="append",
        help="gated package below driftsniff (repeat; default core, secrets, rules)",
    )
    parser.add_argument("--summary", type=Path, help="Markdown file to append the summary to")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    env = os.environ if environ is None else environ
    gated = tuple(args.packages) if args.packages else GATED_PACKAGES
    if not 0.0 <= args.minimum <= 100.0:
        print("error: --min must be between 0 and 100", file=sys.stderr)
        return 2
    try:
        modules = load_modules(args.report)
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    results, total = evaluate(modules, gated, args.minimum)
    print(render_text(results, total, args.minimum))
    summary: Path | None = args.summary
    if summary is None and env.get("GITHUB_STEP_SUMMARY"):
        summary = Path(env["GITHUB_STEP_SUMMARY"])
    if summary is not None:
        with summary.open("a", encoding="utf-8") as handle:
            handle.write(render_markdown(results, total, modules, args.minimum))
    failed = [result for result in results if not result.passed]
    for result in failed:
        print(
            f"::error::{PACKAGE_ROOT}.{result.name} coverage {result.counts.percent:.2f}% "
            f"is below the minimum {args.minimum:g}%",
            file=sys.stderr,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
