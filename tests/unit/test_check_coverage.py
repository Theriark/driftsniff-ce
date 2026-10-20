"""Tests for scripts/check_coverage.py: the per-package gate and the job summary."""

import json
from pathlib import Path

import pytest

from check_coverage import (
    Counts,
    ReportError,
    evaluate,
    load_modules,
    main,
    render_markdown,
    split_path,
)

Entry = dict[str, dict[str, int]]
Files = dict[str, Entry]


def entry(statements: int, covered: int, branches: int = 0, covered_branches: int = 0) -> Entry:
    return {
        "summary": {
            "num_statements": statements,
            "covered_lines": covered,
            "num_branches": branches,
            "covered_branches": covered_branches,
        }
    }


def write_report(tmp_path: Path, files: Files) -> Path:
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"files": files}), encoding="utf-8")
    return path


def healthy_files() -> Files:
    return {
        "src/driftsniff/core/states.py": entry(40, 40, 10, 10),
        "src/driftsniff/core/snapshots.py": entry(50, 48, 10, 8),
        "src/driftsniff/secrets/__init__.py": entry(0, 0),
        "src/driftsniff/rules/__init__.py": entry(0, 0),
        "src/driftsniff/main.py": entry(10, 5),
    }


def test_counts_use_statements_and_branches_together() -> None:
    counts = Counts(statements=8, branches=2, hit=9)
    assert counts.total == 10
    assert counts.missed == 1
    assert counts.percent == pytest.approx(90.0)


def test_counts_without_statements_are_fully_covered() -> None:
    assert Counts().percent == 100.0


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("src/driftsniff/core/states.py", ("core", "driftsniff/core/states.py")),
        ("src\\driftsniff\\rules\\x.py", ("rules", "driftsniff/rules/x.py")),
        ("/work/repo/src/driftsniff/secrets/a/b.py", ("secrets", "driftsniff/secrets/a/b.py")),
        ("src/driftsniff/main.py", ("(top level)", "driftsniff/main.py")),
        ("scripts/other.py", ("(outside driftsniff)", "scripts/other.py")),
        ("driftsniff", ("(outside driftsniff)", "driftsniff")),
    ],
)
def test_split_path(name: str, expected: tuple[str, str]) -> None:
    assert split_path(name) == expected


def test_load_modules_reads_every_file_sorted(tmp_path: Path) -> None:
    modules = load_modules(write_report(tmp_path, healthy_files()))
    assert [module.path for module in modules] == sorted(module.path for module in modules)
    states = next(module for module in modules if module.path.endswith("core/states.py"))
    assert states.package == "core"
    assert states.counts == Counts(statements=40, branches=10, hit=50)


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        json.dumps({"files": []}),
        json.dumps({"files": {"src/driftsniff/core/a.py": {}}}),
        json.dumps({"files": {"src/driftsniff/core/a.py": entry(-1, 0)}}),
        json.dumps({"files": {"src/driftsniff/core/a.py": entry(True, 0)}}),
    ],
)
def test_load_modules_rejects_a_bad_report(tmp_path: Path, content: str) -> None:
    path = tmp_path / "coverage.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ReportError):
        load_modules(path)


def test_load_modules_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="cannot read"):
        load_modules(tmp_path / "missing.json")


def test_evaluate_gates_only_the_named_packages(tmp_path: Path) -> None:
    modules = load_modules(write_report(tmp_path, healthy_files()))
    results, total = evaluate(modules, ("core", "secrets", "rules"), 90.0)
    by_name = {result.name: result for result in results}
    assert by_name["core"].gated and by_name["core"].passed
    assert by_name["secrets"].counts == Counts()
    assert by_name["secrets"].passed
    assert not by_name["(top level)"].gated
    assert by_name["(top level)"].passed
    assert total.statements == 100


def test_evaluate_fails_a_gated_package_below_the_minimum(tmp_path: Path) -> None:
    files = healthy_files()
    files["src/driftsniff/core/bad.py"] = entry(100, 10)
    results, _ = evaluate(load_modules(write_report(tmp_path, files)), ("core",), 90.0)
    assert [result.name for result in results if not result.passed] == ["core"]


def test_evaluate_passes_exactly_at_the_minimum(tmp_path: Path) -> None:
    files = {"src/driftsniff/core/a.py": entry(10, 9)}
    results, _ = evaluate(load_modules(write_report(tmp_path, files)), ("core",), 90.0)
    assert all(result.passed for result in results)


def test_evaluate_fails_just_below_the_minimum(tmp_path: Path) -> None:
    files = {"src/driftsniff/core/a.py": entry(1000, 899)}
    results, _ = evaluate(load_modules(write_report(tmp_path, files)), ("core",), 90.0)
    assert not results[0].passed


def test_evaluate_lists_a_gated_package_that_has_no_files(tmp_path: Path) -> None:
    files = {"src/driftsniff/main.py": entry(4, 4)}
    results, _ = evaluate(load_modules(write_report(tmp_path, files)), ("core",), 90.0)
    assert {(result.name, result.gated, result.passed) for result in results} == {
        ("(top level)", False, True),
        ("core", True, True),
    }


def test_markdown_shows_total_packages_and_modules(tmp_path: Path) -> None:
    modules = load_modules(write_report(tmp_path, healthy_files()))
    results, total = evaluate(modules, ("core", "secrets", "rules"), 90.0)
    text = render_markdown(results, total, modules, 90.0)
    assert text.startswith("## Coverage")
    assert "| **TOTAL** | 100 | 20 |" in text
    assert "| driftsniff.core | 90 | 20 | 4 | 96.36% | pass (minimum 90%) |" in text
    assert "| driftsniff.secrets | 0 | 0 | 0 | no statements | pass (minimum 90%) |" in text
    assert "| driftsniff/core/states.py | 40 | 10 | 0 | 100.00% |" in text
    assert "**pass**" in text


def test_markdown_names_the_failed_package(tmp_path: Path) -> None:
    files = {"src/driftsniff/rules/a.py": entry(10, 1)}
    modules = load_modules(write_report(tmp_path, files))
    results, total = evaluate(modules, ("rules",), 90.0)
    text = render_markdown(results, total, modules, 90.0)
    assert "**FAIL: driftsniff.rules**" in text
    assert "| driftsniff.rules | 10 | 0 | 9 | 10.00% | FAIL (minimum 90%) |" in text


def test_main_passes_and_writes_the_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, healthy_files())
    summary = tmp_path / "summary.md"
    summary.write_text("earlier content\n", encoding="utf-8")
    assert main([str(report)], {"GITHUB_STEP_SUMMARY": str(summary)}) == 0
    written = summary.read_text(encoding="utf-8")
    assert written.startswith("earlier content\n## Coverage")
    assert "TOTAL" in capsys.readouterr().out


def test_main_fails_when_coverage_drops(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    files = healthy_files()
    files["src/driftsniff/core/states.py"] = entry(40, 20, 10, 5)
    report = write_report(tmp_path, files)
    summary = tmp_path / "summary.md"
    assert main([str(report), "--summary", str(summary)], {}) == 1
    assert "FAIL" in summary.read_text(encoding="utf-8")
    assert "::error::driftsniff.core coverage" in capsys.readouterr().err


def test_main_honours_a_custom_minimum_and_packages(tmp_path: Path) -> None:
    report = write_report(tmp_path, healthy_files())
    assert main([str(report), "--min", "99", "--package", "core"], {}) == 1
    assert main([str(report), "--min", "99", "--package", "secrets"], {}) == 0


def test_main_rejects_a_missing_report_and_a_bad_minimum(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(tmp_path / "missing.json")], {}) == 2
    assert "cannot read" in capsys.readouterr().err
    report = write_report(tmp_path, healthy_files())
    assert main([str(report), "--min", "101"], {}) == 2
    assert main([], {}) == 2
