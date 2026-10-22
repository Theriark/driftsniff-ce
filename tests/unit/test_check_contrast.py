"""Tests for scripts/check_contrast.py and the design token files it guards (P10-T1).

The last three tests run against the committed files, so the pull request checks fail when a
token pair drops below its minimum or when docs/mockups/theme.css drifts from the JSON.
"""

import json
import re
from pathlib import Path

import pytest

from check_contrast import (
    GRAPHIC_MINIMUM,
    TEXT_MINIMUM,
    Check,
    TokenError,
    contrast_ratio,
    evaluate,
    load_tokens,
    main,
    parse_hex,
    render_markdown,
)

REPOSITORY = Path(__file__).resolve().parents[2]
TOKENS = REPOSITORY / "docs" / "design-colours.json"
THEME_CSS = REPOSITORY / "docs" / "mockups" / "theme.css"
BRAND = {"ink": "#1E1E24", "slate": "#6B7280", "alert": "#C8342B", "paper": "#F5F5F0"}
# Tokens that are only ever a background: they appear in checks as the background side.
BACKGROUND_ROLES = {
    "paper",
    "surface",
    "surface-2",
    "primary",
    "diff-removed",
    "diff-added",
}


def write_tokens(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
    return path


def small_tokens() -> dict[str, object]:
    return {
        "themes": {"light": {"text": "#1E1E24", "paper": "#F5F5F0", "slate": "#6B7280"}},
        "checks": [
            {"theme": "light", "foreground": "text", "background": "paper", "minimum": 4.5},
            {"theme": "light", "foreground": "slate", "background": "paper", "minimum": 3.0},
        ],
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [("#FFFFFF", (255, 255, 255)), ("000000", (0, 0, 0)), (" #1e1e24 ", (30, 30, 36))],
)
def test_parse_hex(value: str, expected: tuple[int, int, int]) -> None:
    assert parse_hex(value) == expected


@pytest.mark.parametrize("value", ["#FFF", "#GGGGGG", "", "#1E1E2"])
def test_parse_hex_rejects_other_shapes(value: str) -> None:
    with pytest.raises(TokenError):
        parse_hex(value)


def test_contrast_ratio_matches_the_wcag_reference_values() -> None:
    assert contrast_ratio("#FFFFFF", "#000000") == pytest.approx(21.0)
    assert contrast_ratio("#000000", "#FFFFFF") == pytest.approx(21.0)
    assert contrast_ratio("#777777", "#FFFFFF") == pytest.approx(4.48, abs=0.01)
    # The dev work plan states these two figures for the brand palette.
    assert contrast_ratio(BRAND["slate"], BRAND["paper"]) == pytest.approx(4.4, abs=0.05)
    assert contrast_ratio("#4B5563", BRAND["paper"]) == pytest.approx(6.9, abs=0.05)


def test_load_tokens_reads_themes_and_checks(tmp_path: Path) -> None:
    themes, checks = load_tokens(write_tokens(tmp_path, small_tokens()))
    assert themes == {"light": {"text": "#1E1E24", "paper": "#F5F5F0", "slate": "#6B7280"}}
    assert checks == [
        Check("light", "text", "paper", TEXT_MINIMUM, ""),
        Check("light", "slate", "paper", GRAPHIC_MINIMUM, ""),
    ]


@pytest.mark.parametrize(
    "data",
    [
        "not json",
        [],
        {"themes": {}, "checks": []},
        {"themes": {"light": {}}, "checks": []},
        {"themes": {"light": {"text": 1}}, "checks": []},
        {"themes": {"light": {"text": "#12345"}}, "checks": []},
        {"themes": {"light": {"text": "#1E1E24"}}, "checks": []},
        {"themes": {"light": {"text": "#1E1E24"}}, "checks": ["x"]},
        {"themes": {"light": {"text": "#1E1E24"}}, "checks": [{"theme": "light"}]},
        {
            "themes": {"light": {"text": "#1E1E24"}},
            "checks": [{"theme": "light", "foreground": "a", "background": "b", "minimum": 2}],
        },
    ],
)
def test_load_tokens_rejects_a_bad_file(tmp_path: Path, data: object) -> None:
    with pytest.raises(TokenError):
        load_tokens(write_tokens(tmp_path, data))


def test_load_tokens_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(TokenError, match="cannot read"):
        load_tokens(tmp_path / "missing.json")


def test_evaluate_rejects_an_unknown_theme_or_token() -> None:
    themes = {"light": {"text": "#1E1E24"}}
    with pytest.raises(TokenError, match="unknown theme"):
        evaluate(themes, [Check("dark", "text", "text", TEXT_MINIMUM, "")])
    with pytest.raises(TokenError, match="unknown token"):
        evaluate(themes, [Check("light", "text", "paper", TEXT_MINIMUM, "")])


def test_evaluate_passes_exactly_at_the_minimum() -> None:
    # #767676 on white is the classic 4.54 to 1 pair; #777777 is just below 4.5 to 1.
    themes = {"light": {"ok": "#767676", "low": "#777777", "white": "#FFFFFF"}}
    results = evaluate(
        themes,
        [
            Check("light", "ok", "white", TEXT_MINIMUM, "ok"),
            Check("light", "low", "white", TEXT_MINIMUM, "low"),
            Check("light", "low", "white", GRAPHIC_MINIMUM, "graphic"),
        ],
    )
    assert [result.passed for result in results] == [True, False, True]


def test_markdown_lists_every_pair_and_the_count() -> None:
    themes = {"light": {"text": "#1E1E24", "paper": "#F5F5F0", "faint": "#D3D3CB"}}
    results = evaluate(
        themes,
        [
            Check("light", "text", "paper", TEXT_MINIMUM, "body"),
            Check("light", "faint", "paper", TEXT_MINIMUM, "too faint"),
        ],
    )
    text = render_markdown(results)
    assert text.startswith("## Design token contrast")
    assert "| light | text #1E1E24 | paper #F5F5F0 |" in text
    assert "| 4.5 to 1 | body | pass |" in text
    assert "| too faint | FAIL |" in text
    assert text.rstrip().endswith("2 pairs checked, 1 below the minimum.")


def test_main_passes_and_appends_the_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tokens = write_tokens(tmp_path, small_tokens())
    summary = tmp_path / "summary.md"
    summary.write_text("earlier\n", encoding="utf-8")
    assert main([str(tokens)], {"GITHUB_STEP_SUMMARY": str(summary)}) == 0
    assert summary.read_text(encoding="utf-8").startswith("earlier\n## Design token contrast")
    assert "all at or above their minimum" in capsys.readouterr().out


def test_main_fails_a_pair_below_the_minimum(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = small_tokens()
    data["checks"] = [
        {"theme": "light", "foreground": "slate", "background": "paper", "minimum": 4.5},
    ]
    tokens = write_tokens(tmp_path, data)
    summary = tmp_path / "summary.md"
    assert main([str(tokens), "--summary", str(summary)], {}) == 1
    assert "FAIL" in summary.read_text(encoding="utf-8")
    assert "::error::light: slate on paper is 4.4" in capsys.readouterr().err


def test_main_rejects_a_bad_file_and_bad_usage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(tmp_path / "missing.json")], {}) == 2
    assert "::error::cannot read" in capsys.readouterr().err
    assert main(["--no-such-option"], {}) == 2


# ---- the committed token file and the mock-up theme --------------------------------------


def test_the_committed_tokens_pass_every_check() -> None:
    assert main([str(TOKENS)], {}) == 0


def test_the_committed_tokens_keep_the_brand_colours_and_the_dark_theme() -> None:
    themes, checks = load_tokens(TOKENS)
    assert set(themes) == {"light", "dark"}
    for name, value in BRAND.items():
        assert themes["light"][name] == value
    assert themes["light"]["text-2"] == "#4B5563"
    assert set(themes["light"]) == set(themes["dark"]), "every token has a dark theme pair"
    for severity in ("low", "medium", "high", "critical"):
        assert f"sev-{severity}" in themes["light"]
    foregrounds = {(check.foreground, check.theme) for check in checks}
    backgrounds = {(check.background, check.theme) for check in checks}
    for theme in themes:
        for token in themes[theme]:
            if token == "border":
                continue  # decorative hairlines only; inputs and ticks use slate, which is checked
            if token.endswith("-tint") or token in BACKGROUND_ROLES:
                assert (token, theme) in backgrounds, f"{theme} token {token} is never checked"
            else:
                assert (token, theme) in foregrounds, f"{theme} token {token} has no contrast check"


def test_the_mockup_theme_copies_the_token_values() -> None:
    themes, _ = load_tokens(TOKENS)
    css = THEME_CSS.read_text(encoding="utf-8")
    light, dark = css.split("@media (prefers-color-scheme: dark)", 1)
    for theme, block in (("light", light), ("dark", dark)):
        found = dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6});", block))
        for token, value in themes[theme].items():
            assert found.get(token, "").upper() == value, f"{theme} --{token} differs from JSON"
