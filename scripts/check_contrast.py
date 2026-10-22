"""Contrast check for the design tokens of the web interface (P10-T1).

Reads docs/design-colours.json, computes the WCAG 2 contrast ratio of every listed pair of
tokens (foreground on background, per theme) and fails when a pair is below its minimum:
4.5 to 1 for text, 3 to 1 for graphics, focus rings and large text. The ratios are written as
a Markdown table so a reviewer can read them in the job summary without opening the log.

The token file is the single source of the colours; docs/mockups/theme.css and later the
application stylesheet copy its values (tests/unit/test_check_contrast.py keeps them equal).

Usage: python scripts/check_contrast.py [docs/design-colours.json] [--summary FILE]
       (the summary defaults to the file named by GITHUB_STEP_SUMMARY, when set)
Exit code: 0 every pair passes, 1 a pair is below its minimum, 2 token file or usage error.
"""

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_TOKENS = Path("docs/design-colours.json")
TEXT_MINIMUM = 4.5
GRAPHIC_MINIMUM = 3.0


class TokenError(Exception):
    """The token file is missing, unreadable or does not have the expected shape."""


@dataclass(frozen=True)
class Check:
    """One required contrast: the token `foreground` on the token `background` of `theme`."""

    theme: str
    foreground: str
    background: str
    minimum: float
    use: str


@dataclass(frozen=True)
class Result:
    check: Check
    foreground_hex: str
    background_hex: str
    ratio: float

    @property
    def passed(self) -> bool:
        return self.ratio + 1e-9 >= self.check.minimum


def parse_hex(value: str) -> tuple[int, int, int]:
    """Parse #RRGGBB (or RRGGBB) into three channel values 0 to 255."""
    text = value.strip().lstrip("#")
    if len(text) != 6:
        raise TokenError(f"not a six digit hex colour: {value!r}")
    try:
        return int(text[0:2], 16), int(text[2:4], 16), int(text[4:6], 16)
    except ValueError as error:
        raise TokenError(f"not a hex colour: {value!r}") from error


def _channel(value: int) -> float:
    srgb = value / 255.0
    if srgb <= 0.04045:
        return srgb / 12.92
    return ((srgb + 0.055) / 1.055) ** 2.4


def relative_luminance(rgb: tuple[int, int, int]) -> float:
    """Relative luminance as defined by WCAG 2 (sRGB, D65)."""
    red, green, blue = rgb
    return 0.2126 * _channel(red) + 0.7152 * _channel(green) + 0.0722 * _channel(blue)


def contrast_ratio(foreground: str, background: str) -> float:
    """WCAG 2 contrast ratio between two hex colours, 1.0 to 21.0; order does not matter."""
    lighter = relative_luminance(parse_hex(foreground))
    darker = relative_luminance(parse_hex(background))
    if lighter < darker:
        lighter, darker = darker, lighter
    return (lighter + 0.05) / (darker + 0.05)


def _themes(data: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    themes = data.get("themes")
    if not isinstance(themes, dict) or not themes:
        raise TokenError("the token file has no themes object")
    result: dict[str, dict[str, str]] = {}
    for theme_name, tokens in themes.items():
        if not isinstance(tokens, dict) or not tokens:
            raise TokenError(f"theme {theme_name} has no tokens")
        parsed: dict[str, str] = {}
        for token, value in tokens.items():
            if not isinstance(value, str):
                raise TokenError(f"theme {theme_name}: token {token} is not a string")
            parse_hex(value)
            parsed[str(token)] = value.upper()
        result[str(theme_name)] = parsed
    return result


def _checks(data: Mapping[str, Any]) -> list[Check]:
    raw = data.get("checks")
    if not isinstance(raw, list) or not raw:
        raise TokenError("the token file has no checks list")
    checks: list[Check] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise TokenError(f"check {index} is not an object")
        try:
            minimum = float(item["minimum"])
            check = Check(
                theme=str(item["theme"]),
                foreground=str(item["foreground"]),
                background=str(item["background"]),
                minimum=minimum,
                use=str(item.get("use", "")),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise TokenError(f"check {index} is incomplete: {error}") from error
        if minimum not in (TEXT_MINIMUM, GRAPHIC_MINIMUM):
            raise TokenError(
                f"check {index}: minimum must be {TEXT_MINIMUM} (text) or "
                f"{GRAPHIC_MINIMUM} (graphics), not {minimum}"
            )
        checks.append(check)
    return checks


def load_tokens(path: Path) -> tuple[dict[str, dict[str, str]], list[Check]]:
    """Read the token file: the themes with their colours and the list of required pairs."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise TokenError(f"cannot read the token file {path}: {error}") from error
    if not isinstance(data, dict):
        raise TokenError(f"{path} is not a JSON object")
    return _themes(data), _checks(data)


def evaluate(themes: Mapping[str, Mapping[str, str]], checks: Sequence[Check]) -> list[Result]:
    """Compute the ratio of every check; an unknown theme or token is a token file error."""
    results: list[Result] = []
    for check in checks:
        tokens = themes.get(check.theme)
        if tokens is None:
            raise TokenError(f"check uses unknown theme {check.theme!r}")
        try:
            foreground = tokens[check.foreground]
            background = tokens[check.background]
        except KeyError as error:
            raise TokenError(f"theme {check.theme}: unknown token {error.args[0]!r}") from error
        results.append(
            Result(check, foreground, background, contrast_ratio(foreground, background))
        )
    return results


def render_markdown(results: Sequence[Result]) -> str:
    """The results as a Markdown table, failures first within the same order."""
    lines = [
        "## Design token contrast",
        "",
        "| Theme | Foreground | Background | Ratio | Minimum | Use | Result |",
        "|---|---|---|---|---|---|---|",
    ]
    for result in results:
        check = result.check
        lines.append(
            f"| {check.theme} | {check.foreground} {result.foreground_hex} | "
            f"{check.background} {result.background_hex} | {result.ratio:.2f} to 1 | "
            f"{check.minimum:g} to 1 | {check.use} | {'pass' if result.passed else 'FAIL'} |"
        )
    failed = sum(1 for result in results if not result.passed)
    lines.append("")
    lines.append(
        f"{len(results)} pairs checked, {failed} below the minimum."
        if failed
        else f"{len(results)} pairs checked, all at or above their minimum."
    )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Contrast check for the design tokens.")
    parser.add_argument("tokens", nargs="?", type=Path, default=DEFAULT_TOKENS)
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="append the Markdown table to this file (default: $GITHUB_STEP_SUMMARY when set)",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    env = os.environ if environ is None else environ
    try:
        themes, checks = load_tokens(args.tokens)
        results = evaluate(themes, checks)
    except TokenError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2
    markdown = render_markdown(results)
    print(markdown, end="")
    summary: Path | None = args.summary
    if summary is None and env.get("GITHUB_STEP_SUMMARY"):
        summary = Path(env["GITHUB_STEP_SUMMARY"])
    if summary is not None:
        with summary.open("a", encoding="utf-8") as handle:
            handle.write(markdown)
    failures = [result for result in results if not result.passed]
    for result in failures:
        check = result.check
        print(
            f"::error::{check.theme}: {check.foreground} on {check.background} is "
            f"{result.ratio:.2f} to 1, below {check.minimum:g} to 1 ({check.use})",
            file=sys.stderr,
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
