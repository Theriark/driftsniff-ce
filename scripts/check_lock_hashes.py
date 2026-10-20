"""Check that every package in a pip-compile lock file is pinned and has sha256 hashes.

Usage: python scripts/check_lock_hashes.py [LOCKFILE ...]   (default: requirements.txt)
"""

import re
import sys
from collections.abc import Sequence
from pathlib import Path

HASH_PATTERN = re.compile(r"--hash=sha256:[0-9a-f]{64}(?=\s|$)")
PIN_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==\S+")


def logical_lines(text: str) -> list[str]:
    """Join backslash continuations and drop comment and blank lines."""
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            pending = f"{pending} {stripped[:-1].strip()}"
            continue
        lines.append(f"{pending} {stripped}".strip())
        pending = ""
    if pending:
        lines.append(pending.strip())
    return lines


def requirement_names(text: str) -> list[str]:
    """Names of the pinned requirements in a lock file, in file order."""
    names: list[str] = []
    for line in logical_lines(text):
        match = PIN_PATTERN.match(line)
        if match is not None:
            names.append(match.group(1))
    return names


def check_text(text: str) -> tuple[int, list[str]]:
    """Return the package count and one problem per unpinned or unhashed package."""
    problems: list[str] = []
    packages = 0
    for line in logical_lines(text):
        if line.startswith("-"):
            continue
        match = PIN_PATTERN.match(line)
        if match is None:
            problems.append(f"not pinned with ==: {line.split()[0]}")
            continue
        packages += 1
        if not HASH_PATTERN.search(line):
            problems.append(f"no sha256 hash: {match.group(1)}")
    if packages == 0:
        problems.append("no packages found")
    return packages, problems


def main(argv: Sequence[str] | None = None) -> int:
    """Check each lock file; return 0 when every package has a hash, 1 otherwise."""
    args = list(sys.argv[1:] if argv is None else argv)
    paths = [Path(arg) for arg in args] or [Path("requirements.txt")]
    failed = False
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as error:
            print(f"{path}: cannot read file: {error}", file=sys.stderr)
            failed = True
            continue
        packages, problems = check_text(text)
        for problem in problems:
            print(f"{path}: {problem}", file=sys.stderr)
        if problems:
            failed = True
        else:
            print(f"{path}: {packages} packages, every one pinned with sha256 hashes")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
