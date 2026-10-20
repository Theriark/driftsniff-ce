"""Fail when a Dockerfile ARG or ENV name looks like a credential.

Names containing KEY, SECRET, TOKEN or PASS (any case) are rejected: a build argument or an
environment value ends up in an image layer that everyone who can pull the image can read.
Pass secrets at run time (environment or mounted file), never in the Dockerfile.

Usage: python scripts/check_dockerfile_credentials.py [DOCKERFILE ...]   (default: Dockerfile)
"""

import re
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

SENSITIVE_PARTS = ("KEY", "SECRET", "TOKEN", "PASS")
INSTRUCTION = re.compile(r"^(ARG|ENV)\s+(.+)$", re.IGNORECASE)
REASON = "looks like a credential (contains KEY, SECRET, TOKEN or PASS)"


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations and drop comment and blank lines; keep the first line number."""
    lines: list[tuple[int, str]] = []
    pending = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not pending:
            start = number
        if stripped.endswith("\\"):
            pending = f"{pending} {stripped[:-1].strip()}"
            continue
        lines.append((start, f"{pending} {stripped}".strip()))
        pending = ""
    if pending:
        lines.append((start, pending.strip()))
    return lines


def declared_names(instruction: str, arguments: str) -> list[str]:
    """Names declared by one ARG or ENV instruction; arguments is the text after the keyword."""
    tokens = shlex.split(arguments)
    if instruction == "ENV" and tokens and "=" not in tokens[0]:
        return tokens[:1]  # legacy form: ENV NAME value with spaces
    return [token.split("=", 1)[0] for token in tokens]


def is_sensitive(name: str) -> bool:
    """True when the name contains one of the credential-like parts."""
    upper = name.upper()
    return any(part in upper for part in SENSITIVE_PARTS)


def check_text(text: str) -> list[str]:
    """Return one problem per ARG or ENV name that looks like a credential."""
    problems: list[str] = []
    for number, line in logical_lines(text):
        match = INSTRUCTION.match(line)
        if match is None:
            continue
        instruction = match.group(1).upper()
        try:
            names = declared_names(instruction, match.group(2))
        except ValueError:
            problems.append(f"line {number}: cannot parse {instruction} instruction")
            continue
        problems.extend(
            f"line {number}: {instruction} {name} {REASON}" for name in names if is_sensitive(name)
        )
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    """Check each Dockerfile; return 0 when every name is acceptable, 1 otherwise."""
    args = list(sys.argv[1:] if argv is None else argv)
    paths = [Path(arg) for arg in args] or [Path("Dockerfile")]
    failed = False
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as error:
            print(f"{path}: cannot read file: {error}", file=sys.stderr)
            failed = True
            continue
        problems = check_text(text)
        for problem in problems:
            print(f"{path}: {problem}", file=sys.stderr)
        if problems:
            failed = True
        else:
            print(f"{path}: no credential-like ARG or ENV names")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
