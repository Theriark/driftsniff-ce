"""Fail unless a switch variable holds the exact text true.

The promotion workflows run this first. A repository variable that is unset, empty or anything
other than the lower case text true stops the run before any deploy step, so a disabled promotion
shows as a failed run and never as a skipped job that looks like success.

Usage: python scripts/guard_enabled.py VARIABLE_NAME   (the workflow passes the value in the
environment variable of that name)
"""

import os
import sys
from collections.abc import Mapping, Sequence

ENABLED = "true"


def is_enabled(value: str | None) -> bool:
    """True only for the exact text true: no other case, no surrounding white space."""
    return value == ENABLED


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    """Return 0 when the named variable is true, 1 when it is not, 2 for a usage error."""
    args = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if environ is None else environ
    if len(args) != 1 or not args[0]:
        print("usage: guard_enabled.py VARIABLE_NAME", file=sys.stderr)
        return 2
    name = args[0]
    if is_enabled(env.get(name)):
        print(f"{name} is true: the guarded workflow may continue")
        return 0
    print(
        f"{name} is not true (unset or any other value): stopping before any deploy step",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
