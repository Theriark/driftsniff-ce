"""Release notes for release.yml: the pull requests merged since the previous stable release.

Reads the first-parent history of COMMIT back to the newest stable tag below VERSION (the whole
history for the first release) and lists every commit that came from a pull request: a squash
merge "Title (#123)" or a merge commit "Merge pull request #123 from ..." (its title is the first
line of the body). Writes Markdown to stdout and changes nothing.

Usage: release_notes.py VERSION_TAG COMMIT
"""

import re
import subprocess
import sys
from collections.abc import Iterable, Sequence

from release_version import parse

SQUASH = re.compile(r"^(?P<title>.+?)\s*\(#(?P<number>[1-9][0-9]*)\)$")
MERGE = re.compile(r"^Merge pull request #(?P<number>[1-9][0-9]*) from \S+")


def previous_stable(tags: Iterable[str], version_tag: str) -> str | None:
    """Newest stable tag strictly below version_tag, or None for the first release."""
    target = parse(version_tag)
    if target is None or target[1] is not None:
        raise ValueError(f"{version_tag} is not a stable version tag")
    older = []
    for tag in tags:
        found = parse(tag)
        if found is not None and found[1] is None and found[0] < target[0]:
            older.append((found[0], tag.strip()))
    return max(older)[1] if older else None


def pull_requests(commits: Iterable[tuple[str, str]]) -> list[tuple[int, str]]:
    """(number, title) of each (subject, body) that came from a pull request, newest first."""
    found: list[tuple[int, str]] = []
    seen: set[int] = set()
    for subject, body in commits:
        title = ""
        squash = SQUASH.fullmatch(subject.strip())
        merge = MERGE.match(subject.strip())
        if squash:
            number, title = int(squash["number"]), squash["title"]
        elif merge:
            number = int(merge["number"])
            title = next((row.strip() for row in body.splitlines() if row.strip()), subject)
        else:
            continue
        if number not in seen:
            seen.add(number)
            found.append((number, title))
    return found


def render(version_tag: str, previous: str | None, items: Sequence[tuple[int, str]]) -> str:
    since = f"since {previous}" if previous else "in the first release"
    rows = [f"## Pull requests merged {since}", ""]
    rows += [f"- {title} (#{number})" for number, title in items] or ["- none"]
    return "\n".join(rows) + "\n"


def _git(*args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or not re.fullmatch(r"[0-9a-f]{40}", args[1]):
        print("usage: release_notes.py VERSION_TAG COMMIT", file=sys.stderr)
        return 2
    version_tag, commit = args
    try:
        previous = previous_stable(_git("tag", "--list", "v27.*").split(), version_tag)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    span = f"{previous}..{commit}" if previous else commit
    log = _git("log", "--first-parent", "--format=%s%x1f%b%x1e", span)
    commits = []
    for record in log.split("\x1e"):
        if record.strip():
            subject, _, body = record.strip("\n").partition("\x1f")
            commits.append((subject, body))
    print(render(version_tag, previous, pull_requests(commits)), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
