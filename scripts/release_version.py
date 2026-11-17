"""Version line, next release candidate and stable version, read from the repository tags.

promote-stage.yml and release.yml call this so neither needs a typed input. The rules
(docs/ci-cd.md, "Versions"):

- One line for every product. The first release is 27.0.0 and its candidates are
  v27.0.0-rc.1, v27.0.0-rc.2, ... Tags are v27.<minor>.<patch>[-rc.<n>]; anything else is
  ignored.
- The line is 27.0.0 until a stable v27.0.0 tag exists. While no stable tag exists, candidates
  of any other version are ignored, so a mis-numbered tag (v27.1.0-rc.1 before v27.0.0) never
  moves the line.
- After a release the line is the lowest version above the newest stable tag that already has
  candidates, else the next feature version 27.<minor + 1>.0.
- The next candidate is rc.<highest n of the line + 1>. A commit that already carries a
  candidate of the line keeps it (a re-run never creates a second tag for the same commit).
- The stable version of a commit is the line; the commit must carry a candidate of the line, or
  (while the line is unreleased) a candidate numbered above it. A commit that already carries a
  stable tag keeps it, so a re-run of release.yml finds the same version.

Usage:
  release_version.py candidate COMMIT   prints "<candidate tag> new|existing"
  release_version.py release COMMIT     prints "<stable tag> <candidate tag>"
"""

import re
import subprocess
import sys
from collections.abc import Iterable, Sequence

Version = tuple[int, int, int]

TAG = re.compile(r"^v27\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?$")
FIRST: Version = (27, 0, 0)


def parse(tag: str) -> tuple[Version, int | None] | None:
    """(version, rc number) of a well-formed tag, rc None for a stable tag; None otherwise."""
    match = TAG.fullmatch(tag.strip())
    if match is None:
        return None
    minor, patch, rc = match.groups()
    return (27, int(minor), int(patch)), (int(rc) if rc else None)


def text(version: Version, rc: int | None = None) -> str:
    base = "v{}.{}.{}".format(*version)
    return base if rc is None else f"{base}-rc.{rc}"


def _parsed(tags: Iterable[str]) -> list[tuple[Version, int | None]]:
    return [found for found in (parse(tag) for tag in tags) if found is not None]


def line(tags: Iterable[str]) -> Version:
    """The version the next candidate and the next release belong to."""
    parsed = _parsed(tags)
    stables = [version for version, rc in parsed if rc is None]
    if not stables:
        return FIRST
    newest = max(stables)
    open_lines = [version for version, rc in parsed if rc is not None and version > newest]
    if open_lines:
        return min(open_lines)
    return (27, newest[1] + 1, 0)


def candidate(tags: Sequence[str], at_commit: Iterable[str]) -> tuple[str, bool]:
    """(candidate tag for the commit, True when it must be created)."""
    current = line(tags)
    here = [rc for version, rc in _parsed(at_commit) if version == current and rc is not None]
    if here:
        return text(current, max(here)), False
    numbers = [rc for version, rc in _parsed(tags) if version == current and rc is not None]
    return text(current, max(numbers, default=0) + 1), True


def release(tags: Sequence[str], at_commit: Iterable[str]) -> tuple[str, str]:
    """(stable tag, candidate tag) for the commit Stage runs; ValueError when there is none."""
    here = _parsed(at_commit)
    stables = sorted(version for version, rc in here if rc is None)
    if stables:
        # Already released: the re-run reports the same version and changes nothing.
        stable = stables[-1]
        found = [(version, rc) for version, rc in here if rc is not None and version >= stable]
        if not found:
            raise ValueError(f"{text(stable)} is on the commit but no release candidate is")
        own = [item for item in found if item[0] == stable]
        return text(stable), text(*max(own or found))
    current = line(tags)
    own = [(version, rc) for version, rc in here if rc is not None and version == current]
    ahead = [(version, rc) for version, rc in here if rc is not None and version > current]
    if own or ahead:
        return text(current), text(*max(own or ahead))
    raise ValueError(f"the commit carries no release candidate of {text(current)}")


def _git(*args: str) -> list[str]:
    output = subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [row.strip() for row in output.splitlines() if row.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] not in ("candidate", "release"):
        print("usage: release_version.py candidate|release COMMIT", file=sys.stderr)
        return 2
    command, commit = args
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        print("COMMIT must be a full 40-character commit SHA", file=sys.stderr)
        return 2
    tags = _git("tag", "--list", "v27.*")
    at_commit = _git("tag", "--points-at", commit, "--list", "v27.*")
    if command == "candidate":
        tag, new = candidate(tags, at_commit)
        print(tag, "new" if new else "existing")
        return 0
    try:
        stable, rc = release(tags, at_commit)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(stable, rc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
