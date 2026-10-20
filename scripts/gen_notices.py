"""Write THIRD_PARTY_NOTICES from the hashed lock files and the installed package metadata.

Usage: python scripts/gen_notices.py [--output FILE] [RUNTIME_LOCK [DEV_LOCK]]

The runtime lock (default requirements.txt) lists what ships in the image. The development lock
(default requirements-dev.txt, optional) adds the packages that only build and test the project;
they get their own section because they are not shipped. Versions come from the locks. Licence
names, home pages and licence files come from the installed distributions, so run the script in
the environment the locks were installed into. The output holds no dates: the same inputs give
the same bytes. Nothing is written when a locked package is missing or has another version.
"""

import argparse
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from check_licenses import licence_candidates
from check_lock_hashes import PIN_PATTERN, logical_lines

RUNTIME_TITLE = "Runtime dependencies (shipped in the image)"
DEV_TITLE = "Development-only packages (not shipped)"
RULE = "=" * 78
LICENCE_FILE = re.compile(r"(licen[cs]e|copying|notice)[\w.-]*", re.IGNORECASE)
CODE_SUFFIXES = frozenset({".py", ".pyc", ".pyi", ".so", ".pyd"})
MAX_TEXT = 40_000


class NoticeError(Exception):
    """A locked package cannot be described from the installed environment."""


@dataclass(frozen=True)
class Notice:
    """What the notices file says about one package."""

    name: str
    version: str
    licence: str
    homepage: str
    texts: tuple[tuple[str, str], ...]


def normalise(name: str) -> str:
    """Canonical form of a package name (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_versions(text: str) -> dict[str, str]:
    """Package name -> pinned version for every requirement of a lock file, in file order."""
    versions: dict[str, str] = {}
    for line in logical_lines(text):
        match = PIN_PATTERN.match(line)
        if match is not None:
            versions[match.group(1)] = match.group(0).rsplit("==", 1)[1]
    return versions


def _clip(text: str) -> str:
    if len(text) <= MAX_TEXT:
        return text
    return f"{text[:MAX_TEXT]}\n[truncated: see the package for the full text]"


def licence_texts(dist: metadata.Distribution) -> tuple[tuple[str, str], ...]:
    """Licence and notice files shipped in a distribution as (path, text), duplicates dropped."""
    found: dict[str, str] = {}
    for file in sorted(dist.files or [], key=str):
        if file.suffix in CODE_SUFFIXES or LICENCE_FILE.fullmatch(file.name) is None:
            continue
        try:
            text = file.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
        except (OSError, UnicodeDecodeError):
            continue
        if text and text not in found:
            found[text] = str(file)
    return tuple((label, _clip(text)) for text, label in found.items())


def homepage(dist: metadata.Distribution) -> str:
    """The Home-page field, else the first Project-URL, else an empty string."""
    meta = dist.metadata
    page = str(meta.get("Home-page") or "").strip()
    if page and page != "UNKNOWN":
        return page
    for entry in meta.get_all("Project-URL") or []:
        url = str(entry).rsplit(",", 1)[-1].strip()
        if url:
            return url
    return ""


def load_notice(name: str, version: str) -> Notice:
    """Describe one locked package from the installed environment."""
    try:
        dist = metadata.distribution(name)
        candidates = licence_candidates(name)
    except metadata.PackageNotFoundError as error:
        raise NoticeError(f"{name}: not installed, cannot read its licence") from error
    if dist.version != version:
        raise NoticeError(f"{name}: lock says {version} but {dist.version} is installed")
    licence = "; ".join(candidates) or "none declared"
    return Notice(name, version, licence, homepage(dist), licence_texts(dist))


def load_notices(versions: dict[str, str], problems: list[str]) -> list[Notice]:
    """Notices for every locked package, sorted by canonical name; failures go to problems."""
    notices: list[Notice] = []
    for name, version in sorted(versions.items(), key=lambda item: normalise(item[0])):
        try:
            notices.append(load_notice(name, version))
        except NoticeError as error:
            problems.append(str(error))
    return notices


def render_notice(notice: Notice) -> list[str]:
    """The lines for one package."""
    lines = [RULE, f"{notice.name} {notice.version}", f"Licence: {notice.licence}"]
    if notice.homepage:
        lines.append(f"Home page: {notice.homepage}")
    for label, text in notice.texts:
        lines.extend(["", f"--- {label} ---", text])
    lines.append("")
    return lines


def render(runtime: Sequence[Notice], dev: Sequence[Notice]) -> str:
    """The text of THIRD_PARTY_NOTICES."""
    lines = [
        "driftsniff third-party notices",
        "",
        "driftsniff is MIT licensed (see LICENSE). It uses the packages below, each under its",
        "own licence. This file is generated by scripts/gen_notices.py; do not edit it by hand.",
        "",
    ]
    for title, notices in ((RUNTIME_TITLE, runtime), (DEV_TITLE, dev)):
        lines.extend([title, "-" * len(title), ""])
        if not notices:
            lines.extend(["None.", ""])
        for notice in notices:
            lines.extend(render_notice(notice))
    return "\n".join(lines).rstrip() + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Write the notices file; return 0 on success, 1 when a package cannot be described."""
    parser = argparse.ArgumentParser(description="Write THIRD_PARTY_NOTICES.")
    parser.add_argument("runtime_lock", nargs="?", type=Path, default=Path("requirements.txt"))
    parser.add_argument("dev_lock", nargs="?", type=Path, default=Path("requirements-dev.txt"))
    parser.add_argument("--output", type=Path, default=Path("THIRD_PARTY_NOTICES"))
    args = parser.parse_args(argv)
    try:
        runtime_versions = lock_versions(args.runtime_lock.read_text(encoding="utf-8"))
        dev_text = args.dev_lock.read_text(encoding="utf-8") if args.dev_lock.is_file() else ""
    except OSError as error:
        print(f"notices: cannot read lock file: {error}", file=sys.stderr)
        return 1
    problems: list[str] = []
    runtime = load_notices(runtime_versions, problems)
    shipped = {normalise(name) for name in runtime_versions}
    dev_versions = {
        name: version
        for name, version in lock_versions(dev_text).items()
        if normalise(name) not in shipped
    }
    dev = load_notices(dev_versions, problems)
    if not runtime_versions:
        problems.append(f"{args.runtime_lock}: no packages found")
    for problem in problems:
        print(f"notices: {problem}", file=sys.stderr)
    if problems:
        return 1
    args.output.write_text(render(runtime, dev), encoding="utf-8")
    print(f"{args.output}: {len(runtime)} runtime and {len(dev)} development-only packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
