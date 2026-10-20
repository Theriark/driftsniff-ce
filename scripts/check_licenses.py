"""Check that every runtime dependency has an allowed licence.

Usage: python scripts/check_licenses.py [requirements.txt]

The package names come from the hashed runtime lock. The licence text comes from the installed
distribution metadata: License-Expression, else the License field and the classifiers. A package
passes when one of those texts is an allowed SPDX expression. certifi (MPL-2.0, used unmodified
as a library) is the one recorded exception. Development-only packages are not checked.
"""

import re
import sys
from collections.abc import Mapping, Sequence
from importlib import metadata
from pathlib import Path

from check_lock_hashes import requirement_names

ALLOWED = frozenset(
    {
        "0BSD",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "HPND",
        "ISC",
        "MIT",
        "PSF-2.0",
        "Unlicense",
        "Zlib",
    }
)
EXCEPTIONS = {"certifi": "MPL-2.0"}

# Lower-case names seen in package metadata, mapped to SPDX identifiers. The generic BSD and
# Apache classifiers are read as BSD-3-Clause and Apache-2.0; Python-2.0 is the PSF licence.
ALIASES = {
    "0bsd": "0BSD",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "historical permission notice and disclaimer (hpnd)": "HPND",
    "hpnd": "HPND",
    "isc": "ISC",
    "isc license (iscl)": "ISC",
    "mit": "MIT",
    "mit license": "MIT",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "psf-2.0": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "python-2.0": "PSF-2.0",
    "the unlicense (unlicense)": "Unlicense",
    "unlicense": "Unlicense",
    "zlib": "Zlib",
    "zlib/libpng license": "Zlib",
}


class _ParseError(ValueError):
    """The text is not a valid licence expression."""


def canonical_licence(text: str) -> str:
    """Map a licence name to its SPDX identifier when it is a known alias."""
    cleaned = text.strip()
    return ALIASES.get(cleaned.lower(), cleaned)


def _parse_or(words: list[str], pos: int) -> tuple[bool, int]:
    value, pos = _parse_and(words, pos)
    while pos < len(words) and words[pos].upper() == "OR":
        right, pos = _parse_and(words, pos + 1)
        value = value or right
    return value, pos


def _parse_and(words: list[str], pos: int) -> tuple[bool, int]:
    value, pos = _parse_atom(words, pos)
    while pos < len(words) and words[pos].upper() == "AND":
        right, pos = _parse_atom(words, pos + 1)
        value = value and right
    return value, pos


def _parse_atom(words: list[str], pos: int) -> tuple[bool, int]:
    if pos >= len(words):
        raise _ParseError("unexpected end of expression")
    word = words[pos]
    if word == "(":
        value, pos = _parse_or(words, pos + 1)
        if pos >= len(words) or words[pos] != ")":
            raise _ParseError("missing closing parenthesis")
        return value, pos + 1
    if word == ")" or word.upper() in ("AND", "OR", "WITH"):
        raise _ParseError("unexpected operator")
    return canonical_licence(word) in ALLOWED, pos + 1


def licence_allowed(text: str) -> bool:
    """True for an allowed identifier or an AND/OR expression whose terms satisfy the policy."""
    if canonical_licence(text) in ALLOWED:
        return True
    words = re.findall(r"\(|\)|[^\s()]+", text)
    try:
        value, end = _parse_or(words, 0)
    except _ParseError:
        return False
    return value and end == len(words)


def licence_candidates(name: str) -> list[str]:
    """Licence texts declared by an installed distribution, best source first."""
    meta = metadata.distribution(name).metadata
    expression = str(meta.get("License-Expression") or "").strip()
    if expression:
        return [expression]
    candidates: list[str] = []
    field = str(meta.get("License") or "").strip()
    if field and "\n" not in field and len(field) <= 100:
        candidates.append(field)
    for classifier in meta.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            candidates.append(classifier.rsplit(" :: ", 1)[-1])
    return candidates


def _describe(texts: Sequence[str]) -> str:
    return "; ".join(texts) or "none declared"


def find_problems(candidates: Mapping[str, Sequence[str]]) -> list[str]:
    """One problem per package (name -> declared licence texts) that the policy does not allow."""
    problems: list[str] = []
    for name, texts in sorted(candidates.items()):
        if any(licence_allowed(text) for text in texts):
            continue
        exception = EXCEPTIONS.get(re.sub(r"[-_.]+", "-", name).lower())
        canonical = {canonical_licence(text) for text in texts}
        if exception is not None and exception in canonical:
            continue
        problems.append(f"{name}: licence not allowed or not recognised ({_describe(texts)})")
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    """Check the packages of the runtime lock; return 0 when all pass, 1 otherwise."""
    args = list(sys.argv[1:] if argv is None else argv)
    path = Path(args[0]) if args else Path("requirements.txt")
    try:
        names = requirement_names(path.read_text(encoding="utf-8"))
    except OSError as error:
        print(f"{path}: cannot read file: {error}", file=sys.stderr)
        return 1
    candidates: dict[str, list[str]] = {}
    problems: list[str] = []
    for name in names:
        try:
            candidates[name] = licence_candidates(name)
        except metadata.PackageNotFoundError:
            problems.append(f"{name}: not installed, cannot read its licence")
    for name, texts in sorted(candidates.items()):
        print(f"{name}: {_describe(texts)}")
    problems.extend(find_problems(candidates))
    if not names:
        problems.append(f"{path}: no packages found")
    for problem in problems:
        print(f"licence check: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
