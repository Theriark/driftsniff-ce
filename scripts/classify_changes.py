#!/usr/bin/env python3
"""Fail-closed classification of a push to development as documentation-only.

The CI workflow publishes the image and deploys Development on every push to development. That
replaces the running candidate even when the push only adds documentation. This helper decides,
before publication, whether the push changes nothing the runtime is built from.

The comparison base is the commit the Development runtime reports on /healthz, not the previous
push, so an earlier push whose deployment failed or was skipped is never hidden by a later
documentation push. The push is documentation-only only when every path that differs between
that commit and the pushed commit is on the explicit allow list below. A rename or copy is
reported as its old path and its new path (--no-renames), so both must be allowed. Any doubt
(runtime unreachable, answer malformed, base not an ancestor, git failure, unusual path, empty
difference) classifies the push as NOT documentation-only and the normal publish and deploy run.

Writes docs_only=true|false and base=<sha> to GITHUB_OUTPUT when it is set. Always exits 0 so
the deployment decision is never made by a crashed step.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# ASCII only and no leading dot in any segment: a path that needs quoting or hides itself is
# never classified as documentation.
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*$")

# Files at the repository root that no build step copies into the image. Other Markdown files are
# deliberately not listed: LICENSE is copied into the image, and nothing else is on this list.
ROOT_DOCUMENTS = frozenset({"README.md", "CONTRIBUTING.md", "SECURITY.md"})

# Under docs/ only these file types are documentation. The Dockerfile copies src, requirements.txt
# and LICENSE only; tests/unit/test_classify_changes.py fails if that ever stops being true.
DOCS_DIRECTORY = "docs"
DOCS_EXTENSIONS = frozenset({".md", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".json"})

HEALTH_ATTEMPTS = 3
HEALTH_BACKOFF_SECONDS = 5


def is_documentation_path(path: str) -> bool:
    """True only for a path on the explicit documentation allow list."""
    if not SAFE_PATH_RE.fullmatch(path) or ".." in path.split("/"):
        return False
    if path in ROOT_DOCUMENTS:
        return True
    head, _, _ = path.partition("/")
    if head != DOCS_DIRECTORY or path == DOCS_DIRECTORY:
        return False
    name = path.rsplit("/", 1)[-1]
    dot = name.rfind(".")
    return dot > 0 and name[dot:] in DOCS_EXTENSIONS


def blocking_paths(paths: Sequence[str]) -> list[str]:
    return [path for path in paths if not is_documentation_path(path)]


def is_documentation_only(paths: Sequence[str]) -> bool:
    """Documentation-only needs at least one changed path and every path allowed."""
    return bool(paths) and not blocking_paths(paths)


def deployed_commit(
    health_url: str,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
    attempts: int = HEALTH_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> str | None:
    """The commit the runtime reports on /healthz, or None when it cannot be proven."""
    if not health_url.startswith("https://"):
        return None
    request = urllib.request.Request(  # noqa: S310
        health_url,
        headers={"accept": "application/json", "User-Agent": "Theriark-GitHub-Actions/1.0"},
    )
    for attempt in range(1, attempts + 1):
        try:
            with opener(request, timeout=15) as response:
                status_code = response.status
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
            if not isinstance(payload, dict) or status_code != 200 or payload.get("status") != "ok":
                return None
            commit = payload.get("commit")
            if isinstance(commit, str) and COMMIT_RE.fullmatch(commit):
                return commit
            return None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            if attempt < attempts:
                sleep(HEALTH_BACKOFF_SECONDS)
    return None


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        check=False,
        capture_output=True,
    )


def changed_paths(base: str, head: str) -> list[str] | None:
    """Every path that differs between two commits, old and new path of a rename included."""
    result = git("diff", "--name-only", "--no-renames", "--no-ext-diff", "-z", base, head, "--")
    if result.returncode != 0:
        return None
    return [raw.decode("utf-8", errors="replace") for raw in result.stdout.split(b"\0") if raw]


def classify(head: str, health_url: str) -> tuple[bool, str, str]:
    """Return (docs_only, base commit or empty, reason)."""
    if not COMMIT_RE.fullmatch(head):
        return False, "", "pushed commit is not a full lowercase SHA"
    base = deployed_commit(health_url)
    if base is None:
        return False, "", "the Development runtime did not report a valid commit on /healthz"
    if git("cat-file", "-e", f"{base}^{{commit}}").returncode != 0:
        return False, base, f"deployed commit {base} is not in the fetched history"
    if git("merge-base", "--is-ancestor", base, head).returncode != 0:
        return False, base, f"deployed commit {base} is not an ancestor of {head}"
    paths = changed_paths(base, head)
    if paths is None:
        return False, base, "git could not list the changed paths"
    if not paths:
        return False, base, "no changed paths between the deployed commit and the pushed commit"
    blocking = blocking_paths(paths)
    if blocking:
        shown = ", ".join(ascii(path) for path in sorted(blocking)[:10])
        more = f" and {len(blocking) - 10} more" if len(blocking) > 10 else ""
        count = f"{len(blocking)} of {len(paths)} changed paths"
        return False, base, f"{count} are not documentation: {shown}{more}"
    return True, base, f"all {len(paths)} changed paths are documentation"


def write_output(name: str, value: str) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True, help="the pushed commit (full SHA)")
    parser.add_argument("--health-url", required=True, help="Development /healthz URL (https)")
    args = parser.parse_args(argv)
    try:
        docs_only, base, reason = classify(args.head, args.health_url)
    except Exception as exc:  # any failure must fall back to the full deployment
        docs_only, base, reason = False, "", f"classifier error {type(exc).__name__}"
    write_output("docs_only", "true" if docs_only else "false")
    write_output("base", base)
    verdict = "documentation-only" if docs_only else "not documentation-only"
    print(f"{verdict}: {reason}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
