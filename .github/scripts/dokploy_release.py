#!/usr/bin/env python3
"""Stdlib-only helper: deploy an immutable image to a Dokploy application and verify it.

Subcommands: deploy, assert-image, health. Secrets come from the environment only
(DOKPLOY_URL, DOKPLOY_API_KEY, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET) and are
never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

IMAGE_RE = re.compile(r"^ghcr\.io/theriark/driftsniff-ce@sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class DokployError(RuntimeError):
    pass


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise DokployError(f"Required environment variable {name} is missing")
    return value


def request_json(
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    query: dict[str, str] | None = None,
    timeout: int = 30,
) -> Any:
    url = f"{required_env('DOKPLOY_URL').rstrip('/')}/api/{path.lstrip('/')}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    headers = {
        "accept": "application/json",
        "x-api-key": required_env("DOKPLOY_API_KEY"),
        "CF-Access-Client-Id": required_env("CF_ACCESS_CLIENT_ID"),
        "CF-Access-Client-Secret": required_env("CF_ACCESS_CLIENT_SECRET"),
        "User-Agent": "Theriark-GitHub-Actions/1.0",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise DokployError(f"Dokploy API {method} {path} failed with HTTP {exc.code}: {detail}") from exc
    except (TimeoutError, urllib.error.URLError) as exc:
        raise DokployError(f"Dokploy API {method} {path} failed: {exc}") from exc
    if not body.strip():
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def find_key(value: Any, key: str) -> Any | None:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        children: list[Any] = list(value.values())
    elif isinstance(value, list):
        children = list(value)
    else:
        return None
    for child in children:
        found = find_key(child, key)
        if found is not None:
            return found
    return None


def write_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def validate_image(image: str) -> None:
    if not IMAGE_RE.fullmatch(image):
        raise DokployError(
            "Image must be ghcr.io/theriark/driftsniff-ce@sha256:<64 lowercase hex characters>"
        )


def validate_commit(commit: str) -> None:
    if not COMMIT_RE.fullmatch(commit):
        raise DokployError("Expected commit must be a full lowercase 40-character SHA")


def current_image(application_id: str) -> str:
    response = request_json("GET", "application.one", query={"applicationId": application_id})
    image = find_key(response, "dockerImage")
    if not isinstance(image, str) or not image.strip():
        raise DokployError(f"Could not read dockerImage for Dokploy application {application_id}")
    return image.strip()


def wait_health(url: str, timeout_seconds: int, expected_commit: str) -> None:
    """Require two consecutive HTTP 200 answers with status ok and the exact commit."""
    validate_commit(expected_commit)
    deadline = time.monotonic() + timeout_seconds
    last = "health endpoint did not respond"
    matches = 0
    while time.monotonic() < deadline:
        request = urllib.request.Request(
            url, headers={"accept": "application/json", "User-Agent": "Theriark-GitHub-Actions/1.0"}
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read().decode("utf-8", errors="replace")
                status_code = response.status
            payload = json.loads(body)
            observed = str(payload.get("commit") or "")
            if status_code != 200 or payload.get("status") != "ok":
                matches = 0
                last = f"HTTP {status_code}, status {payload.get('status')!r}"
            elif observed != expected_commit:
                matches = 0
                last = f"healthy but reports commit {observed or 'none'}; waiting for {expected_commit}"
            else:
                matches += 1
                if matches >= 2:
                    print(f"PASS: {url} healthy on commit {observed} (two consecutive answers)")
                    return
                last = "first matching answer; confirming"
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, AttributeError) as exc:
            matches = 0
            last = str(exc)
        print(f"WAIT: {url} {last}")
        time.sleep(5)
    raise DokployError(f"Health check timed out for {url} (expected commit {expected_commit}): {last}")


def deploy(args: argparse.Namespace) -> None:
    validate_image(args.image)
    previous = current_image(args.application_id)
    write_output("previous_image", previous)
    write_output("deployed_image", args.image)
    if previous == args.image and args.noop_ok:
        print(f"No image change required for {args.application_id}")
    else:
        request_json(
            "POST",
            "application.update",
            payload={"applicationId": args.application_id, "dockerImage": args.image},
        )
        request_json(
            "POST",
            "application.deploy",
            payload={
                "applicationId": args.application_id,
                "title": args.title,
                "description": args.description,
            },
        )
        print(f"Deployment requested for {args.application_id}: {args.image}")
    wait_health(args.health_url, args.timeout, args.expected_commit)
    observed = current_image(args.application_id)
    if observed != args.image:
        raise DokployError(
            f"Dokploy application {args.application_id} reports {observed}, expected {args.image}"
        )
    print(f"PASS: Dokploy application image is exactly {observed}")


def assert_image(args: argparse.Namespace) -> None:
    validate_image(args.image)
    observed = current_image(args.application_id)
    if observed != args.image:
        raise DokployError(
            f"Application {args.application_id} runs {observed}, expected {args.image}"
        )
    print(f"PASS: {args.application_id} runs {observed}")


def health(args: argparse.Namespace) -> None:
    wait_health(args.health_url, args.timeout, args.expected_commit)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("deploy")
    p.add_argument("--application-id", required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--health-url", required=True)
    p.add_argument("--expected-commit", required=True)
    p.add_argument("--title", default="Immutable image deployment")
    p.add_argument("--description", default="Managed by GitHub Actions")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--noop-ok", action="store_true")
    p.set_defaults(func=deploy)

    p = sub.add_parser("assert-image")
    p.add_argument("--application-id", required=True)
    p.add_argument("--image", required=True)
    p.set_defaults(func=assert_image)

    p = sub.add_parser("health")
    p.add_argument("--health-url", required=True)
    p.add_argument("--expected-commit", required=True)
    p.add_argument("--timeout", type=int, default=120)
    p.set_defaults(func=health)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.func(args)
        return 0
    except DokployError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
