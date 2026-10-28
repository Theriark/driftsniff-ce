"""First-run browser check of the published application image (THE-1556, DRS-447).

The image named by FIRST_RUN_IMAGE (an immutable ``repository@sha256:...`` reference) is pulled and
started with EMPTY temporary volumes on its own 127.0.0.1 port. A real Chromium then walks the
first-run flow: the setup page renders, a too short password is refused, a valid admin is created
and /setup answers 404 afterwards. This is a real browser against an isolated first-run
application image, not the shared Development instance and not a mock.

The one-time setup code is read from the container log and handed straight to the form. It and the
generated password are never printed, never put into an assertion message and never written to the
evidence; the test also scans its own evidence for them. Screenshots are only taken while no secret
is in a field. The container and both volumes are removed at the end and the removal is checked.
Nothing here deploys, rebuilds or resets anything else.

Skipped unless FIRST_RUN_IMAGE is set, so the normal test run never needs Docker. Environment:
FIRST_RUN_IMAGE (required), FIRST_RUN_EXPECTED_COMMIT (optional commit prefix the image revision
label must start with), FIRST_RUN_ARTIFACT_DIR (screenshots and evidence.json).
"""

import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import Page, expect, sync_playwright

IMAGE = os.environ.get("FIRST_RUN_IMAGE", "")
if not IMAGE:
    pytest.skip(
        "FIRST_RUN_IMAGE is not set; this check runs in the first-run-image CI job",
        allow_module_level=True,
    )

EXPECTED_COMMIT = os.environ.get("FIRST_RUN_EXPECTED_COMMIT", "")
HEALTH_WAIT_SECONDS = 60
SETUP_CODE_PATTERN = re.compile(r"first-run setup code \(shown once\): (\S+)")
STATUS_NOISE = re.compile(r"the server responded with a status of 4\d\d")
ADMIN_NAME = "first-run-admin"
TOO_SHORT_INPUT = "short-1"
NAME_PREFIX = "driftsniff-first-run"


@dataclass
class Running:
    """The isolated container: its base URL and the one-time code (never shown in a repr)."""

    name: str
    base_url: str
    setup_code: str = field(repr=False)


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=300
    )


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_until_healthy(name: str) -> None:
    status = ""
    for _ in range(HEALTH_WAIT_SECONDS):
        running = docker("inspect", "--format", "{{.State.Running}}", name).stdout.strip()
        assert running == "true", "the container stopped before it became healthy"
        template = "{{if .State.Health}}{{.State.Health.Status}}{{end}}"
        status = docker("inspect", "--format", template, name).stdout.strip()
        if status == "healthy":
            return
        time.sleep(1)
    pytest.fail(f"the container was not healthy after {HEALTH_WAIT_SECONDS} s (status {status!r})")


def read_setup_code(name: str) -> str:
    """The code from the container log; only the match leaves this function."""
    for _ in range(30):
        logs = docker("logs", name, check=False)
        found = SETUP_CODE_PATTERN.search(logs.stdout + logs.stderr)
        if found:
            return found.group(1)
        time.sleep(1)
    pytest.fail("the container log shows no first-run setup code")


def leftovers(name: str, volumes: list[str]) -> dict[str, list[str]]:
    containers = docker("ps", "--all", "--quiet", "--filter", f"name={name}").stdout.split()
    left_volumes = [
        volume
        for volume in volumes
        if docker("volume", "ls", "--quiet", "--filter", f"name={volume}").stdout.split()
    ]
    return {"containers": containers, "volumes": left_volumes}


@contextmanager
def isolated_container(evidence: dict[str, Any]) -> Iterator[Running]:
    """Start the image with empty volumes; always remove the container and the volumes."""
    suffix = secrets.token_hex(4)
    name = f"{NAME_PREFIX}-{suffix}"
    volumes = [f"{name}-data", f"{name}-keys"]
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"
    try:
        docker("pull", "--quiet", IMAGE)
        digests = json.loads(
            docker("image", "inspect", "--format", "{{json .RepoDigests}}", IMAGE).stdout
        )
        assert IMAGE in digests, "the pulled image does not carry the requested digest"
        revision = docker(
            "image",
            "inspect",
            "--format",
            '{{index .Config.Labels "org.opencontainers.image.revision"}}',
            IMAGE,
        ).stdout.strip()
        if EXPECTED_COMMIT:
            assert revision.startswith(EXPECTED_COMMIT), (
                f"image revision label {revision!r} does not start with {EXPECTED_COMMIT!r}"
            )
        evidence["image"] = {
            "reference": IMAGE,
            "digest_verified": True,
            "revision_label": revision,
        }
        for volume in volumes:
            docker("volume", "create", volume)
        docker(
            "run",
            "--detach",
            "--name",
            name,
            "--read-only",
            "--tmpfs",
            "/tmp",  # noqa: S108
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "512m",
            "--publish",
            f"127.0.0.1:{port}:8080",
            "--volume",
            f"{volumes[0]}:/data",
            "--volume",
            f"{volumes[1]}:/keys",
            "--env",
            f"DRIFTSNIFF_BASE_URL={base_url}",
            IMAGE,
        )
        evidence["container"] = {"name": name, "base_url": base_url, "volumes": volumes}
        wait_until_healthy(name)
        yield Running(name=name, base_url=base_url, setup_code=read_setup_code(name))
    finally:
        docker("rm", "--force", name, check=False)
        for volume in volumes:
            docker("volume", "rm", "--force", volume, check=False)
        left = leftovers(name, volumes)
        evidence["cleanup"] = {"removed": not left["containers"] and not left["volumes"], **left}


def assert_no_secret_in_fields(page: Page) -> None:
    """The refused form must not echo the code or the password back."""
    assert page.locator("#code").input_value() == "", "the setup code field was filled back in"
    assert page.locator("#password").input_value() == "", "the password field was filled back in"


def run_first_run_flow(app: Running, artifacts: Path, evidence: dict[str, Any]) -> list[str]:
    """Walk the flow in Chromium; return the secrets used so the caller can scan the evidence."""
    password = f"first-run phrase {secrets.token_hex(8)}"
    console_errors: list[str] = []
    steps: list[dict[str, object]] = []
    evidence["steps"] = steps

    def console(message: Any) -> None:
        if message.type == "error" and not STATUS_NOISE.search(message.text):
            console_errors.append(message.text)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            page = context.new_page()
            page.on("console", console)
            page.on("pageerror", lambda error: console_errors.append(f"page error: {error}"))

            # 1. The setup page renders.
            response = page.goto(f"{app.base_url}/setup")
            assert response is not None and response.status == 200
            expect(page.get_by_role("heading", name="Create the first admin")).to_be_visible()
            for field_id in ("code", "username", "password"):
                expect(page.locator(f"#{field_id}")).to_be_visible()
            page.screenshot(path=artifacts / "01-setup-page.png", full_page=True)
            steps.append({"step": "setup page renders", "status": response.status, "ok": True})

            # 2. A too short password is refused and the code stays valid.
            page.fill("#code", app.setup_code)
            page.fill("#username", ADMIN_NAME)
            page.fill("#password", TOO_SHORT_INPUT)
            with page.expect_response(
                lambda r: r.url == f"{app.base_url}/setup" and r.request.method == "POST"
            ) as refused:
                page.get_by_role("button", name="Create admin and sign in").click()
            assert refused.value.status == 422, f"expected 422, got {refused.value.status}"
            expect(page.get_by_role("heading", name="Create the first admin")).to_be_visible()
            assert_no_secret_in_fields(page)
            page.screenshot(path=artifacts / "02-weak-password-refused.png", full_page=True)
            steps.append(
                {"step": "weak password refused", "status": refused.value.status, "ok": True}
            )
            again = page.goto(f"{app.base_url}/setup")
            assert again is not None and again.status == 200, "setup closed after a refusal"

            # 3. A valid password creates the admin and signs in.
            page.fill("#code", app.setup_code)
            page.fill("#username", ADMIN_NAME)
            page.fill("#password", password)
            page.get_by_role("button", name="Create admin and sign in").click()
            expect(page).to_have_url(f"{app.base_url}/")
            expect(page.locator(".user-name")).to_have_text(ADMIN_NAME)
            page.screenshot(path=artifacts / "03-admin-created-signed-in.png", full_page=True)
            steps.append({"step": "valid admin created and signed in", "ok": True})

            # 4. /setup is gone once an admin exists.
            gone = page.goto(f"{app.base_url}/setup")
            assert gone is not None and gone.status == 404, "setup still answers after the admin"
            page.screenshot(path=artifacts / "04-setup-returns-404.png", full_page=True)
            steps.append(
                {"step": "setup returns 404 afterwards", "status": gone.status, "ok": True}
            )
        finally:
            browser.close()

    assert not console_errors, "\n".join(console_errors)
    return [app.setup_code, password]


def test_first_run_flow_on_published_image() -> None:
    configured = os.environ.get("FIRST_RUN_ARTIFACT_DIR")
    artifacts = Path(configured) if configured else Path(tempfile.mkdtemp(prefix="first-run-"))
    artifacts.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {
        "check": "real browser against isolated first-run application image in CI",
        "ticket": "THE-1556 / DRS-447",
        "shared_development_instance_used": False,
    }
    secrets_used: list[str] = []
    try:
        with isolated_container(evidence) as app:
            secrets_used = run_first_run_flow(app, artifacts, evidence)
    finally:
        text = json.dumps(evidence, indent=2)
        for secret in secrets_used:
            assert secret not in text, "a secret reached the evidence"
        (artifacts / "evidence.json").write_text(text + "\n", encoding="utf-8")
    cleanup = evidence["cleanup"]
    assert cleanup["removed"], f"the container or a volume is still present: {cleanup}"
