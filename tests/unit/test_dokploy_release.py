"""The Dokploy deploy helper (.github/scripts/dokploy_release.py): the retry path."""

import argparse
import importlib.util
import io
import urllib.error
from email.message import Message
from pathlib import Path
from types import ModuleType
from typing import Any, Self

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "dokploy_release.py"
IMAGE = "ghcr.io/theriark/driftsniff-ce@sha256:" + "a" * 64
COMMIT = "b" * 40
UPDATE_PAYLOAD = {"applicationId": "app1", "dockerImage": IMAGE}


def load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dokploy_release", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://dokploy.example/api/application.update",
        code,
        "error",
        Message(),
        io.BytesIO(b"detail"),
    )


class Transport:
    """Replaces urlopen and sleep: answers from a script and records timeouts and delays."""

    def __init__(self, module: ModuleType, outcomes: list[Any], monkeypatch: pytest.MonkeyPatch):
        self.outcomes = list(outcomes)
        self.timeouts: list[float] = []
        self.sleeps: list[float] = []
        monkeypatch.setenv("DOKPLOY_URL", "https://dokploy.example")
        monkeypatch.setenv("DOKPLOY_API_KEY", "test-key")
        monkeypatch.setenv("CF_ACCESS_CLIENT_ID", "test-id")
        monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", "test-secret")
        monkeypatch.setattr(module.urllib.request, "urlopen", self.urlopen)
        monkeypatch.setattr(module.time, "sleep", self.sleeps.append)

    def urlopen(self, request: Any, timeout: float) -> FakeResponse:
        self.timeouts.append(timeout)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResponse(outcome)


def update(module: ModuleType) -> Any:
    return module.request_json(
        "POST",
        "application.update",
        payload=UPDATE_PAYLOAD,
        timeout=module.UPDATE_TIMEOUT_SECONDS,
        attempts=module.UPDATE_ATTEMPTS,
    )


def test_the_limits_are_the_ones_of_the_fix() -> None:
    module = load_module()
    assert module.UPDATE_TIMEOUT_SECONDS == 90
    assert module.UPDATE_ATTEMPTS == 3
    assert module.UPDATE_BACKOFF_SECONDS == (5, 15)
    assert module.RETRYABLE_HTTP_CODES == frozenset({502, 503, 504})


def test_a_read_timeout_is_retried_once_and_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    transport = Transport(
        module, [TimeoutError("The read operation timed out"), b'{"ok": true}'], monkeypatch
    )
    assert update(module) == {"ok": True}
    assert transport.timeouts == [90, 90]
    assert transport.sleeps == [5]


def test_connection_errors_and_timeouts_back_off_five_then_fifteen_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    transport = Transport(
        module,
        [urllib.error.URLError("connection reset"), TimeoutError("slow"), b"{}"],
        monkeypatch,
    )
    assert update(module) == {}
    assert len(transport.timeouts) == 3
    assert transport.sleeps == [5, 15]


def test_it_gives_up_after_three_attempts_with_the_real_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    transport = Transport(module, [TimeoutError("The read operation timed out")] * 3, monkeypatch)
    with pytest.raises(module.DokployError, match="read operation timed out"):
        update(module)
    assert len(transport.timeouts) == 3
    assert transport.sleeps == [5, 15]


@pytest.mark.parametrize("code", [502, 503, 504])
def test_a_gateway_error_is_retried(code: int, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    transport = Transport(module, [http_error(code), b'{"ok": true}'], monkeypatch)
    assert update(module) == {"ok": True}
    assert len(transport.timeouts) == 2
    assert transport.sleeps == [5]


@pytest.mark.parametrize("code", [400, 401, 403, 404, 500])
def test_a_real_error_is_never_retried(code: int, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    transport = Transport(module, [http_error(code), b"{}"], monkeypatch)
    with pytest.raises(module.DokployError, match=f"HTTP {code}"):
        update(module)
    assert len(transport.timeouts) == 1
    assert transport.sleeps == []


def test_a_call_without_attempts_makes_exactly_one_try(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    transport = Transport(module, [TimeoutError("slow"), b"{}"], monkeypatch)
    with pytest.raises(module.DokployError):
        module.request_json("POST", "application.deploy", payload={"applicationId": "app1"})
    assert transport.timeouts == [30]
    assert transport.sleeps == []


class DeployHarness:
    """Replaces the Dokploy calls inside deploy() and records them in order."""

    def __init__(
        self,
        module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        images: list[str],
        failing_path: str | None = None,
    ) -> None:
        self.module = module
        self.images = list(images)
        self.failing_path = failing_path
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.health_calls = 0
        monkeypatch.setattr(module, "request_json", self.request_json)
        monkeypatch.setattr(module, "current_image", self.current_image)
        monkeypatch.setattr(module, "wait_health", self.wait_health)

    def request_json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        self.requests.append((path, kwargs))
        if path == self.failing_path:
            raise self.module.DokployError(f"Dokploy API {method} {path} failed: timed out")
        return {}

    def current_image(self, application_id: str, *, allow_missing: bool = False) -> str:
        return self.images.pop(0)

    def wait_health(self, url: str, timeout_seconds: int, expected_commit: str) -> None:
        self.health_calls += 1


def deploy_args() -> argparse.Namespace:
    return argparse.Namespace(
        application_id="app1",
        image=IMAGE,
        health_url="https://dev.example/healthz",
        expected_commit=COMMIT,
        title="title",
        description="description",
        timeout=1,
        noop_ok=False,
    )


def test_deploy_retries_only_the_update_and_never_the_deploy_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    harness = DeployHarness(module, monkeypatch, ["", IMAGE])
    module.deploy(deploy_args())
    assert [path for path, _ in harness.requests] == ["application.update", "application.deploy"]
    update_kwargs = harness.requests[0][1]
    assert update_kwargs["timeout"] == 90
    assert update_kwargs["attempts"] == 3
    assert update_kwargs["payload"] == UPDATE_PAYLOAD
    assert harness.requests[1][1].get("attempts", 1) == 1
    assert harness.health_calls == 1


def test_deploy_stops_before_the_deploy_call_when_the_update_keeps_failing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    harness = DeployHarness(module, monkeypatch, [""], failing_path="application.update")
    with pytest.raises(module.DokployError, match="application.update"):
        module.deploy(deploy_args())
    assert [path for path, _ in harness.requests] == ["application.update"]
    assert harness.health_calls == 0


def test_deploy_still_fails_closed_when_dokploy_reports_another_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    other = "ghcr.io/theriark/driftsniff-ce@sha256:" + "c" * 64
    DeployHarness(module, monkeypatch, ["", other])
    with pytest.raises(module.DokployError, match="expected"):
        module.deploy(deploy_args())
