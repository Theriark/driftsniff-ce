"""The Dokploy deploy helper (.github/scripts/dokploy_release.py): deploy, image checks, retries."""

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
OTHER_IMAGE = "ghcr.io/theriark/driftsniff-ce@sha256:" + "b" * 64
COMMIT = "b" * 40
APP = "app-1"
UPDATE_PAYLOAD = {"applicationId": "app1", "dockerImage": IMAGE}

EMPTY_IMAGE_RESPONSES: list[dict[str, Any]] = [
    {"dockerImage": ""},
    {"dockerImage": "   "},
    {"dockerImage": None},
    {},
    {"data": {"name": "app"}},
]


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


# Restored from development (4afc961d): these exercise deploy(), assert_image() and
# current_image(), which the retry change does not alter.


class FakeDokploy:
    """Stands in for request_json: serves application.one answers in order, records POSTs."""

    def __init__(self, one_responses: list[dict[str, Any]]) -> None:
        self.one_responses = list(one_responses)
        self.posts: list[str] = []

    def __call__(self, method: str, path: str, **_kwargs: Any) -> Any:
        if method == "GET" and path == "application.one":
            return self.one_responses.pop(0)
        self.posts.append(path)
        return {}


def make_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "application_id": APP,
        "image": IMAGE,
        "health_url": "https://example.invalid/healthz",
        "expected_commit": COMMIT,
        "title": "title",
        "description": "description",
        "timeout": 1,
        "noop_ok": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def install_fake(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType, responses: list[dict[str, Any]]
) -> FakeDokploy:
    fake = FakeDokploy(responses)
    monkeypatch.setattr(module, "request_json", fake)
    monkeypatch.setattr(module, "wait_health", lambda *_args, **_kwargs: None)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    return fake


@pytest.mark.parametrize("noop_ok", [False, True])
@pytest.mark.parametrize("previous", EMPTY_IMAGE_RESPONSES)
def test_empty_previous_image_updates_and_deploys(
    monkeypatch: pytest.MonkeyPatch, previous: dict[str, Any], noop_ok: bool
) -> None:
    module = load_module()
    fake = install_fake(monkeypatch, module, [previous, {"dockerImage": IMAGE}])
    module.deploy(make_args(noop_ok=noop_ok))
    assert fake.posts == ["application.update", "application.deploy"]


def test_same_image_with_noop_ok_skips_update_and_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake = install_fake(monkeypatch, module, [{"dockerImage": IMAGE}, {"dockerImage": IMAGE}])
    module.deploy(make_args(noop_ok=True))
    assert fake.posts == []


def test_same_image_without_noop_ok_still_deploys(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake = install_fake(monkeypatch, module, [{"dockerImage": IMAGE}, {"dockerImage": IMAGE}])
    module.deploy(make_args())
    assert fake.posts == ["application.update", "application.deploy"]


def test_image_mismatch_after_deploy_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [{"dockerImage": ""}, {"dockerImage": OTHER_IMAGE}])
    with pytest.raises(module.DokployError, match="reports"):
        module.deploy(make_args())


@pytest.mark.parametrize("after", EMPTY_IMAGE_RESPONSES)
def test_missing_image_after_deploy_fails(
    monkeypatch: pytest.MonkeyPatch, after: dict[str, Any]
) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [{"dockerImage": ""}, after])
    with pytest.raises(module.DokployError, match="Could not read dockerImage"):
        module.deploy(make_args())


@pytest.mark.parametrize("response", EMPTY_IMAGE_RESPONSES)
def test_assert_image_is_strict_about_a_missing_image(
    monkeypatch: pytest.MonkeyPatch, response: dict[str, Any]
) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [response])
    with pytest.raises(module.DokployError, match="Could not read dockerImage"):
        module.assert_image(make_args())


def test_current_image_is_strict_unless_allow_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [{}, {}, {"dockerImage": f" {IMAGE} "}])
    with pytest.raises(module.DokployError):
        module.current_image(APP)
    assert module.current_image(APP, allow_missing=True) == ""
    assert module.current_image(APP) == IMAGE


def test_current_image_rejects_a_non_string_even_when_lenient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    install_fake(monkeypatch, module, [{"dockerImage": 5}])
    with pytest.raises(module.DokployError):
        module.current_image(APP, allow_missing=True)
