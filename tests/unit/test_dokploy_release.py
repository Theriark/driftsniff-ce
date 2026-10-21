"""Unit tests for the Dokploy release helper (.github/scripts/dokploy_release.py)."""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import urllib.error
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "dokploy_release.py"
IMAGE = "ghcr.io/theriark/driftsniff-ce@sha256:" + "a" * 64
OTHER_IMAGE = "ghcr.io/theriark/driftsniff-ce@sha256:" + "b" * 64
COMMIT = "c" * 40
APP = "app-1"

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


# --- retry behaviour of request_json_idempotent (THE-606 / THE-652) ---------------------------


class ScriptedDokploy:
    """Stands in for request_json: each (method, path) plays its outcomes in order.

    An Exception outcome is raised, anything else is returned. Every call is recorded.
    """

    def __init__(self, script: dict[tuple[str, str], list[Any]]) -> None:
        self.script = {key: list(outcomes) for key, outcomes in script.items()}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def __call__(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        outcome = self.script[(method, path)].pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def count(self, method: str, path: str) -> int:
        return sum(1 for call in self.calls if call[:2] == (method, path))


def install_scripted(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    script: dict[tuple[str, str], list[Any]],
) -> tuple[ScriptedDokploy, list[float]]:
    fake = ScriptedDokploy(script)
    sleeps: list[float] = []
    monkeypatch.setattr(module, "request_json", fake)
    monkeypatch.setattr(module, "wait_health", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    return fake, sleeps


def test_idempotent_call_retries_a_transient_error_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_scripted(
        monkeypatch,
        module,
        {("GET", "application.one"): [module.DokployTransientError("timed out"), {"ok": 1}]},
    )
    result = module.request_json_idempotent("GET", "application.one", query={"a": "b"})
    assert result == {"ok": 1}
    assert fake.count("GET", "application.one") == 2
    assert fake.calls[0][2] == fake.calls[1][2] == {"query": {"a": "b"}}
    assert sleeps == [module.RETRY_BACKOFF_SECONDS]


def test_update_is_retried_after_a_timeout_and_deploy_is_requested_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_scripted(
        monkeypatch,
        module,
        {
            ("GET", "application.one"): [{"dockerImage": ""}, {"dockerImage": IMAGE}],
            ("POST", "application.update"): [
                module.DokployTransientError("The read operation timed out"),
                {},
            ],
            ("POST", "application.deploy"): [{}],
        },
    )
    module.deploy(make_args())
    assert fake.count("POST", "application.update") == 2
    assert fake.count("POST", "application.deploy") == 1
    assert sleeps == [module.RETRY_BACKOFF_SECONDS]


def test_idempotent_call_gives_up_after_three_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    assert module.IDEMPOTENT_ATTEMPTS == 3
    errors = [module.DokployTransientError(f"timeout {n}") for n in (1, 2, 3)]
    fake, sleeps = install_scripted(
        monkeypatch, module, {("GET", "application.one"): [*errors, {"never": "reached"}]}
    )
    with pytest.raises(module.DokployTransientError, match="timeout 3"):
        module.request_json_idempotent("GET", "application.one")
    assert fake.count("GET", "application.one") == 3
    assert sleeps == [module.RETRY_BACKOFF_SECONDS, module.RETRY_BACKOFF_SECONDS * 2]


def test_exhausted_update_retries_stop_the_deploy_before_application_deploy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    errors = [module.DokployTransientError(f"timeout {n}") for n in (1, 2, 3)]
    fake, _sleeps = install_scripted(
        monkeypatch,
        module,
        {
            ("GET", "application.one"): [{"dockerImage": ""}],
            ("POST", "application.update"): errors,
            ("POST", "application.deploy"): [{}],
        },
    )
    with pytest.raises(module.DokployTransientError):
        module.deploy(make_args())
    assert fake.count("POST", "application.update") == 3
    assert fake.count("POST", "application.deploy") == 0


def test_idempotent_call_does_not_retry_a_non_transient_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_scripted(
        monkeypatch,
        module,
        {("GET", "application.one"): [module.DokployError("HTTP 404"), {"never": "reached"}]},
    )
    with pytest.raises(module.DokployError, match="HTTP 404") as raised:
        module.request_json_idempotent("GET", "application.one")
    assert not isinstance(raised.value, module.DokployTransientError)
    assert fake.count("GET", "application.one") == 1
    assert sleeps == []


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://dokploy.invalid/api/x", code, "status", None, io.BytesIO(b"detail")
    )


def install_urlopen(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType, outcomes: list[Any]
) -> tuple[list[float], list[float]]:
    """Replace urlopen so request_json itself runs; returns (timeouts seen, sleeps)."""
    timeouts: list[float] = []
    sleeps: list[float] = []
    queue = list(outcomes)

    def fake_urlopen(_request: Any, timeout: float = 0) -> FakeResponse:
        timeouts.append(timeout)
        outcome = queue.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResponse(json.dumps(outcome).encode("utf-8"))

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    monkeypatch.setenv("DOKPLOY_URL", "https://dokploy.invalid")
    monkeypatch.setenv("DOKPLOY_API_KEY", "test-key")
    monkeypatch.setenv("CF_ACCESS_CLIENT_ID", "test-id")
    monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", "test-secret")
    return timeouts, sleeps


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 422])
def test_http_4xx_is_a_plain_error_and_is_not_retried(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    module = load_module()
    timeouts, sleeps = install_urlopen(monkeypatch, module, [http_error(code), {"never": 1}])
    with pytest.raises(module.DokployError, match=f"HTTP {code}") as raised:
        module.request_json_idempotent("GET", "application.one")
    assert not isinstance(raised.value, module.DokployTransientError)
    assert len(timeouts) == 1
    assert sleeps == []


@pytest.mark.parametrize("code", [500, 502, 503, 504])
def test_http_5xx_is_transient_and_retried_then_succeeds(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    module = load_module()
    timeouts, sleeps = install_urlopen(monkeypatch, module, [http_error(code), {"ok": True}])
    assert module.request_json_idempotent("GET", "application.one") == {"ok": True}
    assert len(timeouts) == 2
    assert sleeps == [module.RETRY_BACKOFF_SECONDS]


@pytest.mark.parametrize(
    "failure", [TimeoutError("timed out"), urllib.error.URLError("connection reset")]
)
def test_transport_failures_are_transient_and_retried(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    module = load_module()
    timeouts, _sleeps = install_urlopen(monkeypatch, module, [failure, {"ok": True}])
    assert module.request_json_idempotent("GET", "application.one") == {"ok": True}
    assert len(timeouts) == 2


def test_transport_failures_exhaust_after_three_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    timeouts, sleeps = install_urlopen(
        monkeypatch, module, [TimeoutError("t1"), TimeoutError("t2"), TimeoutError("t3")]
    )
    with pytest.raises(module.DokployTransientError):
        module.request_json_idempotent("GET", "application.one")
    assert len(timeouts) == 3
    assert sleeps == [module.RETRY_BACKOFF_SECONDS, module.RETRY_BACKOFF_SECONDS * 2]


def test_application_deploy_is_never_retried_on_a_transient_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_scripted(
        monkeypatch,
        module,
        {
            ("GET", "application.one"): [{"dockerImage": ""}],
            ("POST", "application.update"): [{}],
            ("POST", "application.deploy"): [
                module.DokployTransientError("The read operation timed out"),
                {},
            ],
        },
    )
    with pytest.raises(module.DokployTransientError):
        module.deploy(make_args())
    assert fake.count("POST", "application.update") == 1
    assert fake.count("POST", "application.deploy") == 1
    assert sleeps == []


def test_mutating_calls_use_the_longer_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, _sleeps = install_scripted(
        monkeypatch,
        module,
        {
            ("GET", "application.one"): [{"dockerImage": ""}, {"dockerImage": IMAGE}],
            ("POST", "application.update"): [{}],
            ("POST", "application.deploy"): [{}],
        },
    )
    module.deploy(make_args())
    timeouts = {(c[0], c[1]): c[2].get("timeout") for c in fake.calls}
    assert module.MUTATION_TIMEOUT == 120
    assert timeouts[("POST", "application.update")] == module.MUTATION_TIMEOUT
    assert timeouts[("POST", "application.deploy")] == module.MUTATION_TIMEOUT
    assert timeouts[("GET", "application.one")] is None


def test_success_path_is_unchanged_and_never_sleeps(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_scripted(
        monkeypatch,
        module,
        {
            ("GET", "application.one"): [{"dockerImage": OTHER_IMAGE}, {"dockerImage": IMAGE}],
            ("POST", "application.update"): [{}],
            ("POST", "application.deploy"): [{}],
        },
    )
    module.deploy(make_args())
    assert [call[:2] for call in fake.calls] == [
        ("GET", "application.one"),
        ("POST", "application.update"),
        ("POST", "application.deploy"),
        ("GET", "application.one"),
    ]
    update = fake.calls[1][2]["payload"]
    assert update == {"applicationId": APP, "dockerImage": IMAGE}
    deploy = fake.calls[2][2]["payload"]
    assert deploy == {"applicationId": APP, "title": "title", "description": "description"}
    assert sleeps == []
