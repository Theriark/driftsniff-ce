"""Unit tests for the Dokploy release helper (.github/scripts/dokploy_release.py)."""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
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


# --- retry behaviour of request_json (THE-640 design, tests added in THE-652) ---------------


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://dokploy.invalid/api/x", code, "status", Message(), io.BytesIO(b"detail")
    )


class ScriptedUrlopen:
    """Stands in for urlopen so the real request_json runs.

    Each Dokploy endpoint (the last URL path segment) plays its outcomes in order. An exception
    outcome is raised, anything else is returned as a JSON body. Every call is recorded.
    """

    def __init__(self, script: dict[str, list[Any]]) -> None:
        self.script = {name: list(outcomes) for name, outcomes in script.items()}
        self.calls: list[tuple[str, float, dict[str, Any] | None]] = []

    def __call__(self, request: urllib.request.Request, timeout: float = 0) -> FakeResponse:
        name = urllib.parse.urlparse(request.full_url).path.rsplit("/", 1)[-1]
        payload = None
        if isinstance(request.data, bytes):
            payload = json.loads(request.data)
        self.calls.append((name, timeout, payload))
        outcome = self.script[name].pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResponse(json.dumps(outcome).encode("utf-8"))

    def count(self, name: str) -> int:
        return sum(1 for call in self.calls if call[0] == name)

    def timeouts(self, name: str) -> list[float]:
        return [call[1] for call in self.calls if call[0] == name]


def install_http(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType, script: dict[str, list[Any]]
) -> tuple[ScriptedUrlopen, list[float]]:
    fake = ScriptedUrlopen(script)
    sleeps: list[float] = []
    monkeypatch.setattr(module.urllib.request, "urlopen", fake)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    monkeypatch.setattr(module, "wait_health", lambda *_args, **_kwargs: None)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setenv("DOKPLOY_URL", "https://dokploy.invalid")
    monkeypatch.setenv("DOKPLOY_API_KEY", "test-key")
    monkeypatch.setenv("CF_ACCESS_CLIENT_ID", "test-id")
    monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", "test-secret")
    return fake, sleeps


def test_retry_constants_match_the_reviewed_design() -> None:
    module = load_module()
    assert module.UPDATE_TIMEOUT_SECONDS == 90
    assert module.UPDATE_ATTEMPTS == 3
    assert module.UPDATE_BACKOFF_SECONDS == (5, 15)
    assert module.RETRYABLE_HTTP_CODES == frozenset({502, 503, 504})


@pytest.mark.parametrize("code", [502, 503, 504])
def test_retryable_http_status_is_retried_then_succeeds(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    module = load_module()
    fake, sleeps = install_http(monkeypatch, module, {"application.update": [http_error(code), {}]})
    result = module.request_json("POST", "application.update", payload={"a": 1}, attempts=3)
    assert result == {}
    assert fake.count("application.update") == 2
    assert sleeps == [5]


@pytest.mark.parametrize(
    "failure", [TimeoutError("timed out"), urllib.error.URLError("connection reset")]
)
def test_transport_failure_is_retried_then_succeeds(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch, module, {"application.update": [failure, {"ok": True}]}
    )
    result = module.request_json("POST", "application.update", payload={"a": 1}, attempts=3)
    assert result == {"ok": True}
    assert fake.count("application.update") == 2
    assert sleeps == [5]


def test_retry_exhausts_after_three_calls_with_growing_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {"application.update": [http_error(502), http_error(503), http_error(504), {}]},
    )
    with pytest.raises(module.DokployError, match="HTTP 504") as raised:
        module.request_json("POST", "application.update", payload={"a": 1}, attempts=3)
    assert isinstance(raised.value.__cause__, urllib.error.HTTPError)
    assert fake.count("application.update") == 3
    assert sleeps == [5, 15]


def test_transport_failures_exhaust_after_three_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {"application.update": [TimeoutError("t1"), TimeoutError("t2"), TimeoutError("t3"), {}]},
    )
    with pytest.raises(module.DokployError, match="t3"):
        module.request_json("POST", "application.update", payload={"a": 1}, attempts=3)
    assert fake.count("application.update") == 3
    assert sleeps == [5, 15]


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 422, 500])
def test_non_retryable_http_status_fails_at_once(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    module = load_module()
    fake, sleeps = install_http(monkeypatch, module, {"application.update": [http_error(code), {}]})
    with pytest.raises(module.DokployError, match=f"HTTP {code}"):
        module.request_json("POST", "application.update", payload={"a": 1}, attempts=3)
    assert fake.count("application.update") == 1
    assert sleeps == []


def test_a_single_attempt_is_the_default_even_for_a_retryable_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_http(monkeypatch, module, {"application.one": [http_error(503), {}]})
    with pytest.raises(module.DokployError, match="HTTP 503"):
        module.request_json("GET", "application.one", query={"applicationId": APP})
    assert fake.count("application.one") == 1
    assert sleeps == []


def test_update_is_retried_after_a_gateway_error_and_deploy_is_requested_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": ""}, {"dockerImage": IMAGE}],
            "application.update": [http_error(504), {}],
            "application.deploy": [{}],
        },
    )
    module.deploy(make_args())
    assert fake.count("application.update") == 2
    assert fake.count("application.deploy") == 1
    assert sleeps == [5]


def test_exhausted_update_retries_stop_before_application_deploy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": ""}],
            "application.update": [http_error(503), http_error(503), http_error(503), {}],
            "application.deploy": [{}],
        },
    )
    with pytest.raises(module.DokployError, match="HTTP 503"):
        module.deploy(make_args())
    assert fake.count("application.update") == 3
    assert fake.count("application.deploy") == 0
    assert sleeps == [5, 15]


def test_a_client_error_on_update_is_not_retried_and_stops_the_deploy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": ""}],
            "application.update": [http_error(403), {}],
            "application.deploy": [{}],
        },
    )
    with pytest.raises(module.DokployError, match="HTTP 403"):
        module.deploy(make_args())
    assert fake.count("application.update") == 1
    assert fake.count("application.deploy") == 0
    assert sleeps == []


@pytest.mark.parametrize("failure", [http_error(502), http_error(504), TimeoutError("timed out")])
def test_application_deploy_is_a_single_attempt(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": ""}],
            "application.update": [{}],
            "application.deploy": [failure, {}],
        },
    )
    with pytest.raises(module.DokployError):
        module.deploy(make_args())
    assert fake.count("application.update") == 1
    assert fake.count("application.deploy") == 1
    assert sleeps == []


def test_timeouts_are_90_seconds_for_update_and_30_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, _sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": ""}, {"dockerImage": IMAGE}],
            "application.update": [{}],
            "application.deploy": [{}],
        },
    )
    module.deploy(make_args())
    assert fake.timeouts("application.update") == [90]
    assert fake.timeouts("application.deploy") == [30]
    assert fake.timeouts("application.one") == [30, 30]


def test_success_path_is_unchanged_and_never_sleeps(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": OTHER_IMAGE}, {"dockerImage": IMAGE}],
            "application.update": [{}],
            "application.deploy": [{}],
        },
    )
    module.deploy(make_args())
    assert [call[0] for call in fake.calls] == [
        "application.one",
        "application.update",
        "application.deploy",
        "application.one",
    ]
    assert fake.calls[1][2] == {"applicationId": APP, "dockerImage": IMAGE}
    assert fake.calls[2][2] == {
        "applicationId": APP,
        "title": "title",
        "description": "description",
    }
    assert sleeps == []


# --- HTTP 401 on a read is retried, never on a write (THE-695) -------------------------------


def test_read_retry_constants() -> None:
    module = load_module()
    assert module.READ_ATTEMPTS == 3
    assert module.READ_RETRYABLE_HTTP_CODES == frozenset({401})
    # 401 is not a write retry code: the write set is unchanged.
    assert 401 not in module.RETRYABLE_HTTP_CODES


def test_get_401_is_retried_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch, module, {"application.one": [http_error(401), {"dockerImage": IMAGE}]}
    )
    result = module.request_json("GET", "application.one", query={"applicationId": APP}, attempts=3)
    assert result == {"dockerImage": IMAGE}
    assert fake.count("application.one") == 2
    assert sleeps == [5]


def test_get_401_applies_to_any_read_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch, module, {"project.all": [http_error(401), http_error(401), []]}
    )
    assert module.request_json("GET", "project.all", attempts=3) == []
    assert fake.count("project.all") == 3
    assert sleeps == [5, 15]


def test_get_401_exhausts_after_three_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {"application.one": [http_error(401), http_error(401), http_error(401), {}]},
    )
    with pytest.raises(module.DokployError, match="HTTP 401") as raised:
        module.request_json("GET", "application.one", query={"applicationId": APP}, attempts=3)
    assert isinstance(raised.value.__cause__, urllib.error.HTTPError)
    assert fake.count("application.one") == 3
    assert sleeps == [5, 15]


def test_get_401_is_a_single_attempt_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(monkeypatch, module, {"application.one": [http_error(401), {}]})
    with pytest.raises(module.DokployError, match="HTTP 401"):
        module.request_json("GET", "application.one", query={"applicationId": APP})
    assert fake.count("application.one") == 1
    assert sleeps == []


@pytest.mark.parametrize("code", [400, 403, 404, 409, 422, 500])
def test_other_client_errors_on_a_read_are_not_retried(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    module = load_module()
    fake, sleeps = install_http(monkeypatch, module, {"application.one": [http_error(code), {}]})
    with pytest.raises(module.DokployError, match=f"HTTP {code}"):
        module.request_json("GET", "application.one", query={"applicationId": APP}, attempts=3)
    assert fake.count("application.one") == 1
    assert sleeps == []


def test_current_image_retries_a_401_read(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch, module, {"application.one": [http_error(401), {"dockerImage": IMAGE}]}
    )
    assert module.current_image(APP) == IMAGE
    assert fake.count("application.one") == 2
    assert sleeps == [5]


@pytest.mark.parametrize("code", [403, 404, 409])
def test_current_image_does_not_retry_other_client_errors(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch, module, {"application.one": [http_error(code), {"dockerImage": IMAGE}]}
    )
    with pytest.raises(module.DokployError, match=f"HTTP {code}"):
        module.current_image(APP)
    assert fake.count("application.one") == 1
    assert sleeps == []


def test_assert_image_retries_a_401_read(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch, module, {"application.one": [http_error(401), {"dockerImage": IMAGE}]}
    )
    module.assert_image(make_args())
    assert fake.count("application.one") == 2
    assert sleeps == [5]


def test_first_read_401_is_retried_before_the_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [http_error(401), {"dockerImage": ""}, {"dockerImage": IMAGE}],
            "application.update": [{}],
            "application.deploy": [{}],
        },
    )
    module.deploy(make_args())
    assert fake.count("application.one") == 3
    assert fake.count("application.update") == 1
    assert fake.count("application.deploy") == 1
    assert sleeps == [5]


def test_reread_after_the_health_check_retries_a_401(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Development failure of run 39689087290: deploy and health passed, then the re-read
    # of the deployment record answered one HTTP 401.
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": ""}, http_error(401), {"dockerImage": IMAGE}],
            "application.update": [{}],
            "application.deploy": [{}],
        },
    )
    module.deploy(make_args())
    assert [call[0] for call in fake.calls] == [
        "application.one",
        "application.update",
        "application.deploy",
        "application.one",
        "application.one",
    ]
    assert fake.count("application.update") == 1
    assert fake.count("application.deploy") == 1
    assert sleeps == [5]


def test_reread_after_the_health_check_fails_when_401_persists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [
                {"dockerImage": ""},
                http_error(401),
                http_error(401),
                http_error(401),
                {"dockerImage": IMAGE},
            ],
            "application.update": [{}],
            "application.deploy": [{}],
        },
    )
    with pytest.raises(module.DokployError, match="HTTP 401"):
        module.deploy(make_args())
    assert fake.count("application.one") == 4
    assert fake.count("application.deploy") == 1
    assert sleeps == [5, 15]


def test_a_401_on_update_is_not_retried_and_stops_the_deploy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": ""}],
            "application.update": [http_error(401), {}],
            "application.deploy": [{}],
        },
    )
    with pytest.raises(module.DokployError, match="HTTP 401"):
        module.deploy(make_args())
    assert fake.count("application.update") == 1
    assert fake.count("application.deploy") == 0
    assert sleeps == []


def test_a_401_on_application_deploy_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    fake, sleeps = install_http(
        monkeypatch,
        module,
        {
            "application.one": [{"dockerImage": ""}],
            "application.update": [{}],
            "application.deploy": [http_error(401), {}],
        },
    )
    with pytest.raises(module.DokployError, match="HTTP 401"):
        module.deploy(make_args())
    assert fake.count("application.update") == 1
    assert fake.count("application.deploy") == 1
    assert fake.count("application.one") == 1
    assert sleeps == []


def test_a_401_on_a_post_is_not_retried_even_with_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake, sleeps = install_http(monkeypatch, module, {"application.deploy": [http_error(401), {}]})
    with pytest.raises(module.DokployError, match="HTTP 401"):
        module.request_json("POST", "application.deploy", payload={"a": 1}, attempts=3)
    assert fake.count("application.deploy") == 1
    assert sleeps == []
