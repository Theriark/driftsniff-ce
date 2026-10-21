"""The collector contract and the limits every controller read obeys (collectors/base.py)."""

import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
    ERROR_BODY_TOO_LARGE,
    ERROR_CONNECTION,
    ERROR_HTTP,
    ERROR_REDIRECT,
    ERROR_TIMEOUT,
    MAX_BODY_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    RETRY_BACKOFF_SECONDS,
    STATUS_ERROR,
    STATUS_OK,
    Collector,
    CollectorError,
    FetchResult,
    ResourceSpec,
    fetch_json,
    is_retryable,
    make_client,
    read_limited,
)
from driftsniff.sources.addresses import FOLLOW_REDIRECTS

URL = "https://controller.example/api/networks?token=CANARY-query-0001"
HEADERS = {"X-API-KEY": "CANARY-header-0002"}


def client_for(handler: httpx.MockTransport) -> httpx.Client:
    return make_client(transport=handler)


def error_from(
    handler: Callable[[httpx.Request], httpx.Response],
    url: str = URL,
    *,
    headers: Mapping[str, str] | None = None,
    max_bytes: int = MAX_BODY_BYTES,
) -> pytest.ExceptionInfo[CollectorError]:
    """Run fetch_json against ``handler`` and return the error it must raise."""
    with client_for(httpx.MockTransport(handler)) as client:
        with pytest.raises(CollectorError) as caught:
            fetch_json(client, url, headers=headers, max_bytes=max_bytes)
    return caught


def test_the_limits_are_the_numbers_of_the_plan() -> None:
    assert REQUEST_TIMEOUT_SECONDS == 30.0
    assert MAX_BODY_BYTES == 200 * 1024 * 1024
    assert RETRY_BACKOFF_SECONDS == (1.0, 2.0, 4.0)


@pytest.mark.parametrize(
    ("status", "error_class", "expected"),
    [
        (STATUS_ERROR, ERROR_TIMEOUT, True),
        ("500", ERROR_HTTP, True),
        ("502", ERROR_HTTP, True),
        ("599", ERROR_HTTP, True),
        ("403", ERROR_HTTP, False),
        ("404", ERROR_HTTP, False),
        ("302", ERROR_REDIRECT, False),
        (STATUS_ERROR, ERROR_CONNECTION, False),
        (STATUS_ERROR, ERROR_BAD_JSON, False),
        (STATUS_ERROR, ERROR_BODY_TOO_LARGE, False),
        (STATUS_OK, None, False),
        ("5xx", None, False),
        ("50", None, False),
    ],
)
def test_only_timeouts_and_server_errors_are_retried(
    status: str, error_class: str | None, expected: bool
) -> None:
    assert is_retryable(status, error_class) is expected


def test_a_collector_error_knows_its_class_status_and_whether_to_retry() -> None:
    error = CollectorError(ERROR_HTTP, "the controller answered with HTTP 503", status="503")
    assert (error.error_class, error.status, str(error)) == (
        ERROR_HTTP,
        "503",
        "the controller answered with HTTP 503",
    )
    assert error.retryable is True
    plain = CollectorError(ERROR_CONNECTION, "the controller could not be reached")
    assert plain.status == STATUS_ERROR
    assert plain.retryable is False


def test_a_good_read_has_no_error_and_a_failed_read_has_one() -> None:
    good = FetchResult.success([{"_id": "a"}], bytes_fetched=12)
    assert (good.ok, good.status, good.error_class, good.error_text) == (True, "200", None, None)
    assert good.bytes_fetched == 12
    assert good.retryable is False
    bad = FetchResult.failure(ERROR_TIMEOUT, "no answer", bytes_fetched=3)
    assert (bad.ok, bad.status, bad.error_class, bad.error_text) == (
        False,
        STATUS_ERROR,
        ERROR_TIMEOUT,
        "no answer",
    )
    assert bad.objects == ()
    assert bad.bytes_fetched == 3
    assert bad.retryable is True


@pytest.mark.parametrize(
    ("status", "retryable"),
    [("503", True), ("403", False), ("404", False), (STATUS_ERROR, False)],
)
def test_a_failed_read_is_retried_by_its_status(status: str, retryable: bool) -> None:
    assert FetchResult.failure(ERROR_HTTP, "refused", status=status).retryable is retryable


def test_a_fetch_result_that_contradicts_itself_is_refused() -> None:
    with pytest.raises(ValueError, match="no error class"):
        FetchResult(True, error_class=ERROR_TIMEOUT)
    with pytest.raises(ValueError, match="needs an error class"):
        FetchResult(False)
    with pytest.raises(ValueError, match="no objects"):
        FetchResult(False, objects=({"_id": "a"},), error_class=ERROR_HTTP)


def test_a_resource_spec_needs_only_a_name() -> None:
    assert ResourceSpec("networks") == ResourceSpec("networks", "")
    assert ResourceSpec("networks", "/rest/networkconf").path == "/rest/networkconf"


class Reader(Collector):
    def probe(self) -> str | None:
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        return [ResourceSpec("networks")]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        return FetchResult.success([])


def test_a_collector_must_implement_the_three_calls() -> None:
    with pytest.raises(TypeError):
        Collector()  # type: ignore[abstract]
    reader = Reader()
    assert reader.probe() is None
    assert [spec.name for spec in reader.resources()] == ["networks"]
    assert reader.fetch(ResourceSpec("networks")).ok is True
    assert reader.close() is None


def test_the_client_has_a_timeout_and_never_follows_redirects() -> None:
    with make_client() as client:
        assert client.timeout == httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
        assert client.follow_redirects is False
        assert client.follow_redirects is FOLLOW_REDIRECTS


def test_the_proxy_settings_of_the_environment_are_not_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    with client_for(httpx.MockTransport(handler)) as client:
        parsed, _ = fetch_json(client, "https://controller.example/api")
    assert parsed == {"ok": True}
    assert seen == ["https://controller.example/api"]


def test_fetch_json_returns_the_parsed_body_and_its_size() -> None:
    raw = b'{"data": [{"_id": "a"}, {"_id": "b"}]}'

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "CANARY-header-0002"
        return httpx.Response(200, content=raw)

    with client_for(httpx.MockTransport(handler)) as client:
        parsed, size = fetch_json(client, URL, headers=HEADERS)
    assert parsed == {"data": [{"_id": "a"}, {"_id": "b"}]}
    assert size == len(raw)


@pytest.mark.parametrize("status", [400, 403, 404, 500, 502, 503])
def test_an_http_error_status_is_an_error_with_a_fixed_text(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=b"CANARY-body-0003 internal detail")

    caught = error_from(handler, headers=HEADERS)
    assert caught.value.error_class == ERROR_HTTP
    assert caught.value.status == str(status)
    assert str(caught.value) == f"the controller answered with HTTP {status}"
    assert caught.value.retryable is (status >= 500)


def test_an_error_never_holds_the_url_the_headers_or_the_body() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=b"CANARY-body-0003")

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("CANARY-connect-0004 " + str(request.url), request=request)

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("CANARY-timeout-0005 " + str(request.url), request=request)

    def garbled(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"CANARY-json-0006 is not json")

    texts: list[str] = []
    for handler in (refused, unreachable, slow, garbled):
        caught = error_from(handler, headers=HEADERS)
        texts.append(f"{caught.value} {caught.value.error_class}")
    assert len(texts) == 4
    for text in texts:
        assert "CANARY" not in text
        assert "controller.example" not in text
        assert "token" not in text


@pytest.mark.parametrize(
    ("error", "error_class", "retryable"),
    [
        (httpx.ReadTimeout("slow"), ERROR_TIMEOUT, True),
        (httpx.ConnectTimeout("slow"), ERROR_TIMEOUT, True),
        (httpx.ConnectError("down"), ERROR_CONNECTION, False),
        (httpx.ReadError("reset"), ERROR_CONNECTION, False),
    ],
)
def test_transport_failures_are_timeouts_or_connection_errors(
    error: httpx.TransportError, error_class: str, retryable: bool
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    caught = error_from(handler)
    assert caught.value.error_class == error_class
    assert caught.value.status == STATUS_ERROR
    assert caught.value.retryable is retryable


def test_a_body_that_is_not_json_is_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>login</html>")

    caught = error_from(handler)
    assert caught.value.error_class == ERROR_BAD_JSON
    assert caught.value.retryable is False


def test_a_redirect_is_refused_and_the_new_location_is_never_requested() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.host == "controller.example":
            return httpx.Response(302, headers={"location": "https://169.254.169.254/latest"})
        return httpx.Response(200, json={"leaked": True})

    caught = error_from(handler, "https://controller.example/api")
    assert caught.value.error_class == ERROR_REDIRECT
    assert caught.value.status == "302"
    assert requested == ["https://controller.example/api"]
    assert "169.254" not in str(caught.value)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_every_redirect_status_is_refused(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers={"location": "/elsewhere"})

    caught = error_from(handler, "https://controller.example/api")
    assert caught.value.error_class == ERROR_REDIRECT
    assert caught.value.status == str(status)
    assert caught.value.retryable is False


@contextmanager
def loopback_server() -> Iterator[tuple[str, list[str]]]:
    """A real HTTP server on the loopback interface that records every path it is asked for."""
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/target")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_the_real_http_client_refuses_a_redirect_from_a_real_server() -> None:
    with loopback_server() as (base, seen), make_client() as client:
        parsed, _ = fetch_json(client, f"{base}/data")
        assert parsed == {"ok": True}
        with pytest.raises(CollectorError) as caught:
            fetch_json(client, f"{base}/redirect")
    assert caught.value.error_class == ERROR_REDIRECT
    assert caught.value.status == "302"
    assert seen == ["/data", "/redirect"]


def test_a_body_over_the_limit_is_refused_when_its_length_is_declared() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 20)

    caught = error_from(handler, max_bytes=10)
    assert caught.value.error_class == ERROR_BODY_TOO_LARGE
    assert caught.value.retryable is False


def test_a_body_over_the_limit_is_refused_while_it_streams() -> None:
    chunks = iter([b"abcd", b"efgh", b"ijkl"])
    response = httpx.Response(200, content=chunks)
    assert response.headers.get("content-length") is None
    with pytest.raises(CollectorError) as caught:
        read_limited(response, max_bytes=10)
    assert caught.value.error_class == ERROR_BODY_TOO_LARGE
    assert "10 bytes" in str(caught.value)


def test_a_body_at_the_limit_is_read_whole() -> None:
    assert read_limited(httpx.Response(200, content=b"x" * 10), max_bytes=10) == b"x" * 10
    streamed = httpx.Response(200, content=iter([b"abcde", b"fghij"]))
    assert read_limited(streamed, max_bytes=10) == b"abcdefghij"


def test_a_content_length_that_is_not_a_number_is_ignored_until_the_body_is_read() -> None:
    response = httpx.Response(200, headers={"content-length": "many"}, content=b"abc")
    assert read_limited(response, max_bytes=10) == b"abc"
