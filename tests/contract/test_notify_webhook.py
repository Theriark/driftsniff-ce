"""The webhook sender against a local receiver (P9-T4).

Covers the signature (a receiver can verify it), the headers, the retry classes, redirects that are
never followed, and the send-time target check: the cloud metadata range, link-local addresses and
names that resolve to them are refused before any byte is sent, and the connection goes to the
address that was checked, not to the name.
"""

import hashlib
import hmac
import json
import logging
import time
from pathlib import Path

import pytest

from driftsniff.collectors.base import CollectorError
from driftsniff.collectors.resolve import system_resolver
from driftsniff.notify.message import NotificationMessage, build_message, sample_message
from driftsniff.notify.webhook import (
    ERROR_CONNECTION,
    ERROR_REDIRECT,
    ERROR_REJECTED,
    ERROR_SERVER,
    ERROR_TIMEOUT,
    ERROR_TLS,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    SendResult,
    encode_body,
    send_webhook,
    sign,
    verify,
)

from .fake_notify import Reply, running_receiver, trusting_context
from .fake_tls import make_pki, running_server

KEY = hashlib.sha256(b"test webhook key").digest()
BASE = "https://driftsniff.example"


def message() -> NotificationMessage:
    return build_message(
        event_id=7,
        source="lab",
        severity="high",
        summary="2 changes in 1 resource type, highest severity high",
        item_count=2,
        base_url=BASE,
    )


def loopback(_host: str) -> list[str]:
    return ["127.0.0.1"]


def clock() -> float:
    return 1_800_000_000.0


def post(url: str, *, timeout: float = 10.0) -> SendResult:
    return send_webhook(url, message(), KEY, resolver=loopback, now=clock, timeout=timeout)


def test_a_message_is_posted_as_json_with_a_signature_the_receiver_can_verify() -> None:
    with running_receiver() as receiver:
        result = post(receiver.url)
    assert result.ok is True
    assert result.http_status == 200
    (request,) = receiver.requests
    assert request.headers["content-type"] == "application/json"
    body = json.loads(request.body)
    assert body == {
        "event_id": 7,
        "source": "lab",
        "severity": "high",
        "summary": "2 changes in 1 resource type, highest severity high",
        "item_count": 2,
        "link": "https://driftsniff.example/changes/7",
        "test": False,
    }
    timestamp = request.headers[TIMESTAMP_HEADER.lower()]
    signature = request.headers[SIGNATURE_HEADER.lower()]
    assert timestamp == "1800000000"
    assert verify(KEY, timestamp, request.body, signature, now=1_800_000_000.0)


def test_the_signature_covers_the_timestamp_and_the_body_with_the_documented_construction() -> None:
    body = b'{"a":1}'
    expected = hmac.new(KEY, b"1800000000." + body, hashlib.sha256).hexdigest()
    assert sign(KEY, "1800000000", body) == expected
    assert len(expected) == 64
    assert verify(KEY, "1800000000", body, expected, now=1_800_000_000.0)
    assert not verify(KEY, "1800000001", body, expected, now=1_800_000_000.0)
    assert not verify(KEY, "1800000000", body + b" ", expected, now=1_800_000_000.0)
    assert not verify(b"x" * 32, "1800000000", body, expected, now=1_800_000_000.0)


def test_an_old_or_malformed_timestamp_is_not_accepted() -> None:
    body = b"{}"
    old = sign(KEY, "1800000000", body)
    assert not verify(KEY, "1800000000", body, old, now=1_800_000_000.0 + 301)
    assert verify(KEY, "1800000000", body, old, now=1_800_000_000.0 + 299)
    assert not verify(KEY, "not-a-number", body, old, now=1_800_000_000.0)
    assert not verify(KEY, "-5", body, old, now=1_800_000_000.0)


def test_the_address_of_the_receiver_is_not_logged_by_the_http_library(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "CANARY-hook-query-0001"  # noqa: S105
    with caplog.at_level(logging.DEBUG), running_receiver() as receiver:
        result = post(f"{receiver.url}?token={secret}")
    assert result.ok is True
    assert secret not in caplog.text


def test_the_body_is_the_same_bytes_for_the_same_message() -> None:
    assert encode_body(sample_message(BASE)) == encode_body(sample_message(BASE))
    assert json.loads(encode_body(sample_message(BASE)))["test"] is True


@pytest.mark.parametrize("status", [500, 502, 503, 429])
def test_server_errors_and_rate_limits_can_be_retried(status: int) -> None:
    with running_receiver([Reply(status)]) as receiver:
        result = post(receiver.url)
    assert (result.ok, result.error_class, result.http_status, result.retry) == (
        False,
        ERROR_SERVER,
        status,
        True,
    )


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410])
def test_a_refusal_by_the_receiver_is_not_retried(status: int) -> None:
    with running_receiver([Reply(status)]) as receiver:
        result = post(receiver.url)
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_REJECTED, False)
    assert result.http_status == status


def test_a_redirect_is_never_followed_even_to_an_allowed_address() -> None:
    with running_receiver() as target, running_receiver([Reply(302, target.url)]) as receiver:
        result = post(receiver.url)
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_REDIRECT, False)
    assert target.requests == []
    assert len(receiver.requests) == 1


def test_a_redirect_to_the_metadata_address_is_a_failure_and_nothing_follows_it() -> None:
    redirect = Reply(307, "http://169.254.169.254/latest/meta-data/")
    with running_receiver([redirect]) as receiver:
        result = post(receiver.url)
    assert result.error_class == ERROR_REDIRECT
    assert result.http_status == 307
    assert len(receiver.requests) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.0.1/hook",
        "http://[fe80::1]/hook",
        "http://100.100.100.200/hook",
        "http://[::ffff:169.254.169.254]/hook",
        "http://2852039166/hook",
    ],
)
def test_blocked_literal_targets_are_refused_before_anything_is_sent(url: str) -> None:
    result = send_webhook(url, message(), KEY, resolver=system_resolver, now=clock)
    assert (result.ok, result.error_class, result.retry) == (False, "blocked_address", False)


def test_a_name_that_resolves_to_a_blocked_address_is_refused() -> None:
    def resolver(_host: str) -> list[str]:
        return ["169.254.169.254"]

    with running_receiver() as receiver:
        result = send_webhook(
            f"http://evil.example:{receiver.port}/hook",
            message(),
            KEY,
            resolver=resolver,
            now=clock,
        )
    assert result.error_class == "blocked_address"
    assert receiver.requests == []


def test_one_blocked_answer_among_allowed_ones_refuses_the_target() -> None:
    def resolver(_host: str) -> list[str]:
        return ["127.0.0.1", "169.254.169.254"]

    with running_receiver() as receiver:
        result = send_webhook(receiver.url, message(), KEY, resolver=resolver, now=clock)
    assert result.error_class == "blocked_address"
    assert receiver.requests == []


def test_a_name_that_does_not_resolve_is_a_failure_without_a_request() -> None:
    def resolver(_host: str) -> list[str]:
        raise CollectorError("connection", "cannot be resolved")

    result = send_webhook(
        "http://nowhere.example/hook", message(), KEY, resolver=resolver, now=clock
    )
    assert (result.ok, result.error_class, result.retry) == (False, "unresolved", False)


def test_the_connection_goes_to_the_address_that_was_checked_not_to_the_name() -> None:
    # The name does not exist in DNS; only the approved address 127.0.0.1 can answer.
    with running_receiver() as receiver:
        result = send_webhook(
            f"http://rebind.invalid:{receiver.port}/hook",
            message(),
            KEY,
            resolver=loopback,
            now=clock,
        )
    assert result.ok is True
    assert receiver.requests[0].headers["host"] == f"rebind.invalid:{receiver.port}"


def test_a_closed_port_is_a_connection_failure_that_can_be_retried() -> None:
    with running_receiver() as receiver:
        url = receiver.url
    result = post(url)
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_CONNECTION, True)


def test_a_slow_receiver_is_a_timeout_that_can_be_retried() -> None:
    started = time.monotonic()
    with running_receiver([Reply(200, delay=1.5)]) as receiver:
        result = post(receiver.url, timeout=0.3)
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_TIMEOUT, True)
    assert time.monotonic() - started < 5


def test_https_with_the_right_ca_is_delivered_and_the_name_is_checked(tmp_path: Path) -> None:
    pki = make_pki(tmp_path / "pki")
    with running_server(pki) as server:
        port = server.url.rsplit(":", 1)[1]
        result = send_webhook(
            f"https://localhost:{port}/hook",
            message(),
            KEY,
            resolver=loopback,
            now=clock,
            ssl_context=trusting_context(pki),
        )
        assert server.wait_finished(1)
    assert result.ok is True
    assert SIGNATURE_HEADER.lower().encode() in server.received.lower()


def test_https_with_an_unknown_ca_is_a_tls_failure_and_no_request_byte_is_sent(
    tmp_path: Path,
) -> None:
    pki = make_pki(tmp_path / "pki")
    other = make_pki(tmp_path / "other", "other-ca")
    with running_server(pki) as server:
        port = server.url.rsplit(":", 1)[1]
        result = send_webhook(
            f"https://localhost:{port}/hook",
            message(),
            KEY,
            resolver=loopback,
            now=clock,
            ssl_context=trusting_context(other),
        )
        server.wait_finished(1)
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_TLS, False)
    assert server.received == b""


def test_https_to_a_certificate_for_another_name_is_refused(tmp_path: Path) -> None:
    pki = make_pki(tmp_path / "pki")
    with running_server(pki) as server:
        port = server.url.rsplit(":", 1)[1]
        result = send_webhook(
            f"https://wrong-name.example:{port}/hook",
            message(),
            KEY,
            resolver=loopback,
            now=clock,
            ssl_context=trusting_context(pki),
        )
        server.wait_finished(1)
    assert result.error_class == ERROR_TLS
    assert server.received == b""
