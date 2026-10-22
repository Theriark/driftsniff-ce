"""The newline delimited JSON reader of the collector base (P8-T2).

It reads a streamed body in chunks and parses it line by line. The limits count bytes while the body
streams, a bad line fails with a fixed text, and the transport failures are the ones of
``fetch_json``.
"""

import httpx
import pytest

from driftsniff.collectors.base import (
    ERROR_BAD_PAYLOAD,
    ERROR_BODY_TOO_LARGE,
    ERROR_CONNECTION,
    ERROR_HTTP,
    ERROR_REDIRECT,
    ERROR_TIMEOUT,
    MAX_BODY_BYTES,
    MAX_LINE_BYTES,
    CollectorError,
    fetch_ndjson,
)
from driftsniff.core.canonical import JsonValue

URL = "https://xo.example.test/rest/v0/vms"
LINE = b'{"a":1}\n'


def reading(
    handler: httpx.MockTransport,
    max_bytes: int = MAX_BODY_BYTES,
    max_line_bytes: int = MAX_LINE_BYTES,
) -> tuple[list[JsonValue], int]:
    with httpx.Client(transport=handler) as client:
        return fetch_ndjson(client, URL, max_bytes=max_bytes, max_line_bytes=max_line_bytes)


def answer(response: httpx.Response) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: response)


def test_every_line_is_parsed_and_the_bytes_are_counted() -> None:
    values, size = reading(answer(httpx.Response(200, content=b'{"a":1}\n{"b":[2]}\r\n')))
    assert values == [{"a": 1}, {"b": [2]}]
    assert size == 19


def test_an_empty_body_has_no_lines() -> None:
    assert reading(answer(httpx.Response(200, content=b""))) == ([], 0)


def test_the_last_line_needs_no_newline_and_blank_lines_are_skipped() -> None:
    values, _ = reading(answer(httpx.Response(200, content=b'\n{"a":1}\n  \n{"b":2}')))
    assert values == [{"a": 1}, {"b": 2}]


def test_a_line_split_over_chunks_is_joined() -> None:
    chunks = [b'{"a":', b"1}\n{", b'"b":2}\n']
    values, size = reading(answer(httpx.Response(200, content=iter(chunks))))
    assert values == [{"a": 1}, {"b": 2}]
    assert size == sum(len(chunk) for chunk in chunks)


def test_the_limit_counts_bytes_while_the_body_streams() -> None:
    # No content length is declared, so only the streaming count can stop it.
    response = httpx.Response(200, content=iter([LINE] * 5))
    with pytest.raises(CollectorError) as caught:
        reading(answer(response), max_bytes=20)
    assert caught.value.error_class == ERROR_BODY_TOO_LARGE


def test_a_declared_length_over_the_limit_is_refused_before_reading() -> None:
    with pytest.raises(CollectorError) as caught:
        reading(answer(httpx.Response(200, content=LINE * 10)), max_bytes=10)
    assert caught.value.error_class == ERROR_BODY_TOO_LARGE


def test_a_body_exactly_at_the_limit_is_read() -> None:
    values, size = reading(answer(httpx.Response(200, content=LINE * 2)), max_bytes=16)
    assert values == [{"a": 1}, {"a": 1}]
    assert size == 16


def test_a_line_over_the_line_limit_is_a_bad_payload() -> None:
    response = httpx.Response(200, content=iter([b"x" * 50]))
    with pytest.raises(CollectorError) as caught:
        reading(answer(response), max_line_bytes=10)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


@pytest.mark.parametrize(
    "body",
    [
        b'{"a":1}\nCANARY-line-text\n',
        b'{"a":1}\n{"b"',
        b"{'a': 1}\n",
    ],
)
def test_a_line_that_is_not_json_is_a_bad_payload_that_does_not_quote_it(body: bytes) -> None:
    with pytest.raises(CollectorError) as caught:
        reading(answer(httpx.Response(200, content=body)))
    assert caught.value.error_class == ERROR_BAD_PAYLOAD
    assert "CANARY" not in str(caught.value)
    assert '{"b"' not in str(caught.value)


@pytest.mark.parametrize(
    ("status", "error_class"), [(401, ERROR_HTTP), (404, ERROR_HTTP), (502, ERROR_HTTP)]
)
def test_an_http_error_status_is_an_error_with_that_status(status: int, error_class: str) -> None:
    with pytest.raises(CollectorError) as caught:
        reading(answer(httpx.Response(status, content=b"CANARY-body")))
    assert caught.value.error_class == error_class
    assert caught.value.status == str(status)
    assert "CANARY" not in str(caught.value)


def test_a_redirect_is_never_followed() -> None:
    response = httpx.Response(302, headers={"location": "https://other.example.test/"})
    with pytest.raises(CollectorError) as caught:
        reading(answer(response))
    assert caught.value.error_class == ERROR_REDIRECT


@pytest.mark.parametrize(
    ("failure", "error_class"),
    [
        (httpx.ReadTimeout("slow"), ERROR_TIMEOUT),
        (httpx.ConnectError("CANARY-refused"), ERROR_CONNECTION),
        (httpx.RemoteProtocolError("CANARY-cut"), ERROR_CONNECTION),
    ],
)
def test_a_transport_failure_has_a_fixed_text(failure: httpx.HTTPError, error_class: str) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise failure

    with pytest.raises(CollectorError) as caught:
        reading(httpx.MockTransport(refuse))
    assert caught.value.error_class == error_class
    assert "CANARY" not in str(caught.value)
