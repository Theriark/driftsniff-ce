"""The logging filter scrubs the known credential patterns and URL query strings."""

import io
import logging
from collections.abc import Iterator

import pytest

from driftsniff.secrets.redact import REDACTED, RedactingFilter, install_log_filter, scrub_text

LOGGER = logging.getLogger("driftsniff.test")


def pem_block() -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\nQ0FOQVJZ\n-----END " + "PRIVATE KEY-----"


def jwt() -> str:
    return "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJDQU5BUlkifQ" + "." + "c2lnbmF0dXJl"


def url_with_credentials() -> str:
    return "postgresql://svc:" + "CANARY-pw-0001" + "@db.example.invalid:5432/app"


def prefixed_credential() -> str:
    return "ghp_" + "Q" * 20


LONG_WORD = "Zx9Qp4Lm7Vb2Nc8Kd5Rt1Yw6Hs3"
QUERY_LINE = "GET https://svc.example.invalid/api/v1/items?api_key=CANARY-q-0001&page=2 failed"

SEEDS = [
    ("key follows " + pem_block() + " and more", "Q0FOQVJZ"),
    ("Authorization failed for " + jwt(), jwt()),
    ("connecting to " + url_with_credentials(), "CANARY-pw-0001"),
    ("found " + prefixed_credential() + " in a response", prefixed_credential()),
    ("unexpected value " + LONG_WORD + " in a field", LONG_WORD),
    (QUERY_LINE, "CANARY-q-0001"),
]


@pytest.fixture
def captured(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.handler.addFilter(RedactingFilter())
    caplog.set_level(logging.DEBUG)
    return caplog


@pytest.fixture
def root_handler() -> Iterator[logging.StreamHandler[io.StringIO]]:
    handler = logging.StreamHandler(io.StringIO())
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        for existing in root.handlers:
            for item in list(existing.filters):
                if isinstance(item, RedactingFilter):
                    existing.removeFilter(item)


@pytest.mark.parametrize(("text", "sensitive"), SEEDS)
def test_seeded_patterns_are_removed_from_a_captured_log(
    captured: pytest.LogCaptureFixture, text: str, sensitive: str
) -> None:
    LOGGER.warning(text)
    assert sensitive not in captured.text
    assert REDACTED in captured.text


def test_the_question_mark_of_a_query_string_stays_and_its_content_goes() -> None:
    assert scrub_text("GET /items?api_key=CANARY-q-0001&page=2 done") == (
        "GET /items?" + REDACTED + " done"
    )


def test_arguments_are_formatted_and_scrubbed() -> None:
    record = logging.LogRecord(
        "driftsniff.test",
        logging.WARNING,
        __file__,
        1,
        "failed for %s with status %d",
        (url_with_credentials(), 500),
        None,
    )
    assert RedactingFilter().filter(record) is True
    message = record.getMessage()
    assert "CANARY-pw-0001" not in message
    assert message.endswith("with status 500")
    assert record.args is None


def test_a_record_whose_arguments_do_not_fit_is_kept_as_it_is() -> None:
    record = logging.LogRecord(
        "driftsniff.test", logging.WARNING, __file__, 1, "%s and %s", ("one",), None
    )
    assert RedactingFilter().filter(record) is True
    assert record.getMessage() == "%s and %s"


def test_exception_text_is_scrubbed(captured: pytest.LogCaptureFixture) -> None:
    try:
        raise ValueError("bad value " + url_with_credentials())
    except ValueError:
        LOGGER.exception("collection failed")
    assert "CANARY-pw-0001" not in captured.text
    assert "Traceback" in captured.text
    assert "ValueError" in captured.text
    assert captured.records[-1].exc_info is None


def test_cached_exception_text_and_the_stack_are_scrubbed() -> None:
    record = logging.LogRecord("driftsniff.test", logging.ERROR, __file__, 1, "failed", None, None)
    record.exc_text = "error at " + url_with_credentials()
    record.stack_info = "stack " + prefixed_credential()
    assert RedactingFilter().filter(record) is True
    assert "CANARY-pw-0001" not in str(record.exc_text)
    assert prefixed_credential() not in str(record.stack_info)


def test_ordinary_log_lines_are_not_changed() -> None:
    line = "collected 12 objects from src/driftsniff/core/states.py in 0.3 s (host.example.invalid)"
    assert scrub_text(line) == line
    assert scrub_text("") == ""
    assert scrub_text("what?really") == "what?really"
    assert scrub_text("?a=b") == "?a=b"


def test_overlapping_findings_become_one_marker() -> None:
    text = "see https://u:" + prefixed_credential() + "@h.example.invalid/x ok"
    assert scrub_text(text) == "see https://" + REDACTED + "@h.example.invalid/x ok"


def test_a_pem_header_without_an_end_line_hides_the_rest_of_the_text() -> None:
    text = "before " + "-----BEGIN " + "PRIVATE KEY-----\nQ0FOQVJZ and the rest"
    assert scrub_text(text) == "before " + REDACTED


def test_the_filter_is_installed_once_on_every_root_handler(
    root_handler: logging.StreamHandler[io.StringIO],
) -> None:
    install_log_filter()
    assert install_log_filter() == 0
    assert [type(item) for item in root_handler.filters] == [RedactingFilter]
    LOGGER.warning("connecting to %s", url_with_credentials())
    assert "CANARY-pw-0001" not in root_handler.stream.getvalue()
    assert REDACTED in root_handler.stream.getvalue()
