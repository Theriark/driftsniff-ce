"""The mail sender against a local mail server with TLS (P9-T4).

Covers STARTTLS (the default) and implicit TLS, the login, the refusal of a server that does not
offer STARTTLS (the login must never go in clear), certificate and host name checks, the error
classes, header injection through a source name and the send-time target check.
"""

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from driftsniff.collectors.resolve import system_resolver
from driftsniff.notify.config import SECURITY_STARTTLS, SECURITY_TLS, SmtpConfig
from driftsniff.notify.message import NotificationMessage, build_message, sample_message
from driftsniff.notify.smtp import (
    ERROR_SMTP_LOGIN,
    ERROR_SMTP_NO_STARTTLS,
    ERROR_SMTP_REFUSED,
    ERROR_SMTP_TEMPORARY,
    build_mail,
    send_mail,
)
from driftsniff.notify.webhook import ERROR_CONNECTION, ERROR_TLS

from .fake_notify import running_smtp, trusting_context
from .fake_tls import Pki, make_pki

USER = "alerts"
LOGIN_SECRET = "CANARY-mail-login-0001"  # noqa: S105
LOGIN = (USER, LOGIN_SECRET)


@pytest.fixture
def pki(tmp_path: Path) -> Pki:
    return make_pki(tmp_path / "pki")


def loopback(_host: str) -> list[str]:
    return ["127.0.0.1"]


def config(port: int, **changes: Any) -> SmtpConfig:
    base = SmtpConfig(
        host="localhost",
        port=port,
        security=SECURITY_STARTTLS,
        from_address="driftsniff@example.com",
        to_addresses=("ops@example.com", "lead@example.com"),
        username=USER,
        password=LOGIN_SECRET,
    )
    return replace(base, **changes)


def message(source: str = "lab") -> NotificationMessage:
    return build_message(
        event_id=7,
        source=source,
        severity="critical",
        summary="3 changes in 2 resource types, highest severity critical",
        item_count=3,
        base_url="https://driftsniff.example",
    )


def test_a_mail_is_sent_over_starttls_with_the_login_after_the_upgrade(pki: Pki) -> None:
    with running_smtp(pki, login=LOGIN) as server:
        result = send_mail(
            config(server.port), message(), resolver=loopback, ssl_context=trusting_context(pki)
        )
        assert server.wait_for(lambda state: bool(state.messages))
    assert result.ok is True
    assert server.state.logins == [USER]
    commands = server.state.commands
    assert commands.index("STARTTLS") < commands.index("AUTH") < commands.index("DATA")
    text = server.state.messages[0]
    assert "Subject: [driftsniff] CRITICAL - lab" in text
    assert "To: ops@example.com, lead@example.com" in text
    assert "Event: 7" in text
    assert "Items: 3" in text
    assert "Link: https://driftsniff.example/changes/7" in text


def test_a_mail_is_sent_over_implicit_tls(pki: Pki) -> None:
    with running_smtp(pki, implicit_tls=True, login=LOGIN) as server:
        result = send_mail(
            config(server.port, security=SECURITY_TLS),
            message(),
            resolver=loopback,
            ssl_context=trusting_context(pki),
        )
        assert server.wait_for(lambda state: bool(state.messages))
    assert result.ok is True
    assert "STARTTLS" not in server.state.commands


def test_a_server_without_starttls_is_refused_and_no_login_is_sent(pki: Pki) -> None:
    with running_smtp(pki, offer_starttls=False, login=LOGIN) as server:
        result = send_mail(
            config(server.port), message(), resolver=loopback, ssl_context=trusting_context(pki)
        )
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_SMTP_NO_STARTTLS, False)
    assert "AUTH" not in server.state.commands
    assert "DATA" not in server.state.commands


def test_a_wrong_login_is_a_login_failure_that_is_not_retried(pki: Pki) -> None:
    with running_smtp(pki, login=LOGIN) as server:
        result = send_mail(
            config(server.port, password="CANARY-wrong-login"),
            message(),
            resolver=loopback,
            ssl_context=trusting_context(pki),
        )
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_SMTP_LOGIN, False)
    assert server.state.messages == []


def test_a_server_without_a_login_works_when_none_is_configured(pki: Pki) -> None:
    with running_smtp(pki) as server:
        result = send_mail(
            config(server.port, username=None, password=None),
            message(),
            resolver=loopback,
            ssl_context=trusting_context(pki),
        )
        assert server.wait_for(lambda state: bool(state.messages))
    assert result.ok is True
    assert "AUTH" not in server.state.commands


def test_an_unknown_ca_is_a_tls_failure_and_nothing_is_sent(pki: Pki, tmp_path: Path) -> None:
    other = make_pki(tmp_path / "other", "other-ca")
    with running_smtp(pki, login=LOGIN) as server:
        result = send_mail(
            config(server.port), message(), resolver=loopback, ssl_context=trusting_context(other)
        )
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_TLS, False)
    assert "AUTH" not in server.state.commands
    assert server.state.messages == []


def test_a_certificate_for_another_name_is_refused(pki: Pki) -> None:
    with running_smtp(pki, login=LOGIN) as server:
        result = send_mail(
            config(server.port, host="mail.wrong-name.example"),
            message(),
            resolver=loopback,
            ssl_context=trusting_context(pki),
        )
    assert result.error_class == ERROR_TLS
    assert "AUTH" not in server.state.commands


def test_a_temporary_refusal_can_be_retried_and_a_permanent_one_cannot(pki: Pki) -> None:
    with running_smtp(pki, login=LOGIN, rcpt_reply="451 try later") as server:
        temporary = send_mail(
            config(server.port), message(), resolver=loopback, ssl_context=trusting_context(pki)
        )
    assert (temporary.error_class, temporary.retry) == (ERROR_SMTP_TEMPORARY, True)
    with running_smtp(pki, login=LOGIN, rcpt_reply="550 no such user") as server:
        permanent = send_mail(
            config(server.port), message(), resolver=loopback, ssl_context=trusting_context(pki)
        )
    assert (permanent.error_class, permanent.retry) == (ERROR_SMTP_REFUSED, False)


def test_a_closed_port_is_a_connection_failure_that_can_be_retried(pki: Pki) -> None:
    with running_smtp(pki) as server:
        port = server.port
    result = send_mail(
        config(port), message(), resolver=loopback, ssl_context=trusting_context(pki)
    )
    assert (result.ok, result.error_class, result.retry) == (False, ERROR_CONNECTION, True)


@pytest.mark.parametrize("host", ["169.254.169.254", "fe80::1", "100.100.100.200"])
def test_a_blocked_mail_host_is_refused_before_any_connection(host: str) -> None:
    result = send_mail(config(25, host=host), message(), resolver=system_resolver)
    assert (result.ok, result.error_class) == (False, "blocked_address")


def test_a_name_that_resolves_to_a_blocked_address_is_refused() -> None:
    def resolver(_host: str) -> list[str]:
        return ["169.254.169.254"]

    result = send_mail(config(25, host="mail.example.com"), message(), resolver=resolver)
    assert (result.ok, result.error_class) == (False, "blocked_address")


def test_a_source_name_cannot_inject_a_header() -> None:
    nasty = "lab\r\nBcc: attacker@example.com\r\nX-Evil: 1"
    mail = build_mail(config(25), message(nasty))
    assert "Bcc" not in mail
    assert "X-Evil" not in mail
    assert "\n" not in str(mail["Subject"])
    allowed = {"subject", "from", "to", "content-type", "mime-version", "content-transfer-encoding"}
    assert {name.lower() for name in mail} <= allowed


def test_the_test_mail_says_so_in_the_subject_and_the_text() -> None:
    mail = build_mail(config(25), sample_message("https://driftsniff.example"))
    assert str(mail["Subject"]).startswith("[driftsniff test]")
    assert "This is a test message" in mail.get_content()
