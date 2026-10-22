"""The mail sender (P9-T4, docs/notifications.md).

The mail carries the same fields as the webhook body, as plain text. The connection is always
encrypted: ``starttls`` (the default; the session is upgraded before the login and the message
are sent, and a server that does not offer STARTTLS is refused, so the password never travels in
clear) or ``tls`` (implicit TLS). The certificate and the host name are checked with the system
trust store and certifi. A plain, unencrypted SMTP session is not offered.

As for the webhook, the host is resolved and checked when the mail is sent and the connection
goes to the address that was checked; the host name is kept for the TLS host name check.
"""

import smtplib
import socket
import ssl
from email.message import EmailMessage
from typing import Final

from driftsniff.collectors.resolve import Resolver
from driftsniff.collectors.tls import MODE_VERIFY, TlsSettings, make_ssl_context
from driftsniff.notify.config import SECURITY_TLS, SmtpConfig
from driftsniff.notify.message import NotificationMessage
from driftsniff.notify.targets import CheckedTarget, TargetRefusedError, check_target
from driftsniff.notify.webhook import (
    ERROR_CONNECTION,
    ERROR_TIMEOUT,
    ERROR_TLS,
    ERROR_UNEXPECTED,
    SendResult,
)

DEFAULT_TIMEOUT_SECONDS: Final = 15.0
ERROR_SMTP_LOGIN: Final = "smtp_login"
ERROR_SMTP_REFUSED: Final = "smtp_refused"
ERROR_SMTP_TEMPORARY: Final = "smtp_temporary"
ERROR_SMTP_NO_STARTTLS: Final = "smtp_no_starttls"
LOCAL_HOSTNAME: Final = "driftsniff.invalid"


class _ApprovedAddressSMTP(smtplib.SMTP):
    """An SMTP client that connects to the approved address and keeps the name for TLS.

    ``smtplib`` hands the host name to the TLS handshake as the server name, so the certificate
    is checked against the name while the socket goes to the address that passed the check.
    With ``implicit_tls`` the socket is wrapped at once (port 465 style).
    """

    def __init__(
        self,
        target: CheckedTarget,
        port: int,
        context: ssl.SSLContext,
        *,
        implicit_tls: bool,
        timeout: float,
    ) -> None:
        self._approved = target
        self._context = context
        self._implicit_tls = implicit_tls
        super().__init__(
            host=target.host, port=port, local_hostname=LOCAL_HOSTNAME, timeout=timeout
        )

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        plain = socket.create_connection((self._approved.address, port), timeout)
        if not self._implicit_tls:
            return plain
        try:
            return self._context.wrap_socket(plain, server_hostname=self._approved.host)
        except BaseException:
            plain.close()
            raise


def build_mail(config: SmtpConfig, message: NotificationMessage) -> EmailMessage:
    """The mail: subject with the severity and source, the fields as text, the link last."""
    mail = EmailMessage()
    prefix = "[driftsniff test]" if message.test else "[driftsniff]"
    mail["Subject"] = f"{prefix} {message.severity.upper()} - {message.source}"
    mail["From"] = config.from_address
    mail["To"] = ", ".join(config.to_addresses)
    lines = [
        f"Event: {message.event_id}",
        f"Source: {message.source}",
        f"Severity: {message.severity}",
        f"Summary: {message.summary}",
        f"Items: {message.item_count}",
        f"Link: {message.link}",
    ]
    if message.test:
        lines.insert(0, "This is a test message. No change was found.")
    mail.set_content("\n".join(lines) + "\n")
    return mail


def _classify(error: Exception) -> SendResult:
    if isinstance(error, TimeoutError):
        return SendResult(False, ERROR_TIMEOUT, retry=True)
    if isinstance(error, ssl.SSLError):
        return SendResult(False, ERROR_TLS)
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return SendResult(False, ERROR_SMTP_LOGIN)
    if isinstance(error, smtplib.SMTPNotSupportedError):
        return SendResult(False, ERROR_SMTP_NO_STARTTLS)
    if isinstance(error, smtplib.SMTPResponseException):
        temporary = 400 <= error.smtp_code < 500
        return SendResult(
            False,
            ERROR_SMTP_TEMPORARY if temporary else ERROR_SMTP_REFUSED,
            retry=temporary,
        )
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return SendResult(False, ERROR_SMTP_REFUSED)
    if isinstance(error, smtplib.SMTPException | OSError):
        return SendResult(False, ERROR_CONNECTION, retry=True)
    return SendResult(False, ERROR_UNEXPECTED)


def send_mail(
    config: SmtpConfig,
    message: NotificationMessage,
    *,
    resolver: Resolver,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> SendResult:
    """Send one mail and say what happened. Never raises for a failed delivery."""
    try:
        target = check_target(config.host, resolver)
    except TargetRefusedError as refused:
        return SendResult(False, refused.error_class)
    context = ssl_context or make_ssl_context(TlsSettings(MODE_VERIFY))
    mail = build_mail(config, message)
    implicit = config.security == SECURITY_TLS
    client: _ApprovedAddressSMTP | None = None
    try:
        client = _ApprovedAddressSMTP(
            target, config.port, context, implicit_tls=implicit, timeout=timeout
        )
        if not implicit:
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
        if config.username is not None and config.password is not None:
            client.login(config.username, config.password)
        client.send_message(mail)
        _quit_quietly(client)
    except Exception as error:
        return _classify(error)
    finally:
        # Not a ``with`` block: its exit would send QUIT on a connection that just failed and
        # could replace the real error (a certificate problem) with a reset connection.
        if client is not None:
            client.close()
    return SendResult(True)


def _quit_quietly(client: smtplib.SMTP) -> None:
    """End the session politely; the mail is already taken, so a failure here changes nothing."""
    try:
        client.quit()
    except (smtplib.SMTPException, OSError):
        pass
