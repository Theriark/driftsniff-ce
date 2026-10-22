"""The configuration of the notification channel: validation, storage form and the safe view.

A channel is a webhook (one URL) or an SMTP account (host, port, security, optional login, sender
and recipients). The whole configuration is stored encrypted (``config_ciphertext``), because a
webhook URL often carries a secret in its path or query and an SMTP password is a credential. It is
never returned by the API: :func:`describe` gives a view with the host and port only and says
whether a password is set.

Addresses that can never be used (the cloud metadata range and link-local) are refused when the
channel is saved, if the host is written as an address; names are checked again, after resolving,
every time a message is sent (``targets.py``).
"""

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlsplit

from driftsniff.sources.addresses import blocked_reason

CHANNEL_WEBHOOK: Final = "webhook"
CHANNEL_SMTP: Final = "smtp"
SECURITY_STARTTLS: Final = "starttls"
SECURITY_TLS: Final = "tls"
SMTP_SECURITIES: Final = (SECURITY_STARTTLS, SECURITY_TLS)
DEFAULT_PORTS: Final = {SECURITY_STARTTLS: 587, SECURITY_TLS: 465}

MAX_URL_CHARS: Final = 2048
MAX_HOST_CHARS: Final = 253
MAX_LOGIN_CHARS: Final = 256
MAX_ADDRESS_CHARS: Final = 254
MAX_RECIPIENTS: Final = 10

_HOST_NAME: Final = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?")
_MAIL_ADDRESS: Final = re.compile(r"[^@\s<>,;\"'()\[\]\\]+@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?")
_SEPARATORS: Final = re.compile(r"[\s,;]+")


class ChannelConfigError(ValueError):
    """A field of the channel configuration is wrong. The message names the field, never a value."""


@dataclass(frozen=True, slots=True)
class WebhookConfig:
    """Where the webhook is posted; the URL is secret (it may carry a token)."""

    url: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class SmtpConfig:
    """An SMTP account and the people who get the mail."""

    host: str
    port: int
    security: str
    from_address: str
    to_addresses: tuple[str, ...]
    username: str | None = None
    password: str | None = field(default=None, repr=False)


ChannelConfig = WebhookConfig | SmtpConfig


def _blocked_literal(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return blocked_reason(address) is not None


def validate_webhook_url(url: str) -> str:
    """The URL to store, or ChannelConfigError. http and https are allowed (self-hosted use)."""
    cleaned = url.strip()
    if not cleaned or len(cleaned) > MAX_URL_CHARS:
        raise ChannelConfigError(f"url must have 1 to {MAX_URL_CHARS} characters")
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in cleaned):
        raise ChannelConfigError("url must not contain spaces or control characters")
    try:
        parts = urlsplit(cleaned)
        _ = parts.port
    except ValueError:
        raise ChannelConfigError("url is not a valid address") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ChannelConfigError("url must start with https:// or http:// and name a host")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ChannelConfigError("url must not contain a user name or password")
    if parts.fragment:
        raise ChannelConfigError("url must not contain a fragment")
    if _blocked_literal(parts.hostname):
        raise ChannelConfigError("url names an address that is never allowed")
    return cleaned


def _mail_address(text: str, field_name: str) -> str:
    cleaned = text.strip()
    if (
        len(cleaned) > MAX_ADDRESS_CHARS
        or not cleaned.isprintable()
        or _MAIL_ADDRESS.fullmatch(cleaned) is None
    ):
        raise ChannelConfigError(f"{field_name} is not a mail address")
    return cleaned


def _recipients(text: str) -> tuple[str, ...]:
    parts = [part for part in _SEPARATORS.split(text.strip()) if part]
    if not parts or len(parts) > MAX_RECIPIENTS:
        raise ChannelConfigError(f"to_addresses must hold 1 to {MAX_RECIPIENTS} mail addresses")
    seen: dict[str, None] = {}
    for part in parts:
        seen[_mail_address(part, "to_addresses")] = None
    return tuple(seen)


def _smtp_host(text: str) -> str:
    host = text.strip()
    if not host or len(host) > MAX_HOST_CHARS:
        raise ChannelConfigError(f"host must have 1 to {MAX_HOST_CHARS} characters")
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        if _HOST_NAME.fullmatch(host) is None:
            raise ChannelConfigError("host is not a host name or an address") from None
    if _blocked_literal(host):
        raise ChannelConfigError("host names an address that is never allowed")
    return host


def _smtp_port(text: str | None, security: str) -> int:
    if text is None or not text.strip():
        return DEFAULT_PORTS[security]
    value = text.strip()
    if not (value.isascii() and value.isdigit()) or not 1 <= int(value) <= 65535:
        raise ChannelConfigError("port must be a whole number from 1 to 65535")
    return int(value)


def _login(text: str | None, field_name: str) -> str | None:
    if text is None or not text.strip():
        return None
    cleaned = text.strip() if field_name == "username" else text
    if len(cleaned) > MAX_LOGIN_CHARS or not cleaned.isprintable():
        raise ChannelConfigError(f"{field_name} must have printable characters, at most 256")
    return cleaned


def parse_webhook(fields: Mapping[str, str]) -> WebhookConfig:
    """The webhook configuration of a form or JSON body (the field ``url``)."""
    return WebhookConfig(validate_webhook_url(fields.get("url", "")))


def parse_smtp(fields: Mapping[str, str], existing: SmtpConfig | None = None) -> SmtpConfig:
    """The SMTP configuration of a form or JSON body.

    ``password`` left out keeps the stored password of ``existing`` when the user name is
    unchanged; an empty ``username`` means no login.
    """
    security = fields.get("security", "").strip().lower() or SECURITY_STARTTLS
    if security not in SMTP_SECURITIES:
        raise ChannelConfigError("security must be starttls or tls")
    username = _login(fields.get("username"), "username")
    password = _login(fields.get("password"), "password")
    if username is None:
        password = None
    elif password is None:
        if existing is None or existing.username != username or existing.password is None:
            raise ChannelConfigError("password is required when a username is given")
        password = existing.password
    return SmtpConfig(
        host=_smtp_host(fields.get("host", "")),
        port=_smtp_port(fields.get("port"), security),
        security=security,
        from_address=_mail_address(fields.get("from_address", ""), "from_address"),
        to_addresses=_recipients(fields.get("to_addresses", "")),
        username=username,
        password=password,
    )


def dump_config(config: ChannelConfig) -> bytes:
    """The bytes that are encrypted and stored."""
    if isinstance(config, WebhookConfig):
        document: dict[str, object] = {"url": config.url}
    else:
        document = {
            "host": config.host,
            "port": config.port,
            "security": config.security,
            "from_address": config.from_address,
            "to_addresses": list(config.to_addresses),
            "username": config.username,
            "password": config.password,
        }
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def load_config(channel_type: str, data: bytes) -> ChannelConfig:
    """The configuration of decrypted bytes; ChannelConfigError when they are not one."""
    try:
        document = json.loads(data)
        if channel_type == CHANNEL_WEBHOOK:
            return WebhookConfig(str(document["url"]))
        if channel_type == CHANNEL_SMTP:
            username = document.get("username")
            password = document.get("password")
            return SmtpConfig(
                host=str(document["host"]),
                port=int(document["port"]),
                security=str(document["security"]),
                from_address=str(document["from_address"]),
                to_addresses=tuple(str(item) for item in document["to_addresses"]),
                username=None if username is None else str(username),
                password=None if password is None else str(password),
            )
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ChannelConfigError("the stored channel configuration is damaged") from None
    raise ChannelConfigError("unknown channel type")


def describe(config: ChannelConfig) -> dict[str, object]:
    """What an admin may see: the host and port, never the path, query, login or password."""
    if isinstance(config, WebhookConfig):
        parts = urlsplit(config.url)
        port = parts.port
        host = parts.hostname or ""
        host = f"[{host}]" if ":" in host else host
        shown = f"{parts.scheme}://{host}" + ("" if port is None else f":{port}")
        return {"target": shown, "path_hidden": True}
    return {
        "host": config.host,
        "port": config.port,
        "security": config.security,
        "from_address": config.from_address,
        "to_addresses": list(config.to_addresses),
        "username": config.username,
        "password_set": config.password is not None,
    }
