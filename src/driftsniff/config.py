"""Settings read from DRIFTSNIFF_ environment variables."""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Self
from urllib.parse import urlsplit

ENV_PREFIX = "DRIFTSNIFF_"
LOG_LEVELS = ("debug", "info", "warning", "error", "critical")
DEFAULT_PORT = 8080
DEFAULT_LOG_LEVEL = "info"
DEFAULT_KEY_FILE = "/keys/master.key"
DEFAULT_DATA_DIR = "/data"


class ConfigError(ValueError):
    """Raised when a DRIFTSNIFF_ setting has an invalid value."""


def _raw(env: Mapping[str, str], name: str) -> str | None:
    """Return the trimmed value of a setting, None when unset; blank values are rejected."""
    value = env.get(ENV_PREFIX + name)
    if value is None:
        return None
    value = value.strip()
    if not value:
        raise ConfigError(f"{ENV_PREFIX}{name} must not be blank")
    return value


def _parse_port(value: str) -> int:
    if not (value.isascii() and value.isdigit()) or not 1 <= int(value) <= 65535:
        raise ConfigError(f"{ENV_PREFIX}PORT must be an integer from 1 to 65535")
    return int(value)


def _parse_bool(name: str, value: str) -> bool:
    lowered = value.lower()
    if lowered not in ("true", "false"):
        raise ConfigError(f"{ENV_PREFIX}{name} must be true or false")
    return lowered == "true"


def _parse_log_level(value: str) -> str:
    lowered = value.lower()
    if lowered not in LOG_LEVELS:
        raise ConfigError(f"{ENV_PREFIX}LOG_LEVEL must be one of: {', '.join(LOG_LEVELS)}")
    return lowered


def _parse_base_url(value: str) -> str:
    message = f"{ENV_PREFIX}BASE_URL must be an http or https URL without credentials, query or fragment"
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        raise ConfigError(message) from error
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(message)
    if parts.username is not None or parts.password is not None:
        raise ConfigError(message)
    if parts.query or parts.fragment or (port is not None and port == 0):
        raise ConfigError(message)
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated application settings."""

    base_url: str
    trusted_proxy: bool
    log_level: str
    key_file: Path
    data_dir: Path
    port: int

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Self:
        """Read settings from env (default: the process environment).

        Unset variables use their defaults; invalid values raise ConfigError.
        """
        source = os.environ if env is None else env
        port_text = _raw(source, "PORT")
        port = DEFAULT_PORT if port_text is None else _parse_port(port_text)
        base_url_text = _raw(source, "BASE_URL")
        base_url = f"http://localhost:{port}" if base_url_text is None else _parse_base_url(base_url_text)
        proxy_text = _raw(source, "TRUSTED_PROXY")
        trusted_proxy = False if proxy_text is None else _parse_bool("TRUSTED_PROXY", proxy_text)
        level_text = _raw(source, "LOG_LEVEL")
        log_level = DEFAULT_LOG_LEVEL if level_text is None else _parse_log_level(level_text)
        key_file_text = _raw(source, "KEY_FILE")
        data_dir_text = _raw(source, "DATA_DIR")
        return cls(
            base_url=base_url,
            trusted_proxy=trusted_proxy,
            log_level=log_level,
            key_file=Path(DEFAULT_KEY_FILE if key_file_text is None else key_file_text),
            data_dir=Path(DEFAULT_DATA_DIR if data_dir_text is None else data_dir_text),
            port=port,
        )
