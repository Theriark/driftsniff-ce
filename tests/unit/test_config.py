"""Tests for DRIFTSNIFF_ settings."""

from pathlib import Path

import pytest

from driftsniff.config import ConfigError, Settings


def test_defaults() -> None:
    settings = Settings.from_env({})
    assert settings.port == 8080
    assert settings.base_url == "http://localhost:8080"
    assert settings.trusted_proxy is False
    assert settings.log_level == "info"
    assert settings.key_file == Path("/keys/master.key")
    assert settings.data_dir == Path("/data")
    assert settings.dev_host_suffix is None


def test_every_setting_can_be_overridden() -> None:
    settings = Settings.from_env(
        {
            "DRIFTSNIFF_BASE_URL": "https://example.test/driftsniff/",
            "DRIFTSNIFF_TRUSTED_PROXY": "TRUE",
            "DRIFTSNIFF_LOG_LEVEL": "DEBUG",
            "DRIFTSNIFF_KEY_FILE": "/run/keys/master.key",
            "DRIFTSNIFF_DATA_DIR": "/var/lib/driftsniff",
            "DRIFTSNIFF_PORT": "9000",
        }
    )
    assert settings.base_url == "https://example.test/driftsniff"
    assert settings.trusted_proxy is True
    assert settings.log_level == "debug"
    assert settings.key_file == Path("/run/keys/master.key")
    assert settings.data_dir == Path("/var/lib/driftsniff")
    assert settings.port == 9000


def test_default_base_url_follows_the_port() -> None:
    assert Settings.from_env({"DRIFTSNIFF_PORT": "9100"}).base_url == "http://localhost:9100"


@pytest.mark.parametrize("port", ["1", "65535"])
def test_port_boundaries_are_accepted(port: str) -> None:
    assert Settings.from_env({"DRIFTSNIFF_PORT": port}).port == int(port)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("DRIFTSNIFF_PORT", "abc"),
        ("DRIFTSNIFF_PORT", "0"),
        ("DRIFTSNIFF_PORT", "65536"),
        ("DRIFTSNIFF_PORT", "-1"),
        ("DRIFTSNIFF_PORT", "80.5"),
        ("DRIFTSNIFF_TRUSTED_PROXY", "yes"),
        ("DRIFTSNIFF_TRUSTED_PROXY", "1"),
        ("DRIFTSNIFF_LOG_LEVEL", "verbose"),
        ("DRIFTSNIFF_BASE_URL", "ftp://example.test"),
        ("DRIFTSNIFF_BASE_URL", "localhost:8080"),
        ("DRIFTSNIFF_BASE_URL", "https://user:pw@example.test"),
        ("DRIFTSNIFF_BASE_URL", "https://example.test/?q=1"),
        ("DRIFTSNIFF_KEY_FILE", "   "),
        ("DRIFTSNIFF_DATA_DIR", ""),
        ("DRIFTSNIFF_DEV_HOST_SUFFIX", ""),
        ("DRIFTSNIFF_DEV_HOST_SUFFIX", "dev"),
        ("DRIFTSNIFF_DEV_HOST_SUFFIX", "https://dev.example.com"),
        ("DRIFTSNIFF_DEV_HOST_SUFFIX", "dev.example.com:8443"),
        ("DRIFTSNIFF_DEV_HOST_SUFFIX", "dev.example.com/x"),
        ("DRIFTSNIFF_DEV_HOST_SUFFIX", "-dev.example.com"),
        ("DRIFTSNIFF_DEV_HOST_SUFFIX", "dev..example.com"),
        ("DRIFTSNIFF_DEV_HOST_SUFFIX", "*.example.com"),
    ],
)
def test_invalid_values_are_rejected(name: str, value: str) -> None:
    with pytest.raises(ConfigError, match=name):
        Settings.from_env({name: value})


def test_process_environment_is_the_default_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DRIFTSNIFF_PORT", "9200")
    assert Settings.from_env().port == 9200


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("dev.example.com", "dev.example.com"),
        (" Dev.Example.COM ", "dev.example.com"),
        (".dev.example.com", "dev.example.com"),
        ("ce-dev-app.example.test", "ce-dev-app.example.test"),
    ],
)
def test_the_development_host_is_a_lowercase_host_name(value: str, expected: str) -> None:
    assert Settings.from_env({"DRIFTSNIFF_DEV_HOST_SUFFIX": value}).dev_host_suffix == expected
