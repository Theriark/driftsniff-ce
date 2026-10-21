"""Source base addresses: https by default, blocked ranges always, no redirects."""

import ipaddress

import pytest

from driftsniff.sources.addresses import (
    FOLLOW_REDIRECTS,
    AddressError,
    blocked_reason,
    validate_base_url,
)

BLOCKED_URLS = [
    "https://169.254.169.254/latest/meta-data",
    "https://169.254.0.1",
    "https://169.254.255.254:8443",
    "https://[fe80::1]/",
    "https://[febf::1]/",
    "https://[fe80::1%25eth0]/",
    "https://100.100.100.200/",
    "https://[::ffff:169.254.169.254]/",
    # Old numeric spellings of 169.254.169.254 that the system resolver understands.
    "https://2852039166/",
    "https://0xa9fea9fe/",
    "https://169.254.43518/",
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_a_blocked_address_is_refused(url: str) -> None:
    with pytest.raises(AddressError):
        validate_base_url(url)


@pytest.mark.parametrize("url", ["http://169.254.169.254", "http://100.100.100.200:80/"])
def test_allow_plain_http_never_unblocks_an_address(url: str) -> None:
    with pytest.raises(AddressError, match="blocked"):
        validate_base_url(url, allow_plain_http=True)


@pytest.mark.parametrize(
    ("url", "stored"),
    [
        ("https://203.0.113.10:8443/", "https://203.0.113.10:8443"),
        ("  https://unifi.lab.example/network/  ", "https://unifi.lab.example/network"),
        ("https://[2001:db8::1]/", "https://[2001:db8::1]"),
        ("https://100.100.100.201/", "https://100.100.100.201"),
        ("https://169.253.255.255/", "https://169.253.255.255"),
        ("https://[fec0::1]/", "https://[fec0::1]"),
    ],
)
def test_other_https_addresses_are_accepted(url: str, stored: str) -> None:
    assert validate_base_url(url) == stored


def test_plain_http_needs_the_option() -> None:
    with pytest.raises(AddressError, match="https"):
        validate_base_url("http://203.0.113.10")
    assert validate_base_url("http://203.0.113.10", allow_plain_http=True) == "http://203.0.113.10"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "ftp://203.0.113.10",
        "203.0.113.10",
        "https://",
        "https:///path",
        "https://user:pw@203.0.113.10",
        "https://user@203.0.113.10",
        "https://203.0.113.10/?token=x",
        "https://203.0.113.10/#frag",
        "https://203.0.113.10:99999",
        "https://203.0.113.10/a b",
        "https://203.0.113.10/a" + chr(10) + "b",
        "https://" + "a" * 2100,
    ],
)
def test_malformed_addresses_are_refused(url: str) -> None:
    with pytest.raises(AddressError):
        validate_base_url(url)


def test_an_address_error_never_repeats_the_password_of_the_url() -> None:
    with pytest.raises(AddressError) as caught:
        validate_base_url("https://admin:CANARY-url-password-0001@203.0.113.10")
    assert "CANARY" not in str(caught.value)


def test_blocked_reason_names_the_range() -> None:
    reason = blocked_reason(ipaddress.ip_address("169.254.169.254"))
    assert reason is not None
    assert "169.254.0.0/16" in reason
    assert blocked_reason(ipaddress.ip_address("fe80::abcd")) is not None
    assert blocked_reason(ipaddress.ip_address("100.100.100.200")) is not None
    assert blocked_reason(ipaddress.ip_address("10.0.0.1")) is None
    assert blocked_reason(ipaddress.ip_address("2001:db8::1")) is None


def test_redirects_are_never_followed() -> None:
    assert FOLLOW_REDIRECTS is False
