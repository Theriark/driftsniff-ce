"""Source addresses: lone surrogates and IPv4 addresses carried inside IPv6 addresses.

Decisions pinned here (docs/collectors.md): four forms are unwrapped and judged by the IPv4 address
inside them (IPv4-mapped, the well-known NAT64 prefix 64:ff9b::/96, IPv4-compatible and 6to4);
every other NAT64 prefix is not unwrapped, because it cannot be told from an ordinary address.
"""

import ipaddress

import pytest

from driftsniff.sources.addresses import (
    AddressError,
    _literal_address,
    blocked_reason,
    validate_base_url,
)

LONE_SURROGATE = "\ud800"

# 169.254.169.254 (the metadata address) and 100.100.100.200 in every unwrapped form.
BLOCKED_FORMS = [
    "::ffff:169.254.169.254",
    "::ffff:a9fe:a9fe",
    "64:ff9b::a9fe:a9fe",
    "64:ff9b::169.254.169.254",
    "::a9fe:a9fe",
    "::169.254.169.254",
    "2002:a9fe:a9fe::",
    "2002:a9fe:a9fe:1:2:3:4:5",
    "::ffff:100.100.100.200",
    "64:ff9b::6464:64c8",
    "::6464:64c8",
    "2002:6464:64c8::1",
    "::ffff:169.254.0.1",
    "64:ff9b::a9fe:1",
]

# Addresses that carry a harmless IPv4 address, or that are not one of the four forms.
ALLOWED_FORMS = [
    "::ffff:10.0.0.1",
    "64:ff9b::a00:1",
    "::a00:1",
    "2002:a00:1::",
    "2002:c000:204::",
    "2001:db8::a9fe:a9fe",
    # Other NAT64 prefixes are not unwrapped (the decision of docs/collectors.md).
    "64:ff9b:1::a9fe:a9fe",
    "2001:db8:64::a9fe:a9fe",
    "::1",
    "::",
]


def test_a_lone_surrogate_in_the_host_is_an_address_error() -> None:
    with pytest.raises(AddressError, match="cannot be stored"):
        validate_base_url(f"https://host{LONE_SURROGATE}.example/")


@pytest.mark.parametrize(
    "url",
    [
        f"https://{LONE_SURROGATE}/",
        f"https://controller.example/{LONE_SURROGATE}",
        f"https://controller.example:8443/api{LONE_SURROGATE}",
        f"https://[2001:db8::1]/{LONE_SURROGATE}",
        LONE_SURROGATE,
    ],
)
def test_a_lone_surrogate_anywhere_is_an_address_error_and_never_a_unicode_error(
    url: str,
) -> None:
    with pytest.raises(AddressError):
        validate_base_url(url)


def test_a_lone_surrogate_is_a_name_and_not_an_address() -> None:
    assert _literal_address(LONE_SURROGATE) is None
    assert _literal_address(f"10.0.0.{LONE_SURROGATE}") is None
    assert _literal_address("controller.example") is None


def test_the_address_error_for_a_surrogate_does_not_repeat_it() -> None:
    with pytest.raises(AddressError) as caught:
        validate_base_url(f"https://host{LONE_SURROGATE}.example/")
    assert LONE_SURROGATE not in str(caught.value)


@pytest.mark.parametrize("text", BLOCKED_FORMS)
def test_an_ipv6_address_that_carries_a_blocked_ipv4_address_is_blocked(text: str) -> None:
    reason = blocked_reason(ipaddress.ip_address(text))
    assert reason is not None
    assert "never allowed" in reason


@pytest.mark.parametrize("text", BLOCKED_FORMS)
def test_a_blocked_embedded_address_is_refused_as_a_base_address(text: str) -> None:
    with pytest.raises(AddressError, match="blocked"):
        validate_base_url(f"https://[{text}]/")
    with pytest.raises(AddressError, match="blocked"):
        validate_base_url(f"http://[{text}]:8080/", allow_plain_http=True)


@pytest.mark.parametrize("text", ALLOWED_FORMS)
def test_an_ipv6_address_that_does_not_carry_a_blocked_address_is_not_blocked(text: str) -> None:
    assert blocked_reason(ipaddress.ip_address(text)) is None
    assert validate_base_url(f"https://[{text}]/") == f"https://[{text}]"


def test_the_nat64_form_is_judged_like_the_ipv4_address_it_carries() -> None:
    metadata = blocked_reason(ipaddress.ip_address("169.254.169.254"))
    wrapped = blocked_reason(ipaddress.ip_address("64:ff9b::a9fe:a9fe"))
    assert metadata is not None
    assert wrapped == metadata
    assert "169.254.0.0/16" in metadata


def test_the_ipv4_compatible_form_is_judged_like_the_ipv4_address_it_carries() -> None:
    assert blocked_reason(ipaddress.ip_address("::169.254.169.254")) is not None
    assert blocked_reason(ipaddress.ip_address("::100.100.100.200")) is not None
    assert blocked_reason(ipaddress.ip_address("::10.0.0.1")) is None


def test_the_6to4_form_reads_the_ipv4_address_after_the_prefix() -> None:
    assert blocked_reason(ipaddress.ip_address("2002:a9fe:a9fe::")) is not None
    # The address that follows the prefix is judged, not the bytes at the end of the address.
    assert blocked_reason(ipaddress.ip_address("2002:a00:1:0:0:0:a9fe:a9fe")) is None
    assert blocked_reason(ipaddress.ip_address("2002:a9fe:a9fe:0:0:0:a00:1")) is not None


def test_another_nat64_prefix_is_not_unwrapped() -> None:
    other = ipaddress.ip_address("64:ff9b:1::a9fe:a9fe")
    assert blocked_reason(other) is None
    assert validate_base_url("https://[64:ff9b:1::a9fe:a9fe]/") == "https://[64:ff9b:1::a9fe:a9fe]"


def test_a_link_local_ipv6_address_is_still_blocked_as_ipv6() -> None:
    assert blocked_reason(ipaddress.ip_address("fe80::1")) is not None
    assert blocked_reason(ipaddress.ip_address("64:ff9b::fe80:1")) is None


def test_plain_ipv4_addresses_are_judged_as_before() -> None:
    assert blocked_reason(ipaddress.ip_address("169.254.169.254")) is not None
    assert blocked_reason(ipaddress.ip_address("100.100.100.200")) is not None
    assert blocked_reason(ipaddress.ip_address("10.0.0.1")) is None
    assert blocked_reason(ipaddress.ip_address("203.0.113.10")) is None
