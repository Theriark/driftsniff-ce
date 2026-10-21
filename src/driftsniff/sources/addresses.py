"""Source base addresses: which ones the application will ever connect to.

A source address must be https, unless the admin chose the option ``allow_plain_http`` for that
source. Addresses that lead to a cloud metadata service or a link-local interface are refused in
every case, whatever the options say: 169.254.0.0/16 (this includes the usual metadata address
169.254.169.254), fe80::/10 and the address 100.100.100.200.

``blocked_reason`` also accepts the old numeric spellings of an IPv4 address that the system
resolver understands (``2852039166``, ``0xa9fea9fe``, ``169.254.43518``), so a blocked address
cannot be written in a form this module does not recognise.

An IPv6 address that carries an IPv4 address is judged by the IPv4 address inside it. Four forms
are unwrapped: IPv4-mapped (``::ffff:a.b.c.d``), the well-known NAT64 prefix (``64:ff9b::/96``),
the deprecated IPv4-compatible form (``::a.b.c.d``) and 6to4 (``2002::/16``). Other NAT64
prefixes (an operator can choose its own, or use ``64:ff9b:1::/48``) cannot be told from any other
address and are not unwrapped: a host name that resolves into one is only caught if the resolved
address is blocked as an IPv6 address. docs/collectors.md records this decision.

Only literal addresses can be checked here. A host name is resolved by the collector when it
connects; the collector must call ``blocked_reason`` on every address the name resolves to and
must not follow redirects (``FOLLOW_REDIRECTS``).
"""

import ipaddress
import socket
from urllib.parse import urlsplit

# Collectors read this: a redirect could lead from an allowed address to a blocked one.
FOLLOW_REDIRECTS = False

BLOCKED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.100.100.200/32"),
)

NAT64_NETWORK = ipaddress.ip_network("64:ff9b::/96")
IPV4_COMPATIBLE_NETWORK = ipaddress.ip_network("::/96")
SIX_TO_FOUR_NETWORK = ipaddress.ip_network("2002::/16")

MAX_BASE_URL_CHARS = 2048

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class AddressError(ValueError):
    """A source base address is not acceptable; the message says why and holds no credential."""


def _literal_address(host: str) -> IPAddress | None:
    """The address a host spells, or None when it is a name."""
    bare = host.split("%", 1)[0]
    try:
        return ipaddress.ip_address(bare)
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(bare)
    except (OSError, UnicodeError):
        # OSError: not an IPv4 spelling. UnicodeError: a lone surrogate cannot be encoded.
        return None
    return ipaddress.IPv4Address(packed)


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address carries in one of the four unwrapped forms, or None."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address in NAT64_NETWORK or address in IPV4_COMPATIBLE_NETWORK:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if address in SIX_TO_FOUR_NETWORK:
        return ipaddress.IPv4Address((int(address) >> 80) & 0xFFFFFFFF)
    return None


def blocked_reason(address: IPAddress) -> str | None:
    """Why an address is never allowed, or None.

    An IPv6 address that carries an IPv4 address is judged as the IPv4 address too.
    """
    candidates: list[IPAddress] = [address]
    if isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(address)
        if embedded is not None:
            candidates.append(embedded)
    for candidate in candidates:
        for network in BLOCKED_NETWORKS:
            if candidate.version == network.version and candidate in network:
                return f"addresses in {network} are never allowed"
    return None


def validate_base_url(url: str, *, allow_plain_http: bool = False) -> str:
    """Return the address to store (trimmed, trailing slashes removed) or raise AddressError."""
    cleaned = url.strip()
    if not cleaned:
        raise AddressError("the base address must not be blank")
    if len(cleaned) > MAX_BASE_URL_CHARS:
        raise AddressError(f"the base address is longer than {MAX_BASE_URL_CHARS} characters")
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in cleaned):
        raise AddressError("the base address must not contain spaces or control characters")
    try:
        cleaned.encode("utf-8")
    except UnicodeEncodeError:
        raise AddressError("the base address contains a character that cannot be stored") from None
    try:
        parts = urlsplit(cleaned)
        _ = parts.port  # reading the port validates it
    except ValueError:
        raise AddressError("the base address is not a valid URL") from None
    if parts.scheme not in ("https", "http"):
        raise AddressError("the base address must start with https://")
    if parts.scheme == "http" and not allow_plain_http:
        raise AddressError("the base address must be https unless allow_plain_http is set")
    if not parts.hostname:
        raise AddressError("the base address has no host")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise AddressError("the base address must not contain a user name or password")
    if parts.query or parts.fragment:
        raise AddressError("the base address must not contain a query or a fragment")
    address = _literal_address(parts.hostname)
    if address is not None:
        reason = blocked_reason(address)
        if reason is not None:
            raise AddressError(f"the base address is blocked: {reason}")
    return cleaned.rstrip("/")
