"""Source base addresses: which ones the application will ever connect to.

A source address must be https, unless the admin chose the option ``allow_plain_http`` for that
source. Addresses that lead to a cloud metadata service or a link-local interface are refused in
every case, whatever the options say: 169.254.0.0/16 (this includes the usual metadata address
169.254.169.254), fe80::/10 and the address 100.100.100.200.

``blocked_reason`` also accepts the old numeric spellings of an IPv4 address that the system
resolver understands (``2852039166``, ``0xa9fea9fe``, ``169.254.43518``), so a blocked address
cannot be written in a form this module does not recognise.

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
    except OSError:
        return None
    return ipaddress.IPv4Address(packed)


def blocked_reason(address: IPAddress) -> str | None:
    """Why an address is never allowed, or None."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    for network in BLOCKED_NETWORKS:
        if address.version == network.version and address in network:
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
