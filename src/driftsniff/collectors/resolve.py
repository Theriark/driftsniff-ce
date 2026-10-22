"""Resolving the address of a controller and refusing blocked targets (P8-T2).

The Xen Orchestra client resolves the host name of its source once, before the first request, and
checks every address it gets with :func:`~driftsniff.sources.addresses.blocked_reason` (the cloud
metadata range, link-local and similar targets). The connection then resolves the name again, so a
name that changes its answer between the two is not caught (DNS rebinding); the redirect refusal of
the shared client remains.

The UniFi client does the same inline (``collectors/unifi/client.py``); a later change should let it
use this module so that there is one copy.
"""

import ipaddress
import socket
from collections.abc import Callable, Sequence
from typing import Final
from urllib.parse import urlsplit

from driftsniff.collectors.base import ERROR_CONNECTION, CollectorError
from driftsniff.sources.addresses import blocked_reason

ERROR_BLOCKED_ADDRESS: Final = "blocked_address"

Resolver = Callable[[str], Sequence[str]]


def system_resolver(host: str) -> Sequence[str]:
    """Every address the system resolver gives for ``host``, as text."""
    try:
        found = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise CollectorError(
            ERROR_CONNECTION,
            "the controller address cannot be resolved",
        ) from None
    return [str(entry[4][0]) for entry in found]


def check_address(base_url: str, resolver: Resolver) -> None:
    """Raise :class:`CollectorError` when ``base_url`` names or resolves to a blocked address."""
    host = urlsplit(base_url).hostname or ""
    for text in resolver(host):
        try:
            address = ipaddress.ip_address(text.split("%", 1)[0])
        except ValueError:
            raise CollectorError(
                ERROR_BLOCKED_ADDRESS,
                "the controller address resolves to an unusable value",
            ) from None
        if blocked_reason(address) is not None:
            raise CollectorError(
                ERROR_BLOCKED_ADDRESS,
                "the controller address resolves to a blocked address",
            )
