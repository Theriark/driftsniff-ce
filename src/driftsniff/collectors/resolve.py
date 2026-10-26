"""Resolving the address of a controller and refusing blocked targets (P8-T2, G1).

A collector resolves the host name of its source once, in ``probe()``, and checks every address it
gets with :func:`~driftsniff.sources.addresses.blocked_reason` (the cloud metadata range,
link-local and similar targets). :func:`pin_address` returns the first checked address and the
collector keeps it in an :class:`~driftsniff.collectors.tls.AddressPin`; every connection of the
run is then made to that address, never to the name, so a name that changes its answer after the
check (DNS rebinding) cannot lead the request, and the credential header with it, to another
address. The host name is still used for the TLS host name check, SNI and the ``Host`` header. The
redirect refusal of the shared client remains.

The webhook and mail senders keep their own copy of the check (``notify/targets.py``), which also
maps its failures to delivery classes.
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


def pin_address(base_url: str, resolver: Resolver) -> str:
    """Resolve ``base_url`` now, refuse it when any answer is blocked, return the address to use.

    The resolver is called once. Raises :class:`CollectorError` (``blocked_address`` when an answer
    is blocked or not an address, ``connection`` when there is no answer). The first answer is the
    one every connection must use; a zone suffix (``%eth0``) is removed.
    """
    host = urlsplit(base_url).hostname or ""
    first: str | None = None
    for text in resolver(host):
        bare = text.split("%", 1)[0]
        try:
            address = ipaddress.ip_address(bare)
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
        if first is None:
            first = bare
    if first is None:
        raise CollectorError(ERROR_CONNECTION, "the controller address cannot be resolved")
    return first


def check_address(base_url: str, resolver: Resolver) -> None:
    """Raise :class:`CollectorError` when ``base_url`` names or resolves to a blocked address."""
    pin_address(base_url, resolver)
