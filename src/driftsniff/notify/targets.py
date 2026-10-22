"""Where a notification may go: the check made at send time (P9-T4).

Private network targets are allowed (a self-hosted receiver is the normal case). The cloud
metadata range and link-local addresses are never allowed
(:func:`driftsniff.sources.addresses.blocked_reason`). The name is resolved **when the message is
sent**, every address it gives is checked, and the connection is then made to the address that was
checked, not to the name, so a name that changes its answer between the check and the connection
(DNS rebinding) cannot lead the message to a blocked address. The host name is still used for the
TLS host name check and for the ``Host`` header.
"""

import ipaddress
from dataclasses import dataclass
from typing import Final

from driftsniff.collectors.base import CollectorError
from driftsniff.collectors.resolve import ERROR_BLOCKED_ADDRESS, Resolver
from driftsniff.sources.addresses import blocked_reason

ERROR_UNRESOLVED: Final = "unresolved"


class TargetRefusedError(Exception):
    """The target must not be used; ``error_class`` is the word stored with the delivery."""

    def __init__(self, error_class: str) -> None:
        super().__init__(error_class)
        self.error_class = error_class


@dataclass(frozen=True, slots=True)
class CheckedTarget:
    """A host name and the address every connection to it must use."""

    host: str
    address: str


def check_target(host: str, resolver: Resolver) -> CheckedTarget:
    """Resolve ``host`` now and refuse it when any answer is blocked or unusable.

    Raises :class:`TargetRefusedError` (``blocked_address`` or ``unresolved``). The first answer
    is the one connected to.
    """
    try:
        found = list(resolver(host))
    except CollectorError:
        raise TargetRefusedError(ERROR_UNRESOLVED) from None
    if not found:
        raise TargetRefusedError(ERROR_UNRESOLVED)
    first: str | None = None
    for text in found:
        bare = text.split("%", 1)[0]
        try:
            address = ipaddress.ip_address(bare)
        except ValueError:
            raise TargetRefusedError(ERROR_BLOCKED_ADDRESS) from None
        if blocked_reason(address) is not None:
            raise TargetRefusedError(ERROR_BLOCKED_ADDRESS)
        if first is None:
            first = bare
    if first is None:  # pragma: no cover - found is not empty
        raise TargetRefusedError(ERROR_UNRESOLVED)
    return CheckedTarget(host, first)
