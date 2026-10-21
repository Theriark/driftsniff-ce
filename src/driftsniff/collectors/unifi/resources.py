"""The UniFi resources the collector reads and where it reads them (P7-T2).

Every path below is **unverified**: it comes from third party descriptions (docs/vendor-notes/
unifi.md, statements 1 and 5) and not from the vendor reference, which is dependency D5 and still
open. When D5 arrives, correct :data:`RESOURCES` and nothing else has to change.

``unifi-site-settings`` has no endpoint in any source, so the collector does not list it (the type
table keeps it as a placeholder). A resource that is not listed keeps its previous state in the
run pipeline, so leaving it out can never report an object as removed.

The ordering lists of firewall policies and ACL rules are separate documents; merging them into
the position list is P7-T4 and is not done here.
"""

from dataclasses import dataclass
from typing import Final

# Base paths in the order the probe tries them: the direct integration path, then the console
# proxy path (plan, P7-T2). Both are unverified.
BASE_PATHS: Final = ("/integration", "/proxy/network/integration")
API_VERSION_PREFIX: Final = "/v1"
INFO_PATH: Final = "/info"
SITES_PATH: Final = "/sites"

RESOURCE_SITES: Final = "unifi-sites"


@dataclass(frozen=True, slots=True)
class UnifiResource:
    """One resource: its name in the type tables and its path below a site (None for sites)."""

    name: str
    site_path: str | None


RESOURCES: Final = (
    UnifiResource(RESOURCE_SITES, None),
    UnifiResource("unifi-networks", "/networks"),
    UnifiResource("unifi-wifi-broadcasts", "/wifi/broadcasts"),
    UnifiResource("unifi-firewall-zones", "/firewall/zones"),
    UnifiResource("unifi-firewall-policies", "/firewall/policies"),
    UnifiResource("unifi-acl-rules", "/acl-rules"),
    UnifiResource("unifi-dns-policies", "/dns/policies"),
    UnifiResource("unifi-traffic-matching-lists", "/traffic-matching-lists"),
    UnifiResource("unifi-wans", "/wans"),
    UnifiResource("unifi-vpn-site-to-site-tunnels", "/vpn/site-to-site-tunnels"),
    UnifiResource("unifi-vpn-servers", "/vpn/servers"),
    UnifiResource("unifi-radius-profiles", "/radius/profiles"),
    UnifiResource("unifi-device-tags", "/device-tags"),
    UnifiResource("unifi-devices", "/devices"),
)

RESOURCE_PATHS: Final = {resource.name: resource for resource in RESOURCES}
