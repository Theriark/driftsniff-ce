"""The UniFi resources the collector reads and where it reads them (P7-T2).

Every path below is **unverified**: it comes from third party descriptions (docs/vendor-notes/
unifi.md, statements 1 and 5) and not from the vendor reference, which is dependency D5 and still
open. When D5 arrives, correct :data:`RESOURCES` and nothing else has to change.

``unifi-site-settings`` has no endpoint in any source, so the collector does not list it (the type
table keeps it as a placeholder). A resource that is not listed keeps its previous state in the
run pipeline, so leaving it out can never report an object as removed.

The ordering lists of firewall policies and ACL rules are separate documents (P7-T4). Their paths
below are **unverified** as well; ``collectors/unifi/normalize.py`` merges them into the position
list of the resource.
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
RESOURCE_FIREWALL_POLICIES: Final = "unifi-firewall-policies"
RESOURCE_ACL_RULES: Final = "unifi-acl-rules"

# The ordering documents (unverified, docs/vendor-notes/unifi.md statements 9, 16 and 17). The
# firewall order is asked per pair of zones; the ACL order is one list per site.
FIREWALL_ORDERING_PATH: Final = "/firewall/policies/ordering"
FIREWALL_ORDERING_SOURCE_PARAM: Final = "sourceFirewallZoneId"
FIREWALL_ORDERING_DESTINATION_PARAM: Final = "destinationFirewallZoneId"
ACL_ORDERING_PATH: Final = "/acl-rules/ordering"


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
    UnifiResource(RESOURCE_FIREWALL_POLICIES, "/firewall/policies"),
    UnifiResource(RESOURCE_ACL_RULES, "/acl-rules"),
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
