"""The UniFi Protect resources the collector reads and where it reads them.

Paths and answer shapes were read from Ubiquiti's published OpenAPI document of the UniFi Protect
integration API (developer.ui.com, Protect 7.2.105) on 2026-11-12 (docs/vendor-notes/
unifi_protect.md). No lab console was used. The API documents no paging parameters: every list is
one GET of a JSON array, and ``/nvrs`` answers one object.

Only the resources whose schemas were read are listed. The API also has sirens, speakers, bridges,
relays, fobs, link stations, alarm hubs, arm profiles and users; they are not read (see the
vendor notes) and a resource that is not listed keeps no state, so nothing is reported for it.
"""

from dataclasses import dataclass
from typing import Final

# The local console path of the published server list; the API key header is the one of the
# UniFi Network integration API (collectors/unifi/client.py), imported by the client.
BASE_PATH: Final = "/proxy/protect/integration/v1"
INFO_PATH: Final = "/meta/info"
VERSION_FIELD: Final = "applicationVersion"
KEY_FIELD: Final = "id"

RESOURCE_NVR: Final = "protect-nvr"
RESOURCE_CAMERAS: Final = "protect-cameras"
RESOURCE_VIEWERS: Final = "protect-viewers"
RESOURCE_LIVEVIEWS: Final = "protect-liveviews"
RESOURCE_CHIMES: Final = "protect-chimes"
RESOURCE_LIGHTS: Final = "protect-lights"
RESOURCE_SENSORS: Final = "protect-sensors"


@dataclass(frozen=True, slots=True)
class ProtectResource:
    """One resource: its name in the type tables and its path below :data:`BASE_PATH`."""

    name: str
    path: str


RESOURCES: Final = (
    ProtectResource(RESOURCE_NVR, "/nvrs"),
    ProtectResource(RESOURCE_CAMERAS, "/cameras"),
    ProtectResource(RESOURCE_VIEWERS, "/viewers"),
    ProtectResource(RESOURCE_LIVEVIEWS, "/liveviews"),
    ProtectResource(RESOURCE_CHIMES, "/chimes"),
    ProtectResource(RESOURCE_LIGHTS, "/lights"),
    ProtectResource(RESOURCE_SENSORS, "/sensors"),
)

RESOURCE_PATHS: Final = {resource.name: resource for resource in RESOURCES}
