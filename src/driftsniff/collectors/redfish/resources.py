"""The Redfish resources the collector reads and the fixed names of the Redfish service.

Sources and their status are in docs/vendor-notes/redfish.md. Every resource is found by following
links from the service root (``/redfish/v1/``), never by a vendor path: the ids of systems and
managers differ per vendor (``System.Embedded.1`` on iDRAC, ``1`` on iLO and Supermicro), so no id
is written here. The two fixed paths are the service root and the session collection, which the
Redfish specification fixes; the session link of the root (``Links.Sessions``) is preferred when the
service gives one.

One collector serves every vendor. Vendor differences are handled as data: the type table
``rules/types/redfish.yaml`` lists the DMTF property names, ``Oem`` is ignored, and a property a
vendor adds that is not listed stays unclassified (a fingerprint only).
"""

from typing import Final

ROOT_PATH: Final = "/redfish/v1/"
SESSIONS_PATH: Final = "/redfish/v1/SessionService/Sessions"
TOKEN_HEADER: Final = "X-Auth-Token"  # noqa: S105 - a header name

RESOURCE_SYSTEMS: Final = "redfish-systems"
RESOURCE_BIOS: Final = "redfish-bios"
RESOURCE_MANAGERS: Final = "redfish-managers"
RESOURCE_NETWORK: Final = "redfish-network-protocol"
RESOURCE_INTERFACES: Final = "redfish-manager-interfaces"
RESOURCE_ACCOUNTS: Final = "redfish-accounts"
RESOURCE_ACCOUNT_SERVICE: Final = "redfish-account-service"
RESOURCE_SUBSCRIPTIONS: Final = "redfish-event-subscriptions"
RESOURCE_CERTIFICATES: Final = "redfish-certificates"
RESOURCE_FIRMWARE: Final = "redfish-firmware"

# In reading order: the slow, large reads (BIOS attributes, firmware) come after the small ones.
RESOURCES: Final = (
    RESOURCE_SYSTEMS,
    RESOURCE_MANAGERS,
    RESOURCE_NETWORK,
    RESOURCE_INTERFACES,
    RESOURCE_ACCOUNTS,
    RESOURCE_ACCOUNT_SERVICE,
    RESOURCE_SUBSCRIPTIONS,
    RESOURCE_CERTIFICATES,
    RESOURCE_BIOS,
    RESOURCE_FIRMWARE,
)

# Fields the collector adds: the key of an object built from two ids, the manager an object of a
# manager belongs to, and the path of a certificate (certificates have no id unique over the BMC).
FIELD_OBJECT_KEY: Final = "ObjectKey"
FIELD_MANAGER: Final = "Manager"
FIELD_URI: Final = "Uri"
# A BIOS attribute becomes one object; a password attribute keeps its value in the secret field.
FIELD_VALUE: Final = "value"
FIELD_SECRET_VALUE: Final = "secret_value"  # noqa: S105 - a field name
PASSWORD_MARKERS: Final = ("password", "passwd", "pwd")

# Bounds of one run. BMCs are slow (often a second or more per request) and every request may
# take up to 30 seconds, so a run reads at most this many members per collection and sends at most
# this many requests; the five minute limit of the pipeline still applies on top.
MAX_MEMBERS: Final = 256
MAX_REQUESTS: Final = 600
MAX_LINK_CHARS: Final = 512
