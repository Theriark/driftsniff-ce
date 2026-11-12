"""The Checkmk resources the collector reads and where it reads them.

Paths, query parameters, the header and the answer shapes were read from the Checkmk source of the
REST API (tag ``2.4.0``, ``cmk/gui/openapi/endpoints/``) and the Checkmk REST API documentation on
2026-11-12 (docs/vendor-notes/checkmk.md). No lab Checkmk site was used. Every resource is one GET
of a collection: Checkmk answers the whole collection, without paging.

The REST API lives under ``<site URL>/check_mk/api/1.0``; the address of a source is the site URL
(``https://host/site``), so the collector appends ``API_PREFIX``.
"""

from dataclasses import dataclass
from typing import Final

API_PREFIX: Final = "/check_mk/api/1.0"
AUTH_HEADER: Final = "Authorization"
VERSION_PATH: Final = "/version"

RESOURCE_HOSTS: Final = "checkmk-hosts"
RESOURCE_FOLDERS: Final = "checkmk-folders"
RESOURCE_HOST_GROUPS: Final = "checkmk-host-groups"
RESOURCE_SERVICE_GROUPS: Final = "checkmk-service-groups"
RESOURCE_CONTACT_GROUPS: Final = "checkmk-contact-groups"
RESOURCE_USERS: Final = "checkmk-users"
RESOURCE_TIME_PERIODS: Final = "checkmk-time-periods"
RESOURCE_PASSWORDS: Final = "checkmk-passwords"
RESOURCE_NOTIFICATION_RULES: Final = "checkmk-notification-rules"


@dataclass(frozen=True, slots=True)
class CheckmkResource:
    """One resource: its name in the type tables and its path below ``API_PREFIX``."""

    name: str
    path: str


def _collection(domain_type: str, query: str = "") -> str:
    return f"/domain-types/{domain_type}/collections/all{query}"


# In the order the collector reads them. Hosts are read with their own attributes only: the
# inherited ones are the folders' (read as a resource of their own). Folders are read from the
# root folder down; ``recursive=true`` includes the root folder itself.
RESOURCES: Final = (
    CheckmkResource(RESOURCE_HOSTS, _collection("host_config", "?effective_attributes=false")),
    CheckmkResource(RESOURCE_FOLDERS, _collection("folder_config", "?recursive=true")),
    CheckmkResource(RESOURCE_HOST_GROUPS, _collection("host_group_config")),
    CheckmkResource(RESOURCE_SERVICE_GROUPS, _collection("service_group_config")),
    CheckmkResource(RESOURCE_CONTACT_GROUPS, _collection("contact_group_config")),
    CheckmkResource(RESOURCE_USERS, _collection("user_config")),
    CheckmkResource(RESOURCE_TIME_PERIODS, _collection("time_period")),
    CheckmkResource(RESOURCE_PASSWORDS, _collection("password")),
    CheckmkResource(RESOURCE_NOTIFICATION_RULES, _collection("notification_rule")),
)

RESOURCE_PATHS: Final = {resource.name: resource for resource in RESOURCES}
