"""The Portainer resources the collector reads and where it reads them.

The paths, the header name and the version endpoint were read from the Portainer source and its
swagger annotations on 2026-11-12 (docs/vendor-notes/portainer.md, statements 1 to 12). No lab
Portainer was used, so they are verified against the vendor source only, not against a running
server. Every list is read with one GET and no paging parameters: without ``limit`` Portainer
returns the whole list (statement 5).
"""

from dataclasses import dataclass
from typing import Final

API_KEY_HEADER: Final = "X-API-Key"
VERSION_PATH: Final = "/api/system/version"
VERSION_FIELD: Final = "ServerVersion"
STACK_FILE_PATH: Final = "/api/stacks/{id}/file"
STACK_FILE_FIELD: Final = "StackFileContent"

RESOURCE_ENVIRONMENTS: Final = "portainer-environments"
RESOURCE_ENVIRONMENT_GROUPS: Final = "portainer-environment-groups"
RESOURCE_TAGS: Final = "portainer-tags"
RESOURCE_EDGE_GROUPS: Final = "portainer-edge-groups"
RESOURCE_STACKS: Final = "portainer-stacks"
RESOURCE_USERS: Final = "portainer-users"
RESOURCE_TEAMS: Final = "portainer-teams"
RESOURCE_TEAM_MEMBERSHIPS: Final = "portainer-team-memberships"
RESOURCE_REGISTRIES: Final = "portainer-registries"
RESOURCE_SETTINGS: Final = "portainer-settings"


@dataclass(frozen=True, slots=True)
class PortainerResource:
    """One resource: its name in the type tables, its path and the field that keys its objects."""

    name: str
    path: str
    key_field: str = "Id"


# In the order the collector reads them. Snapshots of an environment are large and volatile, so
# they are not asked for (``excludeSnapshots``, statement 6); the type table ignores them anyway.
RESOURCES: Final = (
    PortainerResource(RESOURCE_ENVIRONMENTS, "/api/endpoints?excludeSnapshots=true"),
    PortainerResource(RESOURCE_ENVIRONMENT_GROUPS, "/api/endpoint_groups"),
    PortainerResource(RESOURCE_TAGS, "/api/tags", "ID"),
    PortainerResource(RESOURCE_EDGE_GROUPS, "/api/edge_groups"),
    PortainerResource(RESOURCE_STACKS, "/api/stacks"),
    PortainerResource(RESOURCE_USERS, "/api/users"),
    PortainerResource(RESOURCE_TEAMS, "/api/teams"),
    PortainerResource(RESOURCE_TEAM_MEMBERSHIPS, "/api/team_memberships"),
    PortainerResource(RESOURCE_REGISTRIES, "/api/registries"),
    PortainerResource(RESOURCE_SETTINGS, "/api/settings"),
)

RESOURCE_PATHS: Final = {resource.name: resource for resource in RESOURCES}
