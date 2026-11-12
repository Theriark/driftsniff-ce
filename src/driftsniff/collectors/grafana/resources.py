"""The Grafana resources the collector reads and where it reads them.

The paths, query parameters and answer shapes were read from the Grafana HTTP API documentation on
2026-11-12 (docs/vendor-notes/grafana.md). No lab Grafana was used, so they are verified against
the vendor documentation only, not against a running server. Every path is under the legacy
``/api`` prefix, which Grafana 13 deprecates in favour of ``/apis`` but keeps serving.
"""

from dataclasses import dataclass
from typing import Final

AUTHORIZATION_HEADER: Final = "Authorization"
HEALTH_PATH: Final = "/api/health"
HEALTH_VERSION_FIELD: Final = "version"
# Any organisation member may read its own organisation: it proves the token works.
ORG_PATH: Final = "/api/org"

SEARCH_PATH: Final = "/api/search"
SEARCH_PAGE_SIZE: Final = 1000
FOLDER_PERMISSIONS_PATH: Final = "/api/folders/{uid}/permissions"
DASHBOARD_PATH: Final = "/api/dashboards/uid/{uid}"
# shortcut: dashboards past this number (by uid) are not read; raise it if an install needs more.
MAX_DASHBOARDS: Final = 500
# Paged lists stop after this many pages (at 1000 per page) rather than loop on a broken server.
MAX_PAGES: Final = 50

RESOURCE_DATASOURCES: Final = "grafana-datasources"
RESOURCE_FOLDERS: Final = "grafana-folders"
RESOURCE_FOLDER_PERMISSIONS: Final = "grafana-folder-permissions"
RESOURCE_DASHBOARDS: Final = "grafana-dashboards"
RESOURCE_ALERT_RULES: Final = "grafana-alert-rules"
RESOURCE_CONTACT_POINTS: Final = "grafana-contact-points"
RESOURCE_NOTIFICATION_POLICIES: Final = "grafana-notification-policies"
RESOURCE_ORG_USERS: Final = "grafana-org-users"
RESOURCE_TEAMS: Final = "grafana-teams"
RESOURCE_SERVICE_ACCOUNTS: Final = "grafana-service-accounts"


@dataclass(frozen=True, slots=True)
class GrafanaResource:
    """One resource: its name in the type tables, its path and the field that keys its objects.

    ``paged`` names the list inside a paged answer (``teams``, ``serviceAccounts``) or ``search``
    for the search endpoint, which answers a bare list page by page.
    """

    name: str
    path: str
    key_field: str = "uid"
    paged: str = ""


# In the order the collector reads them.
RESOURCES: Final = (
    GrafanaResource(RESOURCE_DATASOURCES, "/api/datasources"),
    GrafanaResource(RESOURCE_FOLDERS, f"{SEARCH_PATH}?type=dash-folder", paged="search"),
    GrafanaResource(RESOURCE_FOLDER_PERMISSIONS, f"{SEARCH_PATH}?type=dash-folder", paged="search"),
    GrafanaResource(RESOURCE_DASHBOARDS, f"{SEARCH_PATH}?type=dash-db", paged="search"),
    GrafanaResource(RESOURCE_ALERT_RULES, "/api/v1/provisioning/alert-rules"),
    GrafanaResource(RESOURCE_CONTACT_POINTS, "/api/v1/provisioning/contact-points"),
    GrafanaResource(RESOURCE_NOTIFICATION_POLICIES, "/api/v1/provisioning/policies", "id"),
    GrafanaResource(RESOURCE_ORG_USERS, "/api/org/users", "userId"),
    GrafanaResource(RESOURCE_TEAMS, "/api/teams/search", "id", paged="teams"),
    GrafanaResource(
        RESOURCE_SERVICE_ACCOUNTS, "/api/serviceaccounts/search", "id", paged="serviceAccounts"
    ),
)

RESOURCE_PATHS: Final = {resource.name: resource for resource in RESOURCES}
