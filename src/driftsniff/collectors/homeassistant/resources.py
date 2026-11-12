"""The Home Assistant resources the collector reads and the WebSocket command behind each one.

Home Assistant keeps almost all of its configuration behind the WebSocket API (``/api/websocket``);
the REST API offers ``/api/config`` and little else. Every resource is therefore one read-only
WebSocket command. The command names and answer fields were read from the Home Assistant core
source (``dev`` branch, read 2026-11-12) and the protocol from the developer documentation
(docs/vendor-notes/homeassistant.md); no lab Home Assistant was used.

Automations and scripts have no list command: their entity ids come from ``get_states`` (only the
entity id and, for an automation, whether it is on are kept) and the configuration of each one
from ``automation/config`` or ``script/config``.

A resource that is not listed keeps its previous state in the run pipeline, so leaving one out can
never report an object as removed.
"""

from dataclasses import dataclass
from typing import Final

API_PATH: Final = "/api/websocket"
STATES_COMMAND: Final = "get_states"


@dataclass(frozen=True, slots=True)
class HomeAssistantResource:
    """One resource: its name in the type tables and the command that reads it.

    ``single`` marks a command that answers one object (``get_config``). ``domain`` marks an
    entity-backed resource: its objects are the entities of that domain in ``get_states`` and
    ``command`` is called once per entity with its ``entity_id``.
    """

    name: str
    command: str
    key_field: str
    single: bool = False
    domain: str | None = None


RESOURCES: Final = (
    HomeAssistantResource("homeassistant-core-config", "get_config", "id", single=True),
    HomeAssistantResource("homeassistant-integrations", "config_entries/get", "entry_id"),
    HomeAssistantResource("homeassistant-users", "config/auth/list", "id"),
    HomeAssistantResource(
        "homeassistant-automations", "automation/config", "entity_id", domain="automation"
    ),
    HomeAssistantResource("homeassistant-scripts", "script/config", "entity_id", domain="script"),
    HomeAssistantResource("homeassistant-areas", "config/area_registry/list", "area_id"),
    HomeAssistantResource("homeassistant-entities", "config/entity_registry/list", "id"),
    HomeAssistantResource("homeassistant-dashboards", "lovelace/dashboards/list", "url_path"),
)

RESOURCE_BY_NAME: Final = {resource.name: resource for resource in RESOURCES}
