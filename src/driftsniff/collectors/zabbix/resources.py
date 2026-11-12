"""The Zabbix resources the collector reads: which ``*.get`` method, which parameters, which key.

Every read is one JSON-RPC 2.0 POST to ``<frontend>/api_jsonrpc.php``. Method names, parameters and
field names were read from the Zabbix manual (``current`` = 8.0, and the 7.0, 6.2 and 6.0 pages) on
2026-11-12 (docs/vendor-notes/zabbix.md). No lab Zabbix was used.

Three things differ between the supported versions (6.0 LTS, 7.0 LTS, 8.0 LTS and the releases in
between), and :func:`params_for` picks them from the version ``apiinfo.version`` reported:

* host groups of a host or a maintenance: ``selectGroups`` (``groups``) before 6.2,
  ``selectHostGroups`` (``hostgroups``) from 6.2 (statement 9);
* host group rights of a user group: ``selectRights`` (``rights``) before 6.2,
  ``selectHostGroupRights`` and ``selectTemplateGroupRights`` from 6.2 (statement 10);
* the proxy of a host: ``proxy_hostid`` before 7.0; ``monitored_by``, ``proxyid`` and
  ``proxy_groupid`` from 7.0 (statement 8).

``output`` names the configuration fields where the field set is the same on every supported
version. Where it is not (actions, media types, proxies, maintenance periods, roles and the
authentication settings) ``extend`` is asked for and the type table ignores what is volatile and
classes credentials as secret: Zabbix refuses an ``output`` field it does not know, so a list that
is right for 8.0 would fail on 6.0.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from driftsniff.core.canonical import JsonValue

ENDPOINT: Final = "/api_jsonrpc.php"

Version = tuple[int, int]
MIN_VERSION: Final[Version] = (6, 0)
BEARER_FROM: Final[Version] = (6, 4)  # the Authorization header; before it the "auth" member
HOST_GROUPS_FROM: Final[Version] = (6, 2)
MONITORED_BY_FROM: Final[Version] = (7, 0)

RESOURCE_HOSTS: Final = "zabbix-hosts"
RESOURCE_HOST_GROUPS: Final = "zabbix-host-groups"
RESOURCE_TEMPLATES: Final = "zabbix-templates"
RESOURCE_TRIGGERS: Final = "zabbix-triggers"
RESOURCE_ACTIONS: Final = "zabbix-actions"
RESOURCE_MEDIA_TYPES: Final = "zabbix-media-types"
RESOURCE_USERS: Final = "zabbix-users"
RESOURCE_USER_GROUPS: Final = "zabbix-user-groups"
RESOURCE_USER_ROLES: Final = "zabbix-user-roles"
RESOURCE_GLOBAL_MACROS: Final = "zabbix-global-macros"
RESOURCE_PROXIES: Final = "zabbix-proxies"
RESOURCE_MAINTENANCE: Final = "zabbix-maintenance"
RESOURCE_AUTHENTICATION: Final = "zabbix-authentication"

SINGLETON_KEY_FIELD: Final = "id"
SINGLETON_KEY: Final = "authentication"

MACRO_FIELDS: Final = ["macro", "value", "type", "description"]
HOST_FIELDS: Final = [
    "hostid",
    "host",
    "name",
    "status",
    "description",
    "inventory_mode",
    "ipmi_authtype",
    "ipmi_privilege",
    "ipmi_username",
    "ipmi_password",
    "tls_connect",
    "tls_accept",
    "tls_issuer",
    "tls_subject",
]
INTERFACE_FIELDS: Final = ["interfaceid", "type", "main", "useip", "ip", "dns", "port", "details"]
TRIGGER_FIELDS: Final = [
    "triggerid",
    "description",
    "expression",
    "recovery_mode",
    "recovery_expression",
    "priority",
    "status",
    "type",
    "manual_close",
    "correlation_mode",
    "correlation_tag",
    "event_name",
    "opdata",
    "url",
    "comments",
    "templateid",
]
GROUP_FIELDS: Final = ["groupid", "name"]


def _host_groups(version: Version) -> dict[str, JsonValue]:
    select = "selectHostGroups" if version >= HOST_GROUPS_FROM else "selectGroups"
    return {select: list(GROUP_FIELDS)}


def _hosts(version: Version) -> dict[str, JsonValue]:
    proxy = (
        ["monitored_by", "proxyid", "proxy_groupid"]
        if version >= MONITORED_BY_FROM
        else ["proxy_hostid"]
    )
    return {
        "output": [*HOST_FIELDS, *proxy],
        "selectInterfaces": list(INTERFACE_FIELDS),
        **_host_groups(version),
        "selectParentTemplates": ["templateid", "name"],
        "selectMacros": list(MACRO_FIELDS),
        "selectTags": ["tag", "value"],
        # Plain hosts only: hosts made by low-level discovery come and go with what they find.
        "filter": {"flags": "0"},
    }


def _user_groups(version: Version) -> dict[str, JsonValue]:
    rights: dict[str, JsonValue] = (
        {"selectHostGroupRights": "extend", "selectTemplateGroupRights": "extend"}
        if version >= HOST_GROUPS_FROM
        else {"selectRights": "extend"}
    )
    return {
        "output": ["usrgrpid", "name", "gui_access", "users_status", "debug_mode"],
        **rights,
        "selectTagFilters": "extend",
    }


def _maintenance(version: Version) -> dict[str, JsonValue]:
    return {
        "output": "extend",
        **_host_groups(version),
        "selectHosts": ["hostid", "host"],
        "selectTimeperiods": "extend",
        "selectTags": "extend",
    }


def _fixed(params: dict[str, JsonValue]) -> Callable[[Version], dict[str, JsonValue]]:
    return lambda version: dict(params)


@dataclass(frozen=True, slots=True)
class ZabbixResource:
    """One resource: its name in the type tables, its method, how its parameters are made and the
    field that keys its objects. A ``paged`` resource is listed by id first and then read
    ``CHUNK_SIZE`` ids at a time with ``ids_param``."""

    name: str
    method: str
    key_field: str
    params: Callable[[Version], dict[str, JsonValue]] = field(compare=False)
    paged: bool = False
    ids_param: str = ""


RESOURCES: Final = (
    ZabbixResource(RESOURCE_HOSTS, "host.get", "hostid", _hosts, paged=True, ids_param="hostids"),
    ZabbixResource(
        RESOURCE_HOST_GROUPS, "hostgroup.get", "groupid", _fixed({"output": list(GROUP_FIELDS)})
    ),
    ZabbixResource(
        RESOURCE_TEMPLATES,
        "template.get",
        "templateid",
        _fixed(
            {
                "output": ["templateid", "host", "name", "description"],
                "selectParentTemplates": ["templateid", "name"],
                "selectMacros": list(MACRO_FIELDS),
            }
        ),
    ),
    ZabbixResource(
        RESOURCE_TRIGGERS,
        "trigger.get",
        "triggerid",
        _fixed(
            {
                "output": list(TRIGGER_FIELDS),
                "expandExpression": True,
                "selectHosts": ["hostid", "host"],
                # Plain triggers only, for the same reason as hosts.
                "filter": {"flags": "0"},
            }
        ),
        paged=True,
        ids_param="triggerids",
    ),
    ZabbixResource(
        RESOURCE_ACTIONS,
        "action.get",
        "actionid",
        _fixed(
            {
                "output": "extend",
                "selectFilter": "extend",
                "selectOperations": "extend",
                "selectRecoveryOperations": "extend",
                "selectUpdateOperations": "extend",
            }
        ),
    ),
    ZabbixResource(
        RESOURCE_MEDIA_TYPES, "mediatype.get", "mediatypeid", _fixed({"output": "extend"})
    ),
    ZabbixResource(
        RESOURCE_USERS,
        "user.get",
        "userid",
        _fixed(
            {
                # Never "passwd": it is write-only, and it is not asked for either.
                "output": [
                    "userid",
                    "username",
                    "name",
                    "surname",
                    "roleid",
                    "autologin",
                    "autologout",
                    "url",
                ],
                "selectUsrgrps": ["usrgrpid", "name"],
                "selectRole": ["type"],
            }
        ),
    ),
    ZabbixResource(RESOURCE_USER_GROUPS, "usergroup.get", "usrgrpid", _user_groups),
    ZabbixResource(
        RESOURCE_USER_ROLES,
        "role.get",
        "roleid",
        _fixed({"output": ["roleid", "name", "type"], "selectRules": "extend"}),
    ),
    ZabbixResource(
        RESOURCE_GLOBAL_MACROS,
        "usermacro.get",
        "globalmacroid",
        _fixed({"output": ["globalmacroid", *MACRO_FIELDS], "globalmacro": True}),
    ),
    ZabbixResource(RESOURCE_PROXIES, "proxy.get", "proxyid", _fixed({"output": "extend"})),
    ZabbixResource(RESOURCE_MAINTENANCE, "maintenance.get", "maintenanceid", _maintenance),
    ZabbixResource(
        RESOURCE_AUTHENTICATION,
        "authentication.get",
        SINGLETON_KEY_FIELD,
        _fixed({"output": "extend"}),
    ),
)

RESOURCE_BY_NAME: Final = {resource.name: resource for resource in RESOURCES}
