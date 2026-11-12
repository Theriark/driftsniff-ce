"""A fake Zabbix API on localhost for the contract tests, and a model for a later simulation.

It serves the JSON-RPC 2.0 methods the collector uses, with the shapes read from the Zabbix manual
on 2026-11-12 (docs/vendor-notes/zabbix.md). The data is synthetic (``example.invalid`` names,
RFC 5737 addresses): a Zabbix server host, a web server with an SNMP interface, a database host
monitored by a proxy, a discovered host the collector must skip, host groups, templates, triggers
(one discovered), actions, an email and a webhook media type, users, user groups, roles, global
macros, a proxy, a maintenance period and the authentication settings.

Like Zabbix the fake keeps what it stores and hides what Zabbix does not return: the value of a
secret macro (type "1"), a user's password. What Zabbix does return (an SNMP community, an IPMI
password, a media type password, webhook parameter values) is served, so a test can prove that
driftsniff keeps only fingerprints of them.

Surface: ``POST <any prefix>/api_jsonrpc.php`` with ``Content-Type`` ``application/json-rpc``,
``application/json`` or ``application/jsonrequest`` (another answers HTTP 412; another HTTP method
405; another path 404). Requests and answers are JSON-RPC 2.0 (``{"jsonrpc", "method", "params",
"id"}`` to ``{"jsonrpc", "result", "id"}`` or ``{"jsonrpc", "error": {"code", "message", "data"},
"id"}``).

* ``apiinfo.version`` with no credential answers ``Scenario.version``; with one it is an error.
* The other methods need the token: from 6.4 in ``Authorization: Bearer``, before 6.4 in the
  ``auth`` member (the header is ignored there). From 6.4 to 7.0 the ``auth`` member still works;
  from 7.2 it is refused. A missing or unknown token is ``-32602`` "Not authorized.".
* ``host.get``, ``hostgroup.get``, ``template.get``, ``trigger.get``, ``action.get``,
  ``mediatype.get``, ``user.get``, ``usergroup.get``, ``role.get``, ``usermacro.get``
  (``globalmacro``), ``proxy.get``, ``maintenance.get``, ``authentication.get``. They honour
  ``output`` (``extend`` or a list; an unknown field is refused as Zabbix does), the ``select*``
  parameters the collector sends, ``filter``, the id lists (``hostids``, ``triggerids``),
  ``sortfield`` and ``limit``; an unknown parameter is refused. Version differences are served:
  ``selectGroups``/``groups`` before 6.2 and ``selectHostGroups``/``hostgroups`` from 6.2,
  ``selectRights``/``rights`` before 7.0 and the group rights selects from 6.2, the 6.0 proxy names
  and ``proxy_hostid`` before 7.0.
* ``LIMITED_TOKEN`` belongs to an Admin type user: ``authentication.get``, ``mediatype.get``,
  ``role.get`` and ``proxy.get`` answer ``-32500`` "No permissions to call ..." (an assumption of
  the fake, see the vendor notes).

:class:`Scenario` has helpers that change the configuration so that two reads show a drift
(:meth:`Scenario.drift` applies one low, one medium, one high and one critical change).
"""

import copy
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

ADMIN_TOKEN = "CANARY-zabbix-00"  # noqa: S105 - a test canary, not a credential
LIMITED_TOKEN = "CANARY-zbb-0"  # noqa: S105 - a test canary, not a credential
# Secret values Zabbix stores; tests check that none of them is ever stored in clear.
SNMP_COMMUNITY = "CANARY-zabbix-snmp-00"
IPMI_PASSWORD = "CANARY-zbip-0"  # noqa: S105
SMTP_PASSWORD = "CANARY-zabbix-smtp-00"  # noqa: S105
WEBHOOK_TOKEN = "CANARY-zabbix-webhook-00"  # noqa: S105
HOST_SECRET_MACRO = "CANARY-zbmc-0"  # noqa: S105
GLOBAL_SECRET_MACRO = "CANARY-zbgl-0"  # noqa: S105
USER_PASSWORD = "CANARY-zabbix-user-00"  # noqa: S105
SECRETS = (
    ADMIN_TOKEN,
    SNMP_COMMUNITY,
    IPMI_PASSWORD,
    SMTP_PASSWORD,
    WEBHOOK_TOKEN,
    HOST_SECRET_MACRO,
    GLOBAL_SECRET_MACRO,
    USER_PASSWORD,
)
VERSION = "7.0.5"
ENDPOINT = "/api_jsonrpc.php"
CONTENT_TYPES = ("application/json-rpc", "application/json", "application/jsonrequest")
LIMITED_DENIED = frozenset({"authentication.get", "mediatype.get", "role.get", "proxy.get"})

# method: (state collection, id field, id list parameter, selects {param: (stored, returned)})
_SELECTS_HOST = {
    "selectInterfaces": ("interfaces", "interfaces"),
    "selectParentTemplates": ("parentTemplates", "parentTemplates"),
    "selectMacros": ("macros", "macros"),
    "selectTags": ("tags", "tags"),
}
METHODS: dict[str, tuple[str, str, str, dict[str, tuple[str, str]]]] = {
    "host.get": ("hosts", "hostid", "hostids", _SELECTS_HOST),
    "hostgroup.get": ("hostgroups", "groupid", "groupids", {}),
    "template.get": (
        "templates",
        "templateid",
        "templateids",
        {
            "selectParentTemplates": ("parentTemplates", "parentTemplates"),
            "selectMacros": ("macros", "macros"),
        },
    ),
    "trigger.get": ("triggers", "triggerid", "triggerids", {"selectHosts": ("hosts", "hosts")}),
    "action.get": (
        "actions",
        "actionid",
        "actionids",
        {
            "selectFilter": ("filter", "filter"),
            "selectOperations": ("operations", "operations"),
            "selectRecoveryOperations": ("recovery_operations", "recovery_operations"),
            "selectUpdateOperations": ("update_operations", "update_operations"),
        },
    ),
    "mediatype.get": ("mediatypes", "mediatypeid", "mediatypeids", {}),
    "user.get": (
        "users",
        "userid",
        "userids",
        {"selectUsrgrps": ("usrgrps", "usrgrps"), "selectRole": ("role", "role")},
    ),
    "usergroup.get": (
        "usergroups",
        "usrgrpid",
        "usrgrpids",
        {"selectTagFilters": ("tag_filters", "tag_filters")},
    ),
    "role.get": ("roles", "roleid", "roleids", {"selectRules": ("rules", "rules")}),
    "usermacro.get": ("globalmacros", "globalmacroid", "globalmacroids", {}),
    "proxy.get": ("proxies", "proxyid", "proxyids", {}),
    "maintenance.get": (
        "maintenances",
        "maintenanceid",
        "maintenanceids",
        {
            "selectHosts": ("hosts", "hosts"),
            "selectTimeperiods": ("timeperiods", "timeperiods"),
            "selectTags": ("tags", "tags"),
        },
    ),
}
_COMMON = frozenset({"output", "filter", "limit", "sortfield", "sortorder", "preservekeys"})
_EXTRA = {
    "trigger.get": frozenset({"expandExpression"}),
    "usermacro.get": frozenset({"globalmacro"}),
}


def _version(text: str) -> tuple[int, int]:
    major, minor = text.split(".")[:2]
    return int(major), int(minor)


@dataclass(frozen=True, slots=True)
class Request:
    """One request the server received."""

    http_method: str
    path: str
    query: str
    content_type: str | None
    authorization: str | None
    rpc_method: str | None
    params: Any
    auth_member: Any
    raw: bytes


def _macro(macro: str, value: str, type_: str = "0", description: str = "") -> dict[str, Any]:
    return {"macro": macro, "value": value, "type": type_, "description": description}


def _agent(interfaceid: str, ip: str) -> dict[str, Any]:
    return {
        "interfaceid": interfaceid,
        "type": "1",
        "main": "1",
        "useip": "1",
        "ip": ip,
        "dns": "",
        "port": "10050",
        "details": [],
        "available": "1",
        "error": "",
    }


def _message_operation(operationid: str, actionid: str, usrgrpid: str) -> dict[str, Any]:
    return {
        "operationid": operationid,
        "actionid": actionid,
        "operationtype": "0",
        "esc_period": "0",
        "esc_step_from": "1",
        "esc_step_to": "1",
        "evaltype": "0",
        "opconditions": [],
        "opmessage": {"default_msg": "1", "subject": "", "message": "", "mediatypeid": "0"},
        "opmessage_grp": [{"operationid": operationid, "usrgrpid": usrgrpid}],
        "opmessage_usr": [],
    }


def _rules(type_: str) -> dict[str, Any]:
    return {
        "ui": [
            {"name": "monitoring.dashboard", "status": "1"},
            {"name": "administration.users", "status": "1" if type_ == "3" else "0"},
        ],
        "ui.default_access": "1",
        "services.read.mode": "1",
        "services.read.list": [],
        "services.read.tag": {"tag": "", "value": ""},
        "services.write.mode": "0",
        "services.write.list": [],
        "services.write.tag": {"tag": "", "value": ""},
        "modules": [],
        "modules.default_access": "1",
        "api.access": "1",
        "api.mode": "0",
        "api": [],
        "actions": [{"name": "edit_dashboards", "status": "1"}],
        "actions.default_access": "1",
    }


def default_state() -> dict[str, Any]:
    """The stored configuration of a small synthetic Zabbix installation (7.0 shapes)."""
    snmp = {
        "interfaceid": "12",
        "type": "2",
        "main": "1",
        "useip": "1",
        "ip": "192.0.2.21",
        "dns": "",
        "port": "161",
        "details": {"version": "2", "bulk": "1", "community": SNMP_COMMUNITY},
        "available": "1",
        "error": "",
    }
    linux = {"templateid": "10001", "name": "Linux by Zabbix agent"}
    nginx = {"templateid": "10563", "name": "Nginx by Zabbix agent"}
    host_common = {
        "description": "",
        "inventory_mode": "-1",
        "ipmi_authtype": "-1",
        "ipmi_privilege": "2",
        "ipmi_username": "",
        "ipmi_password": "",
        "tls_connect": "1",
        "tls_accept": "1",
        "tls_issuer": "",
        "tls_subject": "",
        "monitored_by": "0",
        "proxyid": "0",
        "proxy_groupid": "0",
        "flags": "0",
        "maintenance_status": "0",
        "active_available": "1",
        "tags": [],
    }
    return {
        "hosts": [
            {
                **host_common,
                "hostid": "10084",
                "host": "zabbix-server.example.invalid",
                "name": "Zabbix server",
                "status": "0",
                "interfaces": [_agent("1", "192.0.2.10")],
                "hostgroups": [{"groupid": "4", "name": "Zabbix servers"}],
                "parentTemplates": [linux],
                "macros": [_macro("{$CPU.UTIL.CRIT}", "90")],
            },
            {
                **host_common,
                "hostid": "10601",
                "host": "web-01.example.invalid",
                "name": "web-01",
                "status": "0",
                "description": "Front web server",
                "ipmi_username": "ipmi-reader",
                "ipmi_password": IPMI_PASSWORD,
                "tls_connect": "2",
                "tls_accept": "2",
                "interfaces": [_agent("11", "192.0.2.21"), snmp],
                "hostgroups": [{"groupid": "21", "name": "Web servers"}],
                "parentTemplates": [linux, nginx],
                "macros": [
                    _macro("{$NGINX.STUB_STATUS.PORT}", "80"),
                    _macro("{$DB.PASSWORD}", HOST_SECRET_MACRO, "1", "database reader"),
                    _macro("{$API.KEY}", "secret/web:api-key", "2"),
                ],
                "tags": [{"tag": "env", "value": "prod"}],
            },
            {
                **host_common,
                "hostid": "10602",
                "host": "db-01.example.invalid",
                "name": "db-01",
                "status": "0",
                "description": "Primary database",
                "monitored_by": "1",
                "proxyid": "10701",
                "interfaces": [_agent("21", "198.51.100.30")],
                "hostgroups": [{"groupid": "22", "name": "Databases"}],
                "parentTemplates": [linux],
                "macros": [],
            },
            {
                **host_common,
                "hostid": "10650",
                "host": "vm-lld-01.example.invalid",
                "name": "vm-lld-01",
                "status": "0",
                "flags": "4",
                "interfaces": [_agent("31", "203.0.113.40")],
                "hostgroups": [{"groupid": "22", "name": "Databases"}],
                "parentTemplates": [],
                "macros": [],
            },
        ],
        "hostgroups": [
            {"groupid": "4", "name": "Zabbix servers", "flags": "0", "uuid": "6f6799aa"},
            {"groupid": "21", "name": "Web servers", "flags": "0", "uuid": "7f6799aa"},
            {"groupid": "22", "name": "Databases", "flags": "0", "uuid": "8f6799aa"},
        ],
        "templates": [
            {
                "templateid": "10001",
                "host": "Linux by Zabbix agent",
                "name": "Linux by Zabbix agent",
                "description": "Official Linux template.",
                "parentTemplates": [],
                "macros": [_macro("{$CPU.UTIL.CRIT}", "90")],
            },
            {
                "templateid": "10563",
                "host": "Nginx by Zabbix agent",
                "name": "Nginx by Zabbix agent",
                "description": "Official Nginx template.",
                "parentTemplates": [],
                "macros": [],
            },
            {
                "templateid": "10570",
                "host": "Example web stack",
                "name": "Example web stack",
                "description": "",
                "parentTemplates": [linux, nginx],
                "macros": [],
            },
        ],
        "triggers": [
            _trigger("23001", "Linux: High CPU utilization", "10001", "Linux by Zabbix agent"),
            _trigger(
                "23101",
                "Linux: High CPU utilization",
                "10084",
                "zabbix-server.example.invalid",
                templateid="23001",
                value="1",
            ),
            _trigger(
                "23102",
                "Nginx: Service is down",
                "10601",
                "web-01.example.invalid",
                priority="4",
            ),
            _trigger("23900", "Disk is full", "10650", "vm-lld-01.example.invalid", flags="4"),
        ],
        "actions": [
            {
                "actionid": "3",
                "name": "Report problems to Zabbix administrators",
                "eventsource": "0",
                "status": "0",
                "esc_period": "1h",
                "pause_suppressed": "1",
                "notify_if_canceled": "1",
                "pause_symptoms": "1",
                "filter": {
                    "evaltype": "0",
                    "formula": "",
                    "eval_formula": "A",
                    "conditions": [
                        {
                            "conditiontype": "4",
                            "operator": "5",
                            "value": "2",
                            "value2": "",
                            "formulaid": "A",
                        }
                    ],
                },
                "operations": [_message_operation("3", "3", "7")],
                "recovery_operations": [
                    {
                        "operationid": "7",
                        "actionid": "3",
                        "operationtype": "11",
                        "opmessage": {
                            "default_msg": "1",
                            "subject": "",
                            "message": "",
                            "mediatypeid": "0",
                        },
                    }
                ],
                "update_operations": [],
            },
            {
                "actionid": "8",
                "name": "Auto registration",
                "eventsource": "2",
                "status": "1",
                "esc_period": "0",
                "pause_suppressed": "0",
                "notify_if_canceled": "0",
                "pause_symptoms": "0",
                "filter": {"evaltype": "0", "formula": "", "eval_formula": "", "conditions": []},
                "operations": [_message_operation("9", "8", "7")],
                "recovery_operations": [],
                "update_operations": [],
            },
        ],
        "mediatypes": [
            {
                "mediatypeid": "1",
                "name": "Email",
                "type": "0",
                "status": "0",
                "description": "",
                "provider": "0",
                "smtp_server": "mail.example.invalid",
                "smtp_port": "587",
                "smtp_helo": "example.invalid",
                "smtp_email": "zabbix@example.invalid",
                "smtp_security": "1",
                "smtp_verify_peer": "1",
                "smtp_verify_host": "1",
                "smtp_authentication": "1",
                "username": "zabbix",
                "passwd": SMTP_PASSWORD,
                "message_format": "1",
                "maxsessions": "1",
                "maxattempts": "3",
                "attempt_interval": "10s",
                "tokens_status": "0",
                "access_token_updated": "0",
            },
            {
                "mediatypeid": "40",
                "name": "Chat webhook",
                "type": "4",
                "status": "0",
                "description": "Posts problems to the team chat",
                "script": "var params = JSON.parse(value); return 'OK';",
                "timeout": "30s",
                "process_tags": "0",
                "show_event_menu": "0",
                "event_menu_url": "",
                "event_menu_name": "",
                "parameters": [
                    {"name": "URL", "value": "https://chat.example.invalid/hooks/{ALERT.SENDTO}"},
                    {"name": "Token", "value": WEBHOOK_TOKEN},
                ],
                "maxsessions": "1",
                "maxattempts": "3",
                "attempt_interval": "10s",
            },
        ],
        "users": [
            _user("1", "Admin", "3", [("7", "Zabbix administrators"), ("13", "Internal")]),
            _user("2", "guest", "4", [("8", "Guests")]),
            _user("3", "ops", "1", [("14", "Operators")]),
        ],
        "usergroups": [
            _group("7", "Zabbix administrators", "0", []),
            _group("8", "Guests", "0", [{"id": "21", "permission": "2"}]),
            _group("13", "Internal", "1", []),
            _group(
                "14",
                "Operators",
                "0",
                [{"id": "21", "permission": "3"}, {"id": "22", "permission": "2"}],
                [{"groupid": "21", "tag": "env", "value": "prod"}],
            ),
        ],
        "roles": [
            {
                "roleid": "1",
                "name": "User role",
                "type": "1",
                "readonly": "0",
                "rules": _rules("1"),
            },
            {
                "roleid": "2",
                "name": "Admin role",
                "type": "2",
                "readonly": "0",
                "rules": _rules("2"),
            },
            {
                "roleid": "3",
                "name": "Super admin role",
                "type": "3",
                "readonly": "1",
                "rules": _rules("3"),
            },
            {
                "roleid": "4",
                "name": "Guest role",
                "type": "1",
                "readonly": "0",
                "rules": _rules("1"),
            },
        ],
        "globalmacros": [
            {"globalmacroid": "2", **_macro("{$SNMP_TIMEOUT}", "3s")},
            {"globalmacroid": "3", **_macro("{$SMTP.RELAY.PASSWORD}", GLOBAL_SECRET_MACRO, "1")},
            {"globalmacroid": "4", **_macro("{$ALERT.TEAM}", "ops", description="On call team")},
        ],
        "proxies": [
            {
                "proxyid": "10701",
                "name": "proxy-branch",
                "proxy_groupid": "0",
                "local_address": "",
                "local_port": "10051",
                "operating_mode": "0",
                "description": "Branch office proxy",
                "allowed_addresses": "192.0.2.50",
                "address": "127.0.0.1",
                "port": "10051",
                "tls_connect": "1",
                "tls_accept": "2",
                "tls_issuer": "",
                "tls_subject": "",
                "custom_timeouts": "0",
                "lastaccess": "1762905600",
                "version": "70005",
                "compatibility": "1",
                "state": "2",
            }
        ],
        "maintenances": [
            {
                "maintenanceid": "1",
                "name": "Weekly patching",
                "maintenance_type": "0",
                "description": "Database patch window",
                "active_since": "1762905600",
                "active_till": "1794441600",
                "tags_evaltype": "0",
                "hostgroups": [{"groupid": "22", "name": "Databases"}],
                "hosts": [],
                "timeperiods": [
                    {
                        "timeperiodid": "1",
                        "timeperiod_type": "3",
                        "every": "1",
                        "month": "0",
                        "dayofweek": "64",
                        "day": "0",
                        "start_time": "7200",
                        "period": "3600",
                        "start_date": "0",
                    }
                ],
                "tags": [],
            }
        ],
        "authentication": {
            "authentication_type": "0",
            "http_auth_enabled": "0",
            "http_login_form": "0",
            "http_strip_domains": "",
            "http_case_sensitive": "1",
            "ldap_auth_enabled": "0",
            "ldap_case_sensitive": "1",
            "ldap_userdirectoryid": "0",
            "saml_auth_enabled": "0",
            "saml_case_sensitive": "0",
            "passwd_min_length": "12",
            "passwd_check_rules": "15",
            "jit_provision_interval": "1h",
            "saml_jit_status": "0",
            "ldap_jit_status": "0",
            "disabled_usrgrpid": "0",
            "mfa_status": "0",
            "mfaid": "0",
        },
    }


def _trigger(
    triggerid: str,
    description: str,
    hostid: str,
    host: str,
    *,
    templateid: str = "0",
    priority: str = "3",
    value: str = "0",
    flags: str = "0",
) -> dict[str, Any]:
    return {
        "triggerid": triggerid,
        "description": description,
        "expression": f"min(/{host}/system.cpu.util,5m)>{{$CPU.UTIL.CRIT}}",
        "recovery_mode": "0",
        "recovery_expression": "",
        "priority": priority,
        "status": "0",
        "type": "0",
        "manual_close": "0",
        "correlation_mode": "0",
        "correlation_tag": "",
        "event_name": "",
        "opdata": "",
        "url": "",
        "comments": "",
        "templateid": templateid,
        "flags": flags,
        "value": value,
        "lastchange": "1762905600",
        "state": "0",
        "error": "",
        "hosts": [{"hostid": hostid, "host": host}],
    }


def _user(userid: str, username: str, roleid: str, groups: list[tuple[str, str]]) -> dict[str, Any]:
    return {
        "userid": userid,
        "username": username,
        "name": "",
        "surname": "",
        "roleid": roleid,
        "autologin": "0",
        "autologout": "15m",
        "url": "",
        "passwd": USER_PASSWORD,
        "attempt_failed": "0",
        "attempt_clock": "0",
        "attempt_ip": "",
        "usrgrps": [{"usrgrpid": key, "name": name} for key, name in groups],
    }


def _group(
    usrgrpid: str,
    name: str,
    gui_access: str,
    rights: list[dict[str, str]],
    tag_filters: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "usrgrpid": usrgrpid,
        "name": name,
        "gui_access": gui_access,
        "users_status": "0",
        "debug_mode": "0",
        "hostgroup_rights": rights,
        "templategroup_rights": [],
        "tag_filters": tag_filters or [],
    }


class RpcError(Exception):
    """An error answer of the fake."""

    def __init__(self, code: int, message: str, data: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _invalid(data: str) -> RpcError:
    return RpcError(-32602, "Invalid params.", data)


@dataclass
class Scenario:
    """What the fake Zabbix stores and which faults it simulates.

    ``tokens`` maps an accepted token to its user type ("3" Super admin, "2" Admin). Faults are
    keyed by the JSON-RPC method name: ``status`` answers that HTTP status, ``raw`` those bytes,
    ``errors`` that JSON-RPC error ``(code, message, data)``.
    """

    version: str = VERSION
    state: dict[str, Any] = field(default_factory=default_state)
    tokens: dict[str, str] = field(default_factory=lambda: {ADMIN_TOKEN: "3", LIMITED_TOKEN: "2"})
    status: dict[str, int] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    errors: dict[str, tuple[int, str, str]] = field(default_factory=dict)
    # Serve every list in reverse order of its ids (the order must never matter).
    reverse: bool = False
    # Put the received token into the data of error answers (a leaking server).
    echo_key: bool = False

    # -- drift helpers ----------------------------------------------------------------------

    def _find(self, name: str, key: str, value: str) -> dict[str, Any]:
        for item in self.state[name]:
            if item[key] == value:
                return cast("dict[str, Any]", item)
        raise KeyError(f"{name} {value}")

    def set_host_description(self, hostid: str, text: str) -> None:
        """Low: the description of a host."""
        self._find("hosts", "hostid", hostid)["description"] = text

    def set_host_status(self, hostid: str, status: str) -> None:
        """Medium: "1" disables a host, "0" enables it."""
        self._find("hosts", "hostid", hostid)["status"] = status

    def unlink_template(self, hostid: str, templateid: str) -> None:
        """Medium: unlink a template from a host."""
        host = self._find("hosts", "hostid", hostid)
        host["parentTemplates"] = [
            t for t in host["parentTemplates"] if t["templateid"] != templateid
        ]

    def set_host_macro(self, hostid: str, macro: str, value: str) -> None:
        """Medium: give a macro of a host another value."""
        for item in self._find("hosts", "hostid", hostid)["macros"]:
            if item["macro"] == macro:
                item["value"] = value
                return
        raise KeyError(macro)

    def set_trigger_status(self, triggerid: str, status: str) -> None:
        """High when "1": disable a trigger."""
        self._find("triggers", "triggerid", triggerid)["status"] = status

    def set_action_status(self, actionid: str, status: str) -> None:
        """High when "1": disable an action."""
        self._find("actions", "actionid", actionid)["status"] = status

    def set_media_parameter(self, mediatypeid: str, name: str, value: str) -> None:
        """High: change a parameter of a webhook media type."""
        for item in self._find("mediatypes", "mediatypeid", mediatypeid)["parameters"]:
            if item["name"] == name:
                item["value"] = value
                return
        raise KeyError(name)

    def set_user_role(self, userid: str, roleid: str) -> None:
        """Critical when the role is a Super admin role ("3")."""
        self._find("roles", "roleid", roleid)
        self._find("users", "userid", userid)["roleid"] = roleid

    def set_authentication(self, name: str, value: str) -> None:
        """Critical: any authentication setting, e.g. passwd_min_length."""
        self.state["authentication"][name] = value

    def tick(self) -> None:
        """Volatile changes only (trigger values, proxy last access, sign in attempts)."""
        for trigger in self.state["triggers"]:
            trigger["value"] = "1" if trigger["value"] == "0" else "0"
            trigger["lastchange"] = str(int(trigger["lastchange"]) + 60)
            trigger["state"] = "0"
        for proxy in self.state["proxies"]:
            proxy["lastaccess"] = str(int(proxy["lastaccess"]) + 60)
        for user in self.state["users"]:
            user["attempt_clock"] = str(int(user["attempt_clock"]) + 60)
        for media in self.state["mediatypes"]:
            if "access_token_updated" in media:
                media["access_token_updated"] = str(int(media["access_token_updated"]) + 60)

    def drift(self) -> None:
        """The standard drift of the simulation: one change of each severity."""
        self.tick()
        self.set_host_description("10602", "Primary database, moved to rack 4")  # low
        self.set_host_status("10601", "1")  # medium
        self.set_trigger_status("23102", "1")  # high
        self.set_user_role("3", "3")  # critical (and the role id itself: high)

    # -- answering --------------------------------------------------------------------------

    def answer(self, method: str, params: Any, token: str | None) -> Any:
        """The result of one authenticated call, or raise :class:`RpcError`."""
        if method in self.errors:
            raise RpcError(*self.errors[method])
        user_type = self.tokens.get(token or "")
        if user_type is None:
            raise _invalid(f"Not authorized. {token}" if self.echo_key else "Not authorized.")
        if user_type != "3" and method in LIMITED_DENIED:
            raise RpcError(-32500, "Application error.", f'No permissions to call "{method}".')
        if method == "authentication.get":
            self._check_params(method, params, frozenset({"output"}))
            return copy.deepcopy(self.state["authentication"])
        if method not in METHODS:
            raise RpcError(-32601, "Method not found.", f'Incorrect API "{method}".')
        return self._get(method, params)

    def _check_params(self, method: str, params: Any, allowed: frozenset[str]) -> None:
        if not isinstance(params, dict):
            raise _invalid('Invalid parameter "/": an array is expected.')
        for name in params:
            if name not in allowed:
                raise _invalid(f'Invalid parameter "/": unexpected parameter "{name}".')

    def _selects(self, method: str) -> dict[str, tuple[str, str]]:
        selects = dict(METHODS[method][3])
        version = _version(self.version)
        groups = ("hostgroups", "hostgroups" if version >= (6, 2) else "groups")
        if method in ("host.get", "maintenance.get"):
            selects["selectHostGroups" if version >= (6, 2) else "selectGroups"] = groups
        if method == "usergroup.get":
            if version < (7, 0):
                selects["selectRights"] = ("hostgroup_rights", "rights")
            if version >= (6, 2):
                selects["selectHostGroupRights"] = ("hostgroup_rights", "hostgroup_rights")
                selects["selectTemplateGroupRights"] = (
                    "templategroup_rights",
                    "templategroup_rights",
                )
        return selects

    def _stored(self, name: str) -> list[dict[str, Any]]:
        """The objects of a collection as this version stores and returns them."""
        version = _version(self.version)
        items = copy.deepcopy(self.state[name])
        for item in items:
            if name == "hosts" and version < (7, 0):
                item["proxy_hostid"] = item.pop("proxyid")
                item.pop("monitored_by")
                item.pop("proxy_groupid")
            if name == "proxies" and version < (7, 0):
                item["host"] = item.pop("name")
                item["status"] = "5" if item.pop("operating_mode") == "0" else "6"
                item["proxy_address"] = item.pop("allowed_addresses")
                for key in ("proxy_groupid", "local_address", "local_port", "address", "port"):
                    item.pop(key)
                for key in ("custom_timeouts", "version", "compatibility", "state"):
                    item.pop(key)
            if name == "users":
                item.pop("passwd")
                role = self._find("roles", "roleid", item["roleid"])
                item["role"] = {"roleid": role["roleid"], "type": role["type"]}
            if name == "usergroups" and version < (6, 2):
                item.pop("templategroup_rights")
            for macro in item.get("macros", []) if name in ("hosts", "templates") else []:
                if macro["type"] == "1":
                    macro.pop("value")
            if name == "globalmacros" and item["type"] == "1":
                item.pop("value")
        return items

    def _get(self, method: str, params: Any) -> Any:
        collection, id_field, ids_param, _ = METHODS[method]
        selects = self._selects(method)
        allowed = _COMMON | {ids_param} | set(selects) | _EXTRA.get(method, frozenset())
        self._check_params(method, params, frozenset(allowed))
        if method == "usermacro.get" and params.get("globalmacro") is not True:
            raise _invalid("the fake serves global macros only")
        items = self._stored(collection)
        stored_selects = {stored for stored, _ in selects.values()}
        scalar = sorted({key for item in items for key in item if key not in stored_selects})
        for key, value in (params.get("filter") or {}).items():
            wanted = [str(v) for v in value] if isinstance(value, list) else [str(value)]
            items = [item for item in items if str(item.get(key)) in wanted]
        if ids_param in params:
            wanted_ids = {str(v) for v in params[ids_param]}
            items = [item for item in items if item[id_field] in wanted_ids]
        items.sort(key=lambda item: int(item[id_field]), reverse=self.reverse)
        if isinstance(params.get("limit"), int):
            items = items[: params["limit"]]
        output = params.get("output", "extend")
        if isinstance(output, list):
            for index, name in enumerate(output):
                if name not in scalar:
                    raise _invalid(
                        f'Invalid parameter "/output/{index + 1}": value must be one of '
                        + ", ".join(f'"{key}"' for key in scalar)
                        + "."
                    )
        result = []
        for item in items:
            answer = {
                key: value
                for key, value in item.items()
                if key not in stored_selects
                and (output == "extend" or key in output or key == id_field)
            }
            for param, (stored, returned) in selects.items():
                if param in params:
                    answer[returned] = _project(item.get(stored), params[param])
            result.append(answer)
        return result


def _project(value: Any, output: Any) -> Any:
    if output == "extend" or not isinstance(output, list):
        return value
    if isinstance(value, list):
        return [_project(member, output) for member in value]
    if isinstance(value, dict):
        return {key: member for key, member in value.items() if key in output}
    return value


# -- serving -----------------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: object) -> None:
        self._send(200, json.dumps(payload).encode("utf-8"))

    def _refuse(self) -> None:
        server = cast("_Server", self.server)
        path, _, query = self.path.partition("?")
        server.requests.append(
            Request(self.command, path, query, None, None, None, None, None, b"")
        )
        self._send(405, b"Method Not Allowed", "text/plain")

    do_GET = do_PUT = do_PATCH = do_DELETE = _refuse

    def do_POST(self) -> None:
        server = cast("_Server", self.server)
        scenario = server.scenario
        path, _, query = self.path.partition("?")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type")
        authorization = self.headers.get("Authorization")
        try:
            request = json.loads(body)
        except ValueError:
            request = None
        method = request.get("method") if isinstance(request, dict) else None
        params = request.get("params") if isinstance(request, dict) else None
        auth_member = request.get("auth") if isinstance(request, dict) else None
        server.requests.append(
            Request(
                "POST",
                path,
                query,
                content_type,
                authorization,
                method,
                params,
                auth_member,
                body,
            )
        )
        if not path.endswith(ENDPOINT):
            self._send(404, b"Not Found", "text/plain")
            return
        if (content_type or "").split(";")[0].strip() not in CONTENT_TYPES:
            self._send(412, b"Precondition Failed", "text/plain")
            return
        if not isinstance(request, dict) or not isinstance(method, str):
            self._json(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Invalid request.", "data": ""},
                    "id": None,
                }
            )
            return
        if method in scenario.status:
            self._send(scenario.status[method], b"Simulated failure", "text/plain")
            return
        if method in scenario.raw:
            self._send(200, scenario.raw[method])
            return
        request_id = request.get("id")
        try:
            result = self._result(scenario, request, method, params, authorization)
        except RpcError as error:
            self._json(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": error.code, "message": error.message, "data": error.data},
                    "id": request_id,
                }
            )
            return
        self._json({"jsonrpc": "2.0", "result": result, "id": request_id})

    @staticmethod
    def _result(
        scenario: Scenario,
        request: dict[str, Any],
        method: str,
        params: Any,
        authorization: str | None,
    ) -> Any:
        version = _version(scenario.version)
        has_auth = "auth" in request and request["auth"] is not None
        if method in scenario.errors:
            raise RpcError(*scenario.errors[method])
        if method == "apiinfo.version":
            if has_auth or authorization:
                raise _invalid(
                    'The "apiinfo.version" method must be called without the "auth" parameter.'
                )
            return scenario.version
        token: str | None = None
        if version >= (6, 4) and authorization and authorization.startswith("Bearer "):
            token = authorization.removeprefix("Bearer ")
        if has_auth:
            if version >= (7, 2):
                raise _invalid('Invalid parameter "/": unexpected parameter "auth".')
            token = str(request["auth"])
        return scenario.answer(method, params, token)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[Request] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None


class FakeZabbix:
    """A running fake Zabbix."""

    def __init__(self, server: _Server) -> None:
        self._server = server

    @property
    def url(self) -> str:
        """The frontend address, plain http on a free local port, served under ``/zabbix``."""
        return f"http://127.0.0.1:{self._server.server_address[1]}/zabbix"

    @property
    def scenario(self) -> Scenario:
        """The scenario being served; a test may change it between calls."""
        return self._server.scenario

    @property
    def requests(self) -> list[Request]:
        """Every request received, in order."""
        return self._server.requests


@contextmanager
def fake_zabbix(scenario: Scenario | None = None) -> Iterator[FakeZabbix]:
    """Serve ``scenario`` (the default installation when None) until the block ends."""
    server = _Server(scenario or Scenario())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeZabbix(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
