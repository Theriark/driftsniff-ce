"""The Synology DSM resources the collector reads and the Web API calls behind them.

Sources and their status are in docs/vendor-notes/synology.md. ``SYNO.API.Info`` and
``SYNO.API.Auth`` are in Synology's own DSM Login Web API Guide; every ``SYNO.Core.*`` name, method
and parameter below is **unverified**: Synology does not document them, and they come from
community client libraries (notes, sources S2 to S4). No lab DSM was used. When a lab result or a
vendor document arrives, correct :data:`RESOURCES` and the type table ``rules/types/synology.yaml``;
nothing else has to change.

Every call is a form POST to ``/webapi/<path>`` with ``api``, ``method`` and ``version``; the path
comes from the ``SYNO.API.Info`` answer. A resource whose API the NAS does not list is
``not_available`` (coverage 404) and is never requested.

Three resources are views that driftsniff builds from listed objects, so that a risky change shows
up as an added object of its own and the object floor can rate it (a field rule cannot look at the
name of the object it belongs to):

* ``synology-administrators``: the members of the local group ``administrators``;
* ``synology-guest-share-access``: one object per shared folder on which the built in ``guest``
  account has read or write access and is not denied;
* ``synology-file-services``: the SMB, NFS and AFP settings as three objects keyed ``smb``,
  ``nfs`` and ``afp``.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

INFO_PATH: Final = "query.cgi"
API_INFO: Final = "SYNO.API.Info"
API_AUTH: Final = "SYNO.API.Auth"
# Version 6 of the Auth API takes ``format=sid`` and returns the sid in the body (DSM 6.0 and
# later); DSM 7 lists a higher maxVersion and still serves 6.
AUTH_VERSION: Final = 6
SESSION_NAME: Final = "driftsniff"

API_SHARE_PERMISSION: Final = "SYNO.Core.Share.Permission"
API_GROUP_MEMBER: Final = "SYNO.Core.Group.Member"
ADMIN_GROUP: Final = "administrators"
GUEST_USER: Final = "guest"
PAGE_LIMIT: Final = 500

RESOURCE_SHARES: Final = "synology-shares"
RESOURCE_GUEST_ACCESS: Final = "synology-guest-share-access"
RESOURCE_USERS: Final = "synology-users"
RESOURCE_GROUPS: Final = "synology-groups"
RESOURCE_ADMINISTRATORS: Final = "synology-administrators"
RESOURCE_FILE_SERVICES: Final = "synology-file-services"

# The key an object of a singleton resource (a ``get`` that answers one settings object) gets.
SINGLETON_KEY: Final = "settings"
SINGLETON_FIELD: Final = "object_key"


@dataclass(frozen=True, slots=True)
class Call:
    """One Web API call: the API, its method and version, the extra form fields and, for a list,
    the name of the list in ``data`` (None: ``data`` is one settings object; ``""``: ``data`` is
    the list itself). ``paged`` calls take ``offset`` and ``limit`` and report ``total``."""

    api: str
    method: str
    version: int = 1
    params: Mapping[str, str] = field(default_factory=dict)
    list_key: str | None = None
    paged: bool = False


@dataclass(frozen=True, slots=True)
class SynologyResource:
    """One resource: its name in the type tables, the calls it needs and the key of its objects."""

    name: str
    calls: tuple[Call, ...]
    key_field: str


_SHARE_ADDITIONAL: Final = '["hidden","encryption","recyclebin","unite_permission","is_aclmode"]'
_USER_ADDITIONAL: Final = (
    '["description","email","expired","cannot_chg_passwd","passwd_never_expire","2fa_status"]'
)

SHARE_LIST: Final = Call(
    "SYNO.Core.Share",
    "list",
    params={"shareType": "all", "additional": _SHARE_ADDITIONAL},
    list_key="shares",
)
GROUP_LIST: Final = Call(
    "SYNO.Core.Group",
    "list",
    params={"type": "local", "name_only": "false"},
    list_key="groups",
    paged=True,
)
# The permission rows of one share and the members of one group; the client adds the name.
PERMISSION_LIST: Final = Call(
    API_SHARE_PERMISSION,
    "list",
    params={"action": "enum", "is_unite_permission": "false", "with_inherit": "false"},
    list_key="items",
    paged=True,
)
MEMBER_LIST: Final = Call(API_GROUP_MEMBER, "list", params={"ingroup": "true"}, list_key="users")
PRINCIPAL_TYPES: Final = ("local_user", "local_group")
FILE_SERVICE_CALLS: Final = {
    "smb": Call("SYNO.Core.FileServ.SMB", "get"),
    "nfs": Call("SYNO.Core.FileServ.NFS", "get"),
    "afp": Call("SYNO.Core.FileServ.AFP", "get"),
}

RESOURCES: Final = (
    SynologyResource(RESOURCE_SHARES, (SHARE_LIST, PERMISSION_LIST), "name"),
    SynologyResource(RESOURCE_GUEST_ACCESS, (SHARE_LIST, PERMISSION_LIST), "share"),
    SynologyResource(
        RESOURCE_USERS,
        (
            Call(
                "SYNO.Core.User",
                "list",
                params={"type": "local", "additional": _USER_ADDITIONAL},
                list_key="users",
                paged=True,
            ),
        ),
        "name",
    ),
    SynologyResource(RESOURCE_GROUPS, (GROUP_LIST, MEMBER_LIST), "name"),
    SynologyResource(RESOURCE_ADMINISTRATORS, (MEMBER_LIST,), "name"),
    SynologyResource("synology-terminal", (Call("SYNO.Core.Terminal", "get"),), SINGLETON_FIELD),
    SynologyResource(
        "synology-firewall", (Call("SYNO.Core.Security.Firewall", "get"),), SINGLETON_FIELD
    ),
    SynologyResource(
        "synology-firewall-profiles",
        (Call("SYNO.Core.Security.Firewall.Profile", "list", list_key="profiles"),),
        "name",
    ),
    SynologyResource(
        "synology-auto-block", (Call("SYNO.Core.Security.AutoBlock", "get"),), SINGLETON_FIELD
    ),
    SynologyResource(
        "synology-2fa-policy", (Call("SYNO.Core.OTP.EnforcePolicy", "get"),), SINGLETON_FIELD
    ),
    SynologyResource(RESOURCE_FILE_SERVICES, tuple(FILE_SERVICE_CALLS.values()), SINGLETON_FIELD),
    SynologyResource(
        "synology-packages",
        (
            Call(
                "SYNO.Core.Package",
                "list",
                params={"additional": '["status","startable"]'},
                list_key="packages",
            ),
        ),
        "id",
    ),
    SynologyResource(
        "synology-network-interfaces",
        (Call("SYNO.Core.Network.Interface", "list", list_key=""),),
        "ifname",
    ),
    SynologyResource("synology-network", (Call("SYNO.Core.Network", "get"),), SINGLETON_FIELD),
    SynologyResource(
        "synology-quickconnect", (Call("SYNO.Core.QuickConnect", "get"),), SINGLETON_FIELD
    ),
)

RESOURCE_BY_NAME: Final = {resource.name: resource for resource in RESOURCES}
