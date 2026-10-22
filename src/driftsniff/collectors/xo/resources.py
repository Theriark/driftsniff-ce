"""The Xen Orchestra collections the collector reads and how it asks for them (P8-T2).

Every path, name and the cookie below is **unverified**: they come from the plan (statements 1, 2, 4
and 7 of docs/vendor-notes/xo.md) and, for the REST prefix and the credential endpoint, from our own
reading of how such an interface is usually laid out. The vendor reference was not read and no lab
Xen Orchestra exists (Phase 0 tests X1 to X4 are open). When the vendor reference arrives, correct
this module and nothing else has to change.

The request for a collection carries an explicit field list. The list is built from the type table
of the collection (:func:`field_list`): the first segment of every field that is not ignore class,
so a collection that has no type table, and every collection the plan excludes, can never be
requested. A whole nested object (``memory``, ``settings``) is asked for by its first segment; the
ignore class fields inside it are dropped by the normaliser, and a field the table does not name
stays unclassified (shown as a fingerprint) until it is classified.
"""

from typing import Final
from urllib.parse import urlencode

from driftsniff.core.normalize import FieldClass
from driftsniff.rules.schema import ResourceTable

REST_PREFIX: Final = "/rest/v0"
COOKIE_NAME: Final = "authenticationToken"
# The credential in use, as the REST interface lists the credentials of the signed in user.
TOKEN_PATH: Final = "/users/me/authentication_tokens"  # noqa: S105 - a URL path, not a password

# Collections the plan never requests (P8-T1). None of them has a type table.
EXCLUDED_COLLECTIONS: Final = (
    "tasks",
    "alarms",
    "messages",
    "backup-logs",
    "restore-logs",
    "backup-archives",
    "events",
    "vm-snapshots",
    "vdi-snapshots",
    "licenses",
    "sms",
    "pcis",
    "pgpus",
    "vm-controller",
    "xoa",
)

# The collections the collector reads, in the order it reads them (statement 4 of the notes).
COLLECTIONS: Final = (
    "vms",
    "vm-templates",
    "hosts",
    "pools",
    "networks",
    "pifs",
    "pbds",
    "srs",
    "vifs",
    "vbds",
    "vdis",
    "backup-jobs",
    "schedules",
    "backup-repositories",
    "proxies",
    "servers",
    "users",
    "groups",
    "acl-roles",
    "acl-privileges",
)

# A field the collector needs and the type table ignores: the marker of a built in template
# (unverified; notes, decision 3). It is requested for that one collection and dropped after use.
BUILT_IN_TEMPLATE_FIELD: Final = "isDefaultTemplate"
EXTRA_FIELDS: Final = {"vm-templates": (BUILT_IN_TEMPLATE_FIELD,)}


def collection_path(name: str) -> str:
    """The path of a collection below the REST prefix; an unknown or excluded name raises."""
    if name in EXCLUDED_COLLECTIONS or name not in COLLECTIONS:
        raise ValueError("the collection is not read by the collector")
    return f"/{name}"


def field_list(name: str, table: ResourceTable) -> str:
    """The comma separated field list that asks for the kept fields of ``table``.

    The first segment of every field path that is not ignore class, plus the extra fields of the
    collection, sorted so that the request does not depend on the order of the table. The key field
    is always part of it.
    """
    names = {table.object_key_field or "id", *EXTRA_FIELDS.get(name, ())}
    for path, field_class in table.field_classes.items():
        if field_class is not FieldClass.IGNORE:
            names.add(path.split(".", 1)[0])
    return ",".join(sorted(names))


def collection_query(fields: str) -> str:
    """The query of a collection request: the field list and newline delimited output."""
    return urlencode({"fields": fields, "ndjson": "true"})
