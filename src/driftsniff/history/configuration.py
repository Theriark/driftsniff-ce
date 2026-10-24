"""The current configuration of a source, browsed by resource (P10-T7, backend slice).

``ConfigurationQueries.current`` shows the newest snapshot of a source: its resource types, and
the objects of one of them, 50 a page, with the fields of every object. The content is the one
``driftsniff.core.snapshots.resolve_current_state`` returns (the manifest of the newest snapshot
and the state of each object in it); the service reads the states of the shown objects only, so a
large resource costs one page, not the whole resource. A test holds the two equal.

Order. An ordered resource (a firewall policy list) is shown in the order of its position list,
with each object's 1-based ``position``. A list inside an object keeps the order it was stored in
(a set is stored sorted); the fields of a list member carry ``[n]`` in their path, and ``ordered``
tells whether that order means anything.

Secrets. A state holds a secret as a fingerprint marker (``fp1:...``) instead of the value, and
an unclassified field, or any field of a resource without a type table, in clear. The view masks
both the way the change items do (``driftsniff.core.diff``): a marker shows its short fingerprint;
a ``secret`` or ``unclassified`` field never shows its value, only a fingerprint made with the
installation's fingerprint key, so it equals the one a change item of that value shows. A search
reads shown text only, never a hidden value. Vendor text (names, keys, paths, values) passes the
log scrubber of ``driftsniff.secrets.redact``, like the change views.

Reads write nothing and write no audit event; the viewer role is the route's check.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache
from typing import Final

import sqlalchemy as sa
from sqlalchemy import Connection

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.normalize import CollectionMode, FieldClass, StaticTypeTable
from driftsniff.core.snapshots import Manifest, StoredSnapshot, latest_snapshot
from driftsniff.core.states import StoredDataError, get_state
from driftsniff.db.engine import Database
from driftsniff.db.tables import objects
from driftsniff.history.errors import StoredConfigurationError
from driftsniff.history.queries import page_bounds, source_ref
from driftsniff.history.views import (
    FINGERPRINT_SHOWN_CHARS,
    OBJECTS_PER_PAGE,
    SEARCH_MAX_CHARS,
    SEARCH_SCAN_LIMIT,
    VALUE_MAX_CHARS,
    ConfigObject,
    ConfigurationView,
    FieldView,
    ResourceSummary,
    SnapshotRef,
    SourceRef,
)
from driftsniff.rules.loader import load_rules
from driftsniff.rules.schema import ResourceTable
from driftsniff.secrets.fingerprint import Fingerprint, Fingerprinter
from driftsniff.secrets.redact import scrub_text

XO_SOURCE_TYPE: Final = "xo"
_UNREADABLE: Final = "the stored configuration cannot be read"
_NAME_CHUNK: Final = 500
# A resource without a type table has every field unclassified, like in the diff engine.
_NO_TABLE: Final = StaticTypeTable()


@cache
def shipped_tables() -> Mapping[str, ResourceTable]:
    """The type tables of the shipped rules, loaded once."""
    return load_rules().type_tables


def _text_of(value: JsonValue) -> str:
    """A scalar as the text a person reads: a string as it is, anything else as JSON."""
    if isinstance(value, str):
        return value
    return canonical_dumps(value).decode("utf-8")


def _marker_of(value: JsonValue) -> Fingerprint | None:
    return Fingerprint.parse(value) if isinstance(value, str) else None


@dataclass(slots=True)
class _Flatten:
    """The flattening of one object into fields, in stored order."""

    resource: str
    table: StaticTypeTable
    hidden: frozenset[str]
    fingerprinter: Fingerprinter
    found: list[FieldView] = field(default_factory=list)

    def run(self, state: Mapping[str, JsonValue]) -> tuple[FieldView, ...]:
        for key, value in state.items():
            self._value(value, key, scrub_text(key), ordered=False)
        return tuple(self.found)

    def _value(self, value: JsonValue, class_path: str, shown: str, *, ordered: bool) -> None:
        declared = self.table.field_class(class_path)
        marker = _marker_of(value)
        if declared is FieldClass.IGNORE:
            return
        if marker is not None:
            short = marker.short(FINGERPRINT_SHOWN_CHARS)
            self._add(class_path, shown, FieldClass.SECRET, ordered, fingerprint=short)
        elif declared is FieldClass.SECRET:
            self._masked(value, class_path, shown, declared, ordered)
        elif isinstance(value, Mapping):
            if not value:
                self._leaf("{}", class_path, shown, ordered)
            for key, member in value.items():
                child = f"{shown}.{scrub_text(key)}"
                self._value(member, f"{class_path}.{key}", child, ordered=ordered)
        elif isinstance(value, list):
            if not value:
                self._leaf("[]", class_path, shown, ordered)
            in_order = ordered or self.table.collection_mode(class_path) is not CollectionMode.SET
            for position, member in enumerate(value, start=1):
                self._value(member, class_path, f"{shown}[{position}]", ordered=in_order)
        elif declared is FieldClass.UNCLASSIFIED:
            self._masked(value, class_path, shown, declared, ordered)
        else:
            self._leaf(_text_of(value), class_path, shown, ordered)

    def _leaf(self, text: str, class_path: str, shown: str, ordered: bool) -> None:
        scrubbed = scrub_text(text)
        self._add(
            class_path,
            shown,
            FieldClass.CONFIG,
            ordered,
            value=scrubbed[:VALUE_MAX_CHARS],
            truncated=len(scrubbed) > VALUE_MAX_CHARS,
        )

    def _masked(
        self,
        value: JsonValue,
        class_path: str,
        shown: str,
        field_class: FieldClass,
        ordered: bool,
    ) -> None:
        """A secret or unclassified value: never shown, only its fingerprint."""
        short: str | None
        try:
            made = self.fingerprinter.fingerprint(self.resource, class_path, value)
            short = made.short(FINGERPRINT_SHOWN_CHARS)
        except (ValueError, TypeError):
            short = None
        self._add(class_path, shown, field_class, ordered, fingerprint=short)

    def _add(
        self,
        class_path: str,
        shown: str,
        field_class: FieldClass,
        ordered: bool,
        *,
        value: str | None = None,
        fingerprint: str | None = None,
        truncated: bool = False,
    ) -> None:
        hidden = any(
            class_path == path or class_path.startswith(f"{path}.") for path in self.hidden
        )
        self.found.append(
            FieldView(
                path=shown,
                value=value,
                field_class=field_class.value,
                secret=field_class is not FieldClass.CONFIG,
                fingerprint=fingerprint,
                ordered=ordered,
                hidden_by_xo=hidden,
                truncated=truncated,
            )
        )


def _names(
    connection: Connection, source_id: int, resource: str, keys: list[str]
) -> dict[str, str]:
    """The display name of each object key that has one (the ``objects`` table)."""
    found: dict[str, str] = {}
    for start in range(0, len(keys), _NAME_CHUNK):
        chunk = keys[start : start + _NAME_CHUNK]
        rows = connection.execute(
            sa.select(objects.c.object_key, objects.c.display_name).where(
                objects.c.source_id == source_id,
                objects.c.resource == resource,
                objects.c.object_key.in_(chunk),
                objects.c.display_name.is_not(None),
            )
        ).all()
        found.update((str(row.object_key), str(row.display_name)) for row in rows)
    return found


def _empty(source: SourceRef, snapshot: SnapshotRef | None, search: str) -> ConfigurationView:
    return ConfigurationView(
        source=source,
        snapshot=snapshot,
        resources=(),
        selected_resource=None,
        search=search,
        objects=(),
        total=0,
        page=1,
        pages=1,
        page_size=OBJECTS_PER_PAGE,
    )


class ConfigurationQueries:
    """Reads the newest snapshot of a source as browsable objects."""

    def __init__(
        self,
        database: Database,
        fingerprinter: Fingerprinter,
        type_tables: Mapping[str, StaticTypeTable] | None = None,
    ) -> None:
        self._db = database
        self._fingerprinter = fingerprinter
        self._tables = type_tables

    def _table(self, resource: str) -> StaticTypeTable:
        tables: Mapping[str, StaticTypeTable] = (
            shipped_tables() if self._tables is None else self._tables
        )
        return tables.get(resource, _NO_TABLE)

    def _hidden(self, source: SourceRef, resource: str) -> frozenset[str]:
        table = self._table(resource)
        if source.type != XO_SOURCE_TYPE or not isinstance(table, ResourceTable):
            return frozenset()
        return table.hidden_by_xo

    def current(
        self,
        source_id: int,
        *,
        resource: str | None = None,
        search: str = "",
        page: int = 1,
    ) -> ConfigurationView | None:
        """The configuration of the newest snapshot; None for an unknown source.

        ``resource`` names the resource type to browse; none, or one the snapshot does not hold,
        selects the first. ``search`` keeps the objects whose key, name, field path or shown value
        contains the text (any case, matched literally); a search reads at most
        ``SEARCH_SCAN_LIMIT`` objects and says so when it stopped there. Raises
        ``StoredConfigurationError`` when a stored manifest or state is damaged.
        """
        needle = search.strip()[:SEARCH_MAX_CHARS]
        try:
            with self._db.read() as connection:
                source = source_ref(connection, source_id)
                if source is None:
                    return None
                latest = latest_snapshot(connection, source_id)
                if latest is None:
                    return _empty(source, None, needle)
                return self._view(connection, source, latest, resource, needle, page)
        except StoredDataError as error:
            raise StoredConfigurationError(_UNREADABLE) from error

    def _view(
        self,
        connection: Connection,
        source: SourceRef,
        latest: StoredSnapshot,
        resource: str | None,
        needle: str,
        page: int,
    ) -> ConfigurationView:
        manifest = latest.manifest
        version = manifest.controller_version
        snapshot = SnapshotRef(
            id=latest.snapshot_id,
            taken_at=latest.taken_at,
            kind=latest.kind,
            controller_version=None if version is None else scrub_text(version),
        )
        summaries = tuple(
            ResourceSummary(
                resource=name,
                object_count=len(hashes),
                ordered=name in manifest.positions,
                hidden_by_xo=tuple(sorted(self._hidden(source, name))),
            )
            for name, hashes in manifest.objects.items()
        )
        if not summaries:
            return _empty(source, snapshot, needle)
        selected = summaries[0].resource
        if resource is not None and any(summary.resource == resource for summary in summaries):
            selected = resource
        keys = list(manifest.positions.get(selected, list(manifest.objects[selected])))
        positions: dict[str, int] = {}
        if selected in manifest.positions:
            positions = {key: place for place, key in enumerate(keys, start=1)}
        truncated = False
        if needle:
            scan = keys[:SEARCH_SCAN_LIMIT]
            truncated = len(keys) > SEARCH_SCAN_LIMIT
            names = _names(connection, source.id, selected, scan)
            keys = [
                key
                for key in scan
                if self._matches(connection, manifest, source, selected, key, names, needle)
            ]
        total = len(keys)
        shown, pages = page_bounds(page, total, OBJECTS_PER_PAGE)
        window = keys[(shown - 1) * OBJECTS_PER_PAGE : shown * OBJECTS_PER_PAGE]
        names = _names(connection, source.id, selected, window)
        built = tuple(
            self._object(connection, manifest, source, selected, key, names, positions)
            for key in window
        )
        return ConfigurationView(
            source=source,
            snapshot=snapshot,
            resources=summaries,
            selected_resource=selected,
            search=needle,
            objects=built,
            total=total,
            page=shown,
            pages=pages,
            page_size=OBJECTS_PER_PAGE,
            search_truncated=truncated,
        )

    def _object(
        self,
        connection: Connection,
        manifest: Manifest,
        source: SourceRef,
        resource: str,
        key: str,
        names: Mapping[str, str],
        positions: Mapping[str, int],
    ) -> ConfigObject:
        state = get_state(connection, manifest.objects[resource][key])
        flatten = _Flatten(
            resource=resource,
            table=self._table(resource),
            hidden=self._hidden(source, resource),
            fingerprinter=self._fingerprinter,
        )
        name = names.get(key)
        return ConfigObject(
            key=scrub_text(key),
            name=None if name is None else scrub_text(name),
            position=positions.get(key),
            fields=flatten.run(state),
        )

    def _matches(
        self,
        connection: Connection,
        manifest: Manifest,
        source: SourceRef,
        resource: str,
        key: str,
        names: Mapping[str, str],
        needle: str,
    ) -> bool:
        wanted = needle.casefold()
        built = self._object(connection, manifest, source, resource, key, names, {})
        if wanted in built.key.casefold() or wanted in (built.name or "").casefold():
            return True
        return any(
            wanted in shown.path.casefold() or wanted in (shown.value or "").casefold()
            for shown in built.fields
        )
