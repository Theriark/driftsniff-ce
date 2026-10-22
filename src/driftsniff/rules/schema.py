"""The schema of a rule, of a type table and of the files that hold them.

Rule
    ``id``, the ``resource`` it applies to, the field ``path`` (dot separated, see below), an
    optional ``when`` (a predicate from ``rules/predicates.py``), the ``severity`` it gives and a
    one sentence ``rationale``.

Type table
    What the collector side knows about one resource type: how its objects are keyed and named,
    the class of every field, how its lists are compared, and the object floors (the lowest
    severity an added, removed, modified or moved object of this type may get). A loaded type
    table is a :class:`ResourceTable`, which is a ``core.normalize.StaticTypeTable`` and so is
    read by ``normalize``, ``diff`` and ``order`` without any adapter. Its field paths are the
    vendor field names exactly as the diff walks them (``secureBoot``, not ``secure_boot``).

Paths in a rule
    A rule path is dot separated. Every literal segment is turned into lower case snake case
    (``secureBoot`` becomes ``secure_boot``, ``HTTPProxy`` becomes ``http_proxy``), and so is
    every segment of the path of a change item before they are compared. A segment ``*`` matches
    exactly one segment. A segment ``**`` is only allowed last and matches the rest of the path,
    which may be empty: ``**`` alone matches every field of the resource, and the empty path of
    an added or removed object.

Specificity
    ``2 x the number of literal segments``, plus ``1`` when the rule has a ``when``. The most
    specific rule that applies wins; two rules that can apply to the same change with the same
    specificity are refused when the rules are loaded (see ``rules/loader.py``).
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from driftsniff.core.normalize import CollectionMode, FieldClass, StaticTypeTable
from driftsniff.rules.predicates import build_predicate

ANY_SEGMENT: Final = "*"
REST_OF_PATH: Final = "**"
FLOOR_KINDS: Final = ("added", "removed", "modified", "moved")
DEFAULT_BLOCKING_ACTIONS: Final = ("deny", "drop")
# The same four values as ``core.diff.Severity`` (a test keeps them equal); the alias is repeated
# here so that reading the rules does not import the diff engine and what it depends on.
Severity = Literal["low", "medium", "high", "critical"]
FloorKind = Literal["added", "removed", "modified", "moved"]

_NAME_PATTERN: Final = r"^[a-z0-9][a-z0-9_.-]*$"
_CAMEL_BOUNDARY: Final = re.compile(r"([a-z0-9])([A-Z])")
_ACRONYM_BOUNDARY: Final = re.compile(r"([A-Z]+)([A-Z][a-z])")
_NOT_WORD: Final = re.compile(r"[^a-z0-9]+")


def snake_case(segment: str) -> str:
    """Lower case snake case of one path segment: ``secureBoot`` becomes ``secure_boot``."""
    text = _ACRONYM_BOUNDARY.sub(r"\1_\2", _CAMEL_BOUNDARY.sub(r"\1_\2", segment))
    return _NOT_WORD.sub("_", text.lower()).strip("_")


def normalize_path(path: str) -> tuple[str, ...]:
    """The segments of the path of a change item, in snake case. The empty path has none."""
    if path == "":
        return ()
    return tuple(snake_case(segment) for segment in path.split("."))


def path_matches(pattern: Sequence[str], segments: Sequence[str]) -> bool:
    """Whether the rule path ``pattern`` applies to the item path ``segments`` (both snake case)."""
    for index, part in enumerate(pattern):
        if part == REST_OF_PATH:
            return True
        if index >= len(segments):
            return False
        if part != ANY_SEGMENT and part != segments[index]:
            return False
    return len(pattern) == len(segments)


def paths_overlap(first: Sequence[str], second: Sequence[str]) -> bool:
    """Whether some path is matched by both patterns."""
    for index in range(max(len(first), len(second))):
        one = first[index] if index < len(first) else None
        other = second[index] if index < len(second) else None
        if one == REST_OF_PATH or other == REST_OF_PATH:
            return True
        if one is None or other is None:
            return False
        if one != ANY_SEGMENT and other != ANY_SEGMENT and one != other:
            return False
    return True


def _check_segments(path: str, *, wildcards: bool) -> None:
    if path == "":
        raise ValueError("a path cannot be empty")
    parts = path.split(".")
    for index, part in enumerate(parts):
        if part == "":
            raise ValueError(f"the path {path!r} has an empty segment")
        if part in (ANY_SEGMENT, REST_OF_PATH):
            if not wildcards:
                raise ValueError(f"the path {path!r} cannot use a wildcard")
            if part == REST_OF_PATH and index != len(parts) - 1:
                raise ValueError(f"{REST_OF_PATH} can only be the last segment of {path!r}")


class WhenSpec(BaseModel):
    """The ``when`` of a rule: the name of a predicate and its arguments."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    args: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _predicate_is_valid(self) -> Self:
        build_predicate(self.name, self.args)
        return self


class Rule(BaseModel):
    """One classification rule. See the module description for paths and specificity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=_NAME_PATTERN)
    resource: str = Field(pattern=_NAME_PATTERN)
    path: str
    when: WhenSpec | None = None
    severity: Severity
    rationale: str

    @field_validator("path")
    @classmethod
    def _normalise_path(cls, value: str) -> str:
        value = value.strip()
        _check_segments(value, wildcards=True)
        parts = [
            part if part in (ANY_SEGMENT, REST_OF_PATH) else snake_case(part)
            for part in value.split(".")
        ]
        if "" in parts:
            raise ValueError(f"the path {value!r} has a segment without letters or digits")
        return ".".join(parts)

    @field_validator("when", mode="before")
    @classmethod
    def _shape_when(cls, value: object) -> object:
        if value is None or isinstance(value, WhenSpec):
            return value
        if isinstance(value, str):
            return {"name": value, "args": {}}
        if isinstance(value, Mapping):
            if "name" not in value:
                raise ValueError("a predicate with arguments needs a name")
            return {
                "name": value["name"],
                "args": {key: member for key, member in value.items() if key != "name"},
            }
        raise ValueError("when is a predicate name, or a mapping with a name and its arguments")

    @field_validator("rationale")
    @classmethod
    def _rationale_has_text(cls, value: str) -> str:
        value = value.strip()
        if value == "":
            raise ValueError("a rule needs a rationale")
        return value

    @property
    def segments(self) -> tuple[str, ...]:
        """The segments of the (normalised) path."""
        return tuple(self.path.split("."))

    @property
    def specificity(self) -> int:
        """Twice the number of literal segments, plus one when the rule has a predicate."""
        literal = sum(1 for part in self.segments if part not in (ANY_SEGMENT, REST_OF_PATH))
        return 2 * literal + (1 if self.when is not None else 0)


class ListSpec(BaseModel):
    """How one list inside an object is compared, and the field that keys its members."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: CollectionMode
    key_field: str | None = Field(default=None, min_length=1)
    first_match: bool = False

    @model_validator(mode="before")
    @classmethod
    def _shape(cls, data: object) -> object:
        if isinstance(data, str):
            return {"mode": data}
        return data

    @model_validator(mode="after")
    def _first_match_needs_an_order(self) -> Self:
        if self.first_match and self.mode is not CollectionMode.ORDERED_KEYED:
            raise ValueError("first_match needs a list of the mode ordered-keyed")
        return self


@dataclass(frozen=True)
class ResourceTable(StaticTypeTable):
    """A loaded type table: the ``TypeTable`` interface plus what the rule engine needs.

    ``collection`` is the mode of the collection of objects of this resource (``ordered-keyed``
    for a list such as firewall policies, whose position list the collector stores).
    ``floors`` maps ``added``, ``removed``, ``modified`` and ``moved`` to the lowest severity of
    such a change to an object of this type.
    """

    resource: str = ""
    collection: CollectionMode = CollectionMode.SET
    floors: Mapping[str, Severity] = field(default_factory=dict)
    blocking_actions: frozenset[str] = frozenset()
    first_match: bool = False
    first_match_lists: frozenset[str] = frozenset()
    hidden_by_xo: frozenset[str] = frozenset()

    def is_hidden_by_xo(self, path: str) -> bool:
        """Whether Xen Orchestra itself never returns the value at ``path``.

        A change to such a value cannot be observed, so the interface says "hidden by XO" instead
        of showing a field that never moves. The marker does not change the class of the field.
        """
        return path in self.hidden_by_xo

    def floor_for(self, change_kind: str) -> Severity | None:
        """The floor of ``change_kind`` (``added``, ``removed``, ``modified`` or ``moved``)."""
        return self.floors.get(change_kind)

    def is_first_match(self, path: str) -> bool:
        """Whether the order at ``path`` decides what happens (the first matching entry wins).

        The empty path is the order of the objects of the resource itself; any other path is a
        list inside an object, written as the diff writes it (vendor field names, no index).
        """
        return self.first_match if path == "" else path in self.first_match_lists

    def is_blocking(self, action: str) -> bool:
        """Whether ``action`` stops traffic or access: one of the declared ``blocking_actions``."""
        return action.strip().casefold() in self.blocking_actions


class TypeSpec(BaseModel):
    """The type table of one resource, as written in a file of ``rules/types``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    resource: str = Field(pattern=_NAME_PATTERN)
    collection: CollectionMode = CollectionMode.SET
    key_field: str | None = Field(default=None, min_length=1)
    name_field: str | None = Field(default=None, min_length=1)
    floor: Severity | None = None
    floors: dict[FloorKind, Severity] = Field(default_factory=dict)
    fields: dict[str, FieldClass]
    lists: dict[str, ListSpec] = Field(default_factory=dict)
    action_field: str | None = Field(default=None, min_length=1)
    blocking_actions: list[str] | None = None
    first_match: bool = False
    hidden_by_xo: list[str] = Field(default_factory=list)

    @field_validator("blocking_actions")
    @classmethod
    def _actions_have_text(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned = [action.strip().casefold() for action in value]
        if not cleaned or "" in cleaned:
            raise ValueError("blocking_actions is a list of one or more non-empty texts")
        return sorted(set(cleaned))

    @field_validator("fields", "lists")
    @classmethod
    def _paths_are_valid(cls, value: Mapping[str, object]) -> Mapping[str, object]:
        for path in value:
            _check_segments(path, wildcards=False)
        return value

    @field_validator("hidden_by_xo")
    @classmethod
    def _hidden_paths_are_valid(cls, value: list[str]) -> list[str]:
        for path in value:
            _check_segments(path, wildcards=False)
        if len(set(value)) != len(value):
            raise ValueError("hidden_by_xo names a path twice")
        return value

    @model_validator(mode="after")
    def _is_consistent(self) -> Self:
        if self.floor is not None and self.floors:
            raise ValueError("use floor or floors, not both")
        if self.collection is CollectionMode.ORDERED_KEYED and self.key_field is None:
            raise ValueError("an ordered-keyed collection needs a key_field")
        if self.first_match and self.collection is not CollectionMode.ORDERED_KEYED:
            raise ValueError("first_match needs a collection of the mode ordered-keyed")
        if self.action_field is None:
            if self.blocking_actions is not None:
                raise ValueError("blocking_actions needs an action_field")
            if self.first_match or any(spec.first_match for spec in self.lists.values()):
                raise ValueError("first_match needs an action_field")
            return self
        action = self.action_field
        shown = [action] if self.first_match else []
        shown.extend(f"{path}.{action}" for path, spec in self.lists.items() if spec.first_match)
        for path in shown:
            if self.fields.get(path) is not FieldClass.CONFIG:
                raise ValueError(f"the action field {path!r} must have the class config")
        return self

    def effective_blocking_actions(self) -> frozenset[str]:
        """The actions that stop traffic or access: the declared ones, else deny and drop."""
        if self.action_field is None:
            return frozenset()
        if self.blocking_actions is None:
            return frozenset(DEFAULT_BLOCKING_ACTIONS)
        return frozenset(self.blocking_actions)

    def effective_floors(self) -> dict[str, Severity]:
        """The floor of each kind of change: ``floor`` applies to all four kinds."""
        floor = self.floor
        if floor is not None:
            return dict.fromkeys(FLOOR_KINDS, floor)
        return {str(kind): severity for kind, severity in self.floors.items()}

    def to_table(self) -> ResourceTable:
        """The table the normaliser, the diff and the order check read."""
        ordered = frozenset(path for path, spec in self.lists.items() if spec.first_match)
        return ResourceTable(
            object_key_field=self.key_field,
            name_field=self.name_field,
            field_classes=dict(self.fields),
            collection_modes={path: spec.mode for path, spec in self.lists.items()},
            item_key_fields={
                path: spec.key_field for path, spec in self.lists.items() if spec.key_field
            },
            resource=self.resource,
            collection=self.collection,
            floors=self.effective_floors(),
            action_field=self.action_field,
            blocking_actions=self.effective_blocking_actions(),
            first_match=self.first_match,
            first_match_lists=ordered,
            hidden_by_xo=frozenset(self.hidden_by_xo),
        )


class PackFile(BaseModel):
    """A file of ``rules/packs/*``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    rules: list[Rule]


class TypeFile(BaseModel):
    """A file of ``rules/types``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    types: list[TypeSpec]
