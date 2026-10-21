"""Load the rule packs and the type tables, check them and build the index the engine reads.

Layout under the rules root (by default the ``driftsniff.rules`` package folder)::

    packs/unifi/*.yaml     rule packs of the UniFi collector
    packs/xo/*.yaml        rule packs of the Xen Orchestra collector
    types/*.yaml           type tables, one entry per resource

:func:`load_rules` reads every such file, validates it and returns a :class:`RuleIndex`. Anything
wrong stops the load with a :class:`RuleLoadError` that names the file and the line; nothing is
skipped or repaired. Besides the schema (``rules/schema.py``) the load refuses:

- a duplicate rule id, or a duplicate resource in the type tables;
- a rule for a resource that has no type table;
- a tie (:class:`RuleTieError`): two rules of one resource that can apply to the same field and
  have the same specificity, unless their predicates provably exclude each other
  (``predicates.mutually_exclusive``). A tie is never broken silently.

The rule pack version is the first 12 hex characters of one SHA-256 over every file read, in the
order of their paths relative to the root; for each file the hash takes the relative path in
UTF-8, a zero byte, the bytes of the file and a zero byte. It changes when any pack or type file
changes, and it is meant to be stored with each change event (``change_events.rule_pack_version``).
"""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations
from pathlib import Path
from typing import Final

import yaml
from pydantic import BaseModel, ValidationError

from driftsniff.rules.predicates import Predicate, build_predicate, mutually_exclusive
from driftsniff.rules.schema import (
    PackFile,
    ResourceTable,
    Rule,
    TypeFile,
    normalize_path,
    path_matches,
    paths_overlap,
)

DEFAULT_ROOT: Final = Path(__file__).resolve().parent
PACK_DIRECTORIES: Final = ("packs/unifi", "packs/xo")
TYPES_DIRECTORY: Final = "types"
MAX_FILE_BYTES: Final = 1_000_000
MAX_NODES: Final = 100_000
MAX_DEPTH: Final = 32
VERSION_LENGTH: Final = 12


class RuleLoadError(Exception):
    """A rule or type file is not valid. ``file`` and ``line`` (1 based, or None) say where."""

    def __init__(self, file: Path, line: int | None, message: str) -> None:
        self.file = file
        self.line = line
        self.message = message
        location = str(file) if line is None else f"{file}:{line}"
        super().__init__(f"{location}: {message}")


class RuleTieError(RuleLoadError):
    """Two rules can apply to the same change and have the same specificity."""

    def __init__(self, file: Path, line: int, first_id: str, second_id: str, message: str) -> None:
        self.first_id = first_id
        self.second_id = second_id
        super().__init__(file, line, message)


@dataclass(frozen=True)
class CompiledRule:
    """A rule with its predicate built, and where it was read from (``source`` is relative)."""

    rule: Rule
    predicate: Predicate | None
    specificity: int
    source: str
    line: int


@dataclass(frozen=True)
class RuleIndex:
    """Everything loaded: the rules by resource, the type tables and the rule pack version."""

    pack_version: str
    rules: tuple[CompiledRule, ...]
    by_resource: Mapping[str, tuple[CompiledRule, ...]]
    type_tables: Mapping[str, ResourceTable]

    def candidates(self, resource: str, path: str) -> tuple[CompiledRule, ...]:
        """The rules whose resource and path match, most specific first.

        The predicate of a rule is not evaluated here: the engine takes the first candidate
        whose predicate is true, or that has none.
        """
        segments = normalize_path(path)
        return tuple(
            compiled
            for compiled in self.by_resource.get(resource, ())
            if path_matches(compiled.rule.segments, segments)
        )


class _Map(dict[str, object]):
    """A YAML mapping that remembers its own line and the line of each key (1 based)."""

    def __init__(self, line: int) -> None:
        super().__init__()
        self.line = line
        self.key_lines: dict[str, int] = {}


class _Seq(list[object]):
    """A YAML sequence that remembers its line (1 based)."""

    def __init__(self, line: int) -> None:
        super().__init__()
        self.line = line


def _line(node: yaml.Node) -> int:
    return int(node.start_mark.line) + 1


class _Reader:
    """Turns a composed YAML tree into plain values, keeping the line of every mapping key.

    Only text, numbers, booleans and null are accepted as scalars, a key must be text and appear
    once, and the size and the depth are bounded, so an alias cannot expand into a huge value.
    """

    def __init__(self, loader: yaml.SafeLoader, path: Path) -> None:
        self._loader = loader
        self._path = path
        self._nodes = 0

    def error(self, node: yaml.Node, message: str) -> RuleLoadError:
        return RuleLoadError(self._path, _line(node), message)

    def convert(self, node: yaml.Node, depth: int) -> object:
        self._nodes += 1
        if self._nodes > MAX_NODES or depth > MAX_DEPTH:
            raise self.error(node, "the file is too large or nested too deeply")
        if isinstance(node, yaml.MappingNode):
            mapping = _Map(_line(node))
            for key_node, value_node in node.value:
                key = self.convert(key_node, depth + 1)
                if not isinstance(key, str):
                    raise self.error(key_node, "a key must be text")
                if key in mapping:
                    raise self.error(key_node, f"the key {key!r} appears twice")
                mapping.key_lines[key] = _line(key_node)
                mapping[key] = self.convert(value_node, depth + 1)
            return mapping
        if isinstance(node, yaml.SequenceNode):
            sequence = _Seq(_line(node))
            for child in node.value:
                sequence.append(self.convert(child, depth + 1))
            return sequence
        value: object = self._loader.construct_object(node, deep=True)
        if value is None or isinstance(value, str | int | float | bool):
            return value
        raise self.error(node, f"a value of type {type(value).__name__} is not allowed here")


def _yaml_line(error: yaml.YAMLError) -> int | None:
    mark = getattr(error, "problem_mark", None)
    return None if mark is None else int(mark.line) + 1


def _yaml_message(error: yaml.YAMLError) -> str:
    problem = getattr(error, "problem", None)
    return f"not valid YAML: {problem}" if problem else "not valid YAML"


def _parse(path: Path, data: bytes) -> object:
    """The content of one file as plain values (``_Map`` and ``_Seq`` carry the lines)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RuleLoadError(path, None, "the file is not valid UTF-8") from None
    try:
        loader = yaml.SafeLoader(text)
    except yaml.YAMLError as error:
        raise RuleLoadError(path, _yaml_line(error), _yaml_message(error)) from None
    try:
        node = loader.get_single_node()
        if node is None:
            raise RuleLoadError(path, None, "the file is empty")
        return _Reader(loader, path).convert(node, 0)
    except yaml.YAMLError as error:
        raise RuleLoadError(path, _yaml_line(error), _yaml_message(error)) from None
    except RecursionError:
        raise RuleLoadError(path, None, "the file is nested too deeply") from None
    finally:
        loader.dispose()


def _locate(document: object, location: tuple[int | str, ...]) -> int | None:
    """The line of the value at ``location``, or of the closest enclosing mapping or key."""
    line: int | None = getattr(document, "line", None)
    node: object = document
    for step in location:
        if isinstance(node, _Map) and isinstance(step, str):
            line = node.key_lines.get(step, line)
            node = node.get(step)
        elif isinstance(node, _Seq) and isinstance(step, int) and 0 <= step < len(node):
            node = node[step]
            if isinstance(node, _Map | _Seq):
                line = node.line
        else:
            break
    return line


def _validate[Model: BaseModel](model: type[Model], document: object, path: Path) -> Model:
    try:
        return model.model_validate(document)
    except ValidationError as error:
        problems = error.errors(include_url=False)
        first = problems[0]
        where = ".".join(str(part) for part in first["loc"])
        message = str(first["msg"]).removeprefix("Value error, ")
        text = f"{where}: {message}" if where else message
        if len(problems) > 1:
            text += f" (and {len(problems) - 1} more)"
        raise RuleLoadError(path, _locate(document, first["loc"]), text) from None


def _entry_lines(document: object, key: str) -> list[int]:
    """The line of each entry of the list ``key`` of a file that has been validated."""
    entries = document.get(key) if isinstance(document, _Map) else None
    if not isinstance(entries, _Seq):
        return []
    return [entry.line if isinstance(entry, _Map) else 0 for entry in entries]


def _discover(root: Path) -> list[tuple[str, Path]]:
    """The pack and type files under ``root`` as (path relative to root, path), sorted."""
    found: list[tuple[str, Path]] = []
    for directory in (*PACK_DIRECTORIES, TYPES_DIRECTORY):
        folder = root / directory
        if folder.is_dir():
            found.extend((f"{directory}/{entry.name}", entry) for entry in folder.glob("*.yaml"))
    return sorted((relative, path) for relative, path in found if path.is_file())


def _read(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise RuleLoadError(path, None, f"cannot read the file: {error.strerror}") from None
    if len(data) > MAX_FILE_BYTES:
        raise RuleLoadError(path, None, f"the file is larger than {MAX_FILE_BYTES} bytes")
    return data


def _version(files: list[tuple[str, bytes]]) -> str:
    digest = sha256()
    for relative, data in files:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()[:VERSION_LENGTH]


def compute_pack_version(root: Path | None = None) -> str:
    """The rule pack version of the files under ``root``: 12 lower case hex characters."""
    base = DEFAULT_ROOT if root is None else root
    return _version([(relative, _read(path)) for relative, path in _discover(base)])


def _check_ties(rules: list[CompiledRule], base: Path) -> None:
    by_resource: dict[str, list[CompiledRule]] = {}
    for compiled in rules:
        by_resource.setdefault(compiled.rule.resource, []).append(compiled)
    for group in by_resource.values():
        for first, second in combinations(group, 2):
            if first.specificity != second.specificity:
                continue
            if not paths_overlap(first.rule.segments, second.rule.segments):
                continue
            if mutually_exclusive(first.predicate, second.predicate):
                continue
            message = (
                f"rule {second.rule.id!r} ties with rule {first.rule.id!r} "
                f"({first.source}:{first.line}): both apply to the resource "
                f"{first.rule.resource!r} with specificity {first.specificity}; "
                "make one of them more specific"
            )
            raise RuleTieError(
                base / second.source, second.line, first.rule.id, second.rule.id, message
            )


def _load_types(files: list[tuple[str, Path, bytes]]) -> dict[str, ResourceTable]:
    tables: dict[str, ResourceTable] = {}
    origins: dict[str, str] = {}
    for relative, path, data in files:
        document = _parse(path, data)
        type_file = _validate(TypeFile, document, path)
        for spec, line in zip(type_file.types, _entry_lines(document, "types"), strict=True):
            if spec.resource in tables:
                first = origins[spec.resource]
                message = f"the resource {spec.resource!r} is already defined at {first}"
                raise RuleLoadError(path, line, message)
            tables[spec.resource] = spec.to_table()
            origins[spec.resource] = f"{relative}:{line}"
    return tables


def _load_rules(
    files: list[tuple[str, Path, bytes]], tables: Mapping[str, ResourceTable]
) -> list[CompiledRule]:
    compiled: list[CompiledRule] = []
    origins: dict[str, str] = {}
    for relative, path, data in files:
        document = _parse(path, data)
        pack = _validate(PackFile, document, path)
        for rule, line in zip(pack.rules, _entry_lines(document, "rules"), strict=True):
            if rule.id in origins:
                message = f"the rule id {rule.id!r} is already used at {origins[rule.id]}"
                raise RuleLoadError(path, line, message)
            if rule.resource not in tables:
                message = (
                    f"rule {rule.id!r} is for the resource {rule.resource!r}, "
                    "which has no type table"
                )
                raise RuleLoadError(path, line, message)
            origins[rule.id] = f"{relative}:{line}"
            when = rule.when
            predicate = None if when is None else build_predicate(when.name, when.args)
            compiled.append(CompiledRule(rule, predicate, rule.specificity, relative, line))
    return compiled


def load_rules(root: Path | None = None) -> RuleIndex:
    """Load, validate and index the packs and the type tables under ``root``.

    Raises :class:`RuleLoadError` (or :class:`RuleTieError`) for the first problem found. A root
    without any file gives an empty index.
    """
    base = DEFAULT_ROOT if root is None else root
    files = [(relative, path, _read(path)) for relative, path in _discover(base)]
    version = _version([(relative, data) for relative, _, data in files])
    type_files = [entry for entry in files if entry[0].startswith(f"{TYPES_DIRECTORY}/")]
    pack_files = [entry for entry in files if not entry[0].startswith(f"{TYPES_DIRECTORY}/")]
    tables = _load_types(type_files)
    compiled = _load_rules(pack_files, tables)
    _check_ties(compiled, base)
    ordered: dict[str, list[CompiledRule]] = {}
    for item in sorted(compiled, key=lambda entry: (-entry.specificity, entry.rule.id)):
        ordered.setdefault(item.rule.resource, []).append(item)
    return RuleIndex(
        pack_version=version,
        rules=tuple(compiled),
        by_resource={resource: tuple(items) for resource, items in ordered.items()},
        type_tables=tables,
    )
