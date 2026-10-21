"""Check that every field a type table names has a class (P5-T4).

A type table says, for each resource, which fields are config, secret, ignore or unclassified.
The loader already requires a class for every entry under ``fields``. This check closes the other
gap: a table that *names* a field somewhere else and forgets to classify it. That field would be
unclassified, so a secret there would be compared as a fingerprint only by luck and a volatile
value there would raise changes nobody can explain. It fails when, in a shipped type table:

- the ``key_field``, the ``name_field`` or the ``action_field`` has no class of its own;
- a list under ``lists`` has no class, neither for the list path itself nor for any field below it
  (``certificates`` is covered by ``certificates.notAfter``);
- the member key of a keyed list (``lists.<path>.key_field``) has no class (``<path>.<key>``);
- a resource has no field with a class at all.

Usage: PYTHONPATH=src python scripts/check_type_coverage.py [RULES_ROOT ...]
The default root is the shipped ``driftsniff.rules`` package folder. A root holds ``types/*.yaml``
in the shipped format, so the test-only tables of ``tests/golden`` can be checked the same way.
Exit code 0 when every named field has a class, 1 otherwise.
"""

import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol


class TableLike(Protocol):
    """The part of a loaded type table this check reads."""

    @property
    def object_key_field(self) -> str | None: ...

    @property
    def name_field(self) -> str | None: ...

    @property
    def action_field(self) -> str | None: ...

    @property
    def field_classes(self) -> Mapping[str, object]: ...

    @property
    def collection_modes(self) -> Mapping[str, object]: ...

    @property
    def item_key_fields(self) -> Mapping[str, str]: ...


def _has_class(classified: frozenset[str], path: str) -> bool:
    """Whether ``path`` is classified itself or holds a classified field below it."""
    prefix = f"{path}."
    return path in classified or any(entry.startswith(prefix) for entry in classified)


def uncovered(tables: Mapping[str, TableLike]) -> list[str]:
    """One problem text per field that a table names and does not classify, in a stable order."""
    problems: list[str] = []
    for resource in sorted(tables):
        table = tables[resource]
        classified = frozenset(table.field_classes)
        if not classified:
            problems.append(f"{resource}: no field has a class")
            continue
        named = (
            ("key_field", table.object_key_field),
            ("name_field", table.name_field),
            ("action_field", table.action_field),
        )
        for role, path in named:
            if path is not None and path not in classified:
                problems.append(f"{resource}: {role} {path!r} has no class")
        for list_path in sorted(table.collection_modes):
            if not _has_class(classified, list_path):
                problems.append(f"{resource}: list {list_path!r} has no class")
        for list_path, key in sorted(table.item_key_fields.items()):
            member = f"{list_path}.{key}"
            if member not in classified:
                problems.append(f"{resource}: member key {member!r} of a list has no class")
    return problems


def check_root(root: Path | None) -> tuple[int, list[str]]:
    """Load the type tables under ``root`` (default: shipped) and return (count, problems)."""
    # Imported here so that ``uncovered`` can be used without the pydantic based loader.
    from driftsniff.rules.loader import RuleLoadError, load_rules

    try:
        tables = load_rules(root).type_tables
    except RuleLoadError as error:
        return 0, [f"cannot load the rules: {error}"]
    if not tables:
        return 0, ["no type tables found"]
    return len(tables), uncovered(tables)


def main(argv: Sequence[str] | None = None) -> int:
    """Check each root; return 0 when every named field has a class, 1 otherwise."""
    args = list(sys.argv[1:] if argv is None else argv)
    roots: list[Path | None] = [Path(arg) for arg in args] or [None]
    failed = False
    for root in roots:
        label = "shipped rules" if root is None else str(root)
        count, problems = check_root(root)
        for problem in problems:
            print(f"{label}: {problem}", file=sys.stderr)
        if problems:
            failed = True
        else:
            print(f"{label}: {count} type tables, every named field has a class")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
