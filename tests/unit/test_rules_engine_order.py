"""Moves through the whole chain: manifests, ``core/order.py`` and the rule engine.

The order detail carries the actions of the moved entry and of the entries it passed; the engine
turns them into a severity. The type tables are synthetic and are loaded from files in the shipped
format, so the engine reads the floors and the blocking actions from them.
"""

import json
from collections.abc import Mapping

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, StateLookup, compare
from driftsniff.core.normalize import (
    NORMALISER_VERSION,
    CollectionMode,
    FieldClass,
    StaticTypeTable,
    TypeTable,
)
from driftsniff.core.order import compare_order
from driftsniff.core.snapshots import CollectedObject, CollectedResource, Manifest, build_manifest
from driftsniff.rules.engine import MOVE_BLOCKING_RULE_ID, RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.fingerprint import Fingerprinter

FINGERPRINTER = Fingerprinter(bytes(range(32)), "0a1b2c3d")
START = "2026-10-21T10:00:00Z"
END = "2026-10-21T10:05:00Z"

TYPES = """\
version: 1
types:
  - resource: policies
    collection: ordered-keyed
    key_field: _id
    name_field: name
    action_field: action
    first_match: true
    floors: {added: high, removed: critical, modified: high, moved: high}
    fields: {_id: config, name: config, action: config}
  - resource: gateways
    key_field: _id
    name_field: name
    action_field: action
    floor: high
    fields: {_id: config, name: config, rules: config, rules.id: config, rules.action: config}
    lists:
      rules: {mode: ordered-keyed, key_field: id, first_match: true}
"""

type Tables = Mapping[str, TypeTable]

CONFIG = FieldClass.CONFIG
POLICY = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={"_id": CONFIG, "name": CONFIG, "action": CONFIG},
    action_field="action",
)
GATEWAY = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": CONFIG,
        "name": CONFIG,
        "rules": CONFIG,
        "rules.id": CONFIG,
        "rules.action": CONFIG,
    },
    collection_modes={"rules": CollectionMode.ORDERED_KEYED},
    item_key_fields={"rules": "id"},
    action_field="action",
)


def obj(key: str, /, **fields: JsonValue) -> CollectedObject:
    state: dict[str, JsonValue] = {"_id": key, "name": f"n {key}", **fields}
    return CollectedObject(key, state, f"n {key}")


def build(resources: Mapping[str, list[CollectedObject]], *, ordered: tuple[str, ...]) -> Manifest:
    collected = {
        name: CollectedResource(objects, ordered=name in ordered)
        for name, objects in resources.items()
    }
    return build_manifest(
        collected, controller_version="1.0", normaliser_version=NORMALISER_VERSION
    )


def policies(*entries: tuple[str, str], ordered: bool = True) -> Manifest:
    objects = [obj(key, action=action) for key, action in entries]
    return build({"policies": objects}, ordered=("policies",) if ordered else ())


def gateway(*entries: tuple[str, str]) -> Manifest:
    members: list[JsonValue] = [{"id": key, "action": action} for key, action in entries]
    return build({"gateways": [obj("g1", rules=members)]}, ordered=())


def lookup_for(*manifests: Manifest) -> StateLookup:
    pending: dict[str, bytes] = {}
    for manifest in manifests:
        pending.update(manifest.pending_states)

    def lookup(state_hash: str) -> Mapping[str, JsonValue]:
        loaded = json.loads(pending[state_hash])
        assert isinstance(loaded, dict)
        return loaded

    return lookup


def moves(previous: Manifest, new: Manifest, tables: Tables) -> list[ChangeItem]:
    return compare_order(
        previous,
        new,
        lookup_for(previous, new),
        window_start=START,
        window_end=END,
        type_tables=tables,
    )


def changes(previous: Manifest, new: Manifest, tables: Tables) -> list[ChangeItem]:
    return compare(
        previous,
        new,
        lookup_for(previous, new),
        window_start=START,
        window_end=END,
        fingerprinter=FINGERPRINTER,
        type_tables=tables,
    )


def only(items: list[ChangeItem]) -> ChangeItem:
    assert len(items) == 1, items
    return items[0]


def detail(item: ChangeItem) -> Mapping[str, JsonValue]:
    assert item.order_detail is not None
    return item.order_detail


TABLES: Tables = {"policies": POLICY, "gateways": GATEWAY}


# ---- the order detail ------------------------------------------------------------------------


def test_a_moved_object_lists_its_action_and_the_actions_it_passed() -> None:
    previous = policies(("p1", "allow"), ("p2", "deny"), ("p3", "allow"))
    new = policies(("p3", "allow"), ("p1", "allow"), ("p2", "deny"))
    item = only(moves(previous, new, TABLES))
    assert item.object_key == "p3"
    assert detail(item)["moved_actions"] == ["allow"]
    assert detail(item)["jumped_actions"] == ["allow", "deny"]
    assert detail(item)["jumped_count"] == 2
    assert detail(item)["summary"] == "p3 moved from after p2 to before p1"


def test_only_the_entries_that_changed_sides_are_passed() -> None:
    previous = policies(("a", "allow"), ("b", "allow"), ("c", "deny"))
    new = policies(("b", "allow"), ("a", "allow"), ("c", "deny"))
    item = only(moves(previous, new, TABLES))
    assert item.object_key == "b"
    assert detail(item)["jumped_actions"] == ["allow"]
    assert detail(item)["jumped_count"] == 1


def test_the_action_before_and_after_a_change_of_the_action_are_both_listed() -> None:
    previous = policies(("p1", "allow"), ("p2", "deny"))
    new = policies(("p2", "allow"), ("p1", "allow"))
    item = only(moves(previous, new, TABLES))
    assert item.object_key == "p2"
    assert detail(item)["moved_actions"] == ["allow", "deny"]


def test_an_entry_without_a_text_action_has_none() -> None:
    previous = build({"policies": [obj("p1", action=5), obj("p2")]}, ordered=("policies",))
    new = build({"policies": [obj("p2"), obj("p1", action=5)]}, ordered=("policies",))
    item = only(moves(previous, new, TABLES))
    assert detail(item)["moved_actions"] == []
    assert detail(item)["jumped_actions"] == []
    assert detail(item)["jumped_count"] == 1


@pytest.mark.parametrize(
    "field_class", [FieldClass.SECRET, FieldClass.IGNORE, FieldClass.UNCLASSIFIED]
)
def test_an_action_field_that_is_not_config_is_not_read(field_class: FieldClass) -> None:
    table = StaticTypeTable(
        object_key_field="_id",
        field_classes={"_id": CONFIG, "action": field_class},
        action_field="action",
    )
    previous = policies(("p1", "allow"), ("p2", "deny"))
    new = policies(("p2", "deny"), ("p1", "allow"))
    item = only(moves(previous, new, {"policies": table}))
    assert "moved_actions" not in detail(item)
    assert "jumped_count" not in detail(item)


def test_a_table_without_an_action_field_gets_no_actions() -> None:
    table = StaticTypeTable(object_key_field="_id", field_classes={"action": CONFIG})
    previous = policies(("p1", "allow"), ("p2", "deny"))
    new = policies(("p2", "deny"), ("p1", "allow"))
    item = only(moves(previous, new, {"policies": table}))
    plain = {"key", "from_after", "from_before", "to_after", "to_before", "summary"}
    assert set(detail(item)) == plain


def test_a_move_inside_an_object_lists_the_actions_of_the_members() -> None:
    previous = gateway(("r1", "allow"), ("r2", "deny"), ("r3", "allow"))
    new = gateway(("r3", "allow"), ("r1", "allow"), ("r2", "deny"))
    item = only(moves(previous, new, TABLES))
    assert (item.object_key, item.path, detail(item)["key"]) == ("g1", "rules", "r3")
    assert detail(item)["moved_actions"] == ["allow"]
    assert detail(item)["jumped_actions"] == ["allow", "deny"]
    assert detail(item)["jumped_count"] == 2


def test_a_list_member_action_that_is_not_config_is_not_read() -> None:
    classes = {
        "_id": CONFIG,
        "rules": CONFIG,
        "rules.id": CONFIG,
        "rules.action": FieldClass.SECRET,
    }
    table = StaticTypeTable(
        object_key_field="_id",
        field_classes=classes,
        collection_modes={"rules": CollectionMode.ORDERED_KEYED},
        item_key_fields={"rules": "id"},
        action_field="action",
    )
    previous = gateway(("r1", "allow"), ("r2", "deny"))
    new = gateway(("r2", "deny"), ("r1", "allow"))
    item = only(moves(previous, new, {"gateways": table}))
    assert "moved_actions" not in detail(item)


def test_members_without_a_key_still_carry_their_action() -> None:
    table = StaticTypeTable(
        object_key_field="_id",
        field_classes={"_id": CONFIG, "rules": CONFIG, "rules.action": CONFIG},
        collection_modes={"rules": CollectionMode.ORDERED_KEYED},
        action_field="action",
    )
    first: list[JsonValue] = [{"action": "allow", "port": 1}, {"action": "deny", "port": 2}]
    second: list[JsonValue] = [first[1], first[0]]
    previous = build({"gateways": [obj("g1", rules=first)]}, ordered=())
    new = build({"gateways": [obj("g1", rules=second)]}, ordered=())
    item = only(moves(previous, new, {"gateways": table}))
    assert str(detail(item)["key"]).startswith("member:")
    assert detail(item)["moved_actions"] == ["deny"]
    assert detail(item)["jumped_actions"] == ["allow"]


# ---- through the engine ----------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory) -> RuleEngine:
    root = tmp_path_factory.mktemp("rules")
    (root / "types").mkdir()
    (root / "types" / "synthetic.yaml").write_text(TYPES, encoding="utf-8")
    return RuleEngine(load_rules(root))


def tables_of(engine: RuleEngine) -> Tables:
    return engine.index.type_tables


def severities(engine: RuleEngine, items: list[ChangeItem]) -> list[str]:
    return [engine.classify(item).severity for item in items]


def test_a_rule_inserted_at_the_top_of_a_firewall_list_is_high(engine: RuleEngine) -> None:
    tables = tables_of(engine)
    previous = policies(("p1", "allow"), ("p2", "deny"))
    new = policies(("p0", "allow"), ("p1", "allow"), ("p2", "deny"))
    assert moves(previous, new, tables) == []
    item = only(changes(previous, new, tables))
    assert (item.change_kind, item.object_key) == ("added", "p0")
    assert engine.classify(item).severity == "high"


def test_a_rule_moved_above_a_deny_rule_is_critical(engine: RuleEngine) -> None:
    tables = tables_of(engine)
    previous = policies(("p1", "allow"), ("p2", "deny"), ("p3", "allow"))
    new = policies(("p1", "allow"), ("p3", "allow"), ("p2", "deny"))
    item = only(moves(previous, new, tables))
    result = engine.classify(item)
    assert (item.object_key, result.severity, result.rule_id) == (
        "p3",
        "critical",
        MOVE_BLOCKING_RULE_ID,
    )


def test_a_deny_rule_that_moves_is_critical(engine: RuleEngine) -> None:
    tables = tables_of(engine)
    previous = policies(("p1", "allow"), ("p2", "allow"), ("p3", "drop"))
    new = policies(("p3", "drop"), ("p1", "allow"), ("p2", "allow"))
    assert severities(engine, moves(previous, new, tables)) == ["critical"]


def test_a_rule_moved_among_allow_rules_is_high(engine: RuleEngine) -> None:
    tables = tables_of(engine)
    previous = policies(("p1", "allow"), ("p2", "allow"), ("p3", "allow"))
    new = policies(("p3", "allow"), ("p1", "allow"), ("p2", "allow"))
    assert severities(engine, moves(previous, new, tables)) == ["high"]


def test_a_reordered_set_produces_no_item(engine: RuleEngine) -> None:
    tables = tables_of(engine)
    previous = policies(("p1", "allow"), ("p2", "deny"), ordered=False)
    new = policies(("p2", "deny"), ("p1", "allow"), ordered=False)
    assert moves(previous, new, tables) == []
    assert changes(previous, new, tables) == []


def test_removing_a_firewall_rule_is_critical(engine: RuleEngine) -> None:
    tables = tables_of(engine)
    previous = policies(("p1", "allow"), ("p2", "deny"))
    new = policies(("p1", "allow"))
    item = only(changes(previous, new, tables))
    assert (item.change_kind, item.object_key) == ("removed", "p2")
    assert engine.classify(item).severity == "critical"


def test_a_move_inside_an_object_is_read_with_the_member_actions(engine: RuleEngine) -> None:
    tables = tables_of(engine)
    previous = gateway(("r1", "allow"), ("r2", "deny"), ("r3", "allow"))
    across = gateway(("r1", "allow"), ("r3", "allow"), ("r2", "deny"))
    assert severities(engine, moves(previous, across, tables)) == ["critical"]
    assert moves(previous, previous, tables) == []
    plain_before = gateway(("r1", "allow"), ("r2", "allow"))
    plain_after = gateway(("r2", "allow"), ("r1", "allow"))
    assert severities(engine, moves(plain_before, plain_after, tables)) == ["high"]
