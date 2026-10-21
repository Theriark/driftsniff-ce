"""The golden table of the rule engine: 23 realistic changes and their expected severity (P5-T4).

Section 15 of the Dev work plan lists the rows. Each row builds two collections of one resource,
runs the real chain (``compare``, ``compare_order``, the rule engine) against the test-only type
tables and packs in this folder, and checks the single item that comes out: its severity, that
its rule id belongs to the expected rule family, that its rationale is not empty, and for the two
secret rows that only fingerprints are stored or shown. A row whose expected severity is None
must produce no item at all.

Rows 1 to 9 are the false positive controls, 10 to 16 the false negative controls, 17 to 19 the
right-by-luck controls and 21 and 22 the precedence and order controls. Field names of the UniFi
rows are illustrative until P7-T1 maps them to the vendor reference.
"""

from dataclasses import dataclass

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind, Severity
from driftsniff.rules.engine import UNCLASSIFIED_RULE_ID

from .support import State, detect, golden_engine, state

CANARY_OLD = "CANARY-golden-secret-old"
CANARY_NEW = "CANARY-golden-secret-new"


@dataclass(frozen=True)
class Row:
    """One row of the golden table. ``family`` is the rule id, or its prefix, that must decide."""

    number: str
    resource: str
    path: str
    change: str
    severity: Severity | None
    family: str
    before: tuple[State, ...]
    after: tuple[State, ...]
    kind: ChangeKind | None = None
    ordered: bool = False
    secret: bool = False


def _one(**fields: JsonValue) -> tuple[State, ...]:
    return (state(**fields),)


def _policies(*entries: tuple[str, str]) -> tuple[State, ...]:
    return tuple(state(id=key, name=f"policy {key}", action=action) for key, action in entries)


ROWS: tuple[Row, ...] = (
    Row(
        "1",
        "networks",
        "name_label",
        "rename",
        "low",
        "golden.generic_name",
        _one(id="n1", name_label="lab-net"),
        _one(id="n1", name_label="lab-net-renamed"),
        "modified",
    ),
    Row(
        "2",
        "vifs",
        "rateLimit",
        "value changed",
        "medium",
        "golden.network_limits",
        _one(id="f1", rateLimit=1000),
        _one(id="f1", rateLimit=500),
        "modified",
    ),
    Row(
        "3",
        "unifi-networks",
        "name",
        "rename",
        "low",
        "golden.generic_name",
        _one(id="u1", name="Guest"),
        _one(id="u1", name="Guest access"),
        "modified",
    ),
    Row(
        "4",
        "vms",
        "memory.usage",
        "value changed (ignore class)",
        None,
        "",
        _one(id="v1", name_label="vm1", memory={"usage": 1024}),
        _one(id="v1", name_label="vm1", memory={"usage": 2048}),
    ),
    Row(
        "5",
        "unifi-devices",
        "radio.channel",
        "auto channel moved (ignore class)",
        None,
        "",
        _one(id="d1", name="ap-1", radio={"channel": 36}),
        _one(id="d1", name="ap-1", radio={"channel": 40}),
    ),
    Row(
        "6",
        "backup-jobs",
        "settings.reportRecipients",
        "list changed",
        "medium",
        "golden.backup_reporting",
        _one(id="j1", name="nightly", settings={"reportRecipients": ["ops-a@example.test"]}),
        _one(
            id="j1",
            name="nightly",
            settings={"reportRecipients": ["ops-a@example.test", "ops-b@example.test"]},
        ),
        "added",
    ),
    Row(
        "7",
        "unifi-site-settings",
        "guest_portal.title",
        "text changed",
        "low",
        "golden.cosmetic_text",
        _one(id="s1", guest_portal={"title": "Welcome"}),
        _one(id="s1", guest_portal={"title": "Welcome to the lab"}),
        "modified",
    ),
    Row(
        "8",
        "vms",
        "docker.enabled",
        "false to true",
        "low",
        "golden.generic_enabled",
        _one(id="v1", name_label="vm1", docker={"enabled": False}),
        _one(id="v1", name_label="vm1", docker={"enabled": True}),
        "modified",
    ),
    Row(
        "9",
        "unifi-site-settings",
        "mgmt.led_enabled",
        "true to false",
        "low",
        "golden.generic_enabled",
        _one(id="s1", mgmt={"led_enabled": True}),
        _one(id="s1", mgmt={"led_enabled": False}),
        "modified",
    ),
    Row(
        "10",
        "vms",
        "secureBoot",
        "true to false",
        "high",
        "golden.boot_security",
        _one(id="v1", name_label="vm1", secureBoot=True),
        _one(id="v1", name_label="vm1", secureBoot=False),
        "modified",
    ),
    Row(
        "11",
        "users",
        "permission",
        "none to admin",
        "critical",
        "golden.privilege_escalation",
        _one(id="x1", email="user@example.test", permission="none"),
        _one(id="x1", email="user@example.test", permission="admin"),
        "modified",
    ),
    Row(
        "12",
        "servers",
        "readOnly",
        "true to false",
        "high",
        "golden.xo_server_floor",
        _one(id="p1", label="pool-a", readOnly=True),
        _one(id="p1", label="pool-a", readOnly=False),
        "modified",
    ),
    Row(
        "13",
        "backup-jobs",
        "settings.exportRetention",
        "30 to 1",
        "high",
        "golden.retention",
        _one(id="j1", name="nightly", settings={"exportRetention": 30}),
        _one(id="j1", name="nightly", settings={"exportRetention": 1}),
        "modified",
    ),
    Row(
        "14",
        "backup-repositories",
        "url",
        "target changed",
        "high",
        "golden.backup_destination",
        _one(id="r1", name="vault", url="nfs://backup-a.example.test/share"),
        _one(id="r1", name="vault", url="nfs://backup-b.example.test/share"),
        "modified",
    ),
    Row(
        "15",
        "hosts",
        "supplementalPacks",
        "set changed",
        "medium",
        "golden.patch_level",
        _one(id="h1", name_label="host-a", supplementalPacks=["pack-a"]),
        _one(id="h1", name_label="host-a", supplementalPacks=["pack-a", "pack-b"]),
        "added",
    ),
    Row(
        "16",
        "unifi-wlans",
        "security",
        "wpa family to open",
        "critical",
        "golden.wifi_security",
        _one(id="w1", name="staff", security="wpa2"),
        _one(id="w1", name="staff", security="open"),
        "modified",
    ),
    Row(
        "17",
        "unifi-wlans",
        "passphrase",
        "secret changed",
        "critical",
        "golden.wifi_secret",
        _one(id="w1", name="staff", passphrase=CANARY_OLD),
        _one(id="w1", name="staff", passphrase=CANARY_NEW),
        "modified",
        secret=True,
    ),
    Row(
        "18",
        "users",
        "pw_hash",
        "secret changed",
        "critical",
        "golden.user_secret",
        _one(id="x1", email="user@example.test", pw_hash=CANARY_OLD),
        _one(id="x1", email="user@example.test", pw_hash=CANARY_NEW),
        "modified",
        secret=True,
    ),
    Row(
        "19",
        "servers",
        "allowUnauthorized",
        "false to true",
        "critical",
        "golden.tls_verification",
        _one(id="p1", label="pool-a", allowUnauthorized=False),
        _one(id="p1", label="pool-a", allowUnauthorized=True),
        "modified",
    ),
    Row(
        "20",
        "vms",
        "notes",
        "value removed",
        "low",
        "golden.optional_text",
        _one(id="v1", name_label="vm1", notes="Owner: lab"),
        _one(id="v1", name_label="vm1"),
        "removed",
    ),
    Row(
        "20b",
        "vms",
        "notes",
        "key omitted instead of null",
        None,
        "",
        _one(id="v1", name_label="vm1", notes=None),
        _one(id="v1", name_label="vm1"),
    ),
    Row(
        "21",
        "unifi-firewall-policies",
        "",
        "policy deleted",
        "critical",
        "builtin.floor.removed",
        _policies(("p1", "allow"), ("p2", "allow")),
        _policies(("p1", "allow")),
        "removed",
        ordered=True,
    ),
    Row(
        "22",
        "unifi-firewall-policies",
        "",
        "moved above a deny policy",
        "critical",
        "builtin.move.blocking",
        _policies(("p1", "allow"), ("p2", "deny"), ("p3", "allow")),
        _policies(("p1", "allow"), ("p3", "allow"), ("p2", "deny")),
        "moved",
        ordered=True,
    ),
    Row(
        "23",
        "groups",
        "aclRoleIds",
        "set changed",
        "critical",
        "golden.permission_change",
        _one(id="g1", name="staff", aclRoleIds=["role-view"]),
        _one(id="g1", name="staff", aclRoleIds=["role-view", "role-admin"]),
        "added",
    ),
)

EXPECTED_NUMBERS = (*(str(number) for number in range(1, 21)), "20b", "21", "22", "23")


def _items(row: Row) -> list[ChangeItem]:
    return detect(row.resource, row.before, row.after, ordered=row.ordered)


def _only(items: list[ChangeItem]) -> ChangeItem:
    assert len(items) == 1, items
    return items[0]


def test_the_table_holds_the_23_rows_and_row_20b() -> None:
    assert tuple(row.number for row in ROWS) == EXPECTED_NUMBERS
    assert len(ROWS) == 24


def test_the_test_only_rules_load_without_a_tie() -> None:
    index = golden_engine().index
    assert {rule.rule.resource for rule in index.rules} >= {"vms", "users", "unifi-wlans"}
    assert len(index.pack_version) == 12


@pytest.mark.parametrize("row", ROWS, ids=[f"row-{row.number}" for row in ROWS])
def test_the_row_gets_the_expected_severity(row: Row) -> None:
    items = _items(row)
    if row.severity is None:
        assert items == [], row.change
        return
    item = _only(items)
    result = golden_engine().classify(item)
    assert (item.resource, item.path, item.change_kind) == (row.resource, row.path, row.kind)
    assert result.severity == row.severity
    assert result.rule_id == row.family or result.rule_id.startswith(f"{row.family}.")
    assert result.rationale.strip() != ""


@pytest.mark.parametrize("row", [row for row in ROWS if row.secret], ids=lambda row: row.number)
def test_a_secret_row_stores_and_shows_fingerprints_only(row: Row) -> None:
    item = _only(_items(row))
    assert item.before_value is None
    assert item.after_value is None
    assert item.before_fp is not None
    assert item.after_fp is not None
    assert item.before_fp != item.after_fp
    result = golden_engine().classify(item)
    for text in (repr(item), repr(result), str(item.order_detail)):
        assert "CANARY" not in text


def test_the_false_positive_controls_never_reach_high() -> None:
    for row in ROWS:
        if row.number not in {"1", "2", "3", "4", "5", "6", "7", "8", "9"}:
            continue
        for item in _items(row):
            assert golden_engine().classify(item).severity in {"low", "medium"}, row.number


def test_every_item_of_every_row_has_a_rule_id_and_a_rationale() -> None:
    engine = golden_engine()
    for row in ROWS:
        for item in _items(row):
            result = engine.classify(item)
            assert result.rule_id != ""
            assert result.rationale.strip() != ""
            assert result.rule_id != UNCLASSIFIED_RULE_ID, row.number


# ---- near misses: the same field, a change the rule must not take for the dangerous one -------


def _classify_one(resource: str, before: State, after: State) -> tuple[str, str]:
    result = golden_engine().classify(_only(detect(resource, [before], [after])))
    return result.severity, result.rule_id


def test_secure_boot_switched_on_is_not_high() -> None:
    before = state(id="v1", name_label="vm1", secureBoot=False)
    after = state(id="v1", name_label="vm1", secureBoot=True)
    assert _classify_one("vms", before, after) == ("medium", UNCLASSIFIED_RULE_ID)


def test_a_permission_that_does_not_reach_admin_is_high_by_the_floor_not_critical() -> None:
    before = state(id="x1", email="user@example.test", permission="none")
    after = state(id="x1", email="user@example.test", permission="user")
    assert _classify_one("users", before, after) == ("high", "builtin.floor.modified")


def test_a_retention_that_stays_above_one_is_medium() -> None:
    before = state(id="j1", name="nightly", settings={"exportRetention": 30})
    after = state(id="j1", name="nightly", settings={"exportRetention": 20})
    assert _classify_one("backup-jobs", before, after) == (
        "medium",
        "golden.retention_changed.xo_backup_jobs",
    )


def test_a_wifi_change_between_two_secure_modes_is_not_critical() -> None:
    before = state(id="w1", name="staff", security="wpa2")
    after = state(id="w1", name="staff", security="wpa3")
    assert _classify_one("unifi-wlans", before, after) == ("high", "builtin.floor.modified")


def test_a_server_that_becomes_read_only_is_high_only_by_the_floor() -> None:
    before = state(id="p1", label="pool-a", readOnly=False)
    after = state(id="p1", label="pool-a", readOnly=True)
    assert _classify_one("servers", before, after) == ("high", "builtin.floor.modified")
