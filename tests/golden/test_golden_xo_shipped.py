"""The Xen Orchestra rows of the golden table against the shipped pack and type tables (P8-T3).

``test_golden_table.py`` runs all 23 rows against test-only tables. Here the rows whose resource is
a Xen Orchestra resource run again, against ``rules/types/xo.yaml`` and ``rules/packs/xo`` as the
application loads them: rows 1, 2, 4, 6, 8, 10 to 15, 18 to 20 (with 20b) and 23.

Two rows name a field that the shipped table does not keep, so a test below pins that fact instead
of running them as written (the way ``test_golden_unifi_shipped.py`` does for rows 7 and 9):

* row 8 (``docker.enabled``): the plan puts ``docker`` in the ignore class, so the shipped table
  reports no change where the test-only table reports a low one;
* row 18 (``pw_hash``): no password hash is collected. The shipped secret field is
  ``authProviders``; it is run in its place, and its severity is the shipped rule's (high), not the
  critical of the test-only row. That difference is reported to Delivery as an open decision.

Every field name is unverified (no lab Xen Orchestra, docs/vendor-notes/xo.md). The secret values
start with ``CANARY-``.
"""

from functools import cache

import pytest

from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind, Severity
from driftsniff.core.normalize import FieldClass, normalize_object
from driftsniff.rules.engine import UNCLASSIFIED_RULE_ID, RuleEngine
from driftsniff.rules.loader import load_rules

from .support import State, detect, state

CANARY_OLD = "CANARY-shipped-xo-old"
CANARY_NEW = "CANARY-shipped-xo-new"
SHIPPED_ROWS = ("1", "2", "4", "6", "8", "10", "11", "12", "13", "14", "15")
SHIPPED_ROWS_B = ("18", "19", "20", "20b", "23")


@cache
def shipped() -> RuleEngine:
    return RuleEngine(load_rules())


def items(resource: str, before: State, after: State) -> list[ChangeItem]:
    """The items between two collections of one object, normalised as the pipeline does."""
    table = shipped().index.type_tables[resource]
    old = normalize_object(table, before)
    new = normalize_object(table, after)
    return detect(resource, [old], [new], engine=shipped())


def only(found: list[ChangeItem]) -> ChangeItem:
    assert len(found) == 1, found
    return found[0]


def one(**fields: JsonValue) -> State:
    return state(**fields)


# (row, resource, path, kind, severity, rule id, before, after)
ROWS: tuple[tuple[str, str, str, ChangeKind, Severity, str, State, State], ...] = (
    (
        "1",
        "networks",
        "name_label",
        "modified",
        "low",
        "xo.networks.name_label",
        one(id="n1", name_label="lab-net"),
        one(id="n1", name_label="lab-net-renamed"),
    ),
    (
        "2",
        "vifs",
        "rateLimit",
        "modified",
        "medium",
        "xo.vifs.rate_limit",
        one(id="f1", rateLimit=1000),
        one(id="f1", rateLimit=500),
    ),
    (
        "6",
        "backup-jobs",
        "settings.reportRecipients",
        "added",
        "medium",
        "xo.backup_job_settings.report_recipients",
        one(id="j1", name="nightly", settings={"reportRecipients": ["ops-a@example.test"]}),
        one(
            id="j1",
            name="nightly",
            settings={"reportRecipients": ["ops-a@example.test", "ops-b@example.test"]},
        ),
    ),
    (
        "10",
        "vms",
        "secureBoot",
        "modified",
        "high",
        "xo.vms.secure_boot_off",
        one(id="v1", name_label="vm1", secureBoot=True),
        one(id="v1", name_label="vm1", secureBoot=False),
    ),
    (
        "11",
        "users",
        "permission",
        "modified",
        "critical",
        "xo.users.permission_to_admin",
        one(id="x1", email="user@example.test", permission="none"),
        one(id="x1", email="user@example.test", permission="admin"),
    ),
    (
        "12",
        "servers",
        "readOnly",
        "modified",
        "high",
        "xo.servers.read_only",
        one(id="p1", label="pool-a", readOnly=True),
        one(id="p1", label="pool-a", readOnly=False),
    ),
    (
        "13",
        "backup-jobs",
        "settings.exportRetention",
        "modified",
        "high",
        "xo.backup_job_settings.export_retention_drop",
        one(id="j1", name="nightly", settings={"exportRetention": 30}),
        one(id="j1", name="nightly", settings={"exportRetention": 1}),
    ),
    (
        "14",
        "backup-repositories",
        "url",
        "modified",
        "high",
        "xo.backup_repositories.url",
        one(id="r1", name="vault", url="nfs://backup-a.example.test/share"),
        one(id="r1", name="vault", url="nfs://backup-b.example.test/share"),
    ),
    (
        "15",
        "hosts",
        "supplementalPacks",
        "added",
        "medium",
        "xo.hosts.supplemental_packs",
        one(id="h1", name_label="host-a", supplementalPacks=["pack-a"]),
        one(id="h1", name_label="host-a", supplementalPacks=["pack-a", "pack-b"]),
    ),
    (
        "19",
        "servers",
        "allowUnauthorized",
        "modified",
        "critical",
        "xo.servers.allow_unauthorized",
        one(id="p1", label="pool-a", allowUnauthorized=False),
        one(id="p1", label="pool-a", allowUnauthorized=True),
    ),
    (
        "20",
        "vms",
        "notes",
        "removed",
        "low",
        "xo.vms.notes",
        one(id="v1", name_label="vm1", notes="Owner: lab"),
        one(id="v1", name_label="vm1"),
    ),
    (
        "23",
        "groups",
        "aclRoleIds",
        "added",
        "critical",
        "xo.groups.acl_role_ids",
        one(id="g1", name="staff", aclRoleIds=["role-view"]),
        one(id="g1", name="staff", aclRoleIds=["role-view", "role-admin"]),
    ),
)


def test_the_shipped_xo_pack_loads_without_a_tie_and_has_about_forty_rules() -> None:
    xo_rules = [c for c in shipped().index.rules if c.source.startswith("packs/xo/")]
    assert len(xo_rules) >= 40
    assert len({c.rule.id for c in xo_rules}) == len(xo_rules)
    assert all(c.rule.rationale.strip() != "" for c in xo_rules)


def test_every_xo_row_of_the_plan_is_run_or_pinned_here() -> None:
    run = {row[0] for row in ROWS}
    pinned = {"4", "8", "18", "20b"}
    assert run | pinned == set(SHIPPED_ROWS) | set(SHIPPED_ROWS_B)
    assert not run & pinned


@pytest.mark.parametrize("row", ROWS, ids=[f"row-{row[0]}" for row in ROWS])
def test_the_row_gets_the_expected_severity_from_the_shipped_pack(
    row: tuple[str, str, str, ChangeKind, Severity, str, State, State],
) -> None:
    _, resource, path, kind, severity, rule_id, before, after = row
    item = only(items(resource, before, after))
    result = shipped().classify(item)
    assert (item.resource, item.path, item.change_kind) == (resource, path, kind)
    assert (result.severity, result.rule_id) == (severity, rule_id)
    assert result.rationale.strip() != ""


def test_row_4_a_changed_memory_usage_is_no_change() -> None:
    before = one(id="v1", name_label="vm1", memory={"usage": 1024})
    after = one(id="v1", name_label="vm1", memory={"usage": 2048})
    assert items("vms", before, after) == []


def test_row_4_control_a_changed_memory_limit_is_reported() -> None:
    before = one(id="v1", name_label="vm1", memory={"static": [0, 8589934592]})
    after = one(id="v1", name_label="vm1", memory={"static": [0, 17179869184]})
    result = shipped().classify(only(items("vms", before, after)))
    assert (result.severity, result.rule_id) == ("medium", "xo.vms.memory")


def test_row_20b_a_key_omitted_instead_of_null_is_no_change() -> None:
    before = one(id="v1", name_label="vm1", notes=None)
    after = one(id="v1", name_label="vm1")
    assert items("vms", before, after) == []


def test_row_8_is_not_run_because_the_shipped_table_ignores_docker() -> None:
    table = shipped().index.type_tables["vms"]
    assert table.field_class("docker") is FieldClass.IGNORE
    before = one(id="v1", name_label="vm1", docker={"enabled": False})
    after = one(id="v1", name_label="vm1", docker={"enabled": True})
    assert items("vms", before, after) == []


def test_row_18_the_shipped_secret_field_shows_fingerprints_only() -> None:
    table = shipped().index.type_tables["users"]
    assert table.field_class("authProviders") is FieldClass.SECRET
    before = one(id="x1", email="user@example.test", authProviders=CANARY_OLD)
    after = one(id="x1", email="user@example.test", authProviders=CANARY_NEW)
    item = only(items("users", before, after))
    result = shipped().classify(item)
    assert item.path == "authProviders"
    assert (item.before_value, item.after_value) == (None, None)
    assert item.before_fp is not None
    assert item.after_fp is not None
    assert item.before_fp != item.after_fp
    assert (result.severity, result.rule_id) == ("high", "xo.users.auth_providers")
    for shown in (repr(item), repr(result), str(item.order_detail)):
        assert "CANARY" not in shown


def test_row_18_a_password_hash_is_not_collected_and_never_shown_as_a_value() -> None:
    table = shipped().index.type_tables["users"]
    assert table.field_class("pw_hash") is FieldClass.UNCLASSIFIED
    before = one(id="x1", email="user@example.test", pw_hash=CANARY_OLD)
    after = one(id="x1", email="user@example.test", pw_hash=CANARY_NEW)
    for item in items("users", before, after):
        assert (item.before_value, item.after_value) == (None, None)
        assert item.before_fp is not None
        assert item.after_fp is not None
        for shown in (repr(item), repr(shipped().classify(item)), str(item.order_detail)):
            assert "CANARY" not in shown


def test_row_13_control_a_drop_to_two_backups_is_medium() -> None:
    before = one(id="j1", name="nightly", settings={"exportRetention": 30})
    after = one(id="j1", name="nightly", settings={"exportRetention": 2})
    result = shipped().classify(only(items("backup-jobs", before, after)))
    assert (result.severity, result.rule_id) == (
        "medium",
        "xo.backup_job_settings.export_retention",
    )


def test_no_xo_row_ends_as_an_unclassified_item() -> None:
    for _, resource, _, _, _, _, before, after in ROWS:
        for item in items(resource, before, after):
            assert shipped().classify(item).rule_id != UNCLASSIFIED_RULE_ID
