"""Tests for scripts/load_test.py (P11-T1): the fixture, the verdicts and the container steps.

The fixture tests are exact. The end-to-end test runs a small fixture through the real pipeline
(a migrated database, the shipped rules). The container steps run against a fake docker command, so
the order of the commands, the hardening flags and the clean-up are checked without a container; the
real run needs the image and is the job of ``python3 scripts/load_test.py container``.
"""

import copy
import json
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest

import load_test
from driftsniff.web.auth import SESSION_COOKIE

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
VOLATILE = {"uptimeSec", "lastHeartbeatAt"}
SMALL = load_test.FixtureSpec(
    objects=60, changes=40, days=6, polls_per_day=4, noisy_polls=6, noisy_objects=20
)


def configuration(document: load_test.Document) -> dict[str, dict[str, Any]]:
    """The objects of a document by id, without the ignore class counters."""
    return {
        entry["id"]: {key: value for key, value in entry.items() if key not in VOLATILE}
        for entries in document.values()
        for entry in entries
    }


def test_the_default_fixture_is_the_one_of_the_plan() -> None:
    spec = load_test.FixtureSpec()
    spec.validate()
    counts = load_test.resource_counts(spec.objects)
    assert sum(counts.values()) == 1000
    assert counts["unifi-firewall-policies"] == 200
    fed = list(load_test.polls(spec, NOW))
    assert len(fed) == 1 + 90 * spec.polls_per_day
    assert fed[0].planned_changes == 0
    assert sum(poll.planned_changes for poll in fed) == 2000
    assert sum(1 for poll in fed[1:] if poll.planned_changes == 0) == 180
    assert fed[-1].at == NOW
    assert 89.9 < (fed[-1].at - fed[0].at).total_seconds() / 86400 < 90


@pytest.mark.parametrize("total", [8, 60, 137, 1000, 1500])
def test_the_resource_counts_always_add_up(total: int) -> None:
    counts = load_test.resource_counts(total)
    assert sum(counts.values()) == total
    assert min(counts.values()) >= 1


def test_distribute_splits_without_losing_a_change() -> None:
    assert load_test.distribute(10, 3) == [4, 3, 3]
    assert sum(load_test.distribute(2000, 180)) == 2000


def test_every_planned_change_is_one_object_with_one_changed_field() -> None:
    previous: dict[str, dict[str, Any]] | None = None
    for poll in load_test.polls(SMALL, NOW):
        current = copy.deepcopy(configuration(poll.document))
        if previous is not None:
            changed = [key for key in current if current[key] != previous[key]]
            assert len(changed) == poll.planned_changes
            for key in changed:
                after, before = current[key], previous[key]
                assert len([name for name in after if after[name] != before[name]]) == 1
        previous = current


def test_the_ignore_class_counters_move_at_every_poll() -> None:
    seen = [poll.document["unifi-devices"][0]["uptimeSec"] for poll in load_test.polls(SMALL, NOW)]
    assert len(set(seen)) == len(seen)


@pytest.mark.parametrize("resource", [name for name, _ in load_test.RESOURCE_WEIGHTS])
def test_a_mutation_changes_one_configuration_field(resource: str) -> None:
    document = load_test.base_document(load_test.resource_counts(60))
    entry = document[resource][0]
    for revision in range(1, 7):
        before = copy.deepcopy(entry)
        load_test.mutate(resource, entry, revision)
        changed = {key for key in entry if entry[key] != before[key]}
        assert len(changed) == 1
        assert not VOLATILE & changed


def test_the_fixture_holds_only_synthetic_values() -> None:
    text = repr(list(load_test.polls(SMALL, NOW))[-1].document)
    assert "CANARY-load-" in text
    assert "ld-net-0000" in text
    assert "@" not in text
    assert "http" not in text


def test_the_push_fields_cover_every_field_of_the_fixture() -> None:
    document = load_test.base_document(load_test.resource_counts(60))
    assert set(document) == set(load_test.PUSH_FIELDS)
    for resource, entries in document.items():
        assert set(entries[0]) <= set(load_test.PUSH_FIELDS[resource])


@pytest.mark.parametrize(
    "spec",
    [
        load_test.FixtureSpec(objects=3),
        load_test.FixtureSpec(changes=0),
        load_test.FixtureSpec(days=0),
        load_test.FixtureSpec(objects=20, changes=2000, days=2),
        load_test.FixtureSpec(noisy_polls=1),
        load_test.FixtureSpec(noisy_objects=2),
    ],
)
def test_a_fixture_that_cannot_be_made_is_refused(spec: load_test.FixtureSpec) -> None:
    with pytest.raises(load_test.LoadTestError):
        spec.validate()


def test_the_cookie_name_is_the_one_of_the_product() -> None:
    assert load_test.SESSION_COOKIE_NAME == SESSION_COOKIE


def test_the_statistics_helpers() -> None:
    assert load_test.median([3.0, 1.0, 2.0]) == 2.0
    assert load_test.median([1.0, 2.0, 3.0, 4.0]) == 2.5
    assert load_test.median([]) == 0.0
    assert load_test.percentile([float(n) for n in range(1, 11)], 0.95) == 10.0
    assert load_test.percentile([], 0.95) == 0.0
    flat = [(index * 0.25, index * 0.25 * 0.5) for index in range(40)]
    assert round(load_test.burst_percent(flat)) == 50
    spike = [*flat[:10], (2.5, 2.5 * 0.5 + 1.0), *flat[11:]]
    assert load_test.burst_percent(spike) > 100


def test_the_last_json_line_is_the_result() -> None:
    assert load_test._last_json('log line\n{"a": 1}\nnot json {\n{"b": 2}\ntrailing') == {"b": 2}
    with pytest.raises(load_test.LoadTestError):
        load_test._last_json("nothing here")


# ---- the verdicts -----------------------------------------------------------------------------


def seed_part(**changes: Any) -> dict[str, Any]:
    part: dict[str, Any] = {
        "polls": 361,
        "quiet_polls": 180,
        "quiet_polls_stored_snapshot": 0,
        "change_polls_without_event": 0,
        "planned_changes": 2000,
        "last_object_count": 1000,
        "run_seconds_quiet_median": 0.2,
        "run_seconds_change_median": 0.4,
        "run_seconds_p95": 0.5,
        "stored_runs": 361,
        "stored_snapshots": 181,
        "stored_events": 180,
        "stored_states": 3000,
        "stored_change_items": 2000,
        "stored_baseline_bytes": 300000,
        "stored_growth_bytes": 900000,
        "wall_seconds": 90.0,
        "cpu_average_percent": 95.0,
        "cpu_burst_percent": 100.0,
        "rss_peak_mb": 180.0,
        "cgroup_peak_mb": 250.0,
        "oom_killed": False,
        "exit_code": 0,
        "database_bytes": 5_000_000,
    }
    part.update(changes)
    return part


def noisy_part(**changes: Any) -> dict[str, Any]:
    part: dict[str, Any] = {
        "polls": 49,
        "stored_snapshots": 49,
        "stored_change_items": 144,
        "growth_bytes_per_poll": 4096.0,
        "warning_observed": False,
        "warning_signals": [],
    }
    part.update(changes)
    return part


def report(
    seed_changes: dict[str, Any] | None = None,
    server_changes: dict[str, Any] | None = None,
    noisy_changes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    server: dict[str, Any] = {
        "idle_rss_mb": 120.0,
        "peak_rss_mb": 190.0,
        "cgroup_peak_mb": 260.0,
        "running": True,
        "oom_killed": False,
        "cpu_seconds_first_page_and_warm": 1.5,
        "pages": {
            "/": {
                "status": 200,
                "bytes": 40000,
                "cold_seconds": 0.4,
                "warm_median_seconds": 0.1,
                "warm_p95_seconds": 0.2,
                "warm_max_seconds": 0.3,
            }
        },
    }
    server.update(server_changes or {})
    return {
        "mode": "container",
        "image": "driftsniff:ci",
        "spec": {"objects": 1000, "changes": 2000, "days": 90, "polls_per_day": 4, "seed": 1},
        "seed": seed_part(**(seed_changes or {})),
        "server": server,
        "noisy": noisy_part(**(noisy_changes or {})),
    }


def outcomes(data: dict[str, Any]) -> dict[str, str]:
    return {item.check: item.outcome for item in load_test.evaluate(data)}


def test_every_target_met_passes_except_the_missing_warning() -> None:
    result = outcomes(report())
    assert result == {
        "fixture": "pass",
        "ram": "pass",
        "first page": "pass",
        "512 MB limit": "pass",
        "volatility warning": "miss",
    }


def test_a_warning_that_is_found_passes() -> None:
    data = report(noisy_changes={"warning_observed": True, "warning_signals": ["log: noisy"]})
    assert outcomes(data)["volatility warning"] == "pass"


@pytest.mark.parametrize(
    ("seed_changes", "server_changes", "check", "expected"),
    [
        ({"rss_peak_mb": 251.0}, {}, "ram", "miss"),
        ({"rss_peak_mb": 100.0}, {"peak_rss_mb": 120.0}, "ram", "below"),
        ({"rss_peak_mb": 100.0}, {"peak_rss_mb": 260.0}, "ram", "miss"),
        ({"rss_peak_mb": None}, {"peak_rss_mb": None}, "ram", "miss"),
        ({}, {"pages": {"/": {"status": 200, "cold_seconds": 1.0}}}, "first page", "miss"),
        ({}, {"pages": {"/": {"status": 303, "cold_seconds": 0.1}}}, "first page", "miss"),
        ({"oom_killed": True}, {}, "512 MB limit", "miss"),
        ({"exit_code": 137}, {}, "512 MB limit", "miss"),
        ({}, {"running": False}, "512 MB limit", "miss"),
        ({}, {"cgroup_peak_mb": 512.0}, "512 MB limit", "note"),
        ({"stored_change_items": 1999}, {}, "fixture", "miss"),
        ({"last_object_count": 999}, {}, "fixture", "miss"),
        ({"quiet_polls_stored_snapshot": 1}, {}, "fixture", "miss"),
        ({"change_polls_without_event": 1}, {}, "fixture", "miss"),
    ],
)
def test_a_miss_is_reported_as_a_miss(
    seed_changes: dict[str, Any], server_changes: dict[str, Any], check: str, expected: str
) -> None:
    assert outcomes(report(seed_changes, server_changes))[check] == expected


def test_the_markdown_shows_every_check_and_measurement() -> None:
    data = report()
    text = load_test.render_markdown(data, load_test.evaluate(data))
    for expected in (
        "| fixture | pass |",
        "| volatility warning | miss |",
        "Peak resident memory, pipeline",
        "First page `/` (cold) | 0.40 s",
        "Noisy fixture | 49 manifests for 48 polls",
        "Container memory peak",
    ):
        assert expected in text


# ---- the real pipeline, small ------------------------------------------------------------------


def test_a_small_fixture_runs_through_the_real_pipeline() -> None:
    result = load_test.run_local(SMALL)
    seeded, noisy = result["seed"], result["noisy"]
    assert "session" not in seeded
    assert seeded["polls"] == 1 + 6 * 4
    assert seeded["stored_change_items"] == seeded["planned_changes"] == 40
    assert seeded["last_object_count"] == 60
    assert seeded["quiet_polls"] == 12
    assert seeded["quiet_polls_stored_snapshot"] == 0
    assert seeded["change_polls_without_event"] == 0
    assert seeded["stored_snapshots"] == 1 + 12
    assert seeded["stored_events"] == 12
    assert seeded["database_bytes"] > 0
    assert seeded["rss_peak_mb"] is None or seeded["rss_peak_mb"] > 0
    page = result["server"]["pages"]["/"]
    assert page["status"] == 200
    assert page["bytes"] > 0
    assert noisy["stored_snapshots"] == 1 + 6
    assert noisy["stored_events"] == 6
    assert noisy["stored_change_items"] == 6 * load_test.NOISY_CHANGES_PER_POLL
    assert noisy["warning_observed"] is False
    assert noisy["warning_signals"] == []
    checks = outcomes(result)
    assert checks["fixture"] == "pass"
    assert checks["first page"] == "pass"
    assert checks["volatility warning"] == "miss"


# ---- the container steps, against a fake docker -----------------------------------------------


class FakeDocker:
    """Answers the docker commands of a container run and remembers them."""

    def __init__(self, *, oom: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.oom = oom

    def __call__(self, *args: str, timeout: float = 0.0) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, self.answer(args), "")

    def answer(self, args: Sequence[str]) -> str:
        if args[0] == "run" and "--detach" not in args:
            part = seed_part() if "seed" in args else {**noisy_part(), "polls": 49}
            return "a log line\n" + json.dumps({**part, "session": "x"})
        if args[0] == "inspect":
            template = args[2]
            if "OOMKilled" in template:
                return "true" if self.oom else "false"
            if "ExitCode" in template:
                return "0"
            if "Health.Status" in template:
                return "healthy"
            if "HostPort" in template:
                return "49153"
            return "true"
        if args[0] == "exec":
            if args[-1] == "/proc/1/status":
                return "Name:\tpython\nVmHWM:\t 200000 kB\nVmRSS:\t 150000 kB\n"
            if args[-1] == "/proc/1/stat":
                return "1 (python) S " + " ".join(["0"] * 10 + ["150", "50"] + ["0"] * 10)
            return "272629760"
        return ""

    def commands(self, word: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[0] == word]


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    fake = FakeDocker()
    monkeypatch.setattr(load_test, "_docker_status", fake)
    monkeypatch.setattr(load_test.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(load_test, "_fetch", lambda _port, _path, _cookie: (200, 4000, 0.25))
    return fake


def test_the_container_run_uses_the_hardening_flags_and_removes_everything(
    fake_docker: FakeDocker,
) -> None:
    result = load_test.run_container("driftsniff:ci", load_test.FixtureSpec())
    runs = fake_docker.commands("run")
    assert len(runs) == 3
    for command in runs:
        for flag in ("--read-only", "--cap-drop", "--memory"):
            assert flag in command
        assert command[command.index("--memory") + 1] == "512m"
        assert command[command.index("--memory-swap") + 1] == "512m"
    seed_run, server_run, noisy_run = runs
    assert "/load/load_test.py" in seed_run and "seed" in seed_run
    assert "--detach" in server_run
    assert "noisy" in noisy_run
    assert len(fake_docker.commands("rm")) == 3
    volume_steps = [call[1] for call in fake_docker.commands("volume")]
    assert volume_steps.count("create") == 4
    assert volume_steps.count("rm") == 4
    assert "session" not in result["seed"]
    assert result["server"]["pages"]["/"]["cold_seconds"] == 0.25
    assert result["server"]["peak_rss_mb"] == pytest.approx(200000 / 1024)
    assert result["server"]["cgroup_peak_mb"] == pytest.approx(260.0, abs=1)
    assert outcomes(result)["first page"] == "pass"


def test_a_container_killed_for_memory_is_a_miss_and_is_still_cleaned_up(
    fake_docker: FakeDocker,
) -> None:
    fake_docker.oom = True
    with pytest.raises(load_test.LimitMissError):
        load_test.run_container("driftsniff:ci", load_test.FixtureSpec())
    assert len(fake_docker.commands("rm")) == 3
    assert load_test.main(["container", "--image", "driftsniff:ci"]) == 1


def test_the_command_line_defaults_are_the_plan() -> None:
    args = load_test.build_parser().parse_args(["container", "--image", "x"])
    assert load_test._spec_from(args) == load_test.FixtureSpec()
