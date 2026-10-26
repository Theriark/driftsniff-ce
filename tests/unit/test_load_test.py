"""Tests for scripts/load_test.py (P11-T1): the fixture, the verdicts and the container steps.

The fixture tests are exact. The end-to-end test runs a small fixture through the real pipeline
(a migrated database, the shipped rules). The container steps run against a fake docker command, so
the order of the commands, the hardening flags, the clean-up and what happens when a container is
killed for memory are checked without a container; the real run needs the image and is the job of
``python3 scripts/load_test.py container``. A server that drops the connection is tested for real
with a local socket.
"""

import copy
import json
import socket
import subprocess
import threading
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


# ---- a server that does not answer ------------------------------------------------------------


def test_a_refused_connection_is_status_zero_not_a_crash() -> None:
    status, size, seconds = load_test._fetch("1", "/", "x")
    assert (status, size) == (0, 0)
    assert seconds >= 0


def test_a_server_that_drops_the_connection_is_status_zero_not_a_crash() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def drop() -> None:
            connection, _address = listener.accept()
            connection.close()

        thread = threading.Thread(target=drop)
        thread.start()
        status, size, _seconds = load_test._fetch(str(port), "/", "x")
        thread.join(timeout=10)
    assert (status, size) == (0, 0)


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
        "quiet_polls": 48,
        "quiet_polls_stored_snapshot": 0,
        "stored_snapshots": 1,
        "stored_events": 0,
        "stored_change_items": 0,
        "added_snapshots": 0,
        "added_events": 0,
        "added_change_items": 0,
        "added_states": 0,
        "added_bytes": 0,
        "database_bytes_baseline": 400_000,
        "database_bytes": 410_000,
    }
    part.update(changes)
    return part


KILLED_SEED = {"phase": "seed", "partial": True, "oom_killed": True, "exit_code": 137}


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


def test_every_target_met_passes_and_the_run_can_exit_zero() -> None:
    result = outcomes(report())
    assert result == {
        "fixture": "pass",
        "ram": "pass",
        "first page": "pass",
        "512 MB limit": "pass",
        "volatile-field suppression": "pass",
    }
    assert not any(item.outcome == "miss" for item in load_test.evaluate(report()))


@pytest.mark.parametrize(
    "noisy_changes",
    [
        {"added_change_items": 3},
        {"added_events": 1},
        {"added_snapshots": 1},
        {"added_states": 1},
        {"added_bytes": 100},
        {"quiet_polls_stored_snapshot": 1},
    ],
)
def test_volatile_fields_that_cost_something_are_a_miss(noisy_changes: dict[str, Any]) -> None:
    data = report(noisy_changes=noisy_changes)
    assert outcomes(data)["volatile-field suppression"] == "miss"


def test_the_miss_names_what_was_added_and_the_database_file() -> None:
    data = report(noisy_changes={"added_snapshots": 48, "added_bytes": 9000})
    detail = {item.check: item.detail for item in load_test.evaluate(data)}
    text = detail["volatile-field suppression"]
    assert "48 manifests" in text
    assert "9000 stored bytes" in text
    assert "database file 391 KB" in text


@pytest.mark.parametrize(
    ("seed_changes", "server_changes", "check", "expected"),
    [
        ({"rss_peak_mb": 251.0}, {}, "ram", "miss"),
        ({"rss_peak_mb": 100.0}, {"peak_rss_mb": 120.0}, "ram", "below"),
        ({"rss_peak_mb": 100.0}, {"peak_rss_mb": 260.0}, "ram", "miss"),
        ({"rss_peak_mb": None}, {"peak_rss_mb": None}, "ram", "gap"),
        ({}, {"pages": {"/": {"status": 200, "cold_seconds": 1.0}}}, "first page", "miss"),
        ({}, {"pages": {"/": {"status": 303, "cold_seconds": 0.1}}}, "first page", "miss"),
        ({}, {"pages": {"/": {"status": 0, "cold_seconds": 0.1}}}, "first page", "miss"),
        ({}, {"pages": {}}, "first page", "gap"),
        ({"oom_killed": True}, {}, "512 MB limit", "miss"),
        ({"exit_code": 137}, {}, "512 MB limit", "miss"),
        ({}, {"running": False}, "512 MB limit", "miss"),
        ({}, {"oom_killed": True}, "ram", "miss"),
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


def test_a_noisy_container_that_was_killed_is_a_gap() -> None:
    data = report(noisy_changes={"partial": True, "oom_killed": True, "exit_code": 137})
    assert outcomes(data)["volatile-field suppression"] == "gap"
    assert outcomes(data)["512 MB limit"] == "miss"


def test_a_killed_seed_gives_a_miss_and_gaps_and_no_pass() -> None:
    data = report()
    data["seed"] = dict(KILLED_SEED)
    data["server"] = {"skipped": "the seed container was killed for memory"}
    result = outcomes(data)
    assert result == {
        "fixture": "gap",
        "ram": "miss",
        "first page": "gap",
        "512 MB limit": "miss",
        "volatile-field suppression": "pass",
    }
    text = load_test.render_markdown(data, load_test.evaluate(data))
    assert "The run is incomplete" in text
    assert "| 512 MB limit | miss |" in text
    assert "| fixture | gap |" in text


def test_the_markdown_shows_every_check_and_measurement() -> None:
    data = report()
    text = load_test.render_markdown(data, load_test.evaluate(data))
    for expected in (
        "| fixture | pass |",
        "| volatile-field suppression | pass |",
        "Peak resident memory, pipeline",
        "First page `/` (cold) | 0.40 s",
        "Counters-only fixture | 48 polls added 0 items, 0 manifests, 0 states and 0 stored bytes",
        "Container memory peak",
    ):
        assert expected in text


def test_a_page_that_was_not_measured_is_n_a_not_zero() -> None:
    data = report(server_changes={"pages": {}, "running": False, "oom_killed": True})
    text = load_test.render_markdown(data, load_test.evaluate(data))
    assert "First page `/` (cold) | n/a" in text


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
    assert noisy["polls"] == 1 + 6
    assert noisy["quiet_polls"] == 6
    assert noisy["quiet_polls_stored_snapshot"] == 0
    assert noisy["stored_snapshots"] == 1
    assert noisy["stored_events"] == 0
    assert noisy["stored_change_items"] == 0
    assert noisy["added_snapshots"] == noisy["added_events"] == noisy["added_change_items"] == 0
    assert noisy["added_states"] == 0
    assert noisy["added_bytes"] == 0
    assert noisy["database_bytes_baseline"] > 0
    assert outcomes(result) == {
        "fixture": "pass",
        "ram": "gap",
        "first page": "gap",
        "512 MB limit": "gap",
        "volatile-field suppression": "pass",
    }


# ---- the container steps, against a fake docker -----------------------------------------------


class FakeDocker:
    """Answers the docker commands of a container run and remembers them.

    ``oom`` is the set of containers (``seed``, ``server``, ``noisy``) that docker reports as
    killed for memory. The server counts as dead once a page was requested and ``kill_server``.
    """

    def __init__(
        self,
        *,
        oom: Sequence[str] = (),
        kill_server: bool = False,
        die_after_healthy: bool = False,
        exec_fails: bool = False,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.oom = set(oom)
        self.kill_server = kill_server
        self.die_after_healthy = die_after_healthy
        self.exec_fails = exec_fails
        self.dead = False

    def __call__(self, *args: str, timeout: float = 0.0) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        if args[0] == "exec" and (self.dead or self.exec_fails):
            return subprocess.CompletedProcess(args, 1, "", "the container is not running")
        if args[0] == "run" and "--detach" not in args and args[2].rsplit("-", 1)[1] in self.oom:
            return subprocess.CompletedProcess(args, 137, "", "")
        return subprocess.CompletedProcess(args, 0, self.answer(args), "")

    def fetch(self, _port: str, _path: str, _cookie: str) -> tuple[int, int, float]:
        if self.kill_server:
            self.dead = True
            return 0, 0, 0.01
        return 200, 4000, 0.25

    def answer(self, args: Sequence[str]) -> str:
        if args[0] == "run" and "--detach" not in args:
            part = seed_part() if "seed" in args else {**noisy_part(), "polls": 49}
            return "a log line\n" + json.dumps({**part, "session": "x"})
        if args[0] == "inspect":
            template, name = args[2], args[3]
            kind = name.rsplit("-", 1)[1]
            if "OOMKilled" in template:
                return "true" if kind in self.oom else "false"
            if "ExitCode" in template:
                return "137" if kind in self.oom else "0"
            if "Health.Status" in template:
                self.dead = self.dead or self.die_after_healthy
                return "healthy"
            if "HostPort" in template:
                return "49153"
            return "false" if self.dead and kind == "server" else "true"
        if args[0] == "exec":
            if args[-1] == "/proc/1/status":
                return "Name:\tpython\nVmHWM:\t 200000 kB\nVmRSS:\t 150000 kB\n"
            if args[-1] == "/proc/1/stat":
                return "1 (python) S " + " ".join(["0"] * 10 + ["150", "50"] + ["0"] * 10)
            return "272629760"
        return ""

    def commands(self, word: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[0] == word]


def install(monkeypatch: pytest.MonkeyPatch, fake: FakeDocker) -> FakeDocker:
    monkeypatch.setattr(load_test, "_docker_status", fake)
    monkeypatch.setattr(load_test.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(load_test, "_fetch", fake.fetch)
    return fake


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    return install(monkeypatch, FakeDocker())


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


def test_a_seed_killed_for_memory_gives_a_report_and_is_cleaned_up(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(monkeypatch, FakeDocker(oom=["seed"]))
    result = load_test.run_container("driftsniff:ci", load_test.FixtureSpec())
    assert result["seed"]["partial"] is True
    assert result["seed"]["oom_killed"] is True
    assert "skipped" in result["server"]
    assert len(fake.commands("run")) == 2
    assert len(fake.commands("rm")) == 3
    assert load_test.main(["container", "--image", "driftsniff:ci"]) == 1
    printed = capsys.readouterr().out
    assert "| 512 MB limit | miss |" in printed
    assert "::notice title=load-test 512 MB limit::miss" in printed


def test_a_server_killed_while_answering_gives_a_report_and_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(monkeypatch, FakeDocker(oom=["server"], kill_server=True))
    result = load_test.run_container("driftsniff:ci", load_test.FixtureSpec())
    server = result["server"]
    assert server["oom_killed"] is True
    assert server["running"] is False
    assert server["peak_rss_mb"] is None
    assert server["pages"]["/"]["status"] == 0
    assert len(fake.commands("rm")) == 3
    checks = outcomes(result)
    assert checks["first page"] == "miss"
    assert checks["512 MB limit"] == "miss"
    assert checks["ram"] == "miss"
    fake.dead = False
    assert load_test.main(["container", "--image", "driftsniff:ci"]) == 1
    printed = capsys.readouterr().out
    assert "| first page | miss | the server did not answer the request |" in printed
    assert "killed for memory at the limit: server" in printed


def test_a_server_that_stops_before_it_is_healthy_gives_a_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(oom=["server"])
    install(monkeypatch, fake)
    fake.dead = True
    result = load_test.run_container("driftsniff:ci", load_test.FixtureSpec())
    assert result["server"]["stopped_before_healthy"] is True
    assert result["server"]["pages"] == {}
    assert outcomes(result)["512 MB limit"] == "miss"
    assert outcomes(result)["first page"] == "gap"


def test_a_server_that_dies_right_after_its_health_check_gives_a_partial_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(monkeypatch, FakeDocker(oom=["server"], die_after_healthy=True))
    result = load_test.run_container("driftsniff:ci", load_test.FixtureSpec())
    server = result["server"]
    assert server["stopped_after_healthy"] is True
    assert server["running"] is False
    assert server["oom_killed"] is True
    assert server["pages"] == {}
    assert server["peak_rss_mb"] is None
    assert len(fake.commands("rm")) == 3
    checks = outcomes(result)
    assert checks["512 MB limit"] == "miss"
    assert checks["ram"] == "miss"
    assert checks["first page"] == "gap"
    fake.dead = False
    fake.die_after_healthy = True
    assert load_test.main(["container", "--image", "driftsniff:ci"]) == 1
    assert "killed for memory at the limit: server" in capsys.readouterr().out


def test_a_failed_read_from_a_server_that_still_runs_is_a_harness_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(monkeypatch, FakeDocker(exec_fails=True))
    with pytest.raises(load_test.LoadTestError, match="docker exec failed"):
        load_test.run_container("driftsniff:ci", load_test.FixtureSpec())
    assert len(fake.commands("rm")) == 3
    assert load_test.main(["container", "--image", "driftsniff:ci"]) == 2
    assert "load_test: docker exec failed" in capsys.readouterr().err


def test_the_command_line_defaults_are_the_plan() -> None:
    args = load_test.build_parser().parse_args(["container", "--image", "x"])
    assert load_test._spec_from(args) == load_test.FixtureSpec()
