"""The Xen Orchestra client against a fake server on localhost (P8-T2).

Every acceptance check of the plan has a test: flat memory for a large collection (200,000 small
objects served from a generator), excluded collections never requested, the credential never in a
log record, an error text or a request line except the cookie (canary), and the 14 day expiry
warning with an injected clock. Also covered: 403 on admin only collections, an invalid line, a
slow collection and a truncated stream.

The names the fake serves are unverified against the vendor reference (docs/vendor-notes/xo.md).
"""

import logging
import tracemalloc
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

import pytest

from driftsniff.collectors.base import (
    ERROR_BAD_PAYLOAD,
    ERROR_TIMEOUT,
    CollectorError,
    ResourceSpec,
)
from driftsniff.collectors.xo.client import (
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_RESOURCE,
    XoClient,
)
from driftsniff.collectors.xo.resources import COLLECTIONS, EXCLUDED_COLLECTIONS, field_list
from driftsniff.rules.loader import load_rules

from .fake_xo import CANARY_TOKEN, FakeXo, Scenario, fake_xo

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
PASSWORD_CANARY = "CANARY-xo-remote-pass-0001"


def ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def vm(index: int) -> dict[str, Any]:
    return {"id": f"vm-{index:04d}", "name_label": f"vm {index}"}


@contextmanager
def connected(
    scenario: Scenario | None = None,
    **options: Any,
) -> Iterator[tuple[FakeXo, XoClient]]:
    """A fake server and a client for it; the client is closed at the end."""
    with fake_xo(scenario) as server:
        client = XoClient(server.url, CANARY_TOKEN, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


@contextmanager
def probed(
    scenario: Scenario | None = None,
    **options: Any,
) -> Iterator[tuple[FakeXo, XoClient]]:
    with connected(scenario, **options) as (server, client):
        client.probe()
        yield server, client


# -- probe ------------------------------------------------------------------------------------


def test_a_probe_succeeds_and_reports_no_version() -> None:
    with connected() as (server, client):
        assert client.probe() is None
        assert [request.path for request in server.requests] == [
            "/rest/v0",
            "/rest/v0/users/me/authentication_tokens",
        ]


def test_the_credential_travels_only_in_the_cookie() -> None:
    scenario = Scenario(objects={"vms": [vm(1)]})
    with probed(scenario) as (server, client):
        assert client.fetch(ResourceSpec("vms")).ok
        assert len(server.requests) == 3
        for request in server.requests:
            assert request.cookie == f"authenticationToken={CANARY_TOKEN}"
            assert request.authorization is None
            assert CANARY_TOKEN not in request.path
            assert CANARY_TOKEN not in request.query


@pytest.mark.parametrize(
    ("status", "error_class"), [(401, ERROR_UNAUTHORIZED), (403, ERROR_FORBIDDEN)]
)
def test_a_refused_credential_stops_the_probe(status: int, error_class: str) -> None:
    scenario = Scenario(status={"root": status}, echo_cookie=True)
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == error_class
    assert caught.value.status == str(status)
    assert CANARY_TOKEN not in str(caught.value)


def test_a_wrong_credential_is_unauthorized() -> None:
    with connected(Scenario(expected_token="CANARY-other")) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_UNAUTHORIZED


@pytest.mark.parametrize("scenario", [Scenario(status={"root": 404}), Scenario(html_root=True)])
def test_a_server_without_the_rest_interface_is_no_api(scenario: Scenario) -> None:
    with connected(scenario) as (_, client), pytest.raises(CollectorError) as caught:
        client.probe()
    assert caught.value.error_class == ERROR_NO_API


def test_a_blocked_address_is_refused_before_any_request() -> None:
    with connected(resolver=lambda host: ["169.254.169.254"]) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == "blocked_address"
        assert server.requests == []


def test_fetching_before_the_probe_is_refused() -> None:
    with connected() as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.fetch(ResourceSpec("vms"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


@pytest.mark.parametrize("token", ["", "a b", "a;b", "a,b", 'a"b', "a\\b", "ab\n", "ä"])
def test_a_credential_that_a_cookie_cannot_carry_is_refused(token: str) -> None:
    with pytest.raises(ValueError, match="cookie"):
        XoClient("https://xo.example.test", token)


# -- collections ------------------------------------------------------------------------------


def test_the_client_lists_the_collections_of_the_plan_that_have_a_type_table() -> None:
    tables = load_rules().type_tables
    with connected() as (_, client):
        names = [spec.name for spec in client.resources()]
    assert names == list(COLLECTIONS)
    assert len(names) == 20
    assert all(name in tables for name in names)
    assert not set(names) & set(EXCLUDED_COLLECTIONS)


def test_a_full_run_requests_each_collection_once_and_never_an_excluded_one() -> None:
    with probed() as (server, client):
        for spec in client.resources():
            assert client.fetch(spec).ok, spec.name
        requested = [request.path for request in server.requests[2:]]
    assert requested == [f"/rest/v0/{name}" for name in COLLECTIONS]
    for name in EXCLUDED_COLLECTIONS:
        assert not [path for path in requested if path.endswith(f"/{name}")]


def test_a_collection_without_a_type_table_cannot_be_requested() -> None:
    tables = dict(load_rules().type_tables)
    tables["tasks"] = tables["vms"]
    with probed(tables=tables) as (server, client):
        before = len(server.requests)
        for name in ("tasks", "alarms", "nothing"):
            result = client.fetch(ResourceSpec(name))
            assert not result.ok
            assert result.error_class == ERROR_UNKNOWN_RESOURCE
        assert len(server.requests) == before
        assert "tasks" not in [spec.name for spec in client.resources()]


def test_the_request_names_the_kept_fields_of_the_type_table_and_asks_for_ndjson() -> None:
    tables = load_rules().type_tables
    with probed() as (server, client):
        for name in ("vms", "vm-templates", "backup-jobs"):
            assert client.fetch(ResourceSpec(name)).ok
            query = parse_qs(server.requests_for(name)[0].query)
            assert query["ndjson"] == ["true"]
            requested = set(query["fields"][0].split(","))
            assert requested == set(field_list(name, tables[name]).split(","))
            assert {"id", "name_label"} <= requested or name == "backup-jobs"
            assert not requested & {"power_state", "uuid", "_xapiRef", "snapshots", "VDIs"}
            assert "limit" not in query
            assert "offset" not in query
    assert {"memory", "CPUs", "boot"} <= set(field_list("vms", tables["vms"]).split(","))
    assert "isDefaultTemplate" in field_list("vm-templates", tables["vm-templates"]).split(",")
    assert "isDefaultTemplate" not in field_list("vms", tables["vms"]).split(",")
    assert "settings" in field_list("backup-jobs", tables["backup-jobs"]).split(",")


def test_objects_are_sorted_by_id_whatever_order_the_server_used() -> None:
    scenario = Scenario(objects={"vms": [vm(index) for index in (3, 1, 2, 10)]}, reverse={"vms"})
    with probed(scenario) as (_, client):
        result = client.fetch(ResourceSpec("vms"))
    assert result.ok
    assert [item["id"] for item in result.objects] == ["vm-0001", "vm-0002", "vm-0003", "vm-0010"]
    assert result.bytes_fetched > 0


def test_an_empty_collection_is_a_good_read() -> None:
    with probed() as (_, client):
        result = client.fetch(ResourceSpec("vms"))
    assert result.ok
    assert list(result.objects) == []


def test_blank_lines_are_skipped_and_the_last_line_needs_no_newline() -> None:
    raw = b'{"id": "a"}\n\n{"id": "b"}\n \n{"id": "c"}'
    with probed(Scenario(raw={"vms": raw})) as (_, client):
        result = client.fetch(ResourceSpec("vms"))
    assert [item["id"] for item in result.objects] == ["a", "b", "c"]


def test_the_built_in_templates_are_dropped_and_the_custom_ones_stay() -> None:
    templates = [
        {"id": "t-1", "name_label": "builtin", "isDefaultTemplate": True},
        {"id": "t-2", "name_label": "custom", "isDefaultTemplate": False},
        {"id": "t-3", "name_label": "custom without marker"},
    ]
    with probed(Scenario(objects={"vm-templates": templates})) as (_, client):
        result = client.fetch(ResourceSpec("vm-templates"))
    assert [item["id"] for item in result.objects] == ["t-2", "t-3"]


def test_the_user_and_password_part_of_a_repository_address_never_reaches_the_pipeline() -> None:
    with_password = f"smb://svc:{PASSWORD_CANARY}@backup-a.example.test/share"
    remotes = [
        {"id": "r-1", "name": "a", "url": with_password},
        {"id": "r-2", "name": "b", "url": "nfs://backup-b.example.test/share"},
    ]
    with probed(Scenario(objects={"backup-repositories": remotes})) as (_, client):
        result = client.fetch(ResourceSpec("backup-repositories"))
    assert [item["url"] for item in result.objects] == [
        "smb://backup-a.example.test/share",
        "nfs://backup-b.example.test/share",
    ]
    assert PASSWORD_CANARY not in repr(result)


# -- failures and coverage --------------------------------------------------------------------


def test_a_403_is_coverage_403_and_keeps_the_other_collections() -> None:
    scenario = Scenario(
        status={name: 403 for name in ("users", "groups", "servers", "backup-repositories")},
        objects={"vms": [vm(1)]},
    )
    with probed(scenario) as (_, client):
        results = {spec.name: client.fetch(spec) for spec in client.resources()}
    for name in ("users", "groups", "servers", "backup-repositories"):
        assert not results[name].ok
        assert results[name].status == "403"
        assert results[name].error_class == ERROR_FORBIDDEN
        assert results[name].retryable is False
    assert results["vms"].ok
    assert results["hosts"].ok


def test_a_404_is_coverage_404_and_not_a_failure_of_the_run() -> None:
    with probed(Scenario(status={"acl-privileges": 404})) as (_, client):
        result = client.fetch(ResourceSpec("acl-privileges"))
    assert not result.ok
    assert result.status == "404"
    assert result.error_class == ERROR_NOT_AVAILABLE
    assert result.retryable is False


def test_an_invalid_line_fails_that_collection_only() -> None:
    raw = b'{"id": "a"}\nthis is not json\n{"id": "c"}\n'
    scenario = Scenario(raw={"vms": raw}, objects={"hosts": [{"id": "h-1", "name_label": "h"}]})
    with probed(scenario) as (_, client):
        bad = client.fetch(ResourceSpec("vms"))
        good = client.fetch(ResourceSpec("hosts"))
    assert not bad.ok
    assert bad.error_class == ERROR_BAD_PAYLOAD
    assert "this is not json" not in (bad.error_text or "")
    assert good.ok
    assert len(good.objects) == 1


@pytest.mark.parametrize(
    "raw",
    [b"[1, 2]\n", b'"text"\n', b'{"name_label": "no id"}\n', b'{"id": 5}\n', b'{"id": ""}\n'],
)
def test_a_line_that_is_not_an_object_with_an_id_fails_the_collection(raw: bytes) -> None:
    with probed(Scenario(raw={"vms": raw})) as (_, client):
        result = client.fetch(ResourceSpec("vms"))
    assert not result.ok
    assert result.error_class == ERROR_BAD_PAYLOAD


def test_a_truncated_stream_fails_the_collection() -> None:
    with probed(Scenario(truncate={"vms"})) as (_, client):
        result = client.fetch(ResourceSpec("vms"))
    assert not result.ok
    assert result.objects == ()


def test_a_slow_collection_times_out_and_the_next_one_still_works() -> None:
    scenario = Scenario(delay={"vms": 1.5}, objects={"hosts": [{"id": "h-1"}]})
    with probed(scenario, request_timeout=0.3) as (_, client):
        slow = client.fetch(ResourceSpec("vms"))
        fast = client.fetch(ResourceSpec("hosts"))
    assert not slow.ok
    assert slow.error_class == ERROR_TIMEOUT
    assert slow.retryable is True
    assert fast.ok


def test_a_server_error_is_a_retryable_failure() -> None:
    with probed(Scenario(status={"vms": 502})) as (_, client):
        result = client.fetch(ResourceSpec("vms"))
    assert not result.ok
    assert result.status == "502"
    assert result.retryable is True


# -- memory -----------------------------------------------------------------------------------


def test_a_collection_of_200000_objects_stays_under_100_mb_of_growth() -> None:
    scenario = Scenario(generated={"vms": 200_000})
    with probed(scenario, request_timeout=120.0) as (_, client):
        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            base, _ = tracemalloc.get_traced_memory()
            result = client.fetch(ResourceSpec("vms"))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert result.ok
    assert len(result.objects) == 200_000
    assert result.objects[0]["id"] == "vm-000000"
    assert result.objects[-1]["id"] == "vm-199999"
    assert peak - base < 100 * 1024 * 1024


# -- canary: the credential is nowhere but the cookie -----------------------------------------


def test_the_credential_never_appears_in_logs_errors_or_results(
    caplog: pytest.LogCaptureFixture,
) -> None:
    scenario = Scenario(
        echo_cookie=True,
        status={"users": 403, "groups": 404, "servers": 500},
        raw={"vms": b'{"id": "a"}\nnot json\n'},
        truncate={"hosts"},
        objects={"pools": [{"id": "p-1", "name_label": "pool"}]},
    )
    with caplog.at_level(logging.DEBUG):
        with probed(scenario) as (_, client):
            outputs = [repr(client.fetch(spec)) for spec in client.resources()]
        with connected(Scenario(status={"root": 401}, echo_cookie=True)) as (_, other):
            with pytest.raises(CollectorError) as caught:
                other.probe()
            outputs.append(str(caught.value))
    for text in outputs:
        assert CANARY_TOKEN not in text
    assert CANARY_TOKEN not in caplog.text
    assert CANARY_TOKEN not in repr(client.resources())


# -- expiry -----------------------------------------------------------------------------------


def make_client(
    server: FakeXo, *, expires_on: date | datetime | None = None, now: datetime = NOW
) -> XoClient:
    return XoClient(
        server.url,
        CANARY_TOKEN,
        allow_plain_http=True,
        expires_on=expires_on,
        clock=lambda: now,
    )


@pytest.mark.parametrize(
    ("days", "expiring"),
    [(-3, True), (0, True), (13, True), (14, True), (15, False), (90, False)],
)
def test_a_reported_expiry_within_14_days_or_past_sets_the_warning(
    days: int, expiring: bool
) -> None:
    expiration = ms(NOW + timedelta(days=days))
    scenario = Scenario(tokens=[{"id": CANARY_TOKEN, "expiration": expiration}])
    with fake_xo(scenario) as server:
        client = make_client(server)
        try:
            client.probe()
            assert client.credential_expires_at == datetime.fromtimestamp(expiration / 1000, UTC)
            assert client.token_expiring() is expiring
        finally:
            client.close()


def test_only_the_entry_of_the_credential_in_use_counts() -> None:
    tokens = [
        {"id": "CANARY-other-token", "expiration": ms(NOW + timedelta(days=1))},
        {"id": CANARY_TOKEN, "expiration": ms(NOW + timedelta(days=60))},
    ]
    with fake_xo(Scenario(tokens=tokens)) as server:
        client = make_client(server)
        try:
            client.probe()
            assert client.token_expiring() is False
        finally:
            client.close()


def test_an_iso_expiry_is_understood() -> None:
    tokens = [{"id": CANARY_TOKEN, "expiration": (NOW + timedelta(days=2)).isoformat()}]
    with fake_xo(Scenario(tokens=tokens)) as server:
        client = make_client(server)
        try:
            client.probe()
            assert client.token_expiring() is True
        finally:
            client.close()


@pytest.mark.parametrize(
    "scenario",
    [
        Scenario(tokens=None),
        Scenario(status={"tokens": 403}),
        Scenario(status={"tokens": 500}),
        Scenario(raw={"tokens": b"not json"}),
        Scenario(tokens=[{"id": CANARY_TOKEN}]),
        Scenario(tokens=[{"id": CANARY_TOKEN, "expiration": "soon"}]),
        Scenario(tokens=[{"id": CANARY_TOKEN, "expiration": True}]),
        Scenario(raw={"tokens": b'{"unexpected": "shape"}'}),
    ],
)
def test_a_failed_or_unreadable_expiry_read_falls_back_to_the_entered_date(
    scenario: Scenario,
) -> None:
    with fake_xo(scenario) as server:
        near = make_client(server, expires_on=NOW.date() + timedelta(days=3))
        far = make_client(server, expires_on=NOW.date() + timedelta(days=90))
        none = make_client(server)
        try:
            for client in (near, far, none):
                client.probe()  # the read is tolerated: the probe still succeeds
                assert client.credential_expires_at is None
            assert near.token_expiring() is True
            assert far.token_expiring() is False
            assert none.token_expiring() is False
        finally:
            near.close()
            far.close()
            none.close()


def test_the_reported_expiry_wins_over_the_entered_one() -> None:
    far = [{"id": CANARY_TOKEN, "expiration": ms(NOW + timedelta(days=90))}]
    near = [{"id": CANARY_TOKEN, "expiration": ms(NOW + timedelta(days=2))}]
    with fake_xo(Scenario(tokens=far)) as server:
        client = make_client(server, expires_on=NOW.date() + timedelta(days=1))
        try:
            client.probe()
            assert client.token_expiring() is False
        finally:
            client.close()
    with fake_xo(Scenario(tokens=near)) as server:
        client = make_client(server, expires_on=NOW.date() + timedelta(days=90))
        try:
            client.probe()
            assert client.token_expiring() is True
        finally:
            client.close()


def test_the_warning_follows_the_clock() -> None:
    clock = [NOW]
    scenario = Scenario(tokens=[{"id": CANARY_TOKEN, "expiration": ms(NOW + timedelta(days=20))}])
    with fake_xo(scenario) as server:
        client = XoClient(server.url, CANARY_TOKEN, allow_plain_http=True, clock=lambda: clock[0])
        try:
            client.probe()
            assert client.token_expiring() is False
            clock[0] = NOW + timedelta(days=7)
            assert client.token_expiring() is True
        finally:
            client.close()


def test_the_expiry_read_happens_once_per_probe() -> None:
    with fake_xo(Scenario(tokens=[])) as server:
        client = make_client(server)
        try:
            client.probe()
            client.token_expiring()
            client.token_expiring()
            assert len(server.requests_for("users/me/authentication_tokens")) == 1
        finally:
            client.close()
