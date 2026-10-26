"""The UniFi client against a fake controller on localhost (P7-T2).

Every case of the plan has a test and its expected coverage status: the version floor, a version
below it, paging boundaries (exactly 200, 201, 400 objects, empty), a repeated page, a 404 on one
resource, a 403, a truncated body, invalid JSON, a slow response and the base path fallback. The
credential canary must never appear in a log record, an error text or a request line, and an
unsupported version must not run a collection.

The names the fake serves are unverified against the vendor reference (dependency D5).
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import parse_qs

import pytest
from pydantic import ValidationError

from driftsniff.collectors.base import (
    ERROR_BAD_JSON,
    ERROR_CONNECTION,
    ERROR_HTTP,
    ERROR_TIMEOUT,
    STATUS_ERROR,
    CollectorError,
    ResourceSpec,
)
from driftsniff.collectors.resolve import ERROR_BLOCKED_ADDRESS, system_resolver
from driftsniff.collectors.unifi.client import (
    ERROR_BAD_PAYLOAD,
    ERROR_FORBIDDEN,
    ERROR_NO_API,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_PROBED,
    ERROR_PAGING_LOOP,
    ERROR_UNAUTHORIZED,
    ERROR_UNSUPPORTED_VERSION,
    FLOOR_VERSION,
    PAGE_LIMIT,
    UnifiClient,
    UnsupportedVersionError,
    parse_version,
)
from driftsniff.collectors.unifi.models import InfoAnswer, ObjectRef, PageEnvelope
from driftsniff.collectors.unifi.resources import RESOURCE_SITES, RESOURCES
from driftsniff.rules.loader import load_rules
from driftsniff.sources.addresses import AddressError

from .fake_unifi import CANARY_HEADER, FakeUnifi, Scenario, fake_unifi

DIRECT = "/integration"
PROXY = "/proxy/network/integration"


def make_objects(prefix: str, count: int) -> list[dict[str, Any]]:
    return [{"id": f"{prefix}-{index:04d}", "name": f"{prefix} {index}"} for index in range(count)]


@contextmanager
def connected(
    scenario: Scenario | None = None,
    **options: Any,
) -> Iterator[tuple[FakeUnifi, UnifiClient]]:
    """A fake controller and a client for it; the client is closed at the end."""
    with fake_unifi(scenario) as server:
        client = UnifiClient(server.url, CANARY_HEADER, allow_plain_http=True, **options)
        try:
            yield server, client
        finally:
            client.close()


def offsets(server: FakeUnifi, suffix: str) -> list[int]:
    return [int(parse_qs(request.query)["offset"][0]) for request in server.requests_for(suffix)]


# -- version floor and probe -------------------------------------------------------------------


def test_the_floor_is_the_one_of_the_plan() -> None:
    assert FLOOR_VERSION == (10, 1, 84)
    assert PAGE_LIMIT == 200


@pytest.mark.parametrize(
    "version",
    ["10.1.84", "10.1.85", "10.2.0", "10.3.58", "10.10.0", "11.0.1", "10.1.84-rc1"],
)
def test_a_version_at_or_above_the_floor_is_accepted(version: str) -> None:
    with connected(Scenario(version=version)) as (server, client):
        assert client.probe() == version
        assert client.base_path == DIRECT
        assert [request.path for request in server.requests] == [f"{DIRECT}/v1/info"]


@pytest.mark.parametrize("version", ["10.1.83", "10.1.0", "10.0.200", "9.9.9", "1.0.0"])
def test_a_version_below_the_floor_is_unsupported_and_runs_no_collection(version: str) -> None:
    scenario = Scenario(version=version, objects={"networks": make_objects("net", 3)})
    with connected(scenario) as (server, client):
        with pytest.raises(UnsupportedVersionError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_UNSUPPORTED_VERSION
        assert version in str(caught.value)
        assert "10.1.84" in str(caught.value)
        assert caught.value.retryable is False
        with pytest.raises(CollectorError) as refused:
            client.fetch(ResourceSpec("unifi-networks"))
        assert refused.value.error_class == ERROR_NOT_PROBED
        assert [request.path for request in server.requests] == [f"{DIRECT}/v1/info"]


def test_a_version_that_cannot_be_read_is_unsupported_and_is_not_echoed() -> None:
    with connected(Scenario(version="CANARY-version-text")) as (server, client):
        with pytest.raises(UnsupportedVersionError) as caught:
            client.probe()
        assert "CANARY-version-text" not in str(caught.value)
        assert len(server.requests) == 1


def test_the_version_is_compared_as_integer_tuples_not_as_text() -> None:
    nine = parse_version("10.9.0")
    ten = parse_version("10.10.0")
    assert nine is not None
    assert ten is not None
    assert ten == (10, 10, 0)
    assert ten > FLOOR_VERSION
    assert nine < ten
    assert "10.9.0" > "10.10.0"  # the text order would get it wrong


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10.1.84", (10, 1, 84)),
        (" 10.1.84 ", (10, 1, 84)),
        ("10.1.84-rc1", (10, 1, 84)),
        ("10.10.0", (10, 10, 0)),
        ("10.1", None),
        ("v10.1.84", None),
        ("", None),
        ("10.x.1", None),
        ("10.1.84; drop table", None),
    ],
)
def test_parse_version(text: str, expected: tuple[int, int, int] | None) -> None:
    assert parse_version(text) == expected


def test_the_direct_path_is_tried_first_and_the_proxy_path_is_the_fallback() -> None:
    with connected(Scenario(base_path=PROXY)) as (server, client):
        client.probe()
        assert client.base_path == PROXY
        assert [request.path for request in server.requests] == [
            f"{DIRECT}/v1/info",
            f"{PROXY}/v1/info",
        ]


def test_a_web_page_on_the_direct_path_falls_back_to_the_proxy_path() -> None:
    with connected(Scenario(base_path=PROXY, html_elsewhere=True)) as (server, client):
        client.probe()
        assert client.base_path == PROXY
        assert len(server.requests) == 2


def test_a_stored_base_path_is_tried_first() -> None:
    with connected(Scenario(base_path=PROXY), base_path=PROXY) as (server, client):
        client.probe()
        assert [request.path for request in server.requests] == [f"{PROXY}/v1/info"]


def test_a_stored_base_path_that_no_longer_answers_falls_back_to_the_other() -> None:
    with connected(Scenario(base_path=DIRECT), base_path=PROXY) as (server, client):
        client.probe()
        assert client.base_path == DIRECT
        assert len(server.requests) == 2


def test_a_stored_base_path_outside_the_two_known_ones_is_ignored() -> None:
    with connected(Scenario(), base_path="/somewhere/else") as (server, client):
        client.probe()
        assert [request.path for request in server.requests] == [f"{DIRECT}/v1/info"]


def test_no_base_path_that_answers_is_a_plain_error() -> None:
    with connected(Scenario(base_path="/elsewhere")) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_NO_API
        assert client.base_path is None
        assert len(server.requests) == 2


@pytest.mark.parametrize("body", [b"<html>", b'{"unrelated": 1}', b"[]"])
def test_an_information_answer_that_is_not_one_does_not_win(body: bytes) -> None:
    with connected(Scenario(raw={"info": body})) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_NO_API


@pytest.mark.parametrize(
    ("status", "error_class"),
    [(401, ERROR_UNAUTHORIZED), (403, ERROR_FORBIDDEN)],
)
def test_a_refused_credential_stops_the_probe_with_that_status(
    status: int,
    error_class: str,
) -> None:
    with connected(Scenario(status={"info": status})) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == error_class
        assert caught.value.status == str(status)
        assert len(server.requests) == 1


def test_a_wrong_key_is_unauthorized() -> None:
    with connected(Scenario(expected_header="CANARY-another-header-0002")) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_UNAUTHORIZED
        assert caught.value.status == "401"


def test_a_server_error_on_the_information_call_is_not_a_reason_to_try_the_other_path() -> None:
    with connected(Scenario(status={"info": 500})) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_HTTP
        assert caught.value.retryable is True
        assert len(server.requests) == 1


def test_a_slow_information_call_times_out() -> None:
    with connected(Scenario(delay={"info": 1.0}), request_timeout=0.2) as (_, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_TIMEOUT
        assert caught.value.retryable is True


# -- paging ------------------------------------------------------------------------------------


@pytest.mark.parametrize("with_total", [True, False])
@pytest.mark.parametrize("count", [0, 1, 199, 200, 201, 400, 401])
def test_paging_boundaries(count: int, with_total: bool) -> None:
    stored = make_objects("net", count)
    scenario = Scenario(objects={"networks": stored}, omit_total=not with_total)
    with connected(scenario) as (server, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is True
        assert result.status == "200"
        assert [item["id"] for item in result.objects] == [item["id"] for item in stored]
        assert result.bytes_fetched > 0
        pages = max(1, -(-count // PAGE_LIMIT)) if with_total else count // PAGE_LIMIT + 1
        assert offsets(server, "/networks") == [PAGE_LIMIT * index for index in range(pages)]
        pages_asked = server.requests_for("/networks")
        assert {parse_qs(request.query)["limit"][0] for request in pages_asked} == {"200"}


def test_a_controller_that_caps_its_page_size_still_gives_every_object() -> None:
    stored = make_objects("net", 120)
    with connected(Scenario(objects={"networks": stored}, page_cap=50)) as (server, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is True
        assert len(result.objects) == 120
        assert offsets(server, "/networks") == [0, 50, 100]


def test_a_list_that_ends_before_its_reported_total_is_not_a_complete_list() -> None:
    scenario = Scenario(objects={"networks": make_objects("net", 120)})
    scenario.total_override["networks"] = 300
    with connected(scenario) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is False
        assert result.error_class == ERROR_BAD_PAYLOAD
        assert result.objects == ()


@pytest.mark.parametrize("omit_total", [True, False])
def test_a_repeated_page_stops_the_loop_with_paging_loop(omit_total: bool) -> None:
    scenario = Scenario(
        objects={"networks": make_objects("net", 200)},
        ignore_offset={"networks"},
        omit_total=omit_total,
    )
    scenario.total_override["networks"] = 600
    with connected(scenario) as (server, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is False
        assert result.error_class == ERROR_PAGING_LOOP
        assert result.status == STATUS_ERROR
        assert len(server.requests_for("/networks")) == 2


def test_the_objects_of_every_site_are_collected_and_sites_are_listed() -> None:
    scenario = Scenario(sites=["site-a", "site-b"])
    scenario.site_objects[("site-a", "networks")] = make_objects("a", 2)
    scenario.site_objects[("site-b", "networks")] = make_objects("b", 3)
    with connected(scenario) as (server, client):
        client.probe()
        sites = client.fetch(ResourceSpec(RESOURCE_SITES))
        networks = client.fetch(ResourceSpec("unifi-networks"))
        assert [item["id"] for item in sites.objects] == ["site-a", "site-b"]
        assert [item["id"] for item in networks.objects] == [
            "a-0000",
            "a-0001",
            "b-0000",
            "b-0001",
            "b-0002",
        ]
        assert len(server.requests_for("/sites/site-a/networks")) == 1
        assert len(server.requests_for("/sites/site-b/networks")) == 1
        # The site list is read once for the sites resource and reused for the others.
        assert len(server.requests_for("/sites")) == 1


def test_objects_reach_the_pipeline_untouched() -> None:
    stored = [{"id": "n1", "name": "LAN", "vendorOnlyField": {"nested": [1, 2]}, "extra": None}]
    with connected(Scenario(objects={"networks": stored})) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert list(result.objects) == stored


def test_a_site_id_that_could_change_the_path_is_refused() -> None:
    with connected(Scenario(sites=["../admin"])) as (server, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is False
        assert result.error_class == ERROR_BAD_PAYLOAD
        assert all("admin" not in request.path for request in server.requests_for("/networks"))
        assert server.requests_for("/networks") == []


# -- coverage statuses -------------------------------------------------------------------------


def test_a_404_on_one_resource_is_not_available_and_the_others_still_read() -> None:
    scenario = Scenario(status={"wans": 404}, objects={"networks": make_objects("net", 2)})
    with connected(scenario) as (_, client):
        client.probe()
        missing = client.fetch(ResourceSpec("unifi-wans"))
        other = client.fetch(ResourceSpec("unifi-networks"))
        assert missing.ok is False
        assert missing.status == "404"
        assert missing.error_class == ERROR_NOT_AVAILABLE
        assert missing.retryable is False
        assert other.ok is True
        assert len(other.objects) == 2


def test_a_403_is_forbidden_and_is_not_retried() -> None:
    with connected(Scenario(status={"radius/profiles": 403})) as (server, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-radius-profiles"))
        assert result.ok is False
        assert result.status == "403"
        assert result.error_class == ERROR_FORBIDDEN
        assert result.retryable is False
        assert len(server.requests_for("/radius/profiles")) == 1


def test_a_403_on_the_site_list_gives_the_same_status_to_a_site_resource() -> None:
    with connected(Scenario(status={"sites": 403})) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.status == "403"
        assert result.error_class == ERROR_FORBIDDEN


def test_a_server_error_is_retryable_by_the_pipeline() -> None:
    with connected(Scenario(status={"networks": 503})) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is False
        assert result.status == "503"
        assert result.retryable is True


def test_a_truncated_body_is_a_failed_read() -> None:
    with connected(Scenario(truncate={"networks"})) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is False
        assert result.error_class in (ERROR_CONNECTION, ERROR_BAD_JSON)
        assert result.objects == ()


def test_invalid_json_is_bad_json() -> None:
    with connected(Scenario(raw={"networks": b"{not json"})) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is False
        assert result.error_class == ERROR_BAD_JSON
        assert result.retryable is False


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"data": 5}',
        b'{"data": [1, 2]}',
        b'{"totalCount": 3}',
        b'{"data": [], "totalCount": "3"}',
    ],
)
def test_json_that_is_not_a_page_is_bad_payload(body: bytes) -> None:
    with connected(Scenario(raw={"networks": body})) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is False
        assert result.error_class == ERROR_BAD_PAYLOAD


def test_a_slow_resource_times_out_and_can_be_retried() -> None:
    with connected(Scenario(delay={"networks": 1.0}), request_timeout=0.2) as (_, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-networks"))
        assert result.ok is False
        assert result.error_class == ERROR_TIMEOUT
        assert result.status == STATUS_ERROR
        assert result.retryable is True


def test_a_resource_the_client_does_not_read_is_a_plain_failure() -> None:
    with connected() as (server, client):
        client.probe()
        result = client.fetch(ResourceSpec("unifi-site-settings"))
        assert result.ok is False
        assert result.error_class == "unknown_resource"
        assert len(server.requests) == 1


def test_fetch_before_the_probe_is_refused() -> None:
    with connected() as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.fetch(ResourceSpec("unifi-networks"))
        assert caught.value.error_class == ERROR_NOT_PROBED
        assert server.requests == []


# -- the credential never leaks ----------------------------------------------------------------


def test_the_credential_only_travels_in_the_key_header_and_never_shows(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    scenario = Scenario(
        echo_header=True,
        objects={"networks": make_objects("net", 3)},
        status={"wans": 500, "dns/policies": 404, "devices": 403},
        raw={"firewall/zones": b"{not json", "acl-rules": b"[]"},
        truncate={"wifi/broadcasts"},
    )
    shown: list[str] = []
    with connected(scenario) as (server, client):
        client.probe()
        for item in RESOURCES:
            result = client.fetch(ResourceSpec(item.name))
            shown.extend([result.error_text or "", result.error_class or "", result.status])
        scenario.status["info"] = 500
        scenario.status["sites"] = 500
        with pytest.raises(CollectorError) as failed:
            client.probe()
        shown.append(str(failed.value))
        scenario.status.pop("info")
        scenario.expected_header = "CANARY-another-header-0002"
        with pytest.raises(CollectorError) as refused:
            client.probe()
        shown.append(str(refused.value))
        assert server.requests
        for request in server.requests:
            assert CANARY_HEADER not in request.path
            assert CANARY_HEADER not in request.query
        right = [request for request in server.requests if request.header == CANARY_HEADER]
        assert len(right) >= len(RESOURCES)
    assert all(CANARY_HEADER not in text for text in shown)
    assert CANARY_HEADER not in caplog.text


def test_a_credential_a_header_cannot_carry_is_refused_without_showing_it() -> None:
    for bad in ["", "has space", "line\nbreak", "tab\tbed", "ünïcode"]:
        with pytest.raises(ValueError) as caught:
            UnifiClient("https://203.0.113.10", bad)
        if bad:
            assert bad not in str(caught.value)


def test_a_base_address_that_is_blocked_is_refused_by_the_client() -> None:
    with pytest.raises(AddressError):
        UnifiClient("https://169.254.169.254", CANARY_HEADER)
    with pytest.raises(AddressError):
        UnifiClient("http://203.0.113.10", CANARY_HEADER)


# -- addresses ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "resolved",
    [
        ["169.254.169.254"],
        ["127.0.0.1", "169.254.169.254"],
        ["::ffff:169.254.169.254"],
        ["fe80::1%eth0"],
        ["100.100.100.200"],
    ],
)
def test_an_address_a_name_resolves_to_is_checked_before_any_request(resolved: list[str]) -> None:
    with connected(resolver=lambda host: resolved) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_BLOCKED_ADDRESS
        assert server.requests == []


def test_a_resolved_value_that_is_not_an_address_is_refused() -> None:
    with connected(resolver=lambda host: ["not-an-address"]) as (server, client):
        with pytest.raises(CollectorError) as caught:
            client.probe()
        assert caught.value.error_class == ERROR_BLOCKED_ADDRESS
        assert server.requests == []


def test_a_name_that_resolves_to_an_allowed_address_is_used() -> None:
    seen: list[str] = []

    def resolver(host: str) -> list[str]:
        seen.append(host)
        return ["127.0.0.1"]

    with connected(resolver=resolver) as (_, client):
        client.probe()
    assert seen == ["127.0.0.1"]


def test_the_system_resolver_gives_literal_addresses_back_and_fails_plainly() -> None:
    assert "127.0.0.1" in system_resolver("127.0.0.1")
    with pytest.raises(CollectorError) as caught:
        system_resolver("\udcff")
    assert caught.value.error_class == ERROR_CONNECTION


# -- resources and models ----------------------------------------------------------------------


def test_the_resources_are_unique_have_type_tables_and_start_with_sites() -> None:
    names = [item.name for item in RESOURCES]
    assert names[0] == RESOURCE_SITES
    assert len(set(names)) == len(names)
    tables = load_rules().type_tables
    assert set(names) <= set(tables)
    # No endpoint is known for site settings (docs/vendor-notes/unifi.md), so it is not read.
    assert "unifi-site-settings" not in names
    assert all(item.site_path is None or item.site_path.startswith("/") for item in RESOURCES)


def test_the_client_lists_its_resources_for_the_pipeline() -> None:
    with connected() as (_, client):
        specs = client.resources()
        assert [spec.name for spec in specs] == [item.name for item in RESOURCES]


def test_the_paging_envelope_reads_the_total_and_ignores_the_rest() -> None:
    payload = {"offset": 0, "limit": 200, "count": 1, "totalCount": 5, "data": [{"a": 1}]}
    page = PageEnvelope.model_validate({**payload, "more": True})
    assert page.total_count == 5
    assert page.data == [{"a": 1}]
    assert PageEnvelope.model_validate({"data": []}).total_count is None


@pytest.mark.parametrize(
    "payload",
    [{}, {"data": {}}, {"data": [], "totalCount": "5"}, {"data": [], "totalCount": 1.5}],
)
def test_a_bad_paging_envelope_is_rejected(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        PageEnvelope.model_validate(payload)


def test_an_object_ref_reads_only_the_key_and_the_name() -> None:
    ref = ObjectRef.model_validate({"id": "abc", "name": "LAN", "other": 1})
    assert (ref.id, ref.name) == ("abc", "LAN")
    assert ObjectRef.model_validate({"id": "abc"}).name is None
    for bad in ({}, {"id": ""}, {"id": 5}, {"id": "x" * 129}):
        with pytest.raises(ValidationError):
            ObjectRef.model_validate(bad)


def test_the_information_answer_reads_the_application_version() -> None:
    answer = InfoAnswer.model_validate({"applicationVersion": "10.1.84"})
    assert answer.application_version == "10.1.84"
    with pytest.raises(ValidationError):
        InfoAnswer.model_validate({"version": "10.1.84"})
