"""The collectors connect to the address they checked, not to the name (gap G1, DNS rebinding).

``probe()`` resolves the host name once, checks every answer and pins the first one. The host names
below (``rebind.invalid``) do not exist in DNS: a request that succeeds can only have gone to the
pinned address, so no second lookup of the name was made, and a resolver that answers differently
on a later call proves that the later answer is never used. The TLS tests run against a local
HTTPS server and show that the host name check, the pin check and the insecure mode still work
when the connection goes to a pinned address.
"""

import hashlib
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from driftsniff.collectors.base import (
    ERROR_CONNECTION,
    CollectorError,
    ResourceSpec,
    fetch_json,
    make_client,
)
from driftsniff.collectors.resolve import ERROR_BLOCKED_ADDRESS, pin_address
from driftsniff.collectors.tls import (
    ERROR_TLS,
    ERROR_TLS_PIN,
    MODE_CA_FILE,
    MODE_INSECURE,
    MODE_PINNED,
    MODE_VERIFY,
    AddressPin,
    TlsSettings,
)
from driftsniff.collectors.unifi.client import ERROR_NOT_PROBED, UnifiClient
from driftsniff.collectors.xo.client import XoClient

from . import fake_unifi, fake_xo
from .fake_tls import FakeTlsServer, Pki, make_pki, running_server

ALLOWED = "127.0.0.1"
BLOCKED = "169.254.169.254"
NAME = "rebind.invalid"
CANARY = "CANARY-pinning-header-0001"
HEADERS = {"X-API-KEY": CANARY}


class ChangingResolver:
    """Answers with the first list once and the second list on every later call."""

    def __init__(self, first: list[str], later: list[str]) -> None:
        self._answers = [first, later]
        self.calls: list[str] = []

    def __call__(self, host: str) -> list[str]:
        self.calls.append(host)
        return self._answers[min(len(self.calls), 2) - 1]


def port_of(url: str) -> int:
    return int(url.rsplit(":", 1)[1])


# -- pin_address -------------------------------------------------------------------------------


def test_the_first_answer_is_the_address_and_a_zone_suffix_is_removed() -> None:
    assert pin_address("https://xo.example.test", lambda host: ["192.0.2.10", "2001:db8::1"]) == (
        "192.0.2.10"
    )
    assert pin_address("https://xo.example.test", lambda host: ["2001:db8::1%eth0"]) == (
        "2001:db8::1"
    )


@pytest.mark.parametrize(
    "answers",
    [
        [BLOCKED],
        [ALLOWED, BLOCKED],
        ["::ffff:169.254.169.254"],
        ["fe80::1%eth0"],
        ["100.100.100.200"],
        ["not-an-address"],
    ],
)
def test_a_blocked_or_unusable_answer_in_any_position_gives_no_address(
    answers: list[str],
) -> None:
    with pytest.raises(CollectorError) as caught:
        pin_address("https://xo.example.test", lambda host: answers)
    assert caught.value.error_class == ERROR_BLOCKED_ADDRESS


def test_no_answer_gives_no_address() -> None:
    with pytest.raises(CollectorError) as caught:
        pin_address("https://xo.example.test", lambda host: [])
    assert caught.value.error_class == ERROR_CONNECTION


# -- the collectors ----------------------------------------------------------------------------


def test_unifi_connects_to_the_first_answer_and_never_uses_a_later_one() -> None:
    resolver = ChangingResolver([ALLOWED], [BLOCKED])
    scenario = fake_unifi.Scenario(objects={"networks": [{"id": "net-1", "name": "net"}]})
    with fake_unifi.fake_unifi(scenario) as server:
        client = UnifiClient(
            f"http://{NAME}:{port_of(server.url)}",
            fake_unifi.CANARY_HEADER,
            allow_plain_http=True,
            resolver=resolver,
        )
        try:
            client.probe()
            result = client.fetch(ResourceSpec("unifi-networks"))
        finally:
            client.close()
        assert result.ok
        assert len(server.requests) >= 3  # info, sites and the networks of the site
    assert resolver.calls == [NAME]


def test_xo_connects_to_the_first_answer_and_never_uses_a_later_one() -> None:
    resolver = ChangingResolver([ALLOWED], [BLOCKED])
    scenario = fake_xo.Scenario(objects={"pools": [{"id": "p-1", "name_label": "pool"}]})
    with fake_xo.fake_xo(scenario) as server:
        client = XoClient(
            f"http://{NAME}:{port_of(server.url)}",
            fake_xo.CANARY_TOKEN,
            allow_plain_http=True,
            resolver=resolver,
        )
        try:
            client.probe()
            result = client.fetch(ResourceSpec("pools"))
        finally:
            client.close()
        assert result.ok
        assert len(server.requests) >= 2
    assert resolver.calls == [NAME]


def test_unifi_new_probe_is_a_new_lookup_and_a_blocked_answer_stops_the_run() -> None:
    resolver = ChangingResolver([ALLOWED], [BLOCKED])
    with fake_unifi.fake_unifi() as server:
        client = UnifiClient(
            f"http://{NAME}:{port_of(server.url)}",
            fake_unifi.CANARY_HEADER,
            allow_plain_http=True,
            resolver=resolver,
        )
        try:
            client.probe()
            before = len(server.requests)
            with pytest.raises(CollectorError) as caught:
                client.probe()
            assert caught.value.error_class == ERROR_BLOCKED_ADDRESS
            with pytest.raises(CollectorError) as refused:
                client.fetch(ResourceSpec("unifi-networks"))
            assert refused.value.error_class == ERROR_NOT_PROBED
        finally:
            client.close()
        assert len(server.requests) == before


def test_xo_new_probe_is_a_new_lookup_and_a_blocked_answer_stops_the_run() -> None:
    resolver = ChangingResolver([ALLOWED], [BLOCKED])
    with fake_xo.fake_xo() as server:
        client = XoClient(
            f"http://{NAME}:{port_of(server.url)}",
            fake_xo.CANARY_TOKEN,
            allow_plain_http=True,
            resolver=resolver,
        )
        try:
            client.probe()
            before = len(server.requests)
            with pytest.raises(CollectorError) as caught:
                client.probe()
            assert caught.value.error_class == ERROR_BLOCKED_ADDRESS
            with pytest.raises(CollectorError):
                client.fetch(ResourceSpec("pools"))
        finally:
            client.close()
        assert len(server.requests) == before


@pytest.mark.parametrize("answers", [[BLOCKED], [ALLOWED, BLOCKED]])
def test_a_blocked_answer_sends_nothing_to_either_collector(answers: list[str]) -> None:
    with fake_unifi.fake_unifi() as unifi, fake_xo.fake_xo() as xo:
        clients: list[Any] = [
            UnifiClient(
                f"http://{NAME}:{port_of(unifi.url)}",
                fake_unifi.CANARY_HEADER,
                allow_plain_http=True,
                resolver=lambda host: answers,
            ),
            XoClient(
                f"http://{NAME}:{port_of(xo.url)}",
                fake_xo.CANARY_TOKEN,
                allow_plain_http=True,
                resolver=lambda host: answers,
            ),
        ]
        for client in clients:
            try:
                with pytest.raises(CollectorError) as caught:
                    client.probe()
                assert caught.value.error_class == ERROR_BLOCKED_ADDRESS
            finally:
                client.close()
        assert unifi.requests == []
        assert xo.requests == []


# -- the transport -----------------------------------------------------------------------------


def test_a_connection_without_a_pinned_address_fails_closed() -> None:
    client = make_client(address=AddressPin())
    try:
        with pytest.raises(CollectorError) as caught:
            fetch_json(client, f"http://{NAME}:9/info", headers=HEADERS)
    finally:
        client.close()
    assert caught.value.error_class == ERROR_CONNECTION


def test_a_transport_and_an_address_pin_exclude_each_other() -> None:
    with pytest.raises(ValueError, match="exclude"):
        make_client(transport=httpx.HTTPTransport(), address=AddressPin())


# -- the TLS modes with a pinned address -------------------------------------------------------


@pytest.fixture
def pki(tmp_path: Path) -> Pki:
    return make_pki(tmp_path / "pki")


@pytest.fixture
def server(pki: Pki) -> Iterator[FakeTlsServer]:
    with running_server(pki) as running:
        yield running


@pytest.fixture
def data_dir(tmp_path: Path, pki: Pki) -> Path:
    folder = tmp_path / "data"
    (folder / "ca").mkdir(parents=True)
    shutil.copy(pki.ca_pem, folder / "ca" / "right.pem")
    return folder


def get(
    server: FakeTlsServer, name: str, settings: TlsSettings | None, data_dir: Path
) -> object:
    """GET /info of the TLS server under ``name``; the connection goes to the pinned 127.0.0.1."""
    pin = AddressPin()
    pin.set(ALLOWED)
    client = make_client(tls=settings, data_dir=data_dir, address=pin)
    try:
        url = f"https://{name}:{port_of(server.url)}/info"
        parsed, _ = fetch_json(client, url, headers=HEADERS)
    finally:
        client.close()
    return parsed


def test_verify_mode_checks_the_chain_with_a_pinned_address(
    server: FakeTlsServer, data_dir: Path
) -> None:
    for settings in (None, TlsSettings(MODE_VERIFY)):
        with pytest.raises(CollectorError) as caught:
            get(server, "localhost", settings, data_dir)
        assert caught.value.error_class == ERROR_TLS
    assert server.wait_finished(2)
    assert CANARY.encode() not in server.received


def test_ca_file_mode_checks_the_host_name_with_a_pinned_address(
    server: FakeTlsServer, data_dir: Path
) -> None:
    settings = TlsSettings(MODE_CA_FILE, ca_file="right.pem")
    assert get(server, "localhost", settings, data_dir) == {"ok": True}
    assert CANARY.encode() in server.received


def test_ca_file_mode_refuses_a_name_the_certificate_does_not_cover(
    server: FakeTlsServer, data_dir: Path
) -> None:
    settings = TlsSettings(MODE_CA_FILE, ca_file="right.pem")
    with pytest.raises(CollectorError) as caught:
        get(server, "wrong-name.example", settings, data_dir)
    assert caught.value.error_class == ERROR_TLS
    assert server.wait_finished(1)
    assert server.received == b""


def test_pinned_mode_accepts_the_pinned_certificate_with_a_pinned_address(
    server: FakeTlsServer, pki: Pki, data_dir: Path
) -> None:
    pin = hashlib.sha256(pki.server_der).hexdigest()
    assert get(server, NAME, TlsSettings(MODE_PINNED, pin=pin), data_dir) == {"ok": True}
    assert CANARY.encode() in server.received


def test_pinned_mismatch_sends_no_request_byte_with_a_pinned_address(
    server: FakeTlsServer, data_dir: Path
) -> None:
    with pytest.raises(CollectorError) as caught:
        get(server, NAME, TlsSettings(MODE_PINNED, pin="ab" * 32), data_dir)
    assert caught.value.error_class == ERROR_TLS_PIN
    assert server.wait_finished(1)
    assert server.received == b""


def test_insecure_mode_accepts_an_untrusted_certificate_with_a_pinned_address(
    server: FakeTlsServer, data_dir: Path
) -> None:
    assert get(server, NAME, TlsSettings(MODE_INSECURE), data_dir) == {"ok": True}
