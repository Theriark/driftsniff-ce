"""TLS modes against a local HTTPS server: trust, pin in the handshake, insecure (P7-T3).

Certificates are made at test time (``fake_tls``); none is committed. The key of the source is a
canary sent in a header: the tests that refuse a connection assert that the server received no
request byte at all, so the canary never left the client.
"""

import hashlib
import logging
import shutil
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from driftsniff.collectors.base import CollectorError, fetch_json, make_client
from driftsniff.collectors.tls import (
    ERROR_TLS,
    ERROR_TLS_PIN,
    MODE_CA_FILE,
    MODE_INSECURE,
    MODE_PINNED,
    MODE_VERIFY,
    TlsSettings,
)

from .fake_tls import FakeTlsServer, Pki, make_ca, make_pki, running_server

CANARY = "CANARY-tls-header-0001"
HEADERS = {"X-API-KEY": CANARY}


@pytest.fixture
def pki(tmp_path: Path) -> Pki:
    return make_pki(tmp_path / "pki")


@pytest.fixture
def server(pki: Pki) -> Iterator[FakeTlsServer]:
    with running_server(pki) as running:
        yield running


@pytest.fixture
def data_dir(tmp_path: Path, pki: Pki) -> Path:
    """A data folder whose ``ca`` folder holds the right CA as ``right.pem``."""
    folder = tmp_path / "data"
    (folder / "ca").mkdir(parents=True)
    shutil.copy(pki.ca_pem, folder / "ca" / "right.pem")
    return folder


def pin_of(pki: Pki) -> str:
    return hashlib.sha256(pki.server_der).hexdigest()


def get(server: FakeTlsServer, settings: TlsSettings | None, data_dir: Path) -> object:
    client = make_client(tls=settings, data_dir=data_dir)
    try:
        parsed, _ = fetch_json(client, f"{server.url}/info", headers=HEADERS)
    finally:
        client.close()
    return parsed


def test_verify_mode_is_the_default_and_refuses_an_unknown_ca(
    server: FakeTlsServer, data_dir: Path
) -> None:
    for settings in (None, TlsSettings(MODE_VERIFY)):
        with pytest.raises(CollectorError) as caught:
            get(server, settings, data_dir)
        assert caught.value.error_class == ERROR_TLS
    assert server.wait_finished(2)
    assert CANARY.encode() not in server.received


def test_ca_file_mode_trusts_its_ca(server: FakeTlsServer, data_dir: Path) -> None:
    settings = TlsSettings(MODE_CA_FILE, ca_file="right.pem")
    assert get(server, settings, data_dir) == {"ok": True}
    assert CANARY.encode() in server.received


def test_ca_file_mode_refuses_the_wrong_ca(server: FakeTlsServer, data_dir: Path) -> None:
    make_ca(data_dir / "ca", "wrong")
    settings = TlsSettings(MODE_CA_FILE, ca_file="wrong.pem")
    with pytest.raises(CollectorError) as caught:
        get(server, settings, data_dir)
    assert caught.value.error_class == ERROR_TLS
    assert server.wait_finished(1)
    assert server.received == b""


def test_pinned_mode_accepts_the_pinned_certificate_without_any_ca(
    server: FakeTlsServer, pki: Pki, data_dir: Path
) -> None:
    settings = TlsSettings(MODE_PINNED, pin=pin_of(pki))
    assert get(server, settings, data_dir) == {"ok": True}
    assert CANARY.encode() in server.received


def test_pinned_mismatch_is_refused_before_any_request_byte_is_sent(
    server: FakeTlsServer, data_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = TlsSettings(MODE_PINNED, pin="ab" * 32)
    with caplog.at_level(logging.DEBUG), pytest.raises(CollectorError) as caught:
        get(server, settings, data_dir)
    assert caught.value.error_class == ERROR_TLS_PIN
    assert CANARY not in str(caught.value)
    assert server.wait_finished(1)
    assert server.received == b""
    assert CANARY not in caplog.text


def test_pinned_mode_refuses_plain_http_without_connecting(data_dir: Path, pki: Pki) -> None:
    client = make_client(tls=TlsSettings(MODE_PINNED, pin=pin_of(pki)), data_dir=data_dir)
    try:
        with pytest.raises(CollectorError):
            fetch_json(client, "http://127.0.0.1:9/info", headers=HEADERS)
    finally:
        client.close()


def test_insecure_mode_accepts_an_untrusted_certificate(
    server: FakeTlsServer, data_dir: Path
) -> None:
    assert get(server, TlsSettings(MODE_INSECURE), data_dir) == {"ok": True}


def test_a_transport_and_tls_settings_exclude_each_other(data_dir: Path) -> None:
    with pytest.raises(ValueError, match="exclude"):
        make_client(transport=httpx.HTTPTransport(), tls=TlsSettings(), data_dir=data_dir)


def test_no_test_or_fixture_holds_a_key_or_certificate() -> None:
    marker = "-----" + "BEGIN "
    root = Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    # Other suites keep scanner samples on purpose; the TLS tests and the fixtures must be clean.
    for folder in (root / "contract", root / "fixtures"):
        for path in folder.rglob("*"):
            if not path.is_file() or path.suffix == ".pyc":
                continue
            if marker in path.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(path.relative_to(root)))
    assert offenders == []
    assert not [p for p in root.rglob("*") if p.suffix in {".pem", ".crt", ".key", ".p12"}]
