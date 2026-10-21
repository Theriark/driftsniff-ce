"""TLS option checks and the CA bundle loader (P7-T3): names, pins, size, PEM only."""

import ssl
from pathlib import Path

import pytest

from driftsniff.collectors.tls import (
    MAX_CA_BYTES,
    MODE_CA_FILE,
    MODE_INSECURE,
    MODE_PINNED,
    MODE_VERIFY,
    TlsConfigError,
    TlsSettings,
    check_options,
    load_ca_bundle,
    make_ssl_context,
    normalize_pin,
    settings_from_options,
)

PIN = "0123456789abcdef" * 4
BEGIN = "-----" + "BEGIN "
END = "-----" + "END "


def pem(label: str, body: str = "AAAA") -> str:
    return f"{BEGIN}{label}-----\n{body}\n{END}{label}-----\n"


def put(data_dir: Path, name: str, content: bytes | str) -> None:
    folder = data_dir / "ca"
    folder.mkdir(parents=True, exist_ok=True)
    raw = content.encode() if isinstance(content, str) else content
    (folder / name).write_bytes(raw)


def test_no_options_means_verify() -> None:
    assert settings_from_options({}) == TlsSettings(MODE_VERIFY)
    assert check_options({"tls_mode": "verify"}) == TlsSettings(MODE_VERIFY)


def test_each_mode_takes_exactly_its_value() -> None:
    assert check_options({"tls_mode": "ca_file", "tls_ca_file": "corp.pem"}) == TlsSettings(
        MODE_CA_FILE, ca_file="corp.pem"
    )
    assert check_options({"tls_mode": "pinned", "tls_pin": PIN}) == TlsSettings(
        MODE_PINNED, pin=PIN
    )
    assert check_options({"tls_mode": "insecure", "insecure": True}) == TlsSettings(MODE_INSECURE)
    bad: list[dict[str, object]] = [
        {"tls_mode": "ca_file"},
        {"tls_mode": "pinned"},
        {"tls_mode": "verify", "tls_pin": PIN},
        {"tls_mode": "pinned", "tls_pin": PIN, "tls_ca_file": "a.pem"},
        {"tls_mode": "insecure"},
        {"tls_mode": "verify", "insecure": True},
        {"tls_mode": "off"},
        {"tls_mode": "pinned", "tls_pin": PIN, "allow_plain_http": True},
    ]
    for options in bad:
        with pytest.raises(TlsConfigError):
            check_options(options)


@pytest.mark.parametrize("text", ["", "abc", PIN[:-1], PIN + "0", "g" * 64, "ab:" * 21 + "ab"])
def test_a_pin_is_exactly_64_hex_characters(text: str) -> None:
    with pytest.raises(TlsConfigError):
        normalize_pin(text)


def test_a_pin_is_stored_in_lower_case() -> None:
    assert normalize_pin(f"  {PIN.upper()} ") == PIN
    assert check_options({"tls_mode": "pinned", "tls_pin": PIN.upper()}).pin == PIN


@pytest.mark.parametrize(
    "name", ["", ".", "..", "../x.pem", "a/b.pem", "/etc/passwd", ".hidden", "a b.pem"]
)
def test_a_ca_file_is_a_plain_name(name: str) -> None:
    with pytest.raises(TlsConfigError):
        check_options({"tls_mode": "ca_file", "tls_ca_file": name})
    with pytest.raises(TlsConfigError):
        load_ca_bundle(name, Path("/nonexistent"))


def test_the_bundle_must_exist_and_be_pem_certificates(tmp_path: Path) -> None:
    with pytest.raises(TlsConfigError, match="does not exist"):
        load_ca_bundle("missing.pem", tmp_path)
    put(tmp_path, "good.pem", pem("CERTIFICATE"))
    assert "CERTIFICATE" in load_ca_bundle("good.pem", tmp_path)
    put(tmp_path, "text.pem", "hello")
    put(tmp_path, "binary.pem", bytes(range(128, 200)))
    put(tmp_path, "key.pem", pem("PRIVATE KEY"))
    put(tmp_path, "mixed.pem", pem("CERTIFICATE") + pem("PRIVATE KEY"))
    for name in ("text.pem", "binary.pem", "key.pem", "mixed.pem"):
        with pytest.raises(TlsConfigError):
            load_ca_bundle(name, tmp_path)


def test_the_bundle_is_at_most_64_kb(tmp_path: Path) -> None:
    head = pem("CERTIFICATE")
    put(tmp_path, "edge.pem", head + "#" * (MAX_CA_BYTES - len(head)))
    assert load_ca_bundle("edge.pem", tmp_path)
    put(tmp_path, "big.pem", head + "#" * (MAX_CA_BYTES - len(head) + 1))
    with pytest.raises(TlsConfigError, match="64 KB"):
        load_ca_bundle("big.pem", tmp_path)


def test_a_symbolic_link_is_refused(tmp_path: Path) -> None:
    put(tmp_path, "real.pem", pem("CERTIFICATE"))
    (tmp_path / "ca" / "link.pem").symlink_to(tmp_path / "ca" / "real.pem")
    with pytest.raises(TlsConfigError):
        load_ca_bundle("link.pem", tmp_path)


def test_a_bundle_openssl_cannot_load_is_refused(tmp_path: Path) -> None:
    put(tmp_path, "junk.pem", pem("CERTIFICATE", "not base64 !!"))
    with pytest.raises(TlsConfigError, match="no usable certificate"):
        make_ssl_context(TlsSettings(MODE_CA_FILE, ca_file="junk.pem"), tmp_path)


def test_every_context_has_a_tls_floor_and_the_right_checks() -> None:
    verify = make_ssl_context(TlsSettings(MODE_VERIFY))
    assert verify.verify_mode == ssl.CERT_REQUIRED and verify.check_hostname
    for settings in (TlsSettings(MODE_PINNED, pin=PIN), TlsSettings(MODE_INSECURE)):
        context = make_ssl_context(settings)
        assert context.verify_mode == ssl.CERT_NONE and not context.check_hostname
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
