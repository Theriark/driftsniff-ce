"""The QNAP XML parsing and extraction, the shipped QNAP pack and type tables, and the wiring
(factory branch, the ``username`` source option).

The fixtures in tests/fixtures/qnap are synthetic answers in the shape of docs/vendor-notes/qnap.md.
"""

from pathlib import Path

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.qnap import normalize
from driftsniff.collectors.qnap.client import QnapClient
from driftsniff.collectors.qnap.resources import RESOURCES
from driftsniff.core.canonical import JsonValue
from driftsniff.core.diff import ChangeItem, ChangeKind
from driftsniff.core.normalize import FieldClass
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.sources.factory import build_collector
from driftsniff.sources.service import (
    OPTION_USERNAME,
    SourceValidationError,
    _check_options,
    _check_type_options,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "qnap"
WEB, SYSTEM, NICS = "qnap-web-services", "qnap-system", "qnap-network-interfaces"
VOLUMES, SHARES, APPS = "qnap-volumes", "qnap-shared-folders", "qnap-apps"


def document(name: str) -> normalize.Element:
    return normalize.parse_document((FIXTURES / name).read_bytes())


# ---- parsing ----------------------------------------------------------------------------------


def test_cdata_values_are_read_and_stripped() -> None:
    root = document("login.xml")
    assert normalize.text_of(root, "authSid") == "s0000001"
    assert normalize.text_of(root, "missing") is None


@pytest.mark.parametrize(
    "body",
    [
        b'<!DOCTYPE QDocRoot [<!ENTITY a "x">]><QDocRoot>&a;</QDocRoot>',
        b'<!DOCTYPE QDocRoot SYSTEM "http://example.invalid/x.dtd"><QDocRoot/>',
        b"<!DOCTYPE QDocRoot><QDocRoot/>",
    ],
)
def test_any_document_type_declaration_is_refused(body: bytes) -> None:
    with pytest.raises(CollectorError) as caught:
        normalize.parse_document(body)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD
    assert "document type" in str(caught.value)


@pytest.mark.parametrize("body", [b"", b"<other/>", b"<QDocRoot>", b"\xff\xfe", b"<a/><b/>"])
def test_what_is_not_a_qnap_document_is_bad_payload(body: bytes) -> None:
    with pytest.raises(CollectorError) as caught:
        normalize.parse_document(body)
    assert str(caught.value) == "the answer is not a QNAP XML document"


# ---- extraction -------------------------------------------------------------------------------


def test_the_system_object() -> None:
    root = document("sysinfo.xml")
    assert normalize.firmware_version(root) == "5.1.4"
    (system,) = normalize.system(root)
    assert system["dnsServers"] == ["192.0.2.53", "198.51.100.53"]
    assert set(system) == {"id", "hostname", "model", "firmware", "timezone", "dnsServers"}


def test_interfaces_take_no_counters() -> None:
    interfaces = normalize.network_interfaces(document("sysinfo.xml"))
    assert [item["ifname"] for item in interfaces] == ["eth0", "eth1"]
    assert all("rx_packet" not in str(item) for item in interfaces)
    assert interfaces[1]["eth_usage"] == "DHCP"


def test_volumes_and_shared_folders_take_no_sizes() -> None:
    root = document("disk_usage.xml")
    assert [item["volumeLabel"] for item in normalize.volumes(root)] == ["DataVol1", "Scratch"]
    shares = normalize.shared_folders(root)
    assert {item["sharename"]: item["volumeValue"] for item in shares} == {
        "Public": "1",
        "Backups": "1",
        "homes": "1",
        "Container": "2",
    }
    assert next(item for item in shares if item["sharename"] == "Container")["type"] == "system"
    assert all(set(item) <= {"sharename", "volumeValue", "type"} for item in shares)


def test_web_flags_and_apps() -> None:
    (web,) = normalize.web_services(document("login_page.xml"))
    assert set(web) == {"id", *normalize.WEB_FIELDS}
    apps = normalize.apps(document("apps.xml"))
    assert [item["name"] for item in apps] == ["HybridBackup", "container-station"]
    assert "status" not in apps[0]


def test_an_object_without_a_key_fails_the_resource() -> None:
    root = normalize.parse_document(b"<QDocRoot><qItem><attr/></qItem></QDocRoot>")
    with pytest.raises(CollectorError) as caught:
        normalize.apps(root)
    assert str(caught.value) == "an object of the answer has no usable key"


# ---- the shipped pack and type tables ---------------------------------------------------------


def item(resource: str, kind: ChangeKind, path: str, before: str | None, after: str | None):
    def text(value: JsonValue) -> str | None:
        return None if value is None else f'"{value}"'

    return ChangeItem(
        resource=resource,
        object_key="o1",
        object_name="object one",
        change_kind=kind,
        path=path,
        field_class=FieldClass.CONFIG,
        before_value=text(before),
        after_value=text(after),
        before_fp=None,
        after_fp=None,
        window_start="2026-11-12T10:00:00Z",
        window_end="2026-11-12T10:05:00Z",
    )


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return RuleEngine(load_rules())


def test_every_resource_has_a_type_table() -> None:
    tables = load_rules().type_tables
    assert all(name in tables for name in RESOURCES)


@pytest.mark.parametrize(
    ("resource", "kind", "path", "before", "after", "severity", "rule_id"),
    [
        (WEB, "modified", "forceSSL", "1", "0", "high", "qnap.web_services.force_ssl_off"),
        (WEB, "modified", "QWebEnabled", "0", "1", "medium", "qnap.web_services.web_server_on"),
        (SYSTEM, "modified", "dnsServers.0", "a", "b", "high", "qnap.system.dns_servers"),
        (SYSTEM, "modified", "hostname", "a", "b", "low", "qnap.system.hostname"),
        (NICS, "modified", "dns.1", "a", "b", "high", "qnap.network_interfaces.dns"),
        (VOLUMES, "modified", "encryptfs_bool", "1", "0", "high", "qnap.volumes.encryption_off"),
        (VOLUMES, "removed", "", None, None, "high", "builtin.floor.removed"),
        (SHARES, "removed", "", None, None, "high", "builtin.floor.removed"),
        (APPS, "added", "", None, None, "medium", "builtin.unclassified"),
        (APPS, "modified", "unofficial", "0", "1", "high", "qnap.apps.unofficial"),
        (APPS, "modified", "enable", "FALSE", "TRUE", "medium", "qnap.apps.enabled"),
        (APPS, "modified", "displayName", "a", "b", "low", "qnap.apps.display_name"),
    ],
)  # fmt: skip
def test_rules_and_floors(
    engine: RuleEngine,
    resource: str,
    kind: ChangeKind,
    path: str,
    before: str | None,
    after: str | None,
    severity: str,
    rule_id: str,
) -> None:
    result = engine.classify(item(resource, kind, path, before, after))
    assert (result.severity, result.rule_id) == (severity, rule_id)


@pytest.mark.parametrize(
    ("path", "before", "after"), [("forceSSL", "0", "1"), ("QWebEnabled", "1", "0")]
)
def test_the_safe_direction_of_a_flag_is_not_flagged(
    engine: RuleEngine, path: str, before: str, after: str
) -> None:
    result = engine.classify(item("qnap-web-services", "modified", path, before, after))
    assert result.rule_id == "builtin.unclassified"


# ---- wiring -----------------------------------------------------------------------------------


def test_the_factory_builds_a_qnap_client_from_the_username_option() -> None:
    collector = build_collector(
        "qnap", "https://nas.example.invalid", b"secret", {OPTION_USERNAME: "reader"}
    )
    try:
        assert isinstance(collector, QnapClient)
    finally:
        collector.close()


def test_the_factory_refuses_a_qnap_source_without_a_username() -> None:
    with pytest.raises(ValueError, match="user name"):
        build_collector("qnap", "https://nas.example.invalid", b"secret", {})


def test_the_username_option_is_checked_and_only_for_user_and_password_sources() -> None:
    assert _check_options({OPTION_USERNAME: " reader "}) == {OPTION_USERNAME: "reader"}
    for bad in ("", "a\nb", "x" * 129):
        with pytest.raises(SourceValidationError):
            _check_options({OPTION_USERNAME: bad})
    _check_type_options("qnap", {OPTION_USERNAME: "reader"})
    with pytest.raises(SourceValidationError):
        _check_type_options("unifi", {OPTION_USERNAME: "reader"})


def test_the_add_form_needs_and_keeps_the_user_name() -> None:
    from driftsniff.web.routes_sources import parse_form

    fields = {"name": "nas", "base_url": "https://nas.example.invalid", "credential": "pw"}
    missing = parse_form(dict(fields), "qnap")
    assert OPTION_USERNAME in missing.errors
    given = parse_form({**fields, OPTION_USERNAME: " reader "}, "qnap")
    assert OPTION_USERNAME not in given.errors
    assert given.options[OPTION_USERNAME] == "reader"
    assert OPTION_USERNAME not in parse_form(dict(fields), "unifi").errors
