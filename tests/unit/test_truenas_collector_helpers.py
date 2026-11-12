"""Unit tests of the TrueNAS collector helpers: WebSocket framing, object preparation, the type
tables and rule pack, the factory branch and the source page wiring."""

import struct
from typing import Any

import httpcore
import pytest

from driftsniff.collectors.base import (
    ERROR_BAD_PAYLOAD,
    ERROR_BODY_TOO_LARGE,
    ERROR_CONNECTION,
    ERROR_TIMEOUT,
    CollectorError,
)
from driftsniff.collectors.truenas.client import TruenasClient, split_credential
from driftsniff.collectors.truenas.normalize import prepare_objects
from driftsniff.collectors.truenas.resources import RESOURCES
from driftsniff.collectors.truenas.websocket import (
    OP_CLOSE,
    OP_CONTINUATION,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    WebSocket,
    accept_value,
    encode_frame,
    mask,
)
from driftsniff.core.normalize import FieldClass
from driftsniff.rules.loader import load_rules
from driftsniff.sources.factory import build_collector
from driftsniff.web.dashboard import RESOURCE_LABELS, SOURCE_TYPE_LABELS
from driftsniff.web.source_pages import CREDENTIAL_LABELS, resources_of


class FakeStream(httpcore.NetworkStream):
    """Serves ``incoming`` in small pieces and records what is written."""

    def __init__(self, incoming: bytes = b"", *, fail: Exception | None = None) -> None:
        self.incoming = bytearray(incoming)
        self.written: list[bytes] = []
        self.fail = fail
        self.reads = 0

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self.reads += 1
        if self.fail is not None:
            raise self.fail
        piece = bytes(self.incoming[:7])
        del self.incoming[:7]
        return piece

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.written.append(buffer)

    def close(self) -> None:
        return None


class FakeResponse:
    def close(self) -> None:
        return None


def socket_over(stream: FakeStream) -> WebSocket:
    return WebSocket(FakeResponse(), stream, 1.0)  # type: ignore[arg-type]


def server_frame(opcode: int, payload: bytes, *, fin: bool = True) -> bytes:
    frame = encode_frame(opcode, payload)
    return frame if fin else bytes([frame[0] & 0x7F]) + frame[1:]


# -- framing ------------------------------------------------------------------------------------


def test_the_accept_value_is_the_one_of_rfc_6455() -> None:
    assert accept_value("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_masking_twice_gives_the_data_back() -> None:
    data = bytes(range(256)) * 3
    key = b"\x01\x02\x03\x04"
    assert mask(mask(data, key), key) == data
    assert mask(b"", key) == b""


@pytest.mark.parametrize("size", [0, 125, 126, 65535, 65536])
def test_a_frame_of_any_size_reads_back(size: int) -> None:
    payload = b"x" * size
    stream = FakeStream(server_frame(OP_TEXT, payload))
    assert socket_over(stream).receive_text() == payload.decode()


def test_a_client_frame_is_masked() -> None:
    stream = FakeStream()
    socket_over(stream).send_text("hello")
    frame = stream.written[0]
    assert frame[0] == 0x80 | OP_TEXT and frame[1] == 0x80 | 5
    assert mask(frame[6:], frame[2:6]) == b"hello"


def test_fragments_pings_and_pongs_make_one_message() -> None:
    incoming = (
        server_frame(OP_TEXT, b'{"a":', fin=False)
        + server_frame(OP_PING, b"hb")
        + server_frame(OP_CONTINUATION, b" 1", fin=False)
        + server_frame(OP_PONG, b"")
        + server_frame(OP_CONTINUATION, b"}")
    )
    stream = FakeStream(incoming)
    assert socket_over(stream).receive_text() == '{"a": 1}'
    pong = stream.written[0]
    assert pong[0] == 0x80 | OP_PONG and mask(pong[6:], pong[2:6]) == b"hb"


@pytest.mark.parametrize(
    "incoming",
    [
        server_frame(0x2, b"binary"),
        server_frame(OP_CONTINUATION, b"no start"),
        server_frame(OP_TEXT, b"a", fin=False) + server_frame(OP_TEXT, b"b"),
        bytes([0x80 | OP_TEXT | 0x40, 1]) + b"a",
        bytes([0x80 | OP_TEXT, 0x80 | 1]) + b"\x00\x00\x00\x00a",
        server_frame(OP_PING, b"p" * 126),
        server_frame(OP_TEXT, b"\xff\xfe"),
    ],
    ids=["binary", "stray", "nested", "rsv", "masked", "long-ping", "not-utf8"],
)
def test_a_broken_frame_breaks_the_protocol(incoming: bytes) -> None:
    with pytest.raises(CollectorError) as caught:
        socket_over(FakeStream(incoming)).receive_text()
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


def test_a_message_over_the_limit_fails_before_its_payload_is_read() -> None:
    header = struct.pack("!BBQ", 0x80 | OP_TEXT, 127, 10_000_000)
    stream = FakeStream(header)
    with pytest.raises(CollectorError) as caught:
        socket_over(stream).receive_text(max_bytes=1000)
    assert caught.value.error_class == ERROR_BODY_TOO_LARGE
    assert stream.reads <= 2


@pytest.mark.parametrize(
    ("incoming", "fail", "error_class"),
    [
        (server_frame(OP_CLOSE, struct.pack("!H", 1000)), None, ERROR_CONNECTION),
        (b"", None, ERROR_CONNECTION),
        (b"", httpcore.ReadTimeout("slow"), ERROR_TIMEOUT),
        (b"", httpcore.ReadError("reset"), ERROR_CONNECTION),
    ],
)
def test_a_closed_or_failed_stream_is_a_connection_error(
    incoming: bytes, fail: Exception | None, error_class: str
) -> None:
    with pytest.raises(CollectorError) as caught:
        socket_over(FakeStream(incoming, fail=fail)).receive_text()
    assert caught.value.error_class == error_class
    assert "slow" not in str(caught.value) and "reset" not in str(caught.value)


# -- preparation --------------------------------------------------------------------------------


def test_a_config_answer_becomes_a_list_of_one() -> None:
    assert prepare_objects("truenas-ssh", {"id": 1, "tcpport": 22}, single=True) == [
        {"id": 1, "tcpport": 22}
    ]


@pytest.mark.parametrize("answer", [{"id": 1}, [{"name": "no id"}], [{"id": True}], ["text"]])
def test_an_answer_of_the_wrong_shape_fails_the_resource(answer: Any) -> None:
    with pytest.raises(CollectorError) as caught:
        prepare_objects("truenas-pools", answer, single=False)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


def test_objects_are_sorted_by_id() -> None:
    answer: list[Any] = [{"id": "tank/b"}, {"id": "tank"}, {"id": "tank/a"}]
    ids = [item["id"] for item in prepare_objects("truenas-datasets", answer, single=False)]
    assert ids == ["tank", "tank/a", "tank/b"]


def test_an_nfs_share_with_hosts_is_not_open_to_all() -> None:
    share: dict[str, Any] = {"id": 1, "networks": [], "hosts": ["10.0.0.5"]}
    assert prepare_objects("truenas-nfs-shares", [share], single=False)[0]["open_to_all"] is False
    assert share.get("open_to_all") is None  # the raw object is not changed


# -- type tables, rules, wiring ------------------------------------------------------------------


def test_every_resource_has_a_type_table_and_a_label() -> None:
    tables = load_rules().type_tables
    for resource in RESOURCES:
        assert resource.name in tables, resource.name
        assert resource.name in RESOURCE_LABELS, resource.name
    assert resources_of("truenas", {}) == tuple(resource.name for resource in RESOURCES)
    assert "truenas" in SOURCE_TYPE_LABELS and "truenas" in CREDENTIAL_LABELS


def test_secrets_are_secret_and_private_keys_are_ignored() -> None:
    tables = load_rules().type_tables
    users = tables["truenas-users"]
    assert users.field_class("unixhash") is FieldClass.SECRET
    assert users.field_class("smbhash") is FieldClass.SECRET
    credentials = tables["truenas-cloud-credentials"]
    assert credentials.field_class("provider.secret_access_key") is FieldClass.SECRET
    assert tables["truenas-certificates"].field_class("privatekey") is FieldClass.IGNORE
    assert tables["truenas-ssh"].field_class("host_rsa_key") is FieldClass.IGNORE
    assert (
        tables["truenas-cloud-sync-tasks"].field_class("credentials.provider") is FieldClass.IGNORE
    )


@pytest.mark.parametrize(
    "resource",
    [
        "truenas-users",
        "truenas-groups",
        "truenas-ssh",
        "truenas-smb-shares",
        "truenas-nfs-shares",
        "truenas-cloud-credentials",
    ],
)
def test_access_resources_have_the_floor_high(resource: str) -> None:
    table = load_rules().type_tables[resource]
    assert {table.floor_for(kind) for kind in ("added", "removed", "modified")} == {"high"}


def test_the_truenas_rules_are_loaded() -> None:
    ids = {compiled.rule.id for compiled in load_rules().rules}
    assert {
        "truenas.ssh.password_login",
        "truenas.smb.guest_access",
        "truenas.cron.description",
    } <= ids


def test_the_factory_builds_the_truenas_collector() -> None:
    collector = build_collector(
        "truenas", "https://nas.example", b"7-key", {"username": "driftsniff"}
    )
    try:
        assert isinstance(collector, TruenasClient)
    finally:
        collector.close()


def test_a_credential_splits_at_the_first_colon() -> None:
    assert split_credential("admin:7-abc:def") == ("admin", "7-abc:def")
