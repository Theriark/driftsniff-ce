"""Small pieces of the notification channel (P9-T4): configuration, message, target check, crypto.

The senders and the service have their own tests in ``tests/contract``; this file covers what needs
no network: field validation, the stored form and the safe view of a configuration, the cleaning of
message text, the send-time address check, the channel binding of the stored configuration and the
rekey of channels.
"""

import json

import pytest
import sqlalchemy as sa

from driftsniff.collectors.base import CollectorError
from driftsniff.collectors.resolve import Resolver
from driftsniff.db.engine import Database
from driftsniff.db.tables import notification_channel
from driftsniff.notify.config import (
    ChannelConfigError,
    SmtpConfig,
    WebhookConfig,
    describe,
    dump_config,
    load_config,
    parse_smtp,
    parse_webhook,
    validate_webhook_url,
)
from driftsniff.notify.message import (
    MAX_SOURCE_CHARS,
    build_message,
    clean_text,
    event_link,
    sample_message,
)
from driftsniff.notify.targets import TargetRefusedError, check_target
from driftsniff.secrets.crypto import (
    CredentialCipher,
    CredentialDecryptError,
    associated_data,
    channel_associated_data,
)
from driftsniff.secrets.keys import MasterKey
from driftsniff.secrets.rekey import RekeyError, rekey_channels

MASTER = MasterKey(bytes(range(32)))
OTHER_MASTER = MasterKey(bytes(reversed(range(32))))
THIRD_MASTER = MasterKey(bytes([7] * 32))
CANARY = b"CANARY-channel-config-0001"
SMTP_FIELDS = {
    "host": "mail.example",
    "from_address": "driftsniff@example.com",
    "to_addresses": "ops@example.com",
}


# -- configuration ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://hooks.example/x",
        "http://10.0.0.5:8080/hook?token=abc",
        "http://[2001:db8::1]:9000/x",
        "  https://hooks.example/x  ",
    ],
)
def test_good_webhook_urls_are_kept_trimmed(url: str) -> None:
    assert validate_webhook_url(url) == url.strip()


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "hooks.example/x",
        "ftp://hooks.example",
        "https://",
        "https://user@hooks.example/x",
        "https://user:pw@hooks.example/x",
        "https://hooks.example/x#fragment",
        "https://hooks.example/a b",
        "https://hooks.example/\x07",
        "https://hooks.example:99999/x",
        "http://169.254.169.254/latest",
        "http://[fe80::1%25eth0]/x",
        "http://[::ffff:169.254.169.254]/x",
        "https://hooks.example/" + "a" * 2100,
    ],
)
def test_bad_webhook_urls_are_refused(url: str) -> None:
    with pytest.raises(ChannelConfigError):
        validate_webhook_url(url)


def test_the_error_of_a_bad_url_never_repeats_the_url() -> None:
    with pytest.raises(ChannelConfigError) as caught:
        validate_webhook_url("https://user:CANARY-url-pw@hooks.example/x")
    assert "CANARY" not in str(caught.value)


def test_a_webhook_config_repr_hides_the_url() -> None:
    assert "CANARY-url" not in repr(WebhookConfig("https://hooks.example/CANARY-url"))
    assert "CANARY-pw" not in repr(
        SmtpConfig("h", 25, "tls", "a@b.c", ("d@e.f",), "user", "CANARY-pw")
    )


def test_an_smtp_config_has_defaults_per_security_mode() -> None:
    starttls = parse_smtp(SMTP_FIELDS)
    assert (starttls.port, starttls.security, starttls.username) == (587, "starttls", None)
    implicit = parse_smtp({**SMTP_FIELDS, "security": " TLS "})
    assert (implicit.port, implicit.security) == (465, "tls")
    custom = parse_smtp({**SMTP_FIELDS, "port": "2525"})
    assert custom.port == 2525


def test_recipients_are_split_deduplicated_and_limited() -> None:
    config = parse_smtp({**SMTP_FIELDS, "to_addresses": "a@x.example; b@x.example,\na@x.example"})
    assert config.to_addresses == ("a@x.example", "b@x.example")
    many = ",".join(f"u{n}@x.example" for n in range(11))
    with pytest.raises(ChannelConfigError):
        parse_smtp({**SMTP_FIELDS, "to_addresses": many})


@pytest.mark.parametrize(
    "changes",
    [
        {"host": ""},
        {"host": "bad host"},
        {"host": "-bad.example"},
        {"host": "169.254.169.254"},
        {"host": "fe80::1"},
        {"port": "0"},
        {"port": "65536"},
        {"port": "25a"},
        {"security": "plain"},
        {"from_address": "x"},
        {"from_address": "a b@x.example"},
        {"from_address": "a@x.example\r\nBcc: b@x.example"},
        {"to_addresses": "ops@x.example, nobody"},
        {"to_addresses": ""},
        {"username": "u"},
        {"username": "u", "password": "x" * 300},
    ],
)
def test_bad_smtp_fields_are_refused(changes: dict[str, str]) -> None:
    with pytest.raises(ChannelConfigError):
        parse_smtp({**SMTP_FIELDS, **changes})


def test_a_blank_username_means_no_login_and_drops_a_password() -> None:
    config = parse_smtp({**SMTP_FIELDS, "username": "  ", "password": "ignored"})
    assert (config.username, config.password) == (None, None)


def test_a_password_comes_from_the_old_config_only_for_the_same_user() -> None:
    old = parse_smtp({**SMTP_FIELDS, "username": "alerts", "password": "first"})
    same = parse_smtp({**SMTP_FIELDS, "username": "alerts"}, old)
    assert same.password == "first"  # noqa: S105
    with pytest.raises(ChannelConfigError):
        parse_smtp({**SMTP_FIELDS, "username": "other"}, old)
    with pytest.raises(ChannelConfigError):
        parse_smtp({**SMTP_FIELDS, "username": "alerts"})


def test_a_webhook_field_set_has_the_url_only() -> None:
    assert parse_webhook({"url": "https://hooks.example/x"}) == WebhookConfig(
        "https://hooks.example/x"
    )
    with pytest.raises(ChannelConfigError):
        parse_webhook({})


def test_the_stored_form_round_trips() -> None:
    webhook = WebhookConfig("https://hooks.example/x?token=1")
    assert load_config("webhook", dump_config(webhook)) == webhook
    smtp = parse_smtp({**SMTP_FIELDS, "username": "alerts", "password": "pw"})
    assert load_config("smtp", dump_config(smtp)) == smtp
    nologin = parse_smtp(SMTP_FIELDS)
    assert load_config("smtp", dump_config(nologin)) == nologin


@pytest.mark.parametrize(
    ("channel_type", "data"),
    [
        ("webhook", b"not json"),
        ("webhook", b"{}"),
        ("webhook", b"[]"),
        ("smtp", b'{"host": "h"}'),
        ("smtp", b'{"host":"h","port":"x","security":"tls","from_address":"a","to_addresses":1}'),
        ("pigeon", b"{}"),
    ],
)
def test_a_damaged_stored_form_is_refused_without_its_content(
    channel_type: str, data: bytes
) -> None:
    with pytest.raises(ChannelConfigError) as caught:
        load_config(channel_type, data)
    assert "{" not in str(caught.value)


def test_the_safe_view_has_the_host_and_port_and_no_secret() -> None:
    web = describe(WebhookConfig("https://hooks.example:8443/a/CANARY-path?token=CANARY-query"))
    assert web == {"target": "https://hooks.example:8443", "path_hidden": True}
    plain = describe(WebhookConfig("http://10.0.0.5/x"))
    assert plain["target"] == "http://10.0.0.5"
    v6 = describe(WebhookConfig("http://[2001:db8::1]:9000/x"))
    assert v6["target"] == "http://[2001:db8::1]:9000"
    mail = describe(parse_smtp({**SMTP_FIELDS, "username": "alerts", "password": "CANARY-pw"}))
    assert mail["password_set"] is True
    assert "CANARY-pw" not in json.dumps(mail)
    assert describe(parse_smtp(SMTP_FIELDS))["password_set"] is False


# -- message ----------------------------------------------------------------------------------


def test_text_is_one_clean_line_of_limited_length() -> None:
    assert clean_text("a\r\nb\tc\x00d  e", 50) == "a b c d e"
    assert clean_text("x" * 500, 10) == "x" * 10
    assert clean_text("  \n ", 10) == ""


def test_the_link_is_built_from_the_base_address() -> None:
    assert event_link("https://d.example", 5) == "https://d.example/changes/5"
    assert event_link("https://d.example/app/", 5) == "https://d.example/app/changes/5"


def test_a_message_holds_exactly_the_agreed_fields() -> None:
    message = build_message(
        event_id=3,
        source="lab\r\nBcc: x",
        severity="high",
        summary="1 change in 1 resource type, highest severity high",
        item_count=1,
        base_url="https://d.example",
    )
    assert message.as_dict() == {
        "event_id": 3,
        "source": "lab Bcc: x",
        "severity": "high",
        "summary": "1 change in 1 resource type, highest severity high",
        "item_count": 1,
        "link": "https://d.example/changes/3",
        "test": False,
    }
    long = build_message(
        event_id=1,
        source="s" * 400,
        severity="low",
        summary="m",
        item_count=0,
        base_url="https://d.example",
    )
    assert len(long.source) == MAX_SOURCE_CHARS


def test_the_sample_is_marked_as_a_test() -> None:
    sample = sample_message("https://d.example")
    assert sample.test is True
    assert (sample.event_id, sample.item_count) == (0, 0)


# -- the send-time address check --------------------------------------------------------------


@pytest.mark.parametrize(
    "answers",
    [
        ["169.254.169.254"],
        ["fe80::1"],
        ["fe80::1%eth0"],
        ["100.100.100.200"],
        ["::ffff:169.254.169.254"],
        ["10.0.0.5", "169.254.0.7"],
        ["not-an-address"],
    ],
)
def test_a_blocked_or_unusable_answer_refuses_the_target(answers: list[str]) -> None:
    with pytest.raises(TargetRefusedError) as caught:
        check_target("hooks.example", lambda _host: answers)
    assert caught.value.error_class == "blocked_address"


def test_private_and_loopback_targets_are_allowed_and_the_first_answer_is_used() -> None:
    target = check_target("hooks.example", lambda _host: ["10.0.0.5", "192.168.1.9"])
    assert (target.host, target.address) == ("hooks.example", "10.0.0.5")
    assert check_target("h", lambda _host: ["127.0.0.1"]).address == "127.0.0.1"
    assert check_target("h", lambda _host: ["::1"]).address == "::1"


def test_no_answer_and_a_failed_lookup_are_unresolved() -> None:
    def failing(_host: str) -> list[str]:
        raise CollectorError("connection", "cannot be resolved")

    resolvers: list[Resolver] = [lambda _host: [], failing]
    for resolver in resolvers:
        with pytest.raises(TargetRefusedError) as caught:
            check_target("hooks.example", resolver)
        assert caught.value.error_class == "unresolved"


# -- channel crypto and rekey -----------------------------------------------------------------


def test_a_channel_configuration_round_trips_and_is_bound_to_its_channel() -> None:
    cipher = CredentialCipher.from_master(MASTER)
    sealed = cipher.encrypt_channel(4, CANARY)
    assert cipher.decrypt_channel(4, sealed.ciphertext, sealed.key_id) == CANARY
    assert CANARY.decode() not in sealed.ciphertext
    with pytest.raises(CredentialDecryptError):
        cipher.decrypt_channel(5, sealed.ciphertext, sealed.key_id)


def test_a_channel_value_is_not_a_source_credential_and_the_other_way_round() -> None:
    cipher = CredentialCipher.from_master(MASTER)
    channel = cipher.encrypt_channel(4, CANARY)
    source = cipher.encrypt(4, CANARY)
    with pytest.raises(CredentialDecryptError):
        cipher.decrypt(4, channel.ciphertext, channel.key_id)
    with pytest.raises(CredentialDecryptError):
        cipher.decrypt_channel(4, source.ciphertext, source.key_id)
    assert channel_associated_data(4, "0a1b2c3d") != associated_data(4, "0a1b2c3d")
    assert channel_associated_data(4, "0a1b2c3d") == b"driftsniff-channel-v1/channel/4/key/0a1b2c3d"


def test_a_channel_value_of_another_key_is_refused_before_decrypting() -> None:
    sealed = CredentialCipher.from_master(OTHER_MASTER).encrypt_channel(4, CANARY)
    with pytest.raises(CredentialDecryptError, match="encrypted with key"):
        CredentialCipher.from_master(MASTER).decrypt_channel(4, sealed.ciphertext, sealed.key_id)


def add_channel(store: Database, master: MasterKey, plaintext: bytes = CANARY) -> int:
    cipher = CredentialCipher.from_master(master)
    with store.write() as connection:
        channel_id = int(
            connection.execute(
                sa.insert(notification_channel)
                .values(type="webhook", config_ciphertext="", key_id=None)
                .returning(notification_channel.c.id)
            ).scalar_one()
        )
        sealed = cipher.encrypt_channel(channel_id, plaintext)
        connection.execute(
            sa.update(notification_channel)
            .where(notification_channel.c.id == channel_id)
            .values(config_ciphertext=sealed.ciphertext, key_id=sealed.key_id)
        )
    return channel_id


def test_rekey_channels_moves_the_configuration_to_the_new_key(store: Database) -> None:
    channel_id = add_channel(store, MASTER)
    old = CredentialCipher.from_master(MASTER)
    new = CredentialCipher.from_master(OTHER_MASTER)
    with store.write() as connection:
        assert rekey_channels(connection, old, new) == 1
        assert rekey_channels(connection, old, new) == 0
    with store.read() as connection:
        row = connection.execute(sa.select(notification_channel)).one()
    assert row.key_id == OTHER_MASTER.key_id
    assert new.decrypt_channel(channel_id, row.config_ciphertext, row.key_id) == CANARY


def test_rekey_channels_stops_on_a_channel_made_with_a_third_key(store: Database) -> None:
    add_channel(store, THIRD_MASTER)
    old = CredentialCipher.from_master(MASTER)
    new = CredentialCipher.from_master(OTHER_MASTER)
    with pytest.raises(RekeyError, match="neither the old key"), store.write() as connection:
        rekey_channels(connection, old, new)


def test_rekey_channels_stops_on_damaged_data_and_leaves_the_row_alone(store: Database) -> None:
    channel_id = add_channel(store, MASTER)
    with store.write() as connection:
        connection.execute(
            sa.update(notification_channel)
            .where(notification_channel.c.id == channel_id)
            .values(config_ciphertext="AAAA")
        )
    old = CredentialCipher.from_master(MASTER)
    new = CredentialCipher.from_master(OTHER_MASTER)
    with pytest.raises(RekeyError, match=f"channel {channel_id}"), store.write() as connection:
        rekey_channels(connection, old, new)
    with store.read() as connection:
        assert connection.execute(sa.select(notification_channel.c.key_id)).scalar_one() == (
            MASTER.key_id
        )


def test_a_channel_without_a_key_id_is_left_alone_by_a_rekey(store: Database) -> None:
    with store.write() as connection:
        connection.execute(
            sa.insert(notification_channel).values(type="webhook", config_ciphertext="")
        )
    old = CredentialCipher.from_master(MASTER)
    new = CredentialCipher.from_master(OTHER_MASTER)
    with store.write() as connection:
        assert rekey_channels(connection, old, new) == 0
