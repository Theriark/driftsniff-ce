"""The notification service: channel storage, severity filter, retries, stored deliveries (P9-T4).

Real webhook and mail senders talk to local receivers; the clock, the sleeps and the resolver are
fakes, so the retry schedule is checked without waiting. The channel configuration (a URL that
may carry a token, a mail password) must never be readable in the database, the views, the audit
events or the logs.
"""

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import sqlalchemy as sa

from driftsniff.db.engine import Database
from driftsniff.db.tables import audit_events, notification_channel, notification_deliveries
from driftsniff.notify.deliveries import (
    MAX_ATTEMPTS,
    RETRY_BACKOFF_SECONDS,
    ChannelUnreadableError,
    NoChannelError,
    NotificationInputError,
    NotificationService,
)
from driftsniff.notify.webhook import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify
from driftsniff.secrets.keys import WEBHOOK_LABEL, MasterKey
from driftsniff.secrets.rekey import run_rekey

from .fake_notify import (
    Reply,
    add_event,
    make_store,
    running_receiver,
    running_smtp,
    trusting_context,
)
from .fake_tls import make_pki

BASE = "https://driftsniff.example"
MASTER = MasterKey(bytes(range(32)))
OTHER_MASTER = MasterKey(bytes(reversed(range(32))))
URL_SECRET = "CANARY-hook-token-0001"  # noqa: S105
MAIL_SECRET = "CANARY-mail-password-0002"  # noqa: S105
ACTOR = "admin"
SMTP_FIELDS = {
    "host": "mail.example",
    "from_address": "a@b.example",
    "to_addresses": "c@d.example",
}


def loopback(_host: str) -> list[str]:
    return ["127.0.0.1"]


@dataclass
class Rig:
    database: Database
    service: NotificationService
    sleeps: list[float] = field(default_factory=list)


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    database = make_store(tmp_path)
    sleeps: list[float] = []
    service = NotificationService(
        database,
        MASTER,
        base_url=BASE,
        clock=lambda: "2026-10-22T09:00:00Z",
        wall_clock=lambda: 1_800_000_000.0,
        sleep=sleeps.append,
        resolver=loopback,
    )
    try:
        yield Rig(database, service, sleeps)
    finally:
        service.close()
        database.close()


def set_webhook(
    rig: Rig, url: str, *, min_severity: str | None = None, enabled: bool = True
) -> None:
    rig.service.configure(
        actor=ACTOR,
        channel_type="webhook",
        fields={"url": url},
        min_severity=min_severity,
        enabled=enabled,
    )


def all_rows(database: Database, table: sa.Table) -> list[tuple[object, ...]]:
    with database.read() as connection:
        return [tuple(row) for row in connection.execute(sa.select(table))]


def audit(database: Database) -> list[tuple[str, object]]:
    """The (action, detail) of every audit event, oldest first."""
    with database.read() as connection:
        rows = connection.execute(
            sa.select(audit_events.c.action, audit_events.c.detail).order_by(audit_events.c.id)
        )
        return [(row.action, row.detail) for row in rows]


def statuses(rig: Rig, event_id: int) -> list[tuple[int, str, int | None, str | None]]:
    rows = reversed(rig.service.deliveries(event_id))
    return [(row.attempt, row.status, row.http_status, row.error_class) for row in rows]


# -- the channel ------------------------------------------------------------------------------


def test_the_view_shows_the_host_and_port_and_never_the_path_or_query(rig: Rig) -> None:
    view = rig.service.configure(
        actor=ACTOR,
        channel_type="webhook",
        fields={"url": f"https://hooks.example:8443/services/{URL_SECRET}?token={URL_SECRET}"},
    )
    shown = json.dumps(view.as_dict())
    assert URL_SECRET not in shown
    assert view.as_dict()["target"] == "https://hooks.example:8443"
    assert view.min_severity == "high"
    assert view.enabled is True


def test_the_configuration_is_encrypted_at_rest_and_bound_to_the_channel(rig: Rig) -> None:
    set_webhook(rig, f"https://hooks.example/{URL_SECRET}")
    with rig.database.read() as connection:
        row = connection.execute(sa.select(notification_channel)).one()
    assert URL_SECRET not in row.config_ciphertext
    assert "hooks.example" not in row.config_ciphertext
    assert row.key_id == MASTER.key_id
    assert URL_SECRET not in json.dumps(audit(rig.database))


def test_saving_again_replaces_the_one_channel(rig: Rig) -> None:
    set_webhook(rig, "https://one.example/hook")
    first = rig.service.channel()
    assert first is not None
    set_webhook(rig, "https://two.example/hook", min_severity="medium")
    second = rig.service.channel()
    assert second is not None
    assert second.channel_id == first.channel_id
    assert second.as_dict()["target"] == "https://two.example"
    assert second.min_severity == "medium"
    assert len(all_rows(rig.database, notification_channel)) == 1


def test_without_a_channel_the_view_is_none_and_remove_says_so(rig: Rig) -> None:
    assert rig.service.channel() is None
    assert rig.service.remove(actor=ACTOR) is False


@pytest.mark.parametrize(
    ("channel_type", "fields", "severity"),
    [
        ("sms", {"url": "https://a.example"}, None),
        ("webhook", {"url": "https://a.example"}, "urgent"),
        ("webhook", {"url": ""}, None),
        ("webhook", {"url": "ftp://a.example/x"}, None),
        ("webhook", {"url": "https://user:pw@a.example/x"}, None),
        ("webhook", {"url": "https://a.example/x#frag"}, None),
        ("webhook", {"url": "http://169.254.169.254/latest"}, None),
        ("webhook", {"url": "http://[fe80::1]/x"}, None),
        ("webhook", {"url": "https://a.example/with space"}, None),
        ("smtp", {**SMTP_FIELDS, "to_addresses": ""}, None),
        ("smtp", {**SMTP_FIELDS, "host": "169.254.169.254"}, None),
        ("smtp", {**SMTP_FIELDS, "from_address": "not-an-address"}, None),
        ("smtp", {**SMTP_FIELDS, "security": "none"}, None),
        ("smtp", {**SMTP_FIELDS, "port": "70000"}, None),
        ("smtp", {**SMTP_FIELDS, "username": "u"}, None),
    ],
)
def test_bad_input_is_refused_and_nothing_is_stored(
    rig: Rig, channel_type: str, fields: dict[str, str], severity: str | None
) -> None:
    with pytest.raises(NotificationInputError):
        rig.service.configure(
            actor=ACTOR, channel_type=channel_type, fields=fields, min_severity=severity
        )
    assert rig.service.channel() is None
    assert all_rows(rig.database, audit_events) == []


def test_an_smtp_password_is_kept_when_it_is_left_out_and_the_user_is_the_same(rig: Rig) -> None:
    fields = {
        "host": "mail.example",
        "from_address": "a@b.example",
        "to_addresses": "c@d.example, e@f.example",
        "username": "alerts",
        "password": MAIL_SECRET,
    }
    view = rig.service.configure(actor=ACTOR, channel_type="smtp", fields=fields)
    assert view.as_dict()["password_set"] is True
    assert MAIL_SECRET not in json.dumps(view.as_dict())
    assert view.as_dict()["port"] == 587
    assert view.as_dict()["to_addresses"] == ["c@d.example", "e@f.example"]
    without = {key: value for key, value in fields.items() if key != "password"}
    kept = rig.service.configure(actor=ACTOR, channel_type="smtp", fields=without)
    assert kept.as_dict()["password_set"] is True
    with pytest.raises(NotificationInputError, match="password"):
        rig.service.configure(
            actor=ACTOR, channel_type="smtp", fields={**without, "username": "someone-else"}
        )


def test_a_lost_key_makes_the_channel_unreadable_and_the_view_says_so(rig: Rig) -> None:
    set_webhook(rig, "https://hooks.example/x")
    other = NotificationService(rig.database, OTHER_MASTER, base_url=BASE, resolver=loopback)
    view = other.channel()
    assert view is not None
    assert view.as_dict()["config_unreadable"] is True
    with pytest.raises(ChannelUnreadableError):
        other.send_test(actor=ACTOR)
    event = add_event(rig.database)
    outcome = other.deliver_event(event)
    assert (outcome.sent, outcome.error_class) == (False, "config_unreadable")


def test_a_rekey_re_encrypts_the_channel_and_the_signing_key_changes(rig: Rig) -> None:
    set_webhook(rig, f"https://hooks.example/{URL_SECRET}")
    old_key = rig.service.signing_key_hex(actor=ACTOR)
    run_rekey(rig.database, MASTER, OTHER_MASTER, "2026-10-22T09:30:00Z")
    after = NotificationService(rig.database, OTHER_MASTER, base_url=BASE, resolver=loopback)
    view = after.channel()
    assert view is not None
    assert view.as_dict()["target"] == "https://hooks.example"
    assert "config_unreadable" not in view.as_dict()
    assert after.signing_key_hex(actor=ACTOR) == OTHER_MASTER.derive(WEBHOOK_LABEL).hex()
    assert after.signing_key_hex(actor=ACTOR) != old_key
    stale = rig.service.channel()
    assert stale is not None
    assert stale.as_dict()["config_unreadable"] is True


def test_removing_the_channel_removes_its_deliveries(rig: Rig) -> None:
    with running_receiver() as receiver:
        set_webhook(rig, receiver.url)
        event = add_event(rig.database)
        assert rig.service.deliver_event(event).sent is True
    assert len(all_rows(rig.database, notification_deliveries)) == 1
    assert rig.service.remove(actor=ACTOR) is True
    assert rig.service.channel() is None
    assert all_rows(rig.database, notification_deliveries) == []


def test_the_signing_key_is_the_derived_webhook_key_and_its_use_is_audited(rig: Rig) -> None:
    shown = rig.service.signing_key_hex(actor=ACTOR)
    assert shown == MASTER.derive(WEBHOOK_LABEL).hex()
    assert [action for action, _ in audit(rig.database)] == ["notification.signing_key_shown"]


# -- what is sent -----------------------------------------------------------------------------


def test_a_high_event_is_delivered_once_and_the_receiver_can_verify_it(rig: Rig) -> None:
    with running_receiver() as receiver:
        set_webhook(rig, receiver.url)
        event = add_event(rig.database, severity="high")
        outcome = rig.service.deliver_event(event)
        again = rig.service.deliver_event(event)
    assert (outcome.sent, outcome.attempts, outcome.status) == (True, 1, "delivered")
    assert again.sent is False
    assert len(receiver.requests) == 1
    request = receiver.requests[0]
    key = MASTER.derive(WEBHOOK_LABEL)
    assert verify(
        key,
        request.headers[TIMESTAMP_HEADER.lower()],
        request.body,
        request.headers[SIGNATURE_HEADER.lower()],
        now=1_800_000_000.0,
    )
    assert json.loads(request.body)["event_id"] == event
    assert statuses(rig, event) == [(1, "delivered", 200, None)]
    assert rig.sleeps == []


@pytest.mark.parametrize(
    ("minimum", "event_severity", "sent"),
    [
        (None, "low", False),
        (None, "medium", False),
        (None, "high", True),
        (None, "critical", True),
        ("low", "low", True),
        ("medium", "low", False),
        ("critical", "high", False),
        ("critical", "critical", True),
    ],
)
def test_only_events_at_or_above_the_minimum_severity_are_sent(
    rig: Rig, minimum: str | None, event_severity: str, sent: bool
) -> None:
    with running_receiver() as receiver:
        set_webhook(rig, receiver.url, min_severity=minimum)
        event = add_event(rig.database, severity=event_severity)
        outcome = rig.service.deliver_event(event)
    assert outcome.sent is sent
    assert len(receiver.requests) == (1 if sent else 0)
    assert bool(rig.service.deliveries(event)) is sent


def test_a_disabled_channel_and_a_missing_channel_send_nothing(rig: Rig) -> None:
    event = add_event(rig.database, severity="critical")
    assert rig.service.deliver_event(event).sent is False
    with running_receiver() as receiver:
        set_webhook(rig, receiver.url, enabled=False)
        assert rig.service.deliver_event(event).sent is False
    assert receiver.requests == []
    assert rig.service.deliveries() == []


def test_an_unknown_event_sends_nothing(rig: Rig) -> None:
    with running_receiver() as receiver:
        set_webhook(rig, receiver.url)
        assert rig.service.deliver_event(9999).sent is False
    assert receiver.requests == []


def test_an_event_that_is_being_sent_is_not_sent_a_second_time_at_once(rig: Rig) -> None:
    with running_receiver() as receiver:
        set_webhook(rig, receiver.url)
        event = add_event(rig.database)
        rig.service._in_flight.add(event)
        assert rig.service.deliver_event(event).sent is False
        rig.service._in_flight.discard(event)
        assert rig.service.deliver_event(event).sent is True
    assert len(receiver.requests) == 1


# -- retries ----------------------------------------------------------------------------------


def test_three_retries_after_one_two_and_four_seconds_then_the_event_is_given_up(rig: Rig) -> None:
    assert RETRY_BACKOFF_SECONDS == (1.0, 2.0, 4.0)
    assert MAX_ATTEMPTS == 4
    with running_receiver([Reply(500)] * 4) as receiver:
        set_webhook(rig, receiver.url)
        event = add_event(rig.database)
        outcome = rig.service.deliver_event(event)
    assert (outcome.sent, outcome.attempts, outcome.status) == (False, 4, "failed")
    assert rig.sleeps == [1.0, 2.0, 4.0]
    assert len(receiver.requests) == 4
    assert statuses(rig, event) == [
        (1, "failed", 500, "server_error"),
        (2, "failed", 500, "server_error"),
        (3, "failed", 500, "server_error"),
        (4, "failed", 500, "server_error"),
    ]


def test_a_retry_that_succeeds_stops_the_schedule(rig: Rig) -> None:
    with running_receiver([Reply(503), Reply(502), Reply(200)]) as receiver:
        set_webhook(rig, receiver.url)
        event = add_event(rig.database)
        outcome = rig.service.deliver_event(event)
    assert (outcome.sent, outcome.attempts) == (True, 3)
    assert rig.sleeps == [1.0, 2.0]
    assert [row[1] for row in statuses(rig, event)] == ["failed", "failed", "delivered"]
    # A later call does not send it again.
    assert rig.service.deliver_event(event).sent is False
    assert len(receiver.requests) == 3


@pytest.mark.parametrize(
    ("reply", "error_class"),
    [(Reply(404), "rejected"), (Reply(302, "http://127.0.0.1:9/x"), "redirect")],
)
def test_a_refusal_or_a_redirect_is_stored_once_and_not_retried(
    rig: Rig, reply: Reply, error_class: str
) -> None:
    with running_receiver([reply]) as receiver:
        set_webhook(rig, receiver.url)
        event = add_event(rig.database)
        outcome = rig.service.deliver_event(event)
    assert (outcome.sent, outcome.attempts, outcome.error_class) == (False, 1, error_class)
    assert rig.sleeps == []
    assert len(receiver.requests) == 1


def test_a_target_that_resolves_to_a_blocked_address_is_stored_as_blocked_and_not_retried(
    rig: Rig,
) -> None:
    answers = [["127.0.0.1"]]

    def resolver(_host: str) -> list[str]:
        return answers[0]

    service = NotificationService(
        rig.database, MASTER, base_url=BASE, sleep=rig.sleeps.append, resolver=resolver
    )
    with running_receiver() as receiver:
        service.configure(
            actor=ACTOR,
            channel_type="webhook",
            fields={"url": f"http://hooks.example:{receiver.port}/x"},
        )
        event = add_event(rig.database)
        # The name passed the check when it was saved; at send time it points to the metadata host.
        answers[0] = ["169.254.169.254"]
        outcome = service.deliver_event(event)
    assert (outcome.sent, outcome.attempts, outcome.status) == (False, 1, "blocked")
    assert outcome.error_class == "blocked_address"
    assert receiver.requests == []
    assert rig.sleeps == []
    assert [(row.status, row.error_class) for row in service.deliveries(event)] == [
        ("blocked", "blocked_address")
    ]
    service.close()


def test_the_next_event_is_sent_again_after_a_blocked_one(rig: Rig) -> None:
    with running_receiver() as receiver:
        set_webhook(rig, receiver.url)
        first = add_event(rig.database)
        second = add_event(rig.database)
        assert rig.service.deliver_event(first).sent is True
        assert rig.service.deliver_event(second).sent is True
    assert len(receiver.requests) == 2


# -- background -------------------------------------------------------------------------------


def test_notify_event_delivers_in_the_background_and_close_waits_for_it(rig: Rig) -> None:
    with running_receiver() as receiver:
        set_webhook(rig, receiver.url)
        event = add_event(rig.database)
        rig.service.notify_event(event)
        rig.service.close()
    assert len(receiver.requests) == 1
    assert statuses(rig, event) == [(1, "delivered", 200, None)]


def test_a_failing_background_delivery_is_logged_without_the_url(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    set_webhook(rig, f"https://hooks.example/{URL_SECRET}")
    with caplog.at_level(logging.DEBUG):
        rig.service.notify_event(add_event(rig.database))
        rig.service.close()
    assert URL_SECRET not in caplog.text


# -- the test button --------------------------------------------------------------------------


def test_the_test_button_sends_a_marked_sample_once_and_audits_the_outcome(rig: Rig) -> None:
    with running_receiver([Reply(500)]) as receiver:
        set_webhook(rig, receiver.url)
        failed = rig.service.send_test(actor=ACTOR)
        worked = rig.service.send_test(actor=ACTOR)
    assert (failed.ok, failed.error_class, failed.http_status) == (False, "server_error", 500)
    assert worked.ok is True
    assert rig.sleeps == []
    bodies = [json.loads(request.body) for request in receiver.requests]
    assert all(body["test"] is True and body["event_id"] == 0 for body in bodies)
    assert rig.service.deliveries() == []
    tests = [detail for action, detail in audit(rig.database) if action == "notification.test"]
    assert tests == [
        {"ok": False, "error_class": "server_error", "http_status": 500},
        {"ok": True, "http_status": 200},
    ]
    assert receiver.url not in json.dumps(audit(rig.database))


def test_the_test_button_without_a_channel_is_an_error(rig: Rig) -> None:
    with pytest.raises(NoChannelError):
        rig.service.send_test(actor=ACTOR)


# -- mail through the service -----------------------------------------------------------------


def test_an_event_is_mailed_over_starttls_through_the_service(rig: Rig, tmp_path: Path) -> None:
    pki = make_pki(tmp_path / "pki")
    service = NotificationService(
        rig.database,
        MASTER,
        base_url=BASE,
        sleep=rig.sleeps.append,
        resolver=loopback,
        ssl_context=trusting_context(pki),
    )
    with running_smtp(pki, login=("alerts", MAIL_SECRET)) as server:
        view = service.configure(
            actor=ACTOR,
            channel_type="smtp",
            fields={
                "host": "localhost",
                "port": str(server.port),
                "from_address": "driftsniff@example.com",
                "to_addresses": "ops@example.com",
                "username": "alerts",
                "password": MAIL_SECRET,
            },
            min_severity="medium",
        )
        event = add_event(rig.database, severity="medium")
        outcome = service.deliver_event(event)
        assert server.wait_for(lambda state: bool(state.messages))
    assert view.type == "smtp"
    assert (outcome.sent, outcome.attempts) == (True, 1)
    assert f"Link: {BASE}/changes/{event}" in server.state.messages[0]
    assert MAIL_SECRET not in json.dumps(view.as_dict())
    service.close()
