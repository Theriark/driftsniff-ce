"""Canary test of the notifications (P9-T4): no before or after value or path reaches a message.

An event is stored whose items hold a canary in every place a change can carry data: the before
and after values, the object name and the path. The event is delivered by webhook and by mail
through the real senders to local receivers. The test then looks for every canary in what the
receivers got (body and request fields, mail text), in the stored deliveries, in the audit events
and in the log output. The only text of the event that may travel is what the message is made of:
the source name, the severity, the generated summary, the item count and the link.
"""

import json
import logging
import secrets
from pathlib import Path

import pytest
import sqlalchemy as sa
from contract.fake_notify import (
    add_event,
    make_store,
    running_receiver,
    running_smtp,
    trusting_context,
)
from contract.fake_tls import make_pki

from driftsniff.db.tables import audit_events, notification_deliveries
from driftsniff.notify.deliveries import NotificationService
from driftsniff.secrets.keys import MasterKey

MASTER = MasterKey(bytes(range(32)))
BASE = "https://driftsniff.example"
LOGIN_SECRET = "CANARY-" + secrets.token_hex(12)  # noqa: S105
WEBHOOK_SECRET = "CANARY-" + secrets.token_hex(12)


def canary(label: str) -> str:
    return f"CANARY-{label}-{secrets.token_hex(12)}"


def loopback(_host: str) -> list[str]:
    return ["127.0.0.1"]


def test_no_before_after_name_or_path_reaches_a_webhook_or_a_mail(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    planted = {
        "before": canary("before"),
        "after": canary("after"),
        "name": canary("name"),
        "path": canary("path"),
        "second_before": canary("before2"),
        "second_after": canary("after2"),
    }
    database = make_store(tmp_path)
    pki = make_pki(tmp_path / "pki")
    service = NotificationService(
        database,
        MASTER,
        base_url=BASE,
        sleep=lambda _seconds: None,
        resolver=loopback,
        ssl_context=trusting_context(pki),
    )
    event_id = add_event(
        database,
        severity="critical",
        items=[
            {
                "path": f"wifi.{planted['path']}.passphrase",
                "before_value": planted["before"],
                "after_value": planted["after"],
                "object_name_at_time": planted["name"],
            },
            {
                "path": "firewall.order",
                "before_value": planted["second_before"],
                "after_value": planted["second_after"],
                "object_name_at_time": planted["name"],
            },
        ],
    )
    with caplog.at_level(logging.DEBUG), running_receiver() as receiver:
        service.configure(
            actor="admin",
            channel_type="webhook",
            fields={"url": f"{receiver.url}?key={WEBHOOK_SECRET}"},
            min_severity="low",
        )
        assert service.deliver_event(event_id).sent is True
        assert service.send_test(actor="admin").ok is True
        webhook_bytes = b"".join(
            request.body + json.dumps(request.headers).encode() for request in receiver.requests
        )

    with caplog.at_level(logging.DEBUG), running_smtp(pki, login=("alerts", LOGIN_SECRET)) as smtp:
        service.configure(
            actor="admin",
            channel_type="smtp",
            fields={
                "host": "localhost",
                "port": str(smtp.port),
                "from_address": "driftsniff@example.com",
                "to_addresses": "ops@example.com",
                "username": "alerts",
                "password": LOGIN_SECRET,
            },
            min_severity="low",
        )
        other_event = add_event(database, severity="high", items=[{"path": planted["path"]}])
        assert service.deliver_event(other_event).sent is True
        assert smtp.wait_for(lambda state: bool(state.messages))
        mail_text = "\n".join(smtp.state.messages)
    service.close()

    with database.read() as connection:
        stored = json.dumps(
            [
                [str(value) for value in row]
                for table in (notification_deliveries, audit_events)
                for row in connection.execute(sa.select(table))
            ]
        )
    surfaces = {
        "webhook request": webhook_bytes.decode("utf-8", "replace"),
        "mail": mail_text,
        "stored deliveries and audit events": stored,
        "log output": caplog.text,
    }
    for name, text in surfaces.items():
        for label, value in planted.items():
            assert value not in text, f"the {label} canary reached the {name}"
            assert value.removeprefix("CANARY-") not in text, f"the {label} hex reached the {name}"
        # The secrets of the channel configuration must not travel or be stored either.
        assert WEBHOOK_SECRET not in text, f"the webhook address secret reached the {name}"
        assert LOGIN_SECRET not in text, f"the mail login reached the {name}"
    # What the message is made of does arrive: the receivers did get the event.
    assert f'"event_id":{event_id}' in surfaces["webhook request"]
    assert f"Event: {other_event}" in mail_text
