"""Canary harness, extended to API output, the OpenAPI document and the backup file (P9-T6).

The core harness (``canary.py``) plants synthetic secrets in a fake source and looks for them in
the database, the logs and the errors. The notification canary test does the same for messages.
This file covers the rest of what leaves the application:

* API output: the change list and detail, the enrichment answer, the token list and the answers of
  the notification routes, with every response header. Planted: values of secret and unclassified
  items (never written by the pipeline, so the API must not show them even if a row held them),
  credential-shaped text in the path, object name, rationale and order detail, the values of the
  API tokens and the session cookie, a token sent in a request, and the secrets of the channel
  configuration (the webhook address path and query, the mail password; the mail user name is
  shown to admins by design, so it is not planted here).
* The OpenAPI document: none of that, and no data of the installation.
* The backup file: nothing that must never be stored in the clear (token values, the session
  cookie, the login password, the webhook address secrets, the mail login), searched as bytes and,
  row by row, with the compressed columns decompressed.

A hit names the surface and where the canary was planted, never the canary. The last test shows the
scan can find something: a config value is shown by design and must be reported.
"""

from pathlib import Path
from typing import Any

from driftsniff.db.backup import backup_database
from driftsniff.db.engine import Database

from .appkit import CORRECT, Kit, add_change
from .canary import (
    Canary,
    CanaryFactory,
    CanaryScanner,
    Leak,
    assert_no_leaks,
    scan_database_rows,
)

SURFACE_API = "api output"
SURFACE_OPENAPI = "openapi document"
SURFACE_BACKUP = "backup file"
FINGERPRINT = "fp1:0a1b2c3d:" + "ab12cd34ef56" * 2 + "ab12cd34"
OTHER_FINGERPRINT = FINGERPRINT.replace("ab12", "ff00")


def shape_url(canary: Canary) -> str:
    return "https://svc:" + canary.value + "@controller.example.invalid/api"


def shape_prefixed(canary: Canary) -> str:
    return "gh" + "p_" + canary.value


def shape_jwt(canary: Canary) -> str:
    return "ey" + "J" + "hbGciOiJIUzI1NiJ9" + "." + canary.value + "." + "c2lnbmF0dXJl"


def whole(response: Any) -> str:
    """The body and every header of a response, as the client sees them."""
    return response.text + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())


def token_canaries(kit: Kit) -> list[Canary]:
    return [
        Canary(value, f"the value of the {kind} API token")
        for kind, value in kit.token_values.items()
    ]


def put_channel(kit: Kit, admin_headers: dict[str, str], body: dict[str, Any]) -> None:
    response = kit.client.put("/notifications/channel", headers=admin_headers, json=body)
    assert response.status_code == 200, response.text


def test_no_canary_reaches_the_api_output_or_the_openapi_document(kit: Kit) -> None:
    factory = CanaryFactory()
    secret_before = factory.new("the before value of a secret item")
    secret_after = factory.new("the after value of a secret item")
    unclassified = factory.new("the after value of an unclassified item")
    in_path = factory.new("the path of an item")
    in_name = factory.new("the object name of an item")
    in_rationale = factory.new("the rationale of an item")
    in_detail_key = factory.new("the key of an order detail")
    in_detail_list = factory.new("a list in an order detail")
    webhook_path = factory.new("the path of the webhook address")
    webhook_query = factory.new("the query of the webhook address")
    mail_password = factory.new("the mail password")
    sent_token = factory.new("a token sent in a request")

    event_id = add_change(
        kit.store,
        (
            {
                "path": "wifi.passphrase",
                "field_class": "secret",
                "severity": "critical",
                "before_value": secret_before.value,
                "after_value": secret_after.value,
                "before_fp": FINGERPRINT,
                "after_fp": OTHER_FINGERPRINT,
            },
            {"path": "mystery", "field_class": "unclassified", "after_value": unclassified.value},
            {
                "path": "x." + shape_prefixed(in_path),
                "object_name_at_time": shape_url(in_name),
                "rationale": "Fired for " + shape_jwt(in_rationale),
                "order_detail": {
                    "key": shape_prefixed(in_detail_key),
                    "after": [shape_url(in_detail_list)],
                    "count": 3,
                },
            },
        ),
    )
    admin = kit.new_session("admin")
    read, enrich = kit.bearer("read"), kit.bearer("enrich")
    surfaces: dict[str, str] = {}

    surfaces["GET /api/v1/changes"] = whole(kit.client.get("/api/v1/changes", headers=read))
    detail = kit.client.get(f"/api/v1/changes/{event_id}", headers=read)
    surfaces["GET /api/v1/changes/{id}"] = whole(detail)
    created = kit.client.post(
        f"/api/v1/changes/{event_id}/enrichments",
        headers=enrich,
        json={"provider_label": "triage", "summary": "planned change"},
    )
    assert created.status_code == 201
    surfaces["POST enrichments"] = whole(created)
    bad_token = {"Authorization": f"Bearer {sent_token.value}"}
    surfaces["a refused token"] = whole(kit.client.get("/api/v1/changes", headers=bad_token))
    surfaces["GET /tokens"] = whole(kit.client.get("/tokens", headers=admin.headers()))

    put_channel(
        kit,
        admin.headers(),
        {
            "type": "webhook",
            "url": f"https://hooks.example:8443/x/{webhook_path.value}?key={webhook_query.value}",
        },
    )
    surfaces["GET /notifications/channel (webhook)"] = whole(
        kit.client.get("/notifications/channel", headers=admin.headers())
    )
    put_channel(
        kit,
        admin.headers(),
        {
            "type": "smtp",
            "host": "mail.example",
            "port": 465,
            "security": "tls",
            "from_address": "driftsniff@example.com",
            "to_addresses": ["ops@example.com"],
            "username": "alerts",
            "password": mail_password.value,
        },
    )
    surfaces["GET /notifications/channel (smtp)"] = whole(
        kit.client.get("/notifications/channel", headers=admin.headers())
    )
    surfaces["GET /notifications/deliveries"] = whole(
        kit.client.get("/notifications/deliveries", headers=admin.headers())
    )
    kit.client.cookies.clear()
    openapi = whole(kit.client.get("/api/v1/openapi.json"))

    scanner = CanaryScanner(
        [
            *factory.issued,
            *token_canaries(kit),
            Canary(admin.cookie, "the session cookie"),
            Canary(CORRECT, "the login password"),
        ]
    )
    leaks: list[Leak] = []
    for location, text in surfaces.items():
        leaks.extend(scanner.find(SURFACE_API, location, text))
    leaks.extend(scanner.find(SURFACE_OPENAPI, "GET /api/v1/openapi.json", openapi))
    assert_no_leaks(leaks)

    # What the answers are made of is still there: the scan is not looking at empty answers.
    body = detail.json()
    assert [item["field_class"] for item in body["items"]] == ["secret", "unclassified", "config"]
    assert body["items"][0]["before_fingerprint"] == "ab12cd34ef56"
    assert body["items"][2]["order_detail"]["count"] == 3
    assert "***REDACTED***" in detail.text
    assert surfaces["GET /tokens"].count('"prefix"') == len(kit.token_values)
    # The mail user name is shown to admins (the password never is).
    assert '"username":"alerts"' in surfaces["GET /notifications/channel (smtp)"]
    assert '"password_set":true' in surfaces["GET /notifications/channel (smtp)"]


def test_no_canary_reaches_the_backup_file(kit: Kit, tmp_path: Path) -> None:
    factory = CanaryFactory()
    wrong_password = factory.new("a password typed at a failed login")
    webhook_path = factory.new("the path of the webhook address")
    webhook_query = factory.new("the query of the webhook address")
    mail_login = factory.new("the mail login")
    mail_password = factory.new("the mail password")

    admin = kit.new_session("admin")
    failed = kit.client.post("/login", data={"username": "admin", "password": wrong_password.value})
    assert failed.status_code == 401
    put_channel(
        kit,
        admin.headers(),
        {
            "type": "webhook",
            "url": f"https://hooks.example:8443/x/{webhook_path.value}?key={webhook_query.value}",
        },
    )
    put_channel(
        kit,
        admin.headers(),
        {
            "type": "smtp",
            "host": "mail.example",
            "port": 465,
            "security": "tls",
            "from_address": "driftsniff@example.com",
            "to_addresses": ["ops@example.com"],
            "username": mail_login.value,
            "password": mail_password.value,
        },
    )
    kit.client.cookies.clear()

    target = tmp_path / "backup" / "copy.db"
    backup_database(kit.store.path, target)
    scanner = CanaryScanner(
        [
            *factory.issued,
            *token_canaries(kit),
            Canary(admin.cookie, "the session cookie"),
            Canary(CORRECT, "the login password"),
        ]
    )
    leaks = scanner.find(SURFACE_BACKUP, target.name, target.read_bytes())
    copy = Database(target)
    try:
        leaks.extend(scan_database_rows(scanner, copy))
    finally:
        copy.close()
    assert_no_leaks(leaks)
    # The backup is a real copy: it holds the users and the token prefixes it was made from.
    assert target.stat().st_size > 0


def test_the_scan_finds_a_value_that_is_shown_by_design(kit: Kit) -> None:
    factory = CanaryFactory()
    shown = factory.new("the before value of a config item, shown by design")
    event_id = add_change(
        kit.store, ({"path": "name", "field_class": "config", "before_value": shown.value},)
    )
    response = kit.client.get(f"/api/v1/changes/{event_id}", headers=kit.bearer("read"))
    scanner = CanaryScanner(factory.issued)
    leaks = scanner.find(SURFACE_API, "GET /api/v1/changes/{id}", whole(response))
    assert [leak.where for leak in leaks] == [shown.where]
    assert shown.value not in leaks[0].describe()
