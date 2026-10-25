"""Canary test of the admin settings (P10-T8 slice A): no password or typed value is repeated.

The settings routes take a password (a new user) and free text (values that break a rule). The
test posts canaries through every route, accepted and refused, then looks for them in every
answer with its headers, in the database file and rows (audit events included) and in the log
output. The only text of the request that may come back is what the settings show by design: the
user name. The last test proves the scan can find that.
"""

from typing import Any

import sqlalchemy as sa

from driftsniff.db.tables import users

from .appkit import Kit
from .canary import (
    CanaryFactory,
    CanaryScanner,
    Leak,
    assert_no_leaks,
    capture_logs,
    scan_database,
    scan_logs,
)

SURFACE_ANSWER = "settings answer"


def whole(response: Any) -> str:
    """The body and every header of a response, as the client sees them."""
    return response.text + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())


def test_no_canary_reaches_an_answer_the_database_or_the_logs(kit: Kit) -> None:
    factory = CanaryFactory()
    password = factory.new("the password of a new user")
    second = factory.new("the password of a user whose name is taken")
    role = factory.new("a role that does not exist")
    days = factory.new("a retention value that is not a number")
    gigabytes = factory.new("a storage warning value that is not a number")
    headers = kit.new_session("admin").headers()
    new_user = {"username": "ada", "password": password.value, "role": "operator"}
    taken = {"username": "ada", "password": second.value, "role": "viewer"}
    bad_role = {"username": "bob", "password": second.value, "role": role.value}
    calls = [
        ("/settings/users", new_user),
        ("/settings/users", taken),
        ("/settings/users", bad_role),
        ("/settings/retention", {"retention_days": days.value}),
        ("/settings/storage-warning", {"storage_warning_gb": gigabytes.value}),
        ("/settings/retention", {"retention_days": "120"}),
        ("/settings/storage-warning", {"storage_warning_gb": "3"}),
    ]
    with capture_logs() as captured:
        answers = [kit.client.post(path, headers=headers, json=body) for path, body in calls]
        answers.append(kit.client.get("/settings", headers=headers))
    assert [answer.status_code for answer in answers] == [201, 409, 422, 422, 422, 200, 200, 200]

    scanner = CanaryScanner(factory.issued)
    leaks: list[Leak] = []
    for number, answer in enumerate(answers, start=1):
        leaks.extend(scanner.find(SURFACE_ANSWER, f"answer {number}", whole(answer)))
    leaks.extend(scan_logs(scanner, captured))
    leaks.extend(scan_database(scanner, kit.store))
    assert_no_leaks(leaks)


def test_the_stored_password_is_only_a_hash_that_no_answer_shows(kit: Kit) -> None:
    factory = CanaryFactory()
    password = factory.new("the password of a new user")
    headers = kit.new_session("admin").headers()
    body = {"username": "ada", "password": password.value, "role": "viewer"}
    created = kit.client.post("/settings/users", headers=headers, json=body)
    assert created.status_code == 201
    query = sa.select(users.c.password_hash).where(users.c.username == "ada")
    with kit.store.read() as connection:
        stored = str(connection.execute(query).scalar_one())
    assert stored.startswith("$argon2id$")
    assert password.value not in stored
    listing = kit.client.get("/settings", headers=headers)
    assert stored not in whole(listing) + whole(created)


def test_the_scan_finds_a_user_name_because_the_settings_show_it_by_design(kit: Kit) -> None:
    factory = CanaryFactory()
    named = factory.new("the name of a user")
    password = factory.new("the password of the named user")
    headers = kit.new_session("admin").headers()
    body = {"username": "u" + named.hex_part, "password": password.value, "role": "viewer"}
    created = kit.client.post("/settings/users", headers=headers, json=body)
    assert created.status_code == 201
    listing = kit.client.get("/settings", headers=headers)
    leaks = CanaryScanner(factory.issued).find(SURFACE_ANSWER, "the user list", whole(listing))
    assert [leak.where for leak in leaks] == ["the name of a user"]
