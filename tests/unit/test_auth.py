"""Users, passwords, sessions, sign-in limits and the setup code (P9-T1).

The tests run the real service on a migrated database with an injected clock and a cheap argon2
setting (the production cost is asserted separately). Passwords are canaries: none may reach the
database in clear.
"""

import hashlib
import re
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import pytest
import sqlalchemy as sa
from argon2 import PasswordHasher, Type, extract_parameters

from driftsniff.db import tables
from driftsniff.db.engine import Database
from driftsniff.web.auth import (
    ABSOLUTE_LIFETIME,
    ACTION_SETUP_COMPLETED,
    ACTION_USER_DISABLED,
    ACTION_USER_LOCKED,
    IDLE_TIMEOUT,
    SETUP_CODE_SETTING,
    AuthService,
    LoginFailedError,
    LoginThrottle,
    LoginThrottledError,
    PasswordPolicyError,
    SetupCodeError,
    SetupUnavailableError,
    UsernameError,
    check_password_policy,
    make_password_hasher,
    new_setup_code,
    normalise_username,
    stamp,
)

START = datetime(2026, 10, 22, 8, 0, 0, tzinfo=UTC)
CORRECT = "CANARY-correct horse battery"
WRONG = "CANARY-wrong horse battery"
ADDRESS = "203.0.113.7"
OTHER_ADDRESS = "203.0.113.8"


class Clock:
    """A clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **units: float) -> None:
        self.now += timedelta(**units)


class SpyHasher(PasswordHasher):
    """A cheap argon2 hasher that counts how often a hash was checked."""

    def __init__(self) -> None:
        super().__init__(time_cost=1, memory_cost=8, parallelism=1)
        self.verified = 0

    def verify(self, hash: str | bytes, password: str | bytes) -> Literal[True]:
        self.verified += 1
        return super().verify(hash, password)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def hasher() -> SpyHasher:
    return SpyHasher()


@pytest.fixture
def auth(store: Database, clock: Clock, hasher: SpyHasher) -> AuthService:
    return AuthService(store, clock=clock, hasher=hasher)


@pytest.fixture
def ada(auth: AuthService) -> int:
    return auth.create_user("ada", CORRECT, "operator")


def database_text(database: Database) -> str:
    """Every row of every table as text, for the canary checks."""
    with database.read() as connection:
        raw: Any = connection.connection.driver_connection
        assert raw is not None
        return "\n".join(raw.iterdump())


def fail(auth: AuthService, username: str = "ada", address: str = ADDRESS) -> None:
    with pytest.raises(LoginFailedError):
        auth.login(username, WRONG, address)


def wait_time(auth: AuthService, username: str = "ada", address: str = ADDRESS) -> int:
    """The wait a sign-in attempt is told to observe (it must be refused)."""
    with pytest.raises(LoginThrottledError) as raised:
        auth.login(username, CORRECT, address)
    return raised.value.retry_after


def user_row(database: Database, username: str = "ada") -> sa.Row[Any]:
    with database.read() as connection:
        return connection.execute(
            sa.select(tables.users.c.id, tables.users.c.failed_logins, tables.users.c.locked_until)
            .where(tables.users.c.username == username)
            .limit(1)
        ).one()


def session_rows(database: Database) -> list[sa.Row[Any]]:
    with database.read() as connection:
        query = sa.select(
            tables.sessions.c.token_hash,
            tables.sessions.c.created_at,
            tables.sessions.c.last_seen_at,
        )
        return list(connection.execute(query).all())


def audit_actions(database: Database) -> list[str]:
    with database.read() as connection:
        rows = connection.execute(sa.select(tables.audit_events.c.action)).all()
    return [row.action for row in rows]


# -- passwords and user names ------------------------------------------------------------------


def test_the_production_hasher_is_argon2id_with_64_mib_3_passes_and_one_lane() -> None:
    parameters = extract_parameters(make_password_hasher().hash(CORRECT))
    assert parameters.type is Type.ID
    assert parameters.memory_cost == 64 * 1024
    assert parameters.time_cost == 3
    assert parameters.parallelism == 1


@pytest.mark.parametrize("length", [0, 1, 11])
def test_a_password_under_12_characters_is_refused(length: int) -> None:
    with pytest.raises(PasswordPolicyError, match="at least 12"):
        check_password_policy("a" * length)


@pytest.mark.parametrize("length", [12, 100, 256])
def test_a_password_from_12_to_256_characters_is_accepted(length: int) -> None:
    check_password_policy("a" * length)


def test_a_password_over_256_characters_is_refused() -> None:
    with pytest.raises(PasswordPolicyError, match="at most 256"):
        check_password_policy("a" * 257)


def test_the_password_length_counts_characters_not_bytes() -> None:
    check_password_policy("é" * 12)
    with pytest.raises(PasswordPolicyError):
        check_password_policy("é" * 11)


@pytest.mark.parametrize(
    ("raw", "stored"),
    [("  Ada  ", "ada"), ("a.b_c+d@e-f", "a.b_c+d@e-f"), ("abc", "abc"), ("a" * 64, "a" * 64)],
)
def test_a_user_name_is_trimmed_and_lower_cased(raw: str, stored: str) -> None:
    assert normalise_username(raw) == stored


@pytest.mark.parametrize("raw", ["", "ab", "a" * 65, "-ada", "ada smith", "adä", "a/b/c"])
def test_a_bad_user_name_is_refused(raw: str) -> None:
    with pytest.raises(UsernameError):
        normalise_username(raw)


def test_create_user_stores_a_hash_and_an_audit_event(auth: AuthService, store: Database) -> None:
    user_id = auth.create_user("Ada", CORRECT, "operator")
    with store.read() as connection:
        row = connection.execute(sa.select(tables.users).where(tables.users.c.id == user_id)).one()
    assert row.username == "ada"
    assert row.role == "operator"
    assert row.password_hash.startswith("$argon2id$")
    assert CORRECT not in database_text(store)
    assert "user.created" in audit_actions(store)


def test_create_user_refuses_a_taken_name_a_bad_role_and_a_weak_password(
    auth: AuthService, ada: int
) -> None:
    with pytest.raises(UsernameError, match="already taken"):
        auth.create_user("ADA", CORRECT, "viewer")
    with pytest.raises(ValueError, match="role"):
        auth.create_user("bob", CORRECT, "root")
    with pytest.raises(PasswordPolicyError):
        auth.create_user("bob", "short", "viewer")


# -- sign-in -----------------------------------------------------------------------------------


def test_login_starts_a_session_and_stores_only_the_hash_of_the_cookie(
    auth: AuthService, ada: int, store: Database
) -> None:
    grant = auth.login("ada", CORRECT, ADDRESS)
    assert (grant.principal.user_id, grant.principal.username) == (ada, "ada")
    assert grant.principal.role == "operator"
    (row,) = session_rows(store)
    assert row.token_hash == hashlib.sha256(grant.cookie_value.encode()).hexdigest()
    assert grant.cookie_value not in database_text(store)
    assert CORRECT not in database_text(store)
    assert len(grant.cookie_value) >= 43
    assert auth.authenticate(grant.cookie_value) == grant.principal


def test_a_stolen_database_row_cannot_be_used_as_the_cookie(
    auth: AuthService, ada: int, store: Database
) -> None:
    auth.login("ada", CORRECT, ADDRESS)
    (row,) = session_rows(store)
    assert auth.authenticate(row.token_hash) is None


def test_every_login_gets_its_own_cookie_and_csrf_value(auth: AuthService, ada: int) -> None:
    first = auth.login("ada", CORRECT, ADDRESS)
    second = auth.login("  ADA ", CORRECT, ADDRESS)
    assert first.cookie_value != second.cookie_value
    assert first.principal.csrf_token != second.principal.csrf_token
    assert first.principal.session_id != second.principal.session_id


def test_the_grant_does_not_show_secrets_in_its_repr(auth: AuthService, ada: int) -> None:
    grant = auth.login("ada", CORRECT, ADDRESS)
    assert grant.cookie_value not in repr(grant)
    assert grant.principal.csrf_token not in repr(grant)


def test_every_failure_gives_the_same_error_and_the_same_hashing_work(
    auth: AuthService, ada: int, hasher: SpyHasher
) -> None:
    disabled = auth.create_user("bob", CORRECT, "viewer")
    auth.set_user_disabled(disabled, disabled=True, actor="ada")
    cases = [
        ("nobody", WRONG),
        ("nobody", CORRECT),
        ("ada", WRONG),
        ("ada", "x" * 5000),
        ("bob", CORRECT),
        ("", ""),
    ]
    messages = set()
    for index, (username, password) in enumerate(cases):
        hasher.verified = 0
        with pytest.raises(LoginFailedError) as raised:
            auth.login(username, password, f"198.51.100.{index}")
        messages.add(str(raised.value))
        assert hasher.verified == 1, (username, password[:10])
    assert messages == {"invalid user name or password"}


def test_a_failed_login_shows_nothing_about_the_password(auth: AuthService, ada: int) -> None:
    with pytest.raises(LoginFailedError) as raised:
        auth.login("ada", WRONG, ADDRESS)
    assert WRONG not in str(raised.value)
    assert WRONG not in repr(raised.value)


def test_a_weaker_stored_hash_is_replaced_by_the_current_cost_at_login(
    store: Database,
) -> None:
    old = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    old.create_user("ada", CORRECT, "viewer")
    new = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=2))
    new.login("ada", CORRECT, ADDRESS)
    with store.read() as connection:
        stored = connection.execute(sa.select(tables.users.c.password_hash)).scalar_one()
    assert extract_parameters(stored).time_cost == 2
    new.login("ada", CORRECT, ADDRESS)


# -- limits ------------------------------------------------------------------------------------


def test_the_sixth_attempt_inside_a_minute_has_to_wait(
    auth: AuthService, ada: int, clock: Clock, hasher: SpyHasher
) -> None:
    for _ in range(5):
        fail(auth)
    hasher.verified = 0
    assert wait_time(auth) == 1
    assert hasher.verified == 0
    clock.advance(seconds=1)
    assert auth.login("ada", CORRECT, ADDRESS).principal.username == "ada"


def test_every_further_failure_doubles_the_wait(auth: AuthService, ada: int, clock: Clock) -> None:
    for _ in range(5):
        fail(auth)
    assert wait_time(auth) == 1
    clock.advance(seconds=1)
    fail(auth)
    assert wait_time(auth) == 2
    clock.advance(seconds=2)
    fail(auth)
    assert wait_time(auth) == 4
    clock.advance(seconds=3)
    assert wait_time(auth) == 1
    clock.advance(seconds=1)
    fail(auth)
    assert wait_time(auth) == 8


def test_a_quiet_minute_starts_the_count_again(auth: AuthService, ada: int, clock: Clock) -> None:
    for _ in range(5):
        fail(auth)
    clock.advance(seconds=61)
    fail(auth)
    fail(auth)


def test_failures_from_one_address_block_that_address_only(auth: AuthService, ada: int) -> None:
    for index in range(5):
        fail(auth, f"nobody{index}")
    assert wait_time(auth) == 1
    assert auth.login("ada", CORRECT, OTHER_ADDRESS).principal.username == "ada"


def test_failures_against_one_user_block_that_user_from_every_address(
    auth: AuthService, ada: int
) -> None:
    bob = auth.create_user("bob", CORRECT, "viewer")
    for index in range(5):
        fail(auth, "ada", f"198.51.100.{index}")
    assert wait_time(auth, "ada", "192.0.2.99") == 1
    assert auth.login("bob", CORRECT, "192.0.2.99").principal.user_id == bob


def test_ten_failures_in_a_row_lock_the_user_for_15_minutes(
    auth: AuthService, ada: int, clock: Clock, store: Database
) -> None:
    for _ in range(9):
        fail(auth)
        clock.advance(seconds=61)
    fail(auth)
    locked_until = stamp(clock.now + timedelta(minutes=15))
    row = user_row(store)
    assert (row.failed_logins, row.locked_until) == (0, locked_until)
    assert audit_actions(store).count(ACTION_USER_LOCKED) == 1
    clock.advance(minutes=14, seconds=59)
    with pytest.raises(LoginFailedError):
        auth.login("ada", CORRECT, ADDRESS)
    assert user_row(store).locked_until == locked_until
    clock.advance(seconds=1)
    assert auth.login("ada", CORRECT, ADDRESS).principal.username == "ada"
    row = user_row(store)
    assert (row.failed_logins, row.locked_until) == (0, None)


def test_a_locked_user_gets_the_generic_error(
    auth: AuthService, ada: int, clock: Clock, hasher: SpyHasher
) -> None:
    for _ in range(10):
        fail(auth)
        clock.advance(seconds=61)
    hasher.verified = 0
    with pytest.raises(LoginFailedError, match="invalid user name or password"):
        auth.login("ada", CORRECT, ADDRESS)
    assert hasher.verified == 1


def test_a_good_login_clears_the_failure_count(
    auth: AuthService, ada: int, clock: Clock, store: Database
) -> None:
    for _ in range(3):
        fail(auth)
        clock.advance(seconds=61)
    assert user_row(store).failed_logins == 3
    auth.login("ada", CORRECT, ADDRESS)
    assert user_row(store).failed_logins == 0


def test_the_throttle_table_stays_bounded() -> None:
    clock = Clock()
    throttle = LoginThrottle(clock)
    for index in range(5000):
        throttle.record_failure(f"ip:10.0.{index // 256}.{index % 256}")
    assert len(throttle._entries) <= 4096
    assert throttle.retry_after("ip:10.0.0.0") == 0


# -- sessions ----------------------------------------------------------------------------------


def test_a_session_survives_just_under_8_hours_without_requests(
    auth: AuthService, ada: int, clock: Clock
) -> None:
    grant = auth.login("ada", CORRECT, ADDRESS)
    clock.advance(hours=7, minutes=59, seconds=59)
    assert auth.authenticate(grant.cookie_value) is not None


def test_a_session_ends_after_8_hours_without_requests(
    auth: AuthService, ada: int, clock: Clock, store: Database
) -> None:
    grant = auth.login("ada", CORRECT, ADDRESS)
    clock.advance(hours=8)
    assert auth.authenticate(grant.cookie_value) is None
    assert session_rows(store) == []
    assert IDLE_TIMEOUT == timedelta(hours=8)


def test_a_session_ends_7_days_after_login_even_when_it_is_in_use(
    auth: AuthService, ada: int, clock: Clock, store: Database
) -> None:
    grant = auth.login("ada", CORRECT, ADDRESS)
    for _ in range(27):
        clock.advance(hours=6)
        assert auth.authenticate(grant.cookie_value) is not None
    clock.advance(hours=6)
    assert clock.now - START == ABSOLUTE_LIFETIME == timedelta(days=7)
    assert auth.authenticate(grant.cookie_value) is None
    assert session_rows(store) == []


def test_the_last_seen_time_moves_at_most_once_a_minute(
    auth: AuthService, ada: int, clock: Clock, store: Database
) -> None:
    grant = auth.login("ada", CORRECT, ADDRESS)
    clock.advance(seconds=30)
    auth.authenticate(grant.cookie_value)
    assert session_rows(store)[0].last_seen_at == stamp(START)
    clock.advance(seconds=31)
    auth.authenticate(grant.cookie_value)
    assert session_rows(store)[0].last_seen_at == stamp(clock.now)


def test_an_ended_session_is_removed_by_the_next_login(
    auth: AuthService, ada: int, clock: Clock, store: Database
) -> None:
    auth.login("ada", CORRECT, ADDRESS)
    clock.advance(hours=9)
    auth.login("ada", CORRECT, ADDRESS)
    assert len(session_rows(store)) == 1


def test_logout_deletes_the_session_row(auth: AuthService, ada: int, store: Database) -> None:
    keep = auth.login("ada", CORRECT, ADDRESS)
    gone = auth.login("ada", CORRECT, ADDRESS)
    auth.logout(gone.cookie_value)
    assert auth.authenticate(gone.cookie_value) is None
    assert auth.authenticate(keep.cookie_value) is not None
    assert len(session_rows(store)) == 1
    auth.logout("not-a-session")


def test_a_disabled_user_loses_every_session_at_once(
    auth: AuthService, ada: int, store: Database
) -> None:
    first = auth.login("ada", CORRECT, ADDRESS)
    second = auth.login("ada", CORRECT, OTHER_ADDRESS)
    other = auth.create_user("bob", CORRECT, "viewer")
    bob = auth.login("bob", CORRECT, ADDRESS)
    assert auth.set_user_disabled(ada, disabled=True, actor="bob") is True
    assert auth.authenticate(first.cookie_value) is None
    assert auth.authenticate(second.cookie_value) is None
    assert auth.authenticate(bob.cookie_value) is not None
    assert len(session_rows(store)) == 1
    with pytest.raises(LoginFailedError):
        auth.login("ada", CORRECT, ADDRESS)
    assert ACTION_USER_DISABLED in audit_actions(store)
    assert auth.set_user_disabled(ada, disabled=False, actor="bob") is True
    assert auth.login("ada", CORRECT, ADDRESS).principal.username == "ada"
    assert auth.set_user_disabled(other + 100, disabled=True, actor="bob") is False


@pytest.mark.parametrize("cookie", [None, "", "x" * 500, "unknown-cookie-value"])
def test_a_missing_or_unknown_cookie_is_no_session(
    auth: AuthService, ada: int, cookie: str | None
) -> None:
    auth.login("ada", CORRECT, ADDRESS)
    assert auth.authenticate(cookie) is None


# -- the setup code ----------------------------------------------------------------------------


def test_a_setup_code_has_four_groups_of_four_readable_characters() -> None:
    codes = {new_setup_code() for _ in range(50)}
    assert len(codes) == 50
    for code in codes:
        assert re.fullmatch(r"[A-Z2-9]{4}(-[A-Z2-9]{4}){3}", code)
        assert not set(code) & set("01ILO")


def test_only_the_hash_of_the_setup_code_is_stored(auth: AuthService, store: Database) -> None:
    code = auth.issue_setup_code()
    with store.read() as connection:
        stored = connection.execute(
            sa.select(tables.settings.c.value).where(tables.settings.c.key == SETUP_CODE_SETTING)
        ).scalar_one()
    assert stored == hashlib.sha256(code.replace("-", "").encode()).hexdigest()
    assert code not in database_text(store)
    assert code.replace("-", "") not in database_text(store)


def test_ensure_setup_code_issues_one_code_only_while_there_is_no_admin(
    auth: AuthService,
) -> None:
    first = auth.ensure_setup_code()
    assert first is not None
    assert auth.ensure_setup_code() is None
    auth.complete_setup(first, "ada", CORRECT, ADDRESS)
    assert auth.ensure_setup_code() is None


def test_issue_setup_code_replaces_the_earlier_code(auth: AuthService) -> None:
    first = auth.issue_setup_code()
    second = auth.issue_setup_code()
    with pytest.raises(SetupCodeError):
        auth.complete_setup(first, "ada", CORRECT, ADDRESS)
    assert auth.complete_setup(second, "ada", CORRECT, ADDRESS).principal.role == "admin"


def test_setup_creates_the_first_admin_and_signs_them_in(
    auth: AuthService, store: Database
) -> None:
    code = auth.issue_setup_code()
    assert auth.has_admin() is False
    grant = auth.complete_setup(code, " Ada ", CORRECT, ADDRESS)
    assert (grant.principal.username, grant.principal.role) == ("ada", "admin")
    assert auth.authenticate(grant.cookie_value) == grant.principal
    assert auth.has_admin() is True
    assert ACTION_SETUP_COMPLETED in audit_actions(store)
    assert auth.login("ada", CORRECT, ADDRESS).principal.role == "admin"
    assert CORRECT not in database_text(store)


def test_the_setup_code_accepts_lower_case_and_missing_dashes(auth: AuthService) -> None:
    code = auth.issue_setup_code()
    grant = auth.complete_setup(code.replace("-", "").lower(), "ada", CORRECT, ADDRESS)
    assert grant.principal.role == "admin"


def test_a_second_use_of_the_setup_code_fails(auth: AuthService) -> None:
    code = auth.issue_setup_code()
    auth.complete_setup(code, "ada", CORRECT, ADDRESS)
    with pytest.raises(SetupUnavailableError):
        auth.complete_setup(code, "bob", CORRECT, ADDRESS)
    assert auth.has_admin() is True


def test_the_code_is_gone_even_if_every_admin_row_is_removed(
    auth: AuthService, store: Database
) -> None:
    code = auth.issue_setup_code()
    auth.complete_setup(code, "ada", CORRECT, ADDRESS)
    with store.write() as connection:
        connection.execute(sa.delete(tables.users))
    with pytest.raises(SetupCodeError):
        auth.complete_setup(code, "bob", CORRECT, ADDRESS)
    assert auth.has_admin() is False


def test_a_wrong_code_creates_nothing_and_keeps_the_real_code_valid(
    auth: AuthService, store: Database
) -> None:
    code = auth.issue_setup_code()
    with pytest.raises(SetupCodeError, match="not valid"):
        auth.complete_setup("AAAA-AAAA-AAAA-AAAA", "ada", CORRECT, ADDRESS)
    assert auth.has_admin() is False
    assert auth.complete_setup(code, "ada", CORRECT, ADDRESS).principal.role == "admin"


def test_no_code_at_all_is_a_wrong_code(auth: AuthService) -> None:
    with pytest.raises(SetupCodeError):
        auth.complete_setup("", "ada", CORRECT, ADDRESS)


def test_repeated_wrong_codes_make_the_address_wait(auth: AuthService) -> None:
    code = auth.issue_setup_code()
    for _ in range(5):
        with pytest.raises(SetupCodeError):
            auth.complete_setup("AAAA-AAAA-AAAA-AAAA", "ada", CORRECT, ADDRESS)
    with pytest.raises(LoginThrottledError) as raised:
        auth.complete_setup(code, "ada", CORRECT, ADDRESS)
    assert raised.value.retry_after == 1
    assert auth.complete_setup(code, "ada", CORRECT, OTHER_ADDRESS).principal.role == "admin"


def test_a_weak_password_or_bad_name_does_not_use_up_the_code(auth: AuthService) -> None:
    code = auth.issue_setup_code()
    with pytest.raises(PasswordPolicyError):
        auth.complete_setup(code, "ada", "short", ADDRESS)
    with pytest.raises(UsernameError):
        auth.complete_setup(code, "a b", CORRECT, ADDRESS)
    assert auth.complete_setup(code, "ada", CORRECT, ADDRESS).principal.role == "admin"


def test_two_requests_with_one_code_make_exactly_one_admin(store: Database, clock: Clock) -> None:
    auth = AuthService(store, clock=clock, hasher=SpyHasher())
    code = auth.issue_setup_code()
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def attempt(name: str) -> None:
        barrier.wait()
        try:
            auth.complete_setup(code, name, CORRECT, f"10.0.0.{len(name)}")
        except SetupUnavailableError:
            outcomes.append("unavailable")
        except SetupCodeError:
            outcomes.append("wrong code")
        else:
            outcomes.append("created")

    threads = [threading.Thread(target=attempt, args=(name,)) for name in ("first", "second")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert outcomes.count("created") == 1
    with store.read() as connection:
        admins = connection.execute(
            sa.select(sa.func.count()).select_from(tables.users)
        ).scalar_one()
    assert admins == 1
