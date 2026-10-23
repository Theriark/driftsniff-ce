"""Tests for the Development-only test accounts (docs/dev-test-accounts.md)."""

import json
import logging
import re
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa

from driftsniff import devseed
from driftsniff.cli import COMMANDS, DEV_COMMANDS, main
from driftsniff.config import Settings
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.db.tables import USER_ROLES, audit_events, users
from driftsniff.devseed import (
    CREDENTIALS_FILE_NAME,
    MARKER_VALUE,
    MARKER_VARIABLE,
    SEED_ROLES,
    DevSeedError,
    DevSeedRefusedError,
    check_development_only,
    new_password,
    seed_dev_accounts,
    username_for,
)
from driftsniff.web.auth import (
    AuthService,
    LoginFailedError,
    SetupUnavailableError,
    check_password_policy,
    make_password_hasher,
)

CHEAP_HASHER = make_password_hasher(memory_kib=8, time_cost=1)
PASSWORD_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{10,62}[A-Za-z0-9]")
ROOT = Path(__file__).resolve().parents[2]
# A synthetic value that stands for a credential somebody else already holds.
CANARY = "CANARY-existing-credential-0001"


@pytest.fixture(autouse=True)
def cheap_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The command line hashes with the production cost; the tests need not wait for it."""
    monkeypatch.setattr(devseed, "make_password_hasher", lambda: CHEAP_HASHER)


@pytest.fixture
def development(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A Development-marked installation whose data directory does not exist yet."""
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    monkeypatch.setenv(MARKER_VARIABLE, MARKER_VALUE)
    monkeypatch.delenv("DRIFTSNIFF_BASE_URL", raising=False)
    monkeypatch.delenv("DRIFTSNIFF_ENVIRONMENT_LABEL", raising=False)
    return data_dir


@pytest.fixture
def migrated(tmp_path: Path) -> Iterator[Database]:
    """A migrated database without any user."""
    database = Database(database_path(tmp_path))
    try:
        upgrade_to_head(database)
        yield database
    finally:
        database.close()


def stored_accounts(data_dir: Path) -> dict[str, tuple[str, str]]:
    """Every user in the database: user name to (role, password hash)."""
    database = Database(database_path(data_dir))
    try:
        with database.read() as connection:
            rows = connection.execute(
                sa.select(users.c.username, users.c.role, users.c.password_hash)
            ).all()
    finally:
        database.close()
    return {row.username: (row.role, row.password_hash) for row in rows}


def credentials(data_dir: Path) -> dict[str, dict[str, str]]:
    """The accounts in the credentials file the command wrote."""
    document = json.loads((data_dir / CREDENTIALS_FILE_NAME).read_text(encoding="utf-8"))
    accounts: dict[str, dict[str, str]] = document["accounts"]
    return accounts


def can_sign_in(data_dir: Path, username: str, secret: str) -> bool:
    database = Database(database_path(data_dir))
    try:
        AuthService(database, hasher=CHEAP_HASHER).login(username, secret, "127.0.0.1")
    except LoginFailedError:
        return False
    finally:
        database.close()
    return True


# -- the Development-only guard --------------------------------------------------------------


def test_refuses_without_the_development_marker(
    development: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(MARKER_VARIABLE)
    assert main(["seed-dev-accounts"]) == 1
    assert "Development only" in capsys.readouterr().err
    assert not development.exists()


@pytest.mark.parametrize("value", ["true", "development", "Development-Only-", "stage"])
def test_refuses_a_wrong_marker_value(
    value: str,
    development: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(MARKER_VARIABLE, value)
    assert main(["seed-dev-accounts"]) == 1
    assert "Development only" in capsys.readouterr().err
    assert not development.exists()


@pytest.mark.parametrize(
    "base_url",
    [
        "https://ce-stg-driftsniff.theriark.dev",
        "https://ee-stg-driftsniff.theriark.dev",
        "https://driftsniff.theriark.dev",
        "https://driftsniff.example.com",
        "https://ce-dev-driftsniff.example.com",
        "https://example.com/ce-dev-driftsniff.theriark.dev",
    ],
)
def test_refuses_a_stage_or_production_address_even_with_the_marker(
    base_url: str,
    development: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_BASE_URL", base_url)
    assert main(["seed-dev-accounts"]) == 1
    assert "not a Development address" in capsys.readouterr().err
    assert not development.exists()


def test_refuses_an_environment_badge_that_is_not_development(
    development: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DRIFTSNIFF_ENVIRONMENT_LABEL", "Stage")
    assert main(["seed-dev-accounts"]) == 1
    assert "ENVIRONMENT_LABEL" in capsys.readouterr().err
    assert not development.exists()


@pytest.mark.parametrize(
    "base_url",
    ["https://ce-dev-driftsniff.theriark.dev", "http://localhost:8080", "http://127.0.0.1:9000"],
)
def test_accepts_the_development_addresses(base_url: str) -> None:
    settings = Settings.from_env({"DRIFTSNIFF_BASE_URL": base_url})
    check_development_only(settings, {MARKER_VARIABLE: MARKER_VALUE})


def test_accepts_a_development_badge() -> None:
    settings = Settings.from_env({"DRIFTSNIFF_ENVIRONMENT_LABEL": "Development"})
    check_development_only(settings, {MARKER_VARIABLE: MARKER_VALUE})


def test_an_address_alone_is_not_enough_without_the_marker() -> None:
    settings = Settings.from_env({"DRIFTSNIFF_BASE_URL": "http://localhost:8080"})
    with pytest.raises(DevSeedRefusedError):
        check_development_only(settings, {})


@pytest.mark.parametrize(
    "name", ["deploy/dokploy.json", "compose.yaml", "Dockerfile", ".github/workflows/ci.yml"]
)
def test_no_deployment_file_sets_the_marker(name: str) -> None:
    assert MARKER_VARIABLE not in (ROOT / name).read_text(encoding="utf-8")


# -- what the command creates ----------------------------------------------------------------


def test_creates_one_account_per_role(
    development: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["seed-dev-accounts"]) == 0
    accounts = stored_accounts(development)
    assert set(accounts) == {username_for(role) for role in SEED_ROLES}
    for role in SEED_ROLES:
        assert accounts[username_for(role)][0] == role
    written = credentials(development)
    assert set(written) == set(SEED_ROLES)
    for role in SEED_ROLES:
        assert written[role]["username"] == username_for(role)
        assert can_sign_in(development, username_for(role), written[role]["password"])
    output = capsys.readouterr().out
    for role in SEED_ROLES:
        assert f"{role}: created" in output


def test_the_roles_are_the_roles_of_the_product() -> None:
    assert set(SEED_ROLES) == set(USER_ROLES)


def test_the_passwords_are_throwaway_and_fit_the_registration_rules(development: Path) -> None:
    assert main(["seed-dev-accounts"]) == 0
    written = [entry["password"] for entry in credentials(development).values()]
    assert len(set(written)) == len(SEED_ROLES)
    for item in written:
        assert 12 <= len(item) <= 64
        assert PASSWORD_SHAPE.fullmatch(item) is not None
        check_password_policy(item)
    mode = stat.S_IMODE((development / CREDENTIALS_FILE_NAME).stat().st_mode)
    assert mode == 0o600


def test_new_passwords_are_never_repeated_and_never_start_with_a_dash() -> None:
    seen = {new_password() for _ in range(300)}
    assert len(seen) == 300
    assert all(PASSWORD_SHAPE.fullmatch(item) for item in seen)


def test_a_second_run_changes_nothing(
    development: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["seed-dev-accounts"]) == 0
    capsys.readouterr()
    before_file = (development / CREDENTIALS_FILE_NAME).read_bytes()
    before_accounts = stored_accounts(development)
    assert main(["seed-dev-accounts"]) == 0
    output = capsys.readouterr().out
    assert stored_accounts(development) == before_accounts
    assert (development / CREDENTIALS_FILE_NAME).read_bytes() == before_file
    for role in SEED_ROLES:
        assert f"{role}: already exists, unchanged" in output
    assert "created" not in output
    assert "no new passwords" in output


def test_a_second_run_writes_no_file_after_the_first_one_was_deleted(development: Path) -> None:
    assert main(["seed-dev-accounts"]) == 0
    (development / CREDENTIALS_FILE_NAME).unlink()
    assert main(["seed-dev-accounts"]) == 0
    assert not (development / CREDENTIALS_FILE_NAME).exists()


def test_a_missing_account_is_added_and_the_others_keep_their_password(
    development: Path,
) -> None:
    assert main(["seed-dev-accounts"]) == 0
    first = credentials(development)
    database = Database(database_path(development))
    try:
        with database.write() as connection:
            connection.execute(sa.delete(users).where(users.c.username == username_for("viewer")))
    finally:
        database.close()
    assert main(["seed-dev-accounts"]) == 0
    second = credentials(development)
    assert second["admin"] == first["admin"]
    assert second["operator"] == first["operator"]
    assert second["viewer"]["password"] != first["viewer"]["password"]
    assert can_sign_in(development, username_for("viewer"), second["viewer"]["password"])


def test_the_credentials_file_can_be_put_elsewhere(development: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    assert main(["seed-dev-accounts", "--credentials-file", str(target)]) == 0
    assert target.is_file()
    assert not (development / CREDENTIALS_FILE_NAME).exists()


def test_a_failing_credentials_file_leaves_no_account_behind(
    development: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "missing-directory" / "credentials.json"
    assert main(["seed-dev-accounts", "--credentials-file", str(target)]) == 1
    assert "could not write the credentials file" in capsys.readouterr().err
    assert stored_accounts(development) == {}


# -- existing accounts -----------------------------------------------------------------------


def test_an_existing_account_is_left_alone_and_gets_no_entry(
    migrated: Database, tmp_path: Path
) -> None:
    auth = AuthService(migrated, hasher=CHEAP_HASHER)
    auth.create_user(username_for("admin"), CANARY, "admin")
    target = tmp_path / "credentials.json"
    report = seed_dev_accounts(migrated, target, hasher=CHEAP_HASHER)
    assert report.existing == ("admin",)
    assert report.created == ("operator", "viewer")
    text = target.read_text(encoding="utf-8")
    assert set(json.loads(text)["accounts"]) == {"operator", "viewer"}
    assert CANARY not in text
    assert auth.login(username_for("admin"), CANARY, "127.0.0.1").principal.role == "admin"


def test_an_earlier_unregistered_file_is_kept_for_the_accounts_it_covers(
    migrated: Database, tmp_path: Path
) -> None:
    AuthService(migrated, hasher=CHEAP_HASHER).create_user(username_for("admin"), CANARY, "admin")
    target = tmp_path / "credentials.json"
    earlier = {
        "version": 1,
        "accounts": {"admin": {"username": username_for("admin"), "password": CANARY}},
    }
    target.write_text(json.dumps(earlier), encoding="utf-8")
    seed_dev_accounts(migrated, target, hasher=CHEAP_HASHER)
    written = json.loads(target.read_text(encoding="utf-8"))["accounts"]
    assert written["admin"]["password"] == CANARY
    assert set(written) == set(SEED_ROLES)


def test_an_account_with_another_role_stops_the_run_before_any_change(
    migrated: Database, tmp_path: Path
) -> None:
    AuthService(migrated, hasher=CHEAP_HASHER).create_user(
        username_for("admin"), "a long enough password", "viewer"
    )
    target = tmp_path / "credentials.json"
    with pytest.raises(DevSeedError, match="another role"):
        seed_dev_accounts(migrated, target, hasher=CHEAP_HASHER)
    assert not target.exists()
    with migrated.read() as connection:
        names = {row.username for row in connection.execute(sa.select(users.c.username))}
    assert names == {username_for("admin")}


def test_a_corrupt_earlier_file_is_replaced(migrated: Database, tmp_path: Path) -> None:
    target = tmp_path / "credentials.json"
    target.write_text("{not json", encoding="utf-8")
    seed_dev_accounts(migrated, target, hasher=CHEAP_HASHER)
    assert set(json.loads(target.read_text(encoding="utf-8"))["accounts"]) == set(SEED_ROLES)


def test_the_first_admin_setup_is_gone_after_the_seed(migrated: Database, tmp_path: Path) -> None:
    auth = AuthService(migrated, hasher=CHEAP_HASHER)
    setup_code = auth.issue_setup_code()
    seed_dev_accounts(migrated, tmp_path / "credentials.json", hasher=CHEAP_HASHER)
    assert auth.has_admin()
    with pytest.raises(SetupUnavailableError):
        auth.complete_setup(setup_code, "ada", "a long enough password", "127.0.0.1")


# -- resetting passwords ---------------------------------------------------------------------


def test_reset_passwords_replaces_them_unlocks_and_ends_sessions(development: Path) -> None:
    assert main(["seed-dev-accounts"]) == 0
    first = credentials(development)
    database = Database(database_path(development))
    try:
        auth = AuthService(database, hasher=CHEAP_HASHER)
        grant = auth.login(username_for("operator"), first["operator"]["password"], "127.0.0.1")
        with database.write() as connection:
            connection.execute(
                sa.update(users)
                .where(users.c.username == username_for("viewer"))
                .values(failed_logins=4, locked_until="2999-01-01T00:00:00Z", disabled=True)
            )
    finally:
        database.close()
    assert main(["seed-dev-accounts", "--reset-passwords"]) == 0
    second = credentials(development)
    for role in SEED_ROLES:
        assert second[role]["password"] != first[role]["password"]
        assert not can_sign_in(development, username_for(role), first[role]["password"])
        assert can_sign_in(development, username_for(role), second[role]["password"])
    database = Database(database_path(development))
    try:
        assert AuthService(database, hasher=CHEAP_HASHER).authenticate(grant.cookie_value) is None
        with database.read() as connection:
            actions = connection.execute(sa.select(audit_events.c.action)).scalars().all()
    finally:
        database.close()
    assert actions.count(devseed.ACTION_CREDENTIALS_RESET) == len(SEED_ROLES)


# -- nothing secret is printed or logged -----------------------------------------------------


def test_no_password_or_setup_code_reaches_the_output_or_the_logs(
    development: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    development.mkdir(parents=True)
    database = Database(database_path(development))
    try:
        upgrade_to_head(database)
        setup_code = AuthService(database, hasher=CHEAP_HASHER).issue_setup_code()
    finally:
        database.close()
    capsys.readouterr()
    assert main(["seed-dev-accounts"]) == 0
    issued = [entry["password"] for entry in credentials(development).values()]
    assert main(["seed-dev-accounts"]) == 0
    assert main(["seed-dev-accounts", "--reset-passwords"]) == 0
    issued += [entry["password"] for entry in credentials(development).values()]
    captured = capsys.readouterr()
    shown = captured.out + captured.err + caplog.text
    assert len(issued) == 2 * len(SEED_ROLES)
    for item in [setup_code, setup_code.replace("-", ""), *issued]:
        assert item not in shown


def test_the_output_names_the_file_and_the_user_names(
    development: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["seed-dev-accounts"]) == 0
    output = capsys.readouterr().out
    assert str(development / CREDENTIALS_FILE_NAME) in output
    for role in SEED_ROLES:
        assert username_for(role) in output


# -- the command line ------------------------------------------------------------------------


def test_the_seed_command_is_listed_apart_from_the_six_product_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert set(DEV_COMMANDS) == {"seed-dev-accounts"}
    assert not set(DEV_COMMANDS) & set(COMMANDS)
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    assert "seed-dev-accounts" in capsys.readouterr().out
