"""Tests for the Development-only test accounts (docs/dev-test-accounts.md)."""

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
import uvicorn

from driftsniff import devseed
from driftsniff.cli import COMMANDS, DEV_COMMANDS, main
from driftsniff.config import Settings
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.db.tables import USER_ROLES, audit_events, users
from driftsniff.devseed import (
    MARKER_VALUE,
    MARKER_VARIABLE,
    SEED_ROLES,
    DevSeedError,
    DevSeedRefusedError,
    check_development_only,
    password_variable_for,
    passwords_from_env,
    seed_at_startup,
    seed_dev_accounts,
    username_for,
)
from driftsniff.secrets.redact import RedactingFilter
from driftsniff.web.auth import (
    AuthService,
    LoginFailedError,
    SetupUnavailableError,
    make_password_hasher,
)

CHEAP_HASHER = make_password_hasher(memory_kib=8, time_cost=1)
ROOT = Path(__file__).resolve().parents[2]
DEV_URL = "https://ce-dev-driftsniff.theriark.dev"
# Synthetic values that stand for the generated passwords and for a credential somebody holds.
CANARY = "CANARY-existing-credential-0001"


def configured(role: str) -> str:
    """The synthetic generated value of a role's password variable."""
    return f"CANARY-{role}-generated-0123456789"


def configured_env() -> dict[str, str]:
    return {password_variable_for(role): configured(role) for role in SEED_ROLES}


def configured_values() -> dict[str, str]:
    return {role: configured(role) for role in SEED_ROLES}


@pytest.fixture(autouse=True)
def cheap_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The seed hashes with the production cost; the tests need not wait for it."""
    monkeypatch.setattr(devseed, "make_password_hasher", lambda: CHEAP_HASHER)


@pytest.fixture(autouse=True)
def clean_root_log_filters() -> Iterator[None]:
    """serve installs the log filter on the root handlers; do not leave it for other tests."""
    yield
    for handler in logging.getLogger().handlers:
        for item in list(handler.filters):
            if isinstance(item, RedactingFilter):
                handler.removeFilter(item)


@pytest.fixture
def development(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A Development-marked installation, passwords configured, data directory not yet made."""
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    monkeypatch.setenv(MARKER_VARIABLE, MARKER_VALUE)
    monkeypatch.delenv("DRIFTSNIFF_BASE_URL", raising=False)
    monkeypatch.delenv("DRIFTSNIFF_ENVIRONMENT_LABEL", raising=False)
    for name, value in configured_env().items():
        monkeypatch.setenv(name, value)
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


def can_sign_in(data_dir: Path, username: str, secret: str) -> bool:
    database = Database(database_path(data_dir))
    try:
        AuthService(database, hasher=CHEAP_HASHER).login(username, secret, "127.0.0.1")
    except LoginFailedError:
        return False
    finally:
        database.close()
    return True


def everything_stored_in(data_dir: Path) -> bytes:
    """The bytes of every file under the data directory (database, journal, anything else)."""
    return b"".join(path.read_bytes() for path in sorted(data_dir.rglob("*")) if path.is_file())


# -- the Development-only guard of the command -----------------------------------------------


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


def test_refuses_without_the_configured_passwords(
    development: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(password_variable_for("operator"))
    assert main(["seed-dev-accounts"]) == 1
    error = capsys.readouterr().err
    assert password_variable_for("operator") in error
    assert password_variable_for("admin") not in error
    assert not development.exists()


@pytest.mark.parametrize(
    "base_url",
    [DEV_URL, "http://localhost:8080", "http://127.0.0.1:9000"],
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


# -- the manifest ----------------------------------------------------------------------------

PREVIOUS_ENV = [
    {"name": "DRIFTSNIFF_BASE_URL", "kind": "base_url"},
    {"name": "DRIFTSNIFF_TRUSTED_PROXY", "kind": "literal", "value": "true"},
    {"name": "DRIFTSNIFF_LOG_LEVEL", "kind": "literal", "value": "info"},
    {"name": "DRIFTSNIFF_PORT", "kind": "literal", "value": "8080"},
    {"name": "DRIFTSNIFF_DATA_DIR", "kind": "literal", "value": "/data"},
    {"name": "DRIFTSNIFF_KEY_FILE", "kind": "literal", "value": "/keys/master.key"},
]
# The header badge of the Development installation (docs/deploy-development.md).
ENVIRONMENT_LABEL_ENV = {
    "name": "DRIFTSNIFF_ENVIRONMENT_LABEL",
    "kind": "literal",
    "value": "Development",
}


def manifest() -> dict[str, object]:
    document: dict[str, object] = json.loads(
        (ROOT / "deploy" / "dokploy.json").read_text(encoding="utf-8")
    )
    return document


def test_the_manifest_keeps_the_database_the_volumes_and_every_earlier_setting() -> None:
    document = manifest()
    assert set(document) == {"database", "volumes", "env", "browserAccounts"}
    assert document["database"] is None
    assert document["volumes"] == ["/data", "/keys"]
    env = document["env"]
    assert isinstance(env, list)
    assert env[: len(PREVIOUS_ENV)] == PREVIOUS_ENV


def test_the_manifest_declares_the_development_environment_badge_once() -> None:
    env = manifest()["env"]
    assert isinstance(env, list)
    assert env.count(ENVIRONMENT_LABEL_ENV) == 1
    assert [item for item in env if item["name"] == "DRIFTSNIFF_ENVIRONMENT_LABEL"] == [
        ENVIRONMENT_LABEL_ENV
    ]


def test_the_generated_passwords_are_declared_without_a_value() -> None:
    env = manifest()["env"]
    assert isinstance(env, list)
    declared = [
        item for item in env if item not in PREVIOUS_ENV and item != ENVIRONMENT_LABEL_ENV
    ]
    assert declared == [
        {"name": password_variable_for(role), "kind": "token24"} for role in SEED_ROLES
    ]


def test_the_browser_accounts_have_only_the_allowed_fields_and_match_the_seed() -> None:
    accounts = manifest()["browserAccounts"]
    assert isinstance(accounts, list)
    assert [item["email"] for item in accounts] == [username_for(role) for role in SEED_ROLES]
    assert [item["label"] for item in accounts] == list(SEED_ROLES)
    for item, role in zip(accounts, SEED_ROLES, strict=True):
        assert set(item) == {"email", "label", "passwordEnv"}
        assert item["passwordEnv"] == password_variable_for(role)


def test_every_password_variable_of_the_accounts_is_a_generated_development_password() -> None:
    document = manifest()
    env = document["env"]
    accounts = document["browserAccounts"]
    assert isinstance(env, list)
    assert isinstance(accounts, list)
    generated = {item["name"] for item in env if item["kind"] == "token24"}
    for item in accounts:
        assert item["passwordEnv"] in generated
        assert re.fullmatch(r"DRIFTSNIFF_DEV_[A-Z]+_PASSWORD", item["passwordEnv"])


def test_no_password_literal_is_in_the_manifest() -> None:
    text = (ROOT / "deploy" / "dokploy.json").read_text(encoding="utf-8")
    assert "CANARY" not in text
    env = manifest()["env"]
    assert isinstance(env, list)
    for item in env:
        if "PASSWORD" in item["name"]:
            assert set(item) == {"name", "kind"}


# -- what the command creates ----------------------------------------------------------------


def test_creates_one_account_per_role_with_the_configured_passwords(
    development: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["seed-dev-accounts"]) == 0
    accounts = stored_accounts(development)
    assert set(accounts) == set(SEED_ROLES)
    for role in SEED_ROLES:
        assert accounts[username_for(role)][0] == role
        assert can_sign_in(development, username_for(role), configured(role))
        assert not can_sign_in(development, username_for(role), configured("other"))
    output = capsys.readouterr().out
    for role in SEED_ROLES:
        assert f"{role}: created" in output


def test_the_roles_are_the_roles_of_the_product() -> None:
    assert set(SEED_ROLES) == set(USER_ROLES)


def test_the_command_writes_no_file_of_credentials(development: Path) -> None:
    assert main(["seed-dev-accounts"]) == 0
    names = {path.name for path in development.rglob("*") if path.is_file()}
    assert not any("credential" in name for name in names)
    assert not any(name.endswith(".json") for name in names)


def test_a_second_run_changes_nothing(
    development: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["seed-dev-accounts"]) == 0
    capsys.readouterr()
    before = stored_accounts(development)
    assert main(["seed-dev-accounts"]) == 0
    output = capsys.readouterr().out
    assert stored_accounts(development) == before
    for role in SEED_ROLES:
        assert f"{role}: already exists, unchanged" in output
    assert "created" not in output
    assert "not the configured one" not in output


def test_a_missing_account_is_added_and_the_others_are_left_alone(development: Path) -> None:
    assert main(["seed-dev-accounts"]) == 0
    before = stored_accounts(development)
    database = Database(database_path(development))
    try:
        with database.write() as connection:
            connection.execute(sa.delete(users).where(users.c.username == username_for("viewer")))
    finally:
        database.close()
    assert main(["seed-dev-accounts"]) == 0
    after = stored_accounts(development)
    assert after["admin"] == before["admin"]
    assert after["operator"] == before["operator"]
    assert can_sign_in(development, username_for("viewer"), configured("viewer"))


# -- existing accounts and data --------------------------------------------------------------


def test_other_users_and_their_data_are_preserved(migrated: Database) -> None:
    auth = AuthService(migrated, hasher=CHEAP_HASHER)
    auth.create_user("alice", CANARY, "operator")
    with migrated.read() as connection:
        before = connection.execute(sa.select(users)).all()
    seed_dev_accounts(migrated, configured_values(), hasher=CHEAP_HASHER)
    seed_dev_accounts(migrated, configured_values(), hasher=CHEAP_HASHER)
    with migrated.read() as connection:
        rows = connection.execute(sa.select(users).order_by(users.c.id)).all()
    assert rows[: len(before)] == before
    assert {row.username for row in rows} == {"alice", *SEED_ROLES}
    assert auth.login("alice", CANARY, "127.0.0.1").principal.role == "operator"


def test_an_existing_account_with_another_password_is_left_alone_and_reported(
    migrated: Database,
) -> None:
    auth = AuthService(migrated, hasher=CHEAP_HASHER)
    auth.create_user(username_for("admin"), CANARY, "admin")
    with migrated.read() as connection:
        before = connection.execute(
            sa.select(users.c.password_hash).where(users.c.username == "admin")
        ).scalar_one()
    report = seed_dev_accounts(migrated, configured_values(), hasher=CHEAP_HASHER)
    assert report.existing == ("admin",)
    assert report.created == ("operator", "viewer")
    assert report.differing == ("admin",)
    with migrated.read() as connection:
        after = connection.execute(
            sa.select(users.c.password_hash).where(users.c.username == "admin")
        ).scalar_one()
    assert after == before
    assert auth.login(username_for("admin"), CANARY, "127.0.0.1").principal.role == "admin"


def test_the_command_reports_an_account_with_another_password(
    development: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    development.mkdir(parents=True)
    database = Database(database_path(development))
    try:
        upgrade_to_head(database)
        AuthService(database, hasher=CHEAP_HASHER).create_user("viewer", CANARY, "viewer")
    finally:
        database.close()
    assert main(["seed-dev-accounts"]) == 0
    output = capsys.readouterr().out
    assert "viewer: the stored password is not the configured one" in output
    assert "--reset-passwords" in output
    assert CANARY not in output


def test_an_account_with_another_role_stops_the_run_before_any_change(migrated: Database) -> None:
    AuthService(migrated, hasher=CHEAP_HASHER).create_user(
        username_for("admin"), "a long enough password", "viewer"
    )
    with pytest.raises(DevSeedError, match="another role"):
        seed_dev_accounts(migrated, configured_values(), hasher=CHEAP_HASHER)
    with migrated.read() as connection:
        names = {row.username for row in connection.execute(sa.select(users.c.username))}
    assert names == {username_for("admin")}


def test_the_first_admin_setup_is_gone_after_the_seed(migrated: Database) -> None:
    auth = AuthService(migrated, hasher=CHEAP_HASHER)
    setup_code = auth.issue_setup_code()
    seed_dev_accounts(migrated, configured_values(), hasher=CHEAP_HASHER)
    assert auth.has_admin()
    with pytest.raises(SetupUnavailableError):
        auth.complete_setup(setup_code, "ada", "a long enough password", "127.0.0.1")


# -- the configured passwords ----------------------------------------------------------------


def test_passwords_from_env_names_every_missing_variable_and_no_value() -> None:
    env = {password_variable_for("admin"): configured("admin")}
    with pytest.raises(DevSeedError) as caught:
        passwords_from_env(env)
    message = str(caught.value)
    assert password_variable_for("operator") in message
    assert password_variable_for("viewer") in message
    assert configured("admin") not in message


def test_an_empty_variable_counts_as_missing() -> None:
    env = {**configured_env(), password_variable_for("viewer"): ""}
    with pytest.raises(DevSeedError, match=password_variable_for("viewer")):
        passwords_from_env(env)


def test_a_password_below_the_policy_is_refused_without_showing_it() -> None:
    short = "CANARY-pw"
    env = {**configured_env(), password_variable_for("admin"): short}
    with pytest.raises(DevSeedError) as caught:
        passwords_from_env(env)
    assert password_variable_for("admin") in str(caught.value)
    assert short not in str(caught.value)


def test_passwords_from_env_returns_the_values_by_role() -> None:
    assert passwords_from_env(configured_env()) == configured_values()


# -- resetting passwords ---------------------------------------------------------------------


def test_reset_passwords_replaces_them_unlocks_and_ends_sessions(
    development: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert main(["seed-dev-accounts"]) == 0
    database = Database(database_path(development))
    try:
        auth = AuthService(database, hasher=CHEAP_HASHER)
        grant = auth.login(username_for("operator"), configured("operator"), "127.0.0.1")
        with database.write() as connection:
            connection.execute(
                sa.update(users)
                .where(users.c.username == username_for("viewer"))
                .values(failed_logins=4, locked_until="2999-01-01T00:00:00Z", disabled=True)
            )
    finally:
        database.close()
    for role in SEED_ROLES:
        monkeypatch.setenv(password_variable_for(role), configured(role) + "-rotated")
    assert main(["seed-dev-accounts", "--reset-passwords"]) == 0
    for role in SEED_ROLES:
        assert not can_sign_in(development, username_for(role), configured(role))
        assert can_sign_in(development, username_for(role), configured(role) + "-rotated")
    database = Database(database_path(development))
    try:
        assert AuthService(database, hasher=CHEAP_HASHER).authenticate(grant.cookie_value) is None
        with database.read() as connection:
            actions = connection.execute(sa.select(audit_events.c.action)).scalars().all()
    finally:
        database.close()
    assert actions.count(devseed.ACTION_CREDENTIALS_RESET) == len(SEED_ROLES)


# -- nothing secret is printed, logged or stored in clear ------------------------------------


def test_no_password_reaches_the_output_the_logs_or_the_disk(
    development: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    assert main(["seed-dev-accounts"]) == 0
    assert main(["seed-dev-accounts"]) == 0
    assert main(["seed-dev-accounts", "--reset-passwords"]) == 0
    monkeypatch.delenv(password_variable_for("viewer"))
    assert main(["seed-dev-accounts"]) == 1
    captured = capsys.readouterr()
    shown = captured.out + captured.err + caplog.text
    stored = everything_stored_in(development)
    for role in SEED_ROLES:
        assert configured(role) not in shown
        assert configured(role).encode() not in stored
    assert "CANARY" not in shown


def test_the_output_names_the_user_names(
    development: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["seed-dev-accounts"]) == 0
    output = capsys.readouterr().out
    for role in SEED_ROLES:
        assert f"user name {username_for(role)}" in output


# -- the start-up hook -----------------------------------------------------------------------


def settings_for(url: str, label: str = "") -> Settings:
    env = {"DRIFTSNIFF_BASE_URL": url}
    if label:
        env["DRIFTSNIFF_ENVIRONMENT_LABEL"] = label
    return Settings.from_env(env)


def user_names(database: Database) -> set[str]:
    with database.read() as connection:
        return {row.username for row in connection.execute(sa.select(users.c.username))}


def test_startup_does_nothing_and_logs_nothing_without_the_variables(
    migrated: Database, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    assert seed_at_startup(settings_for(DEV_URL), {}, migrated) is None
    assert user_names(migrated) == set()
    assert caplog.records == []


def test_startup_creates_the_accounts_on_a_development_address(
    migrated: Database, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    report = seed_at_startup(settings_for(DEV_URL), configured_env(), migrated)
    assert report is not None
    assert report.created == SEED_ROLES
    assert user_names(migrated) == set(SEED_ROLES)
    assert "created" in caplog.text
    assert "CANARY" not in caplog.text


def test_startup_is_a_no_op_the_second_time(
    migrated: Database, caplog: pytest.LogCaptureFixture
) -> None:
    seed_at_startup(settings_for(DEV_URL), configured_env(), migrated)
    with migrated.read() as connection:
        before = connection.execute(sa.select(users).order_by(users.c.id)).all()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    report = seed_at_startup(settings_for(DEV_URL), configured_env(), migrated)
    assert report is not None
    assert report.created == ()
    assert report.existing == SEED_ROLES
    with migrated.read() as connection:
        assert connection.execute(sa.select(users).order_by(users.c.id)).all() == before
    assert "already exist" in caplog.text


@pytest.mark.parametrize(
    "url",
    [
        "https://ce-stg-driftsniff.theriark.dev",
        "https://ee-dev-driftsniff.theriark.dev",
        "https://driftsniff.theriark.dev",
        "https://ce-dev-driftsniff.example.com",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
)
def test_startup_never_seeds_a_stage_production_or_local_address(
    url: str, migrated: Database, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    assert seed_at_startup(settings_for(url), configured_env(), migrated) is None
    assert user_names(migrated) == set()
    assert "not a Development address" in caplog.text
    assert "CANARY" not in caplog.text


def test_startup_never_seeds_another_environment_badge(migrated: Database) -> None:
    settings = settings_for(DEV_URL, label="Stage")
    assert seed_at_startup(settings, configured_env(), migrated) is None
    assert user_names(migrated) == set()


def test_startup_with_an_incomplete_configuration_logs_the_names_and_changes_nothing(
    migrated: Database, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    env = {password_variable_for("admin"): configured("admin")}
    assert seed_at_startup(settings_for(DEV_URL), env, migrated) is None
    assert user_names(migrated) == set()
    assert password_variable_for("operator") in caplog.text
    assert "CANARY" not in caplog.text


def test_startup_survives_a_database_failure(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    caplog.set_level(logging.DEBUG)
    database = Database(database_path(tmp_path))
    try:
        assert seed_at_startup(settings_for(DEV_URL), configured_env(), database) is None
    finally:
        database.close()
    assert "not seeded" in caplog.text
    assert "CANARY" not in caplog.text


def test_serve_seeds_the_accounts_before_the_setup_code_and_leaks_nothing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: None)
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    monkeypatch.setenv("DRIFTSNIFF_BASE_URL", DEV_URL)
    monkeypatch.delenv(MARKER_VARIABLE, raising=False)
    for name, value in configured_env().items():
        monkeypatch.setenv(name, value)
    assert main(["serve"]) == 0
    assert main(["serve"]) == 0
    captured = capsys.readouterr()
    assert "setup code" not in captured.out
    assert set(stored_accounts(data_dir)) == set(SEED_ROLES)
    for role in SEED_ROLES:
        assert can_sign_in(data_dir, username_for(role), configured(role))
    shown = captured.out + captured.err + caplog.text
    assert "CANARY" not in shown
    assert b"CANARY" not in everything_stored_in(data_dir)


def test_serve_on_stage_ignores_the_variables(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: None)
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    monkeypatch.setenv("DRIFTSNIFF_BASE_URL", "https://ce-stg-driftsniff.theriark.dev")
    monkeypatch.setenv(MARKER_VARIABLE, MARKER_VALUE)
    for name, value in configured_env().items():
        monkeypatch.setenv(name, value)
    assert main(["serve"]) == 0
    assert stored_accounts(data_dir) == {}
    assert "first-run setup code" in capsys.readouterr().out


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
