"""Command line interface: serve, migrate, backup, rekey, create-admin-code, healthcheck.

``seed-dev-accounts`` is a seventh, Development-only command (docs/dev-test-accounts.md); it is
listed apart from the six product commands and refuses to run outside Development.
"""

import argparse
import http.client
import json
import logging
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from driftsniff import __version__
from driftsniff.config import ConfigError, Settings
from driftsniff.db.backup import KEY_WARNING, BackupError, backup_database, default_backup_path
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import DatabaseTooNewError, upgrade_to_head
from driftsniff.devseed import (
    DevSeedError,
    check_development_only,
    passwords_from_env,
    seed_at_startup,
    seed_dev_accounts,
    username_for,
)
from driftsniff.secrets.keys import (
    MasterKey,
    MasterKeyError,
    ensure_master_key,
    load_master_key,
    master_key_or_exit,
)
from driftsniff.secrets.redact import install_log_filter
from driftsniff.secrets.rekey import RekeyError, run_rekey
from driftsniff.sources.retention import RetentionJob

EXIT_CONFIG = 1
EXIT_NOT_IMPLEMENTED = 2
EXIT_DATABASE_TOO_NEW = 3
HEALTHCHECK_HOST = "127.0.0.1"
HEALTHCHECK_TIMEOUT_SECONDS = 3.0

COMMANDS = {
    "serve": "Run the web application (one worker).",
    "migrate": "Upgrade the database schema to the latest revision.",
    "backup": "Write a consistent backup of the database to a new file.",
    "rekey": "Re-encrypt stored credentials with a new master key.",
    "create-admin-code": "Print a one-time code for creating the first admin.",
    "healthcheck": "Exit 0 when the local server answers /healthz (container health check).",
}
DEV_COMMANDS = {
    "seed-dev-accounts": "Development only: create the test accounts from the configured passwords",
}


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with one sub-command per entry of COMMANDS."""
    parser = argparse.ArgumentParser(
        prog="driftsniff",
        description="Records changes to UniFi Network and Xen Orchestra configuration.",
    )
    parser.add_argument("--version", action="version", version=f"driftsniff {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    for name, summary in COMMANDS.items():
        command_parser = subparsers.add_parser(name, help=summary, description=summary)
        if name == "backup":
            command_parser.add_argument(
                "target",
                nargs="?",
                type=Path,
                help="the new file to write (default: a time-stamped file in DATA_DIR/backups)",
            )
        if name == "rekey":
            command_parser.add_argument(
                "--old-key-lost",
                action="store_true",
                help="the old master key is lost: re-stamp fingerprints without comparing them",
            )
    for name, summary in DEV_COMMANDS.items():
        dev_parser = subparsers.add_parser(name, help=summary, description=summary)
        dev_parser.add_argument(
            "--reset-passwords",
            action="store_true",
            help="put the configured passwords on accounts that exist, clear a lock, end sessions",
        )
    return parser


def _migrate(settings: Settings) -> int:
    """Upgrade the database to the newest revision; refuse one written by a newer version."""
    try:
        settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        database = Database(database_path(settings.data_dir))
        try:
            revision = upgrade_to_head(database)
        finally:
            database.close()
    except DatabaseTooNewError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        return EXIT_DATABASE_TOO_NEW
    except (OSError, SQLAlchemyError) as error:
        print(f"driftsniff: database error: {error}", file=sys.stderr)
        return EXIT_CONFIG
    print(f"database is at revision {revision}")
    return 0


def _backup(settings: Settings, target: Path | None) -> int:
    """Write a checked copy of the database to a new file; never overwrite an existing one."""
    destination = target or default_backup_path(settings.data_dir, datetime.now(UTC))
    try:
        result = backup_database(database_path(settings.data_dir), destination)
    except BackupError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        return EXIT_CONFIG
    print(f"backup written to {result.path} ({result.size_bytes} bytes), integrity check passed")
    print(f"warning: {KEY_WARNING}")
    return 0


def _rekey(settings: Settings, *, old_key_lost: bool) -> int:
    """Start a rekey: re-encrypt the credentials and open the collection cycle.

    The new master key is the file named by DRIFTSNIFF_KEY_FILE (created when it does not exist);
    the old one is the file named by DRIFTSNIFF_OLD_KEY_FILE, or lost (--old-key-lost).
    """
    if old_key_lost == (settings.old_key_file is not None):
        print(
            "driftsniff: set DRIFTSNIFF_OLD_KEY_FILE to the old key file, or pass "
            "--old-key-lost when it is gone (not both)",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    try:
        old = None if settings.old_key_file is None else load_master_key(settings.old_key_file)
        new = ensure_master_key(settings.key_file, fingerprints_exist=False)
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        database = Database(database_path(settings.data_dir))
        try:
            result = run_rekey(database, old, new, now)
        finally:
            database.close()
    except (MasterKeyError, RekeyError) as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        return EXIT_CONFIG
    except (OSError, SQLAlchemyError) as error:
        print(f"driftsniff: rekey failed: {error}", file=sys.stderr)
        return EXIT_CONFIG
    print(f"re-encrypted {result.credentials_rekeyed} credential(s) with key {new.key_id}")
    if old is None:
        print("old key lost: fingerprints are re-stamped without a comparison during one cycle")
        print("credentials made with the lost key cannot be recovered: enter them again")
    else:
        print(
            "keep the old key file in place until every enabled source has finished one clean "
            "collection cycle; a fingerprint_rekey audit event then marks the rekey complete"
        )
    return 0


def _create_admin_code(settings: Settings) -> int:
    """Print a new one-time setup code for the first admin (it replaces an unused earlier one)."""
    from driftsniff.web.auth import AuthService, SetupUnavailableError

    try:
        settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        database = Database(database_path(settings.data_dir))
        try:
            upgrade_to_head(database)
            code = AuthService(database).issue_setup_code()
        finally:
            database.close()
    except SetupUnavailableError:
        print(
            "driftsniff: an admin already exists, so there is no setup code to create",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    except DatabaseTooNewError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        return EXIT_DATABASE_TOO_NEW
    except (OSError, SQLAlchemyError) as error:
        print(f"driftsniff: database error: {error}", file=sys.stderr)
        return EXIT_CONFIG
    print(f"setup code: {code}")
    print("Enter it on the setup page. It works once and replaces any earlier code.")
    return 0


def _seed_dev_accounts(settings: Settings, *, reset_passwords: bool) -> int:
    """Create the Development test accounts from the configured passwords (never printed)."""
    try:
        check_development_only(settings, os.environ)
        passwords = passwords_from_env(os.environ)
        settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        database = Database(database_path(settings.data_dir))
        try:
            upgrade_to_head(database)
            report = seed_dev_accounts(database, passwords, reset_passwords=reset_passwords)
        finally:
            database.close()
    except DevSeedError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        return EXIT_CONFIG
    except DatabaseTooNewError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        return EXIT_DATABASE_TOO_NEW
    except (OSError, SQLAlchemyError) as error:
        print(f"driftsniff: database error: {error}", file=sys.stderr)
        return EXIT_CONFIG
    for outcome, roles in (
        ("created", report.created),
        ("password replaced", report.reset),
        ("already exists, unchanged", report.existing),
    ):
        for role in roles:
            print(f"{role}: {outcome} (user name {username_for(role)})")
    for role in report.differing:
        print(
            f"{role}: the stored password is not the configured one "
            "(use --reset-passwords to replace it)"
        )
    return 0


def _prepare_master_key(settings: Settings) -> MasterKey:
    """Load or create the master key; stops the process with exit code 4 or 1 when it cannot."""
    database = Database(database_path(settings.data_dir))
    try:
        return master_key_or_exit(settings.key_file, database)
    finally:
        database.close()


def _serve(settings: Settings) -> int:
    import uvicorn

    from driftsniff.enrich.api import ChangeService
    from driftsniff.history.service import HistoryService
    from driftsniff.main import create_app
    from driftsniff.notify.deliveries import NotificationService
    from driftsniff.plugins.defaults import make_defaults
    from driftsniff.plugins.registry import PluginError, load_plugins
    from driftsniff.rules.loader import RuleLoadError
    from driftsniff.secrets.fingerprint import Fingerprinter
    from driftsniff.secrets.scanner import OverrideFileError
    from driftsniff.sources.wiring import build_collection
    from driftsniff.web.auth import AuthService
    from driftsniff.web.bearer import TokenService
    from driftsniff.web.change_pages import ChangePages
    from driftsniff.web.dashboard import DashboardService
    from driftsniff.web.replay import ReplayService
    from driftsniff.web.routes_push import PushGateway
    from driftsniff.web.source_pages import SourcePages

    status = _migrate(settings)
    if status != 0:
        return status
    master_key = _prepare_master_key(settings)
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    install_log_filter()
    # The container must listen on all interfaces; the platform routes to the published port.
    host = "0.0.0.0"  # noqa: S104
    # The one database of the process: the daily retention job writes through it.
    database = Database(database_path(settings.data_dir))
    try:
        auth = AuthService(database)
        try:
            plugins = load_plugins(make_defaults(auth))
        except PluginError as error:
            print(f"driftsniff: {error}", file=sys.stderr)
            return EXIT_CONFIG
        # Development only (by address): the three test accounts; before the setup code, because
        # an admin account ends first-run setup.
        seed_at_startup(settings, os.environ, database)
        setup_code = auth.ensure_setup_code()
        if setup_code is not None:
            # Shown once: only a hash is stored. `driftsniff create-admin-code` makes another.
            print(f"first-run setup code (shown once): {setup_code}", flush=True)
        notifications = NotificationService(database, master_key, base_url=settings.base_url)
        try:
            collection = build_collection(
                database, master_key, settings.data_dir, notifier=notifications.notify_event
            )
        except (RuleLoadError, OverrideFileError) as error:
            print(f"driftsniff: {error}", file=sys.stderr)
            return EXIT_CONFIG
        uvicorn.run(
            create_app(
                settings,
                master_key,
                scheduler=collection.scheduler,
                push_gateway=PushGateway(collection.service, collection.pipeline),
                retention=RetentionJob(database),
                auth=auth,
                tokens=TokenService(database),
                notifications=notifications,
                changes=ChangeService(database),
                plugins=plugins,
                dashboard=DashboardService(database),
                # Test connection builds its collector with the factory; run now and the
                # schedule use the scheduler, which create_app starts with the application.
                sources=SourcePages(
                    database, collection.service, probe_factory=collection.factory.for_target
                ),
                change_pages=ChangePages(database),
                history=HistoryService(database, Fingerprinter.from_master(master_key)),
                replay=ReplayService(database),
            ),
            host=host,
            port=settings.port,
            log_level=settings.log_level,
            log_config=None,
            access_log=False,
            server_header=False,
            proxy_headers=settings.trusted_proxy,
            forwarded_allow_ips="*",
        )
    finally:
        database.close()
    return 0


def _healthcheck(settings: Settings) -> int:
    """Standard library only: the image has no curl."""
    connection = http.client.HTTPConnection(
        HEALTHCHECK_HOST,
        settings.port,
        timeout=HEALTHCHECK_TIMEOUT_SECONDS,
    )
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        body = json.loads(response.read(4096))
    except (OSError, http.client.HTTPException, ValueError):
        return EXIT_CONFIG
    finally:
        connection.close()
    ok = response.status == 200 and isinstance(body, dict) and body.get("status") == "ok"
    return 0 if ok else EXIT_CONFIG


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command
    if command is None:
        parser.print_usage(sys.stderr)
        return EXIT_NOT_IMPLEMENTED
    try:
        settings = Settings.from_env()
    except ConfigError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        return EXIT_CONFIG
    if command == "healthcheck":
        return _healthcheck(settings)
    if command == "migrate":
        return _migrate(settings)
    if command == "backup":
        return _backup(settings, args.target)
    if command == "rekey":
        return _rekey(settings, old_key_lost=args.old_key_lost)
    if command == "create-admin-code":
        return _create_admin_code(settings)
    if command == "seed-dev-accounts":
        return _seed_dev_accounts(settings, reset_passwords=args.reset_passwords)
    return _serve(settings)
