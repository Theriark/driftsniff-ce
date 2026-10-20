"""Command line interface: serve, migrate, backup, rekey, create-admin-code, healthcheck."""

import argparse
import http.client
import json
import logging
import sys
from collections.abc import Sequence

from sqlalchemy.exc import SQLAlchemyError

from driftsniff import __version__
from driftsniff.config import ConfigError, Settings
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import DatabaseTooNewError, upgrade_to_head
from driftsniff.secrets.keys import MasterKey, master_key_or_exit
from driftsniff.secrets.redact import install_log_filter

EXIT_CONFIG = 1
EXIT_NOT_IMPLEMENTED = 2
EXIT_DATABASE_TOO_NEW = 3
HEALTHCHECK_HOST = "127.0.0.1"
HEALTHCHECK_TIMEOUT_SECONDS = 3.0

COMMANDS = {
    "serve": "Run the web application (one worker).",
    "migrate": "Upgrade the database schema to the latest revision.",
    "backup": "Write a consistent backup of the database.",
    "rekey": "Re-encrypt stored credentials with a new master key.",
    "create-admin-code": "Print a one-time code for creating the first admin.",
    "healthcheck": "Exit 0 when the local server answers /healthz (container health check).",
}
NOT_IMPLEMENTED_COMMANDS = ("backup", "rekey", "create-admin-code")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with one sub-command per entry of COMMANDS."""
    parser = argparse.ArgumentParser(
        prog="driftsniff",
        description="Records changes to UniFi Network and Xen Orchestra configuration.",
    )
    parser.add_argument("--version", action="version", version=f"driftsniff {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    for name, summary in COMMANDS.items():
        subparsers.add_parser(name, help=summary, description=summary)
    return parser


def _not_implemented(command: str) -> int:
    print(f"driftsniff {command}: not implemented yet", file=sys.stderr)
    return EXIT_NOT_IMPLEMENTED


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


def _prepare_master_key(settings: Settings) -> MasterKey:
    """Load or create the master key; stops the process with exit code 4 or 1 when it cannot."""
    database = Database(database_path(settings.data_dir))
    try:
        return master_key_or_exit(settings.key_file, database)
    finally:
        database.close()


def _serve(settings: Settings) -> int:
    import uvicorn

    from driftsniff.main import create_app

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
    uvicorn.run(
        create_app(settings, master_key),
        host=host,
        port=settings.port,
        log_level=settings.log_level,
        log_config=None,
        access_log=False,
        server_header=False,
        proxy_headers=settings.trusted_proxy,
        forwarded_allow_ips="*",
    )
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
    if command in NOT_IMPLEMENTED_COMMANDS:
        return _not_implemented(command)
    try:
        settings = Settings.from_env()
    except ConfigError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        return EXIT_CONFIG
    if command == "healthcheck":
        return _healthcheck(settings)
    if command == "migrate":
        return _migrate(settings)
    return _serve(settings)
