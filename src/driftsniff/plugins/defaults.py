"""The CE implementation of each extension point (P9-T5, docs/plugin-api.md)."""

from collections.abc import Callable, Mapping
from pathlib import Path

from driftsniff.db.engine import database_path
from driftsniff.db.tables import DEFAULT_WORKSPACE_ID
from driftsniff.rules.loader import DEFAULT_ROOT, PACK_DIRECTORIES
from driftsniff.sources.retention import DEFAULT_RETENTION_DAYS
from driftsniff.web.auth import AuthService, SessionGrant


class LocalAuthProvider:
    """Users and passwords of this installation."""

    def __init__(self, service: AuthService) -> None:
        self._service = service

    def login(self, username: str, password: str, address: str) -> SessionGrant:
        return self._service.login(username, password, address)


class OneChannel:
    """One active notification channel."""

    def max_active_channels(self) -> int:
        return 1


class ShippedRules:
    """The rule packs that ship with the image."""

    def pack_directories(self) -> tuple[Path, ...]:
        return tuple(DEFAULT_ROOT / directory for directory in PACK_DIRECTORIES)


class FixedRetention:
    """One retention setting for the whole installation (the default is a year)."""

    def retention_days(self) -> int:
        return DEFAULT_RETENTION_DAYS


class NoActorResolver:
    """CE cannot tell who made a change on a controller."""

    def resolve(self, hint: str | None) -> str | None:
        return None


class SingleWorkspace:
    """Everything belongs to workspace 1."""

    def current_workspace_id(self) -> int:
        return DEFAULT_WORKSPACE_ID


class NoReportGenerator:
    """CE has no report documents."""

    def generate(self, event_id: int) -> bytes | None:
        return None


class InProcessRunner:
    """Runs a job right here, on the calling thread."""

    def execute[T](self, job: Callable[[], T]) -> T:
        return job()


class SqliteStorage:
    """The database is a SQLite file in the data directory."""

    def database_location(self, data_dir: Path) -> Path:
        return database_path(data_dir)


class EmptySlots:
    """Every named template slot is empty."""

    def slot(self, name: str) -> str:
        return ""


def make_defaults(auth: AuthService) -> Mapping[str, object]:
    """The CE implementation of every extension point, by point name."""
    return {
        "auth": LocalAuthProvider(auth),
        "channels": OneChannel(),
        "rules": ShippedRules(),
        "retention": FixedRetention(),
        "actors": NoActorResolver(),
        "workspaces": SingleWorkspace(),
        "reports": NoReportGenerator(),
        "runner": InProcessRunner(),
        "storage": SqliteStorage(),
        "templates": EmptySlots(),
    }
