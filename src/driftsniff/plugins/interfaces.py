"""The ten extension points of driftsniff CE, as typing protocols (P9-T5, docs/plugin-api.md).

An extension point is a small contract that a plugin may implement in place of the CE default
(:mod:`driftsniff.plugins.defaults`). Each point has a stable name (the key a plugin uses) and a
protocol. CE itself calls only the defaults; the points exist so that a later edition adds
behaviour without changing CE code. ``PLUGIN_API_VERSION`` changes only when a protocol changes
in a way an existing plugin cannot follow.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

from driftsniff.web.auth import SessionGrant

PLUGIN_API_VERSION: Final = 1


@runtime_checkable
class AuthProvider(Protocol):
    """Checks a user name and password and opens a session (CE: local users)."""

    def login(self, username: str, password: str, address: str) -> SessionGrant: ...


@runtime_checkable
class ChannelPolicy(Protocol):
    """How many notification channels may be active at once (CE: one)."""

    def max_active_channels(self) -> int: ...


@runtime_checkable
class RuleSource(Protocol):
    """Where the rule packs are read from (CE: the shipped packs; path mutes apply on top)."""

    def pack_directories(self) -> tuple[Path, ...]: ...


@runtime_checkable
class RetentionPolicy(Protocol):
    """How many days of history are kept (CE: one setting for the whole installation)."""

    def retention_days(self) -> int: ...


@runtime_checkable
class ActorResolver(Protocol):
    """Names who made a change when the source can say so (CE: nobody)."""

    def resolve(self, hint: str | None) -> str | None: ...


@runtime_checkable
class WorkspaceProvider(Protocol):
    """Tells which workspace a request belongs to (CE: the one workspace)."""

    def current_workspace_id(self) -> int: ...


@runtime_checkable
class ReportGenerator(Protocol):
    """Builds a report document for a change (CE: none; returns None)."""

    def generate(self, event_id: int) -> bytes | None: ...


@runtime_checkable
class RunExecutor(Protocol):
    """Runs the work of one collection (CE: in this process, on the calling thread)."""

    def execute[T](self, job: Callable[[], T]) -> T: ...


@runtime_checkable
class StorageBackend(Protocol):
    """Where the database lives (CE: a SQLite file in the data directory)."""

    def database_location(self, data_dir: Path) -> Path: ...


@runtime_checkable
class TemplateSlots(Protocol):
    """Extra markup a page has room for, by slot name (CE: every slot is empty)."""

    def slot(self, name: str) -> str: ...


@dataclass(frozen=True)
class ExtensionPoint[T]:
    """A named extension point and the protocol its implementation must follow."""

    name: str
    protocol: type


AUTH = ExtensionPoint[AuthProvider]("auth", AuthProvider)
CHANNELS = ExtensionPoint[ChannelPolicy]("channels", ChannelPolicy)
RULES = ExtensionPoint[RuleSource]("rules", RuleSource)
RETENTION = ExtensionPoint[RetentionPolicy]("retention", RetentionPolicy)
ACTORS = ExtensionPoint[ActorResolver]("actors", ActorResolver)
WORKSPACES = ExtensionPoint[WorkspaceProvider]("workspaces", WorkspaceProvider)
REPORTS = ExtensionPoint[ReportGenerator]("reports", ReportGenerator)
RUNNER = ExtensionPoint[RunExecutor]("runner", RunExecutor)
STORAGE = ExtensionPoint[StorageBackend]("storage", StorageBackend)
TEMPLATES = ExtensionPoint[TemplateSlots]("templates", TemplateSlots)

ALL_POINTS: Final[tuple[ExtensionPoint[Any], ...]] = (
    AUTH,
    CHANNELS,
    RULES,
    RETENTION,
    ACTORS,
    WORKSPACES,
    REPORTS,
    RUNNER,
    STORAGE,
    TEMPLATES,
)
