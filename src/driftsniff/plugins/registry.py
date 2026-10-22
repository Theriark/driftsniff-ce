"""Finds plugins, checks them and builds the registry (P9-T5, docs/plugin-api.md).

A plugin is an object published under the entry point group ``driftsniff.plugins``. It has two
attributes:

- ``plugin_api_version``: a whole number; CE ships version 1. Any other value is refused when
  the application starts, with an error that names the plugin.
- ``extensions``: a mapping from extension point name to an implementation of that point. An
  implementation replaces the CE default of the same point.

Everything that can go wrong is refused at start, not later: a plugin that cannot be imported, a
wrong or missing version, an unknown point name, an implementation that lacks a method of its
protocol, and two plugins that claim the same point. The messages name the plugin and never hold
text from the plugin's own errors. Plugins run with the full rights of the process; installing one
is a decision of the person who runs the installation.
"""

import logging
from collections.abc import Iterable, Mapping
from importlib.metadata import entry_points
from typing import Any, Final, Protocol, cast

from driftsniff.plugins.interfaces import ALL_POINTS, PLUGIN_API_VERSION, ExtensionPoint

logger = logging.getLogger(__name__)

PLUGIN_GROUP: Final = "driftsniff.plugins"
DEFAULT_PROVIDER: Final = "default"


class PluginError(Exception):
    """A plugin cannot be used; the message names it."""


class PluginVersionError(PluginError):
    """A plugin was written for another plugin API version."""


class PluginEntry(Protocol):
    """What the registry needs of an entry point (``importlib.metadata.EntryPoint`` has it)."""

    @property
    def name(self) -> str: ...

    def load(self) -> Any: ...


class PluginRegistry:
    """The implementation of every extension point, and who provides it."""

    def __init__(self, defaults: Mapping[str, object]) -> None:
        missing = sorted({point.name for point in ALL_POINTS} - set(defaults))
        if missing:
            raise PluginError(f"no default for the extension point {missing[0]!r}")
        self._implementations: dict[str, object] = dict(defaults)
        self._providers: dict[str, str] = dict.fromkeys(defaults, DEFAULT_PROVIDER)

    def get[T](self, point: ExtensionPoint[T]) -> T:
        """The implementation of an extension point."""
        return cast(T, self._implementations[point.name])

    def provider_of(self, point: ExtensionPoint[Any]) -> str:
        """The plugin name that provides an extension point, or ``default``."""
        return self._providers[point.name]

    def replace(self, point_name: str, implementation: object, plugin: str) -> None:
        """Put a plugin's implementation in place of the current one; PluginError when refused."""
        point = next((known for known in ALL_POINTS if known.name == point_name), None)
        if point is None:
            raise PluginError(f"plugin {plugin!r} names an unknown extension point {point_name!r}")
        if self._providers[point_name] != DEFAULT_PROVIDER:
            raise PluginError(
                f"plugins {self._providers[point_name]!r} and {plugin!r} both provide"
                f" the extension point {point_name!r}"
            )
        if not isinstance(implementation, point.protocol):
            raise PluginError(
                f"plugin {plugin!r} does not follow the contract of the extension point"
                f" {point_name!r}"
            )
        self._implementations[point_name] = implementation
        self._providers[point_name] = plugin


def _load(entry: PluginEntry) -> tuple[str, Mapping[str, object]]:
    """Import one plugin and check its version; returns its name and its extensions."""
    name = entry.name
    try:
        plugin = entry.load()
    except Exception as error:  # a plugin may fail in any way; only its class is reported
        logger.warning("plugin %s could not be imported: %s", name, type(error).__name__)
        raise PluginError(f"plugin {name!r} could not be imported") from None
    version = getattr(plugin, "plugin_api_version", None)
    if isinstance(version, bool) or not isinstance(version, int):
        raise PluginVersionError(f"plugin {name!r} does not declare a plugin_api_version")
    if version != PLUGIN_API_VERSION:
        raise PluginVersionError(
            f"plugin {name!r} was written for plugin API version {version}; this driftsniff"
            f" supports version {PLUGIN_API_VERSION}"
        )
    extensions = getattr(plugin, "extensions", None)
    if not isinstance(extensions, Mapping):
        raise PluginError(f"plugin {name!r} does not declare its extensions as a mapping")
    return name, extensions


def load_plugins(
    defaults: Mapping[str, object], entries: Iterable[PluginEntry] | None = None
) -> PluginRegistry:
    """Build the registry: the defaults, with every installed plugin's extensions on top.

    ``entries`` default to the installed entry points of the group ``driftsniff.plugins``.
    Raises PluginError (or PluginVersionError) at the first plugin that cannot be used; plugins
    are taken in name order so the first error is the same on every start.
    """
    found: list[PluginEntry] = (
        list(entry_points(group=PLUGIN_GROUP)) if entries is None else list(entries)
    )
    names = [entry.name for entry in found]
    if len(set(names)) != len(names):
        raise PluginError("two plugins have the same name")
    registry = PluginRegistry(defaults)
    for entry in sorted(found, key=lambda each: each.name):
        name, extensions = _load(entry)
        for point_name, implementation in extensions.items():
            registry.replace(str(point_name), implementation, name)
        logger.info("plugin %s loaded", name)
    return registry
