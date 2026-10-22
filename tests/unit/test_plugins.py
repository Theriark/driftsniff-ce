"""The plugin registry and the CE defaults (P9-T5, docs/plugin-api.md).

Discovery is tested through real entry points: a plugin module and a ``.dist-info`` folder are
written to a temporary directory that is put on the import path, so the registry finds the plugin
the way it finds an installed one.
"""

import logging
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI

from driftsniff.cli import main
from driftsniff.db.engine import Database, database_path
from driftsniff.enrich.api import ChangeService
from driftsniff.plugins import interfaces
from driftsniff.plugins import registry as registry_module
from driftsniff.plugins.defaults import (
    EmptySlots,
    FixedRetention,
    InProcessRunner,
    NoActorResolver,
    NoReportGenerator,
    OneChannel,
    ShippedRules,
    SingleWorkspace,
    SqliteStorage,
    make_defaults,
)
from driftsniff.plugins.interfaces import ALL_POINTS, PLUGIN_API_VERSION
from driftsniff.plugins.registry import (
    PLUGIN_GROUP,
    PluginError,
    PluginRegistry,
    PluginVersionError,
    load_plugins,
)
from driftsniff.secrets.redact import RedactingFilter
from driftsniff.web.auth import AuthService, make_password_hasher

CORRECT = "CANARY-correct horse battery"

RESOLVER_PLUGIN = """
class Resolver:
    def resolve(self, hint):
        return "plugin:" + str(hint)


class Plugin:
    plugin_api_version = {version}
    extensions = {{"actors": Resolver()}}


PLUGIN = Plugin()
"""


class FakeEntry:
    """What the registry needs of an entry point, without touching the import system."""

    def __init__(self, name: str, plugin: object) -> None:
        self.name = name
        self._plugin = plugin

    def load(self) -> object:
        return self._plugin


class Declared:
    """A plugin object with the two attributes the registry reads."""

    def __init__(self, version: object, extensions: object) -> None:
        self.plugin_api_version = version
        self.extensions = extensions


class Greeter:
    def resolve(self, hint: str | None) -> str | None:
        return "hello"


@pytest.fixture(autouse=True)
def clean_root_log_filters() -> Iterator[None]:
    """serve installs the log filter on the root handlers; do not leave it for other tests."""
    yield
    for handler in logging.getLogger().handlers:
        for item in list(handler.filters):
            if isinstance(item, RedactingFilter):
                handler.removeFilter(item)


@pytest.fixture
def auth(store: Database) -> AuthService:
    service = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    service.create_user("admin", CORRECT, "admin")
    return service


@pytest.fixture
def defaults(auth: AuthService) -> dict[str, object]:
    return dict(make_defaults(auth))


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A directory on the import path where a test installs a plugin."""
    monkeypatch.syspath_prepend(str(tmp_path))
    before = set(sys.modules)
    yield tmp_path
    for name in set(sys.modules) - before:
        sys.modules.pop(name, None)


def install(root: Path, module: str, source: str, entry_name: str = "dummy") -> None:
    (root / f"{module}.py").write_text(source, encoding="utf-8")
    dist = root / f"{module}-1.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {module}\nVersion: 1.0\n", encoding="utf-8"
    )
    (dist / "entry_points.txt").write_text(
        f"[{PLUGIN_GROUP}]\n{entry_name} = {module}:PLUGIN\n", encoding="utf-8"
    )


# -- defaults -----------------------------------------------------------------------------------


def test_there_are_ten_points_with_distinct_names() -> None:
    names = [point.name for point in ALL_POINTS]
    assert len(names) == 10
    assert len(set(names)) == 10
    assert PLUGIN_API_VERSION == 1


def test_every_default_follows_the_contract_of_its_point(defaults: dict[str, object]) -> None:
    assert set(defaults) == {point.name for point in ALL_POINTS}
    for point in ALL_POINTS:
        assert isinstance(defaults[point.name], point.protocol), point.name


def test_the_ce_defaults_do_what_the_plan_says(auth: AuthService, tmp_path: Path) -> None:
    registry = load_plugins(make_defaults(auth), [])
    assert registry.get(interfaces.CHANNELS).max_active_channels() == 1
    assert registry.get(interfaces.WORKSPACES).current_workspace_id() == 1
    assert registry.get(interfaces.RETENTION).retention_days() == 365
    assert registry.get(interfaces.ACTORS).resolve("someone") is None
    assert registry.get(interfaces.REPORTS).generate(1) is None
    assert registry.get(interfaces.TEMPLATES).slot("header") == ""
    assert registry.get(interfaces.RUNNER).execute(lambda: 41 + 1) == 42
    assert registry.get(interfaces.STORAGE).database_location(tmp_path) == database_path(tmp_path)
    packs = registry.get(interfaces.RULES).pack_directories()
    assert [path.name for path in packs] == ["unifi", "xo"]
    assert all(path.is_dir() for path in packs)
    grant = registry.get(interfaces.AUTH).login("admin", CORRECT, "10.0.0.1")
    assert grant.principal.username == "admin"
    assert {type(registry.get(point)) for point in ALL_POINTS} >= {
        OneChannel,
        SingleWorkspace,
        FixedRetention,
        NoActorResolver,
        NoReportGenerator,
        EmptySlots,
        InProcessRunner,
        SqliteStorage,
        ShippedRules,
    }


def test_a_registry_needs_a_default_for_every_point(defaults: dict[str, object]) -> None:
    del defaults["storage"]
    with pytest.raises(PluginError, match="storage"):
        PluginRegistry(defaults)


# -- discovery through real entry points ---------------------------------------------------------


def test_a_dummy_plugin_is_found_and_overrides_one_default(
    installed: Path, defaults: dict[str, object]
) -> None:
    install(installed, "ds_dummy_ok", RESOLVER_PLUGIN.format(version=1))
    registry = load_plugins(defaults)
    assert registry.get(interfaces.ACTORS).resolve("x") == "plugin:x"
    assert registry.provider_of(interfaces.ACTORS) == "dummy"
    for point in ALL_POINTS:
        if point is not interfaces.ACTORS:
            assert registry.provider_of(point) == "default"
            assert registry.get(point) is defaults[point.name]


def test_with_no_plugin_installed_every_point_is_the_default(defaults: dict[str, object]) -> None:
    registry = load_plugins(defaults)
    assert all(registry.provider_of(point) == "default" for point in ALL_POINTS)


@pytest.mark.parametrize("version", [0, 2, 99])
def test_a_plugin_of_another_version_is_refused_by_name(
    installed: Path, defaults: dict[str, object], version: int
) -> None:
    install(installed, f"ds_dummy_v{version}", RESOLVER_PLUGIN.format(version=version))
    with pytest.raises(PluginVersionError) as caught:
        load_plugins(defaults)
    message = str(caught.value)
    assert "'dummy'" in message
    assert f"version {version}" in message
    assert f"version {PLUGIN_API_VERSION}" in message


@pytest.mark.parametrize("version", ["1", 1.0, True, None])
def test_a_missing_or_odd_version_is_refused(defaults: dict[str, object], version: object) -> None:
    entry = FakeEntry("odd", Declared(version, {}))
    with pytest.raises(PluginVersionError, match="'odd'"):
        load_plugins(defaults, [entry])


def test_a_plugin_that_cannot_be_imported_is_refused_without_its_error_text(
    installed: Path, defaults: dict[str, object], caplog: pytest.LogCaptureFixture
) -> None:
    install(installed, "ds_dummy_broken", 'raise RuntimeError("CANARY-from-the-plugin")\n')
    with caplog.at_level(logging.INFO), pytest.raises(PluginError) as caught:
        load_plugins(defaults)
    assert "'dummy'" in str(caught.value)
    assert "CANARY" not in str(caught.value)
    assert "CANARY" not in caplog.text
    assert "RuntimeError" in caplog.text


# -- what is refused at start -------------------------------------------------------------------


def test_an_unknown_point_name_is_refused(defaults: dict[str, object]) -> None:
    entry = FakeEntry("p", Declared(1, {"teleport": Greeter()}))
    with pytest.raises(PluginError, match=r"'p'.*'teleport'"):
        load_plugins(defaults, [entry])


def test_an_implementation_that_breaks_the_contract_is_refused(
    defaults: dict[str, object],
) -> None:
    entry = FakeEntry("p", Declared(1, {"actors": object()}))
    with pytest.raises(PluginError, match=r"'p'.*'actors'"):
        load_plugins(defaults, [entry])


def test_extensions_must_be_a_mapping(defaults: dict[str, object]) -> None:
    for extensions in (None, ["actors"], "actors"):
        entry = FakeEntry("p", Declared(1, extensions))
        with pytest.raises(PluginError, match="'p'"):
            load_plugins(defaults, [entry])


def test_two_plugins_cannot_claim_the_same_point(defaults: dict[str, object]) -> None:
    entries = [
        FakeEntry("zeta", Declared(1, {"actors": Greeter()})),
        FakeEntry("alpha", Declared(1, {"actors": Greeter()})),
    ]
    with pytest.raises(PluginError, match=r"'alpha' and 'zeta'"):
        load_plugins(defaults, entries)


def test_two_plugins_with_different_points_both_load(defaults: dict[str, object]) -> None:
    class OneSlot:
        def slot(self, name: str) -> str:
            return f"<b>{name}</b>"

    entries = [
        FakeEntry("one", Declared(1, {"actors": Greeter()})),
        FakeEntry("two", Declared(1, {"templates": OneSlot()})),
    ]
    registry = load_plugins(defaults, entries)
    assert registry.provider_of(interfaces.ACTORS) == "one"
    assert registry.provider_of(interfaces.TEMPLATES) == "two"
    assert registry.get(interfaces.TEMPLATES).slot("top") == "<b>top</b>"


def test_two_plugins_with_one_name_are_refused(defaults: dict[str, object]) -> None:
    entries: list[Any] = [FakeEntry("same", Declared(1, {})), FakeEntry("same", Declared(1, {}))]
    with pytest.raises(PluginError, match="same name"):
        load_plugins(defaults, entries)


def test_the_first_error_does_not_depend_on_the_order_of_discovery(
    defaults: dict[str, object],
) -> None:
    bad_a = FakeEntry("a", Declared(2, {}))
    bad_b = FakeEntry("b", Declared(3, {}))
    for entries in ([bad_a, bad_b], [bad_b, bad_a]):
        with pytest.raises(PluginVersionError, match="'a'"):
            load_plugins(defaults, entries)


# -- serve ---------------------------------------------------------------------------------------


def serve_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DRIFTSNIFF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DRIFTSNIFF_KEY_FILE", str(tmp_path / "keys" / "master.key"))


def test_serve_gives_the_app_the_change_service_and_the_plugin_registry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apps: list[FastAPI] = []

    def fake_run(app: FastAPI, **kwargs: object) -> None:
        apps.append(app)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    serve_environment(monkeypatch, tmp_path)
    assert main(["serve"]) == 0
    assert isinstance(apps[0].state.changes, ChangeService)
    assert isinstance(apps[0].state.plugins, PluginRegistry)


def test_serve_refuses_to_start_with_a_plugin_of_another_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Future:
        plugin_api_version = 2
        extensions: dict[str, object] = {}

    calls: list[object] = []

    def fake_run(app: object, **kwargs: object) -> None:
        calls.append(app)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    entries = [FakeEntry("future-plugin", Future())]
    monkeypatch.setattr(registry_module, "entry_points", lambda group: entries)
    serve_environment(monkeypatch, tmp_path)
    assert main(["serve"]) == 1
    captured = capsys.readouterr()
    assert "future-plugin" in captured.err
    assert "setup code" not in captured.out
    assert calls == []
