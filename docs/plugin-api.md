# Plugin API

driftsniff CE has ten extension points. Each is a small typing protocol
(`driftsniff/plugins/interfaces.py`) with a CE default (`driftsniff/plugins/defaults.py`). CE calls
only the defaults; a plugin replaces a default by providing another implementation of the same
point. The registry (`driftsniff/plugins/registry.py`) finds the plugins, checks them **when the
application starts** and refuses to start when one cannot be used.

Plugins run with the full rights of the process. Installing one is a decision of the person who
runs the installation; nothing here is a sandbox.

## The points

| Name | Protocol | CE default |
|---|---|---|
| `auth` | `AuthProvider.login(username, password, address)` returns a session grant | local users and passwords |
| `channels` | `ChannelPolicy.max_active_channels()` | one channel |
| `rules` | `RuleSource.pack_directories()` | the shipped packs (path mutes apply on top) |
| `retention` | `RetentionPolicy.retention_days()` | one setting for the installation, a year by default |
| `actors` | `ActorResolver.resolve(hint)` | nobody (returns `None`) |
| `workspaces` | `WorkspaceProvider.current_workspace_id()` | workspace 1 |
| `reports` | `ReportGenerator.generate(event_id)` | none (returns `None`) |
| `runner` | `RunExecutor.execute(job)` | in this process, on the calling thread |
| `storage` | `StorageBackend.database_location(data_dir)` | a SQLite file in the data directory |
| `templates` | `TemplateSlots.slot(name)` | every slot is empty |

CE only reads these points for itself; whether a later edition calls a point is that edition's
business. The names and signatures above are this task's reading of the plan's one-line list of
CE defaults; the R&D report that defines the ten points was not available to the author, so
Delivery should check them against it before an edition builds on them.

## Writing a plugin

A plugin is an object published under the entry point group `driftsniff.plugins`:

```toml
[project.entry-points."driftsniff.plugins"]
my-plugin = "my_package.plugin:PLUGIN"
```

```python
class Resolver:
    def resolve(self, hint: str | None) -> str | None:
        return f"corp:{hint}"


class Plugin:
    plugin_api_version = 1
    extensions = {"actors": Resolver()}


PLUGIN = Plugin()
```

- `plugin_api_version` is a whole number. CE ships **1**. Any other value, a missing value, a
  boolean or a text is refused at start with a message that names the plugin and both versions.
- `extensions` maps a point name to an implementation. The implementation must have every method
  of the point's protocol (checked with `isinstance`; argument types are not checked at start).

## What is refused at start

Each is an error that stops `driftsniff serve` with exit code 1 and a message that names the
plugin (the entry point name), never the text of the plugin's own error:

- the plugin cannot be imported (the log line names the error class only);
- no `plugin_api_version`, or a version other than 1;
- `extensions` is not a mapping;
- a point name that does not exist;
- an implementation without a method of its protocol;
- two plugins that provide the same point (both names are in the message);
- two entry points with the same name.

Plugins are taken in name order, so the first error is the same on every start.
`PluginRegistry.provider_of(point)` says which plugin provides a point, or `default`.

## Not verified

The registry has been tested with a dummy plugin installed through a real entry point and with
fake entry points. No third-party plugin has been run, and `PLUGIN_API_VERSION` has never changed,
so the upgrade path between two versions is untested.
