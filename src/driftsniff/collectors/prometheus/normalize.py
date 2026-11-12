"""What the Prometheus collector makes of the three answers before the pipeline sees them.

The running configuration arrives as YAML text. It is parsed here with PyYAML's safe loader (the
library the rule packs use) under a node and depth limit, so an alias cannot expand into a huge
value, and every scalar that is not JSON (a date, for example) is kept as the text Prometheus
wrote. It becomes four resources:

* ``prometheus-global``: one object keyed ``global`` with the ``global`` section, ``rule_files``,
  ``scrape_config_files``, ``runtime`` and ``storage``;
* ``prometheus-scrape-jobs``: one object per scrape config, keyed by ``job_name``;
* ``prometheus-alerting``: one object keyed ``alerting`` with ``alertmanagers`` and
  ``alert_relabel_configs``;
* ``prometheus-remote-write``: one object per target, keyed by its ``name``, else by its ``url``.
  A password written into a URL is replaced by ``<secret>`` before anything else sees it.

The flags become one object keyed ``flags``; a flag name such as ``web.enable-admin-api`` becomes
the field ``web_enable_admin_api`` (a dot would split the path of the field). The rule list becomes
rule groups keyed ``<file> / <group>`` and alerting and recording rules keyed
``<file> / <group> / <rule>``.

Maps with free keys (labels, annotations, ``external_labels``, ``params``) become lists of
``{"name", "value"}``, which the type tables compare as sets keyed by ``name``. Objects are
sorted by key. Everything else is raw: redaction, normalisation and keying belong to the pipeline.
"""

from collections.abc import Mapping
from typing import Final
from urllib.parse import urlsplit, urlunsplit

import yaml

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.prometheus.resources import (
    RESOURCE_ALERTING,
    RESOURCE_ALERTING_RULES,
    RESOURCE_GLOBAL,
    RESOURCE_RECORDING_RULES,
    RESOURCE_REMOTE_WRITE,
    RESOURCE_RULE_GROUPS,
    RESOURCE_SCRAPE_JOBS,
)
from driftsniff.core.canonical import JsonValue

KEY_FIELD: Final = "id"
FLAGS_KEY: Final = "flags"
GLOBAL_KEY: Final = "global"
ALERTING_KEY: Final = "alerting"
URL_SECRET: Final = "<secret>"  # noqa: S105 - the placeholder Prometheus prints, not a password
MAX_NODES: Final = 500_000
MAX_DEPTH: Final = 64
_TOP_LEVEL: Final = ("rule_files", "scrape_config_files", "runtime", "storage")
_FREE_KEYS: Final = ("labels", "annotations", "external_labels", "params")

Objects = list[dict[str, JsonValue]]


def _bad(text: str) -> CollectorError:
    return CollectorError(ERROR_BAD_PAYLOAD, text)


class _Plain:
    """A composed YAML tree as JSON values, with the size and the depth bounded."""

    def __init__(self, loader: yaml.SafeLoader) -> None:
        self._loader = loader
        self._nodes = 0

    def convert(self, node: yaml.Node, depth: int) -> JsonValue:
        self._nodes += 1
        if self._nodes > MAX_NODES or depth > MAX_DEPTH:
            raise _bad("the configuration is too large or nested too deeply")
        if isinstance(node, yaml.MappingNode):
            return {
                str(self.convert(key, depth + 1)): self.convert(value, depth + 1)
                for key, value in node.value
            }
        if isinstance(node, yaml.SequenceNode):
            return [self.convert(child, depth + 1) for child in node.value]
        value = self._loader.construct_object(node, deep=True)
        if value is None or isinstance(value, str | int | float | bool):
            return value
        return str(node.value)


def parse_yaml(text: str) -> JsonValue:
    """The configuration text as JSON values; an empty text is an empty mapping."""
    try:
        loader = yaml.SafeLoader(text)
    except yaml.YAMLError:
        raise _bad("the configuration is not valid YAML") from None
    try:
        node = loader.get_single_node()
        return {} if node is None else _Plain(loader).convert(node, 0)
    except (yaml.YAMLError, RecursionError):
        raise _bad("the configuration is not valid YAML") from None
    finally:
        loader.dispose()


def _pairs(value: JsonValue) -> JsonValue:
    """A map with free keys as ``[{"name", "value"}]`` sorted by name; anything else unchanged."""
    if not isinstance(value, Mapping):
        return value
    return [{"name": key, "value": value[key]} for key in sorted(value)]


def _reshape(item: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """The free-key maps of one object, and of its static configs, as lists."""
    result = {key: _pairs(value) if key in _FREE_KEYS else value for key, value in item.items()}
    configs = result.get("static_configs")
    if isinstance(configs, list):
        result["static_configs"] = [
            _reshape(config) if isinstance(config, Mapping) else config for config in configs
        ]
    return result


def _mapping(parent: Mapping[str, JsonValue], name: str) -> dict[str, JsonValue]:
    value = parent.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _bad("a section of the configuration is not a mapping")
    return value


def _list(parent: Mapping[str, JsonValue], name: str) -> list[dict[str, JsonValue]]:
    value = parent.get(name)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise _bad("a list of the configuration is not a list of mappings")
    return [item for item in value if isinstance(item, dict)]


def _finish(objects: Objects) -> Objects:
    """Objects sorted by key; a key seen twice fails the resource."""
    objects.sort(key=lambda item: str(item[KEY_FIELD]))
    keys = [item[KEY_FIELD] for item in objects]
    if len(set(map(str, keys))) != len(keys):
        raise _bad("two objects of the answer have the same key")
    return objects


def _text(value: JsonValue) -> str:
    if not isinstance(value, str) or value == "":
        raise _bad("an object of the answer has no usable name")
    return value


def hide_url_password(url: str) -> str:
    """``https://user:pw@host/x`` as ``https://user:<secret>@host/x``; other URLs unchanged."""
    try:
        parts = urlsplit(url)
        password = parts.password
    except ValueError:
        raise _bad("a URL of the configuration cannot be read") from None
    if password is None:
        return url
    host = parts.netloc.rpartition("@")[2]
    return urlunsplit(parts._replace(netloc=f"{parts.username or ''}:{URL_SECRET}@{host}"))


def config_objects(doc: JsonValue) -> dict[str, Objects]:
    """The four configuration resources of one parsed configuration."""
    if not isinstance(doc, dict):
        raise _bad("the configuration is not a mapping")
    settings: dict[str, JsonValue] = {KEY_FIELD: GLOBAL_KEY}
    settings[GLOBAL_KEY] = _reshape(_mapping(doc, GLOBAL_KEY))
    settings.update({name: doc[name] for name in _TOP_LEVEL if name in doc})
    jobs: Objects = []
    for job in _list(doc, "scrape_configs"):
        jobs.append({**_reshape(job), KEY_FIELD: _text(job.get("job_name"))})
    section = _mapping(doc, ALERTING_KEY)
    alerting: dict[str, JsonValue] = {**section, KEY_FIELD: ALERTING_KEY}
    if "alertmanagers" in section:
        alerting["alertmanagers"] = [_reshape(item) for item in _list(section, "alertmanagers")]
    targets: Objects = []
    for target in _list(doc, "remote_write"):
        url = hide_url_password(_text(target.get("url")))
        name = target.get("name")
        key = name if isinstance(name, str) and name else url
        targets.append({**_reshape(target), "url": url, KEY_FIELD: key})
    return {
        RESOURCE_GLOBAL: [settings],
        RESOURCE_SCRAPE_JOBS: _finish(jobs),
        RESOURCE_ALERTING: [alerting],
        RESOURCE_REMOTE_WRITE: _finish(targets),
    }


def flag_field(name: str) -> str:
    """``web.enable-admin-api`` as ``web_enable_admin_api``."""
    return name.replace(".", "_").replace("-", "_")


def flags_object(data: JsonValue) -> Objects:
    """The flags as one object keyed ``flags``."""
    if not isinstance(data, dict):
        raise _bad("the flags answer is not an object")
    flags: dict[str, JsonValue] = {flag_field(name): value for name, value in data.items()}
    return [{**flags, KEY_FIELD: FLAGS_KEY}]


def rules_objects(data: JsonValue) -> dict[str, Objects]:
    """Rule groups, alerting rules and recording rules of one rule list."""
    groups = data.get("groups") if isinstance(data, dict) else None
    if not isinstance(groups, list):
        raise _bad("the rules answer has no list of groups")
    found: dict[str, Objects] = {
        RESOURCE_RULE_GROUPS: [],
        RESOURCE_ALERTING_RULES: [],
        RESOURCE_RECORDING_RULES: [],
    }
    for group in groups:
        if not isinstance(group, dict):
            raise _bad("a rule group is not an object")
        name, file = _text(group.get("name")), _text(group.get("file"))
        group_key = f"{file} / {name}"
        found[RESOURCE_RULE_GROUPS].append(
            {**{k: v for k, v in group.items() if k != "rules"}, KEY_FIELD: group_key}
        )
        rules = group.get("rules") or []
        if not isinstance(rules, list):
            raise _bad("the rules of a group are not a list")
        seen: dict[str, int] = {}
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("type") not in ("alerting", "recording"):
                raise _bad("a rule is not an alerting or a recording rule")
            key = f"{group_key} / {_text(rule.get('name'))}"
            # shortcut: a repeated rule name is told apart by its rank in the group, so removing
            # the first of two shifts the second; key by labels too if that proves noisy.
            seen[key] = seen.get(key, 0) + 1
            if seen[key] > 1:
                key = f"{key} #{seen[key]}"
            resource = (
                RESOURCE_ALERTING_RULES if rule["type"] == "alerting" else RESOURCE_RECORDING_RULES
            )
            found[resource].append({**_reshape(rule), KEY_FIELD: key, "group": name, "file": file})
    return {name: _finish(objects) for name, objects in found.items()}
