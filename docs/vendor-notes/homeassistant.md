# Home Assistant vendor notes

driftsniff's own notes on the Home Assistant interface that the Home Assistant collector reads
(`src/driftsniff/collectors/homeassistant/`). They are written for the people who build and review
the collector and the type table `src/driftsniff/rules/types/homeassistant.yaml`. Every statement is
in our own words, with its source and the date it was read.

## Status in one paragraph

**Nothing here is lab-verified.** No lab Home Assistant was read. The protocol comes from the
developer documentation (S1, S2) and the command names and answer fields from the Home Assistant
core source on GitHub, `dev` branch (S3), all read on 2026-11-12. The collector, the rule pack and
the pipeline are tested against a fake Home Assistant on localhost
(`tests/contract/fake_homeassistant.py`) that serves those names. That shows what driftsniff does
with them; it does not show that a released Home Assistant answers exactly so. Every field name is
therefore **UNVERIFIED** against a live system, as the header of the type table says.

## Sources

| Id | Source | Read | Used for |
|---|---|---|---|
| S1 | Developer docs, WebSocket API (`developers.home-assistant.io/docs/api/websocket`, now redirected to `contributors.home-assistant.io/core/internals/websocket-api/`) | 2026-11-12 | Path `/api/websocket`; `auth_required` / `auth` with `access_token` / `auth_ok` or `auth_invalid` (with `ha_version`); command `{id, type}`; result `{id, type: result, success, result \| error {code, message}}`; error codes; `get_config`, `get_states` |
| S2 | Developer docs, REST API (`developers.home-assistant.io/docs/api/rest`, now `contributors.home-assistant.io/core/internals/rest-api/`) | 2026-11-12 | `Authorization: Bearer <token>`; `/api/config` and the few other REST endpoints; no automation, user or registry endpoint is documented there |
| S3 | Core source, `github.com/home-assistant/core`, `dev` branch: `components/websocket_api/{auth,commands,const}.py`, `core_config.py` (`as_dict`), `config_entries.py` (`as_json_fragment`), `components/config/{auth,area_registry,entity_registry,config_entries}.py`, `helpers/{area,entity}_registry.py`, `components/{automation,script}/__init__.py`, `components/lovelace/{__init__,dashboard,const}.py`, `components/homeassistant/exposed_entities.py`, `components/cloud/const.py`, `auth/const.py`, `util/unit_system.py` | 2026-11-12 | Command names, which need an administrator, answer fields |

## Lab check: Home Assistant 2026.10.4 (2026-11-13)

A local Home Assistant 2026.10.4 was read over `wss://<host>/api/websocket` with a long-lived
token of an administrator. Statements 1, 2 and 6 hold: the token signs in once, and all eight
commands answered (4,047 objects, 3,895 of them entities). Two readings in a row gave no change.

- Eight entity paths were not in the table: `has_entity_name`, `categories.automation`,
  `options.battery_notes.entity_id` (an integration's own options), `options.collection.hash`
  and four `options.sensor.*` display settings. They are classified now
  (`tests/unit/test_homeassistant_real_shapes.py`).
- The high-entropy rule of the secret scanner took identifiers for secrets: about 2,500 entity
  `unique_id`s (ULIDs, MAC addresses, serial numbers), 309 `config_entry_id`s, 172 long
  `entity_id`s and some integration `entry_id`s, so they were stored as fingerprints only.
  `rules/overrides.yaml` now exempts those id paths from the high-entropy rule, and from no other
  rule, with a reason each.
- The core location (`latitude`, `longitude`, `elevation`), area pictures and the triggers,
  conditions and actions of automations stay secret, by decision of the type table.

## REST or WebSocket: the decision

- The REST API (S2) has `/api/config` and states, services, events, history and templates. It has
  no endpoint for users, integrations, areas, the entity registry, dashboards or the configuration
  of an automation in the documentation. (The config panel has an undocumented
  `/api/config/automation/config/<id>`; it only covers automations stored in `automations.yaml`
  that have an `id`, so it is not used.)
- The WebSocket API carries everything driftsniff reads, including `get_config`, which is the same
  `as_dict()` as `/api/config` (S3). **driftsniff uses only the WebSocket API**, on one connection
  per check, with the WebSocket client the TrueNAS collector already has
  (`collectors/truenas/websocket.py`, imported unchanged). The token is sent once, in the `auth`
  message, instead of in a header on every request.

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | The endpoint is `/api/websocket`; the server first sends `{"type": "auth_required", "ha_version"}`. | S1, S3 `websocket_api/auth.py` | documented |
| 2 | The client answers `{"type": "auth", "access_token": <long-lived token>}`; the server answers `{"type": "auth_ok", "ha_version"}` or `{"type": "auth_invalid", "message"}` and closes the connection. | S1, S3 | documented |
| 3 | A command is `{"id": <increasing int>, "type": <command>, ...}`; the answer is `{"id", "type": "result", "success", "result"}` or `success: false` with `error {code, message}`. | S1 | documented |
| 4 | Error codes include `unknown_command`, `unauthorized`, `not_allowed`, `not_found`, `home_assistant_error`. driftsniff maps `unknown_command` to 404 and `unauthorized` / `not_allowed` to 403. | S1, S3 `websocket_api/const.py` | documented; the mapping is ours |
| 5 | Commands read: `get_config`, `config_entries/get`, `config/auth/list`, `get_states`, `automation/config` (`entity_id`), `script/config` (`entity_id`), `config/area_registry/list`, `config/entity_registry/list`, `lovelace/dashboards/list`. | S1 (`get_config`, `get_states`), S3 (the rest) | in the source, UNVERIFIED live |
| 6 | `config/auth/list`, `automation/config` and `script/config` need an administrator (`require_admin`); the others do not. | S3 | in the source, UNVERIFIED live |
| 7 | `automation/config` and `script/config` answer `{"config": raw_config}`; `raw_config` is the configuration as written, after YAML loading. | S3 | in the source; that a `!secret` arrives resolved is our reading, UNVERIFIED |
| 8 | A user is an administrator when its `group_ids` hold `system-admin` (`auth/const.py` `GROUP_ID_ADMIN`). `config/auth/list` returns `id, username, name, is_owner, is_active, local_only, system_generated, group_ids, credentials [{type}]`. | S3 | in the source |
| 9 | `get_config` leaves out `external_url` for a user whose `local_only` is true. | S3 `commands.py` | in the source |
| 10 | An automation entity's state is `on` or `off` (enabled), or `unavailable`; a script entity's state is `on` while it runs. | S3, our reading | UNVERIFIED |
| 11 | Entity options for voice assistants are `options.<assistant>.should_expose` with assistants `cloud.alexa`, `cloud.google_assistant`, `conversation`; Google also has `disable_2fa`. | S3 `exposed_entities.py`, `cloud/const.py` | in the source, UNVERIFIED live |
| 12 | Run state that changes without a configuration change: all entity states and attributes; `state`, `version`, `components`, `recovery_mode`, `safe_mode` of the core config; `state`, `reason`, `error_reason_*` and `modified_at` of a config entry; `created_at` / `modified_at` of registry entries; `original_name`, `translation_key`, `next_name_part` of an entity (provided by the integration). | S3, our reading | ignore class; volatility not measured on a live system |
| 13 | `lovelace/dashboards/list` answers the configured dashboards (not the default one): storage ones `{id, url_path, title, icon, show_in_sidebar, require_admin, mode}`, YAML ones with `filename` and no `id`. | S3 | in the source |

## What the collector does to the answers

Read from `get_states`: only the entity id of each `automation.*` and `script.*` entity and the
on/off state of each automation. No other state or attribute is kept. Derived: `id: "core"` on the
core config, `is_admin` on users (`system-admin` in `group_ids`), `enabled` on automations.
Classed secret (fingerprint only): the home latitude, longitude and elevation, and the triggers,
conditions, actions, sequences, variables and blueprint inputs of automations and scripts, because
they can carry credentials written inline. Everything else is passed raw and classified by the
type table.

## Known limits

- An added object has no field values a rule can test, so a new administrator account cannot be
  told from any new account: every new or removed user is critical.
- Whether an automation guards security cannot be told from its configuration, so an automation
  turned off is medium.
- Automations and scripts are keyed by entity id: renaming the entity id is a removal and an
  addition.

## Not covered (yet)

Devices (`config/device_registry/list`), floors and labels registries, persons and zones, the
content of dashboards (`lovelace/config`), blueprints, add-ons and Supervisor settings, backups,
the HTTP integration settings (trusted proxies, IP ban) and `configuration.yaml` itself. Each is
one more entry in `collectors/homeassistant/resources.py` and a type table.
