# Prometheus vendor notes

driftsniff's own notes on the Prometheus HTTP API that the Prometheus collector reads
(`src/driftsniff/collectors/prometheus/`, type table `src/driftsniff/rules/types/prometheus.yaml`).
Nothing here is copied from the vendor; every statement is in our own words, with its source and
the date it was read.

## Status in one paragraph

The statements below were read from the Prometheus documentation (`latest`) on **2026-11-12**.
**No lab Prometheus was used**: nothing here is checked against a running server, and the contract
tests run against `tests/contract/fake_prometheus.py`, which follows these notes. Names marked
**UNVERIFIED** were not found in what was read.

## Sources

| Id | Source | Read on |
|---|---|---|
| S1 | https://prometheus.io/docs/prometheus/latest/querying/api/ (envelope, buildinfo, config, flags, rules) | 2026-11-12 |
| S2 | https://prometheus.io/docs/prometheus/latest/configuration/configuration/ (global, scrape_config, http_config, static_config, relabel_config, alertmanager_config, remote_write, tsdb, exemplars) | 2026-11-12 |
| S3 | https://prometheus.io/docs/prometheus/latest/command-line/prometheus/ (flag names and defaults) | 2026-11-12 |
| S4 | https://prometheus.io/docs/prometheus/latest/configuration/https/ (web configuration file: TLS and basic auth) | 2026-11-12 |

## Statements

| # | Statement | Source | Status |
|---|---|---|---|
| 1 | Every API answer is a JSON envelope with `status` (`success` or `error`) and `data`; `errorType` and `error` are set only on an error, and `warnings` may be present. | S1 | vendor doc |
| 2 | `GET /api/v1/status/buildinfo` answers text values: `version`, `revision`, `branch`, `buildUser`, `buildDate`, `goVersion`. The page warns that the set may change between versions. | S1 | vendor doc |
| 3 | `GET /api/v1/status/config` answers `data.yaml`: the loaded configuration dumped as YAML, without comments. | S1 | vendor doc |
| 4 | `GET /api/v1/status/flags` answers every flag as a text value, keyed by the flag name (`query.max-concurrency`). | S1 | vendor doc |
| 5 | `GET /api/v1/rules` answers `data.groups`; a group has `name`, `file`, `interval`, `limit` and `rules`. An alerting rule has `name`, `query`, `duration`, `labels`, `annotations`, `alerts`, `health`, `type` (`alerting`); a recording rule `name`, `query`, `health`, `type` (`recording`). Parameters: `type=alert\|record`, `exclude_alerts`, `rule_name[]`, `rule_group[]`, `file[]`, `match[]`, `group_limit`, `group_next_token`. Without `group_limit` all groups are returned. | S1 | vendor doc |
| 6 | Fields of rules and groups that the example of S1 does not show: `keepFiringFor`, `lastError`, `evaluationTime`, `lastEvaluation`, `state`, `queryOffset`. Listed in the type table (volatile ones ignored) so they are classified if they arrive. | none | **UNVERIFIED** |
| 7 | Top-level configuration keys: `global`, `runtime`, `rule_files`, `scrape_config_files`, `scrape_configs`, `alerting`, `remote_write`, `remote_read`, `otlp`, `storage`, `tracing`. | S2 | vendor doc |
| 8 | The fields of `global`, `scrape_config`, `static_config` (`targets`, `labels`), `relabel_config` (`source_labels`, `separator`, `target_label`, `regex`, `modulus`, `replacement`, `action`), `alertmanager_config` (`timeout`, `api_version`, `path_prefix`, `scheme`, `sigv4`, http config, `static_configs`, `relabel_configs`, `alert_relabel_configs`), `remote_write` (`url`, `name`, `protobuf_message`, `remote_timeout`, `headers`, `write_relabel_configs`, `send_exemplars`, `send_native_histograms`, `round_robin_dns`, `sigv4`, `azuread`, `google_iam`, `queue_config`, `metadata_config`, `convert_nhcb_to_classic`) and `tsdb` (`out_of_order_time_window`, `retention.time`, `retention.size`, `retention.percentage`) are as listed in the type table. | S2 | vendor doc |
| 9 | Secret-typed fields (printed as `<secret>` when the configuration is dumped): `basic_auth.password`; `authorization.credentials`; `oauth2.client_secret`; `oauth2.client_certificate_key`; `tls_config.key`, the values of `proxy_connect_header` and `http_headers` secrets; `sigv4.secret_key`; the Azure AD certificate password; and secrets of several service discovery blocks (`consul_sd_configs.token`; `ec2_sd_configs.secret_key`; `azure_sd_configs.client_secret`, ...). | S2 | vendor doc |
| 10 | Not secret-typed, so served in clear: `remote_write.headers` (plain text values) and the Azure AD OAuth `client_secret`. driftsniff classes them secret anyway. | S2 | vendor doc |
| 11 | Whether Prometheus hides a password written into a remote write `url` when it dumps the configuration was not read. The collector replaces it with `<secret>` either way. | none | **UNVERIFIED** |
| 12 | Flags: `web.enable-admin-api` and `web.enable-lifecycle` default to false; `storage.tsdb.retention.time` and `storage.tsdb.retention.size` are deprecated in favour of the configuration's `storage.tsdb.retention`; `log.level` is deprecated in favour of `runtime.log_level`. | S3 | vendor doc |
| 13 | The members of `runtime` (`gogc`, `log_level`) were not read in full. | S2, S3 | **UNVERIFIED** |
| 14 | Prometheus has no token check of its own. Its web configuration file offers basic auth (`basic_auth_users`, bcrypt hashes) and TLS client certificates; a bearer token is not mentioned. A bearer token works only through a reverse proxy in front of Prometheus. | S4 | vendor doc |
| 15 | In agent mode the rules and parts of the configuration are not served; the exact answer (status and error type) was not read. The collector reports such a read as a failed resource with its HTTP status. | none | **UNVERIFIED** |

## What the collector does with it

- It reads three answers per run (config, flags, rules), each once, and makes eight resources of
  them (`resources.py`); the alerts of a rule, the targets and their live state are never read.
- The configuration YAML is parsed with PyYAML's safe loader under a node and depth limit.
- Maps with free keys (labels, annotations, `external_labels`, `params`) become lists keyed by
  `name`; flag names have their dots and dashes turned into underscores.
- Remote write targets are keyed by `name`, else by `url`; rules by `<file> / <group> / <name>`,
  with `#2`, `#3` for a name repeated in one group (a known shortcut: removing the first of two
  shifts the second).
