# Setting up a Prometheus source

This guide connects driftsniff to a Prometheus server so that it records changes to its running
configuration (global settings, scrape jobs, Alertmanagers, remote write targets), its startup
flags and the alerting and recording rules it evaluates.

## Read this first

- **No lab Prometheus has been used.** The API paths and fields come from the Prometheus
  documentation, read on 2026-11-12 (`docs/vendor-notes/prometheus.md`). The collector is tested
  against a fake Prometheus on localhost (`tests/contract/fake_prometheus.py`), not a real server.
- driftsniff **only reads**: it sends `GET` requests and nothing else. It never reads targets or
  their live state, and never uses the admin API.

## How driftsniff signs in

Prometheus has no token check of its own. With the **User name** field empty, driftsniff sends
the credential you enter as `Authorization: Bearer <token>`, which suits Prometheus behind a
reverse proxy (nginx, Traefik, an OAuth proxy) that checks that token.

- **Prometheus without any sign in:** the form still asks for a credential. Enter any text, for
  example `none`; Prometheus ignores the header. Keep such a Prometheus off untrusted networks.
- **Prometheus with its own basic auth** (`basic_auth_users` in its web configuration file): enter
  the user name in **User name** and its password as the credential. driftsniff then sends
  `Authorization: Basic`. A user name cannot contain a colon.

## What driftsniff reads

| Resource | Prometheus path | What it holds |
|---|---|---|
| `prometheus-global` | `/api/v1/status/config` | the `global` section, `rule_files`, `scrape_config_files`, `runtime`, `storage` |
| `prometheus-scrape-jobs` | `/api/v1/status/config` | one object per scrape job, by `job_name` |
| `prometheus-alerting` | `/api/v1/status/config` | the Alertmanagers and alert relabelling |
| `prometheus-remote-write` | `/api/v1/status/config` | one object per remote write target, by name or URL |
| `prometheus-flags` | `/api/v1/status/flags` | the startup flags (`web.enable-admin-api` becomes `web_enable_admin_api`) |
| `prometheus-rule-groups` | `/api/v1/rules?exclude_alerts=true` | rule groups: file, name, interval, limit |
| `prometheus-alerting-rules` | same | alerting rules: expression, `for`, labels, annotations |
| `prometheus-recording-rules` | same | recording rules: expression and labels |

The version comes from `/api/v1/status/buildinfo`. Each path is read once per check. Rule health,
evaluation times, alert states and active alerts are ignored, so a firing alert is not a change.

## Steps

1. If a proxy guards Prometheus, create a token for driftsniff there, limited to `GET` on
   `/api/v1/status/*` and `/api/v1/rules` if the proxy can do that.
2. In driftsniff, select **Add source**, choose **Prometheus**, and enter a name, the address of
   the Prometheus server (for example `https://prometheus.example.invalid:9090`; add the route
   prefix if Prometheus runs under one), the bearer token (or a user name and password for basic
   auth), the interval, the resources and the TLS
   mode.
3. Select **Test connection**. It reads the version and each resource once and stores nothing.

The token is sent only in the `Authorization` header, stored encrypted and never shown again.

## What is never stored in clear

Prometheus already prints `<secret>` for its own secret fields. driftsniff also keeps only a keyed
fingerprint of what Prometheus does show: remote write headers (often a tenant id or a token), a
password written into a remote write URL, the Azure AD client secret of a remote write target,
`http_headers` and proxy headers of a job. It can tell that one changed but not what it is.

## What is rated how

- Critical: the admin API switched on (`web.enable-admin-api`).
- High: a scrape job removed, an alerting rule deleted, a remote write target added, removed or
  pointed elsewhere, the Alertmanagers changed, the lifecycle API or the remote write receiver
  switched on, the rule files changed, certificate checks of a job switched off.
- Medium: retention changed, an alert expression, `for` or labels changed, scrape targets changed.
- Low: scrape and evaluation intervals, alert annotations.
