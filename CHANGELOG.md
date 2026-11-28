# Changelog

All notable changes to Driftsniff CE are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow the
`27.<minor>.<patch>` line described in [docs/ci-cd.md](docs/ci-cd.md#versions).

## [Unreleased]

## [27.0.0] - Unreleased

The first release. The full notes are in
[docs/release-notes/v27.0.0.md](docs/release-notes/v27.0.0.md).

### Added

- Collection from fourteen kinds of system on a schedule: UniFi Network, UniFi Protect, Xen
  Orchestra, Proxmox VE, Portainer, TrueNAS, Synology DSM, QNAP QTS / QuTS hero, Redfish BMCs
  (iDRAC, iLO, Supermicro), Home Assistant, Grafana, Prometheus, Zabbix and Checkmk, each with a
  setup guide and a rule pack. Push sources take a configuration from a sender.
- Change detection that stores only differences, keeps secrets as keyed fingerprints and rates
  each item low, medium, high or critical with the rule and its reason.
- Web interface: dashboard with a 3D view of the lab, change list and detail, sources with change
  replay and coverage, history and configuration, settings and an Account page. Light and dark
  themes, phone and tablet layouts.
- Viewer, operator and admin roles, first-admin setup, API tokens, the `/api/v1` API, one
  notification channel (webhook or SMTP).
- Health route, online backup, nightly retention, master key rotation and a hardened container
  image at `ghcr.io/theriark/driftsniff-ce:27.0.0`.
- `DRIFTSNIFF_DEV_HOST_SUFFIX`, a Development-only setting (unset by default) that names the
  Development site allowed to create test accounts and synthetic data at start.

### Changed

- Collectors, type tables and rules follow what real UniFi Network, Xen Orchestra, TrueNAS,
  Portainer, Checkmk, Home Assistant and Grafana systems return.
- The dashboard counts changes everywhere, and a resource label two products share names its
  product.
- The header no longer shows an environment badge; `DRIFTSNIFF_ENVIRONMENT_LABEL` is not read.

### Fixed

- A value that only moved between clear text and a fingerprint is no longer reported as a change.
- The master key rekey finishes after one clean collection cycle instead of staying open. A
  resource that is refused or missing no longer holds it open, a disabled or deleted source is
  no longer waited for, and a rekey that can no longer finish is replaced by a new one.
- Source ids are never given twice, and the activity of a deleted source never shows the name
  of another source.
- An added or removed whole object says so on the change page, has its own rule instead of the
  unclassified one, and offers no mute.
- A push source refuses a resource without a type table when it is saved; a CA file that is not
  in the CA folder is refused when the source is saved.
- The sender key page of a push source can be refreshed without making a new key; an expired
  form shows a page that says so; a malformed change address shows the not-found page; a
  reversed date range in the change list is swapped and the page says so.
- Sources sort by version numerically; History opens each reading and only its changes; the
  Account picture upload works in every browser; a change number has no thousands separator.
- The application reports version 27.0.0.

[Unreleased]: https://github.com/Theriark/driftsniff-ce/compare/v27.0.0...HEAD
[27.0.0]: https://github.com/Theriark/driftsniff-ce/releases/tag/v27.0.0
