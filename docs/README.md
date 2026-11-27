# driftsniff CE documentation

Documentation for **Driftsniff CE 27.0.0**. Screenshots taken on the Development site, synthetic
data.

## For people who use driftsniff

| Document | Read it to |
|---|---|
| [Installation](install.md) | run driftsniff with Docker Compose and create the first admin |
| [Configuration](configuration.md) | see every setting, its default and when to change it |
| [User guide](user-guide.md) | read the dashboard, the changes, the sources, the history and the configuration |
| [Admin guide](admin-guide.md) | add sources, users, API tokens and a notification channel; set retention |
| [API guide](api-guide.md) | read changes and attach notes from a script, or push a configuration |
| [Operations](operations.md) | check health, back up, restore, upgrade and roll back |
| [Release notes 27.0.0](release-notes/v27.0.0.md) | see what the release contains, what changed since the last candidate, and its known limits |
| [Changelog](../CHANGELOG.md) | see every notable change by version |
| [Release notes v27.0.0-rc.5 (superseded)](release-notes/v27.0.0-rc.5.md) | history only: the candidate tagged `v27.0.0-rc.5`, superseded by 27.0.0 |
| [Release notes v27.0.0-rc.4 (superseded)](release-notes/v27.0.0-rc.4.md) | history only: the label of candidate `63eaa6ad`, never tagged |
| [Release notes v27.0.0-rc.3 (superseded)](release-notes/v27.0.0-rc.3.md) | history only: the label of the previous candidate `51051220`, never tagged; its push form hint was wrong |
| [Release notes v27.0.0-rc.2 (superseded)](release-notes/v27.0.0-rc.2.md) | history only: an earlier label of candidate `51051220`, never tagged; its push example was wrong |
| [Release notes v27.0.0-rc.1 (superseded)](release-notes/v27.0.0-rc.1.md) | history only: the first label of candidate `51051220`, never tagged |

## Tutorials

Step by step, with a screenshot of each step. See the [tutorial index](tutorials/README.md).

1. [Sign in for the first time](tutorials/01-first-sign-in.md)
2. [Review a change and acknowledge it](tutorials/02-review-a-change.md)
3. [Add a source](tutorials/03-add-a-source.md)
4. [Add a user and make an API token](tutorials/04-add-a-user.md)
5. [Read the history and the configuration of a source](tutorials/05-history-and-configuration.md)

## Setup guides for the systems driftsniff reads

- [Setting up a UniFi source](guides/unifi-setup.md)
- [Setting up a Xen Orchestra source](guides/xo-setup.md)
- [Setting up a QNAP source](guides/qnap-setup.md)
- [Setting up a Synology DSM source](guides/synology-setup.md)
- [Setting up a Grafana source](guides/grafana-setup.md)
- [Setting up a Prometheus source](guides/prometheus-setup.md)
- [Setting up a UniFi Protect source](guides/unifi-protect-setup.md)
- [Setting up a Checkmk source](guides/checkmk-setup.md)
- [Setting up a Home Assistant source](guides/homeassistant-setup.md)
- [Setting up a Proxmox VE source](guides/proxmox-setup.md)
- [Setting up a Redfish source (iDRAC, iLO, Supermicro)](guides/redfish-setup.md)
- [Setting up a Zabbix source](guides/zabbix-setup.md)
- [Setting up a Portainer source](guides/portainer-setup.md)
- [Setting up a TrueNAS source](guides/truenas-setup.md)

The UniFi Network, Xen Orchestra, TrueNAS, Portainer, Checkmk, Home Assistant and Grafana guides
were checked on lab systems; the others were checked against simulations only and mark the
statements about the vendor side that no real system has confirmed. See
[Checked on real systems](release-notes/v27.0.0.md#checked-on-real-systems).

## Reference documents

The engineering notes of each part. They describe how the code works and which tests check it.

| Area | Documents |
|---|---|
| Web interface | [web-interface.md](web-interface.md), [csrf-and-headers.md](csrf-and-headers.md) |
| Sign-in and access | [auth.md](auth.md), [api-access.md](api-access.md), [security-model.md](security-model.md), [secrets-handling.md](secrets-handling.md), [key-management.md](key-management.md), [tls.md](tls.md) |
| Sources and collection | [sources.md](sources.md), [collectors.md](collectors.md), [push.md](push.md), [scheduler.md](scheduler.md), [unifi-client.md](unifi-client.md), [unifi-pack.md](unifi-pack.md), [xo-client.md](xo-client.md), [xo-volatility.md](xo-volatility.md), [vendor-notes/checkmk.md](vendor-notes/checkmk.md), [vendor-notes/grafana.md](vendor-notes/grafana.md), [vendor-notes/homeassistant.md](vendor-notes/homeassistant.md), [vendor-notes/portainer.md](vendor-notes/portainer.md), [vendor-notes/prometheus.md](vendor-notes/prometheus.md), [vendor-notes/proxmox.md](vendor-notes/proxmox.md), [vendor-notes/qnap.md](vendor-notes/qnap.md), [vendor-notes/redfish.md](vendor-notes/redfish.md), [vendor-notes/synology.md](vendor-notes/synology.md), [vendor-notes/truenas.md](vendor-notes/truenas.md), [vendor-notes/unifi.md](vendor-notes/unifi.md), [vendor-notes/unifi-drive.md](vendor-notes/unifi-drive.md), [vendor-notes/unifi_protect.md](vendor-notes/unifi_protect.md), [vendor-notes/xo.md](vendor-notes/xo.md), [vendor-notes/zabbix.md](vendor-notes/zabbix.md) |
| Changes and rules | [normaliser.md](normaliser.md), [diff.md](diff.md), [order.md](order.md), [rules.md](rules.md), [snapshots.md](snapshots.md), [changes-service.md](changes-service.md), [history-service.md](history-service.md), [golden-table.md](golden-table.md) |
| Integrations | [enrichment-api.md](enrichment-api.md), [notifications.md](notifications.md), [plugin-api.md](plugin-api.md) |
| Storage and settings | [database.md](database.md), [retention-and-backup.md](retention-and-backup.md), [settings.md](settings.md) |
| Build, test and deploy | [ci-cd.md](ci-cd.md), [canary-harness.md](canary-harness.md) |

The design mock-ups of the web interface are HTML files in the `docs/mockups/` folder of the source
repository. They are kept there as design history and are not part of the published documentation
package; the screenshots in this documentation show the built product.

## Screenshots

All screenshots are in the `images` folder next to this file. They were taken on the Development
site on 27 November 2026, on the 27.0.0 build, and hold synthetic test data and simulated sources
only. Solid black boxes hide one account row and five test token names on the Settings page and the
address of a simulated source; nothing is blurred.
