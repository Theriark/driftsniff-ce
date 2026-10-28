# driftsniff CE documentation

Documentation for release candidate **v27.0.0-rc.5**, Development candidate
`40963ddf3b52f689ca48028611e79374ba362b8a` (image digest `sha256:bb09f8a3…`). Its application
files are identical to those of build `63eaa6ad764955d1d57124ca7727e7bfcb49ddc9` (image digest
`sha256:53ee8584…`), on which the application behaviour was verified; the candidate differs from
that build only in the CI workflow and a CI test, which the image does not contain. Build
`63eaa6ad` in turn differs from the earlier build `36f78cc95919b115103af19bd10773d9d69a7386` only
in the hint under the push source form. The push form screenshot was taken on `63eaa6ad` at
`https://ce-dev-driftsniff.theriark.dev` on 28 October 2026; the other screenshots were taken
there on build `36f78cc9` on 26 October 2026 and show pages that neither later build changes. No
screenshot was taken on `40963ddf`. All captures hold synthetic test data only. The
[documentation manifest](documentation-manifest.json) lists every file with its SHA-256 and, for
every screenshot, the build it was taken on.

## For people who use driftsniff

| Document | Read it to |
|---|---|
| [Installation](install.md) | run driftsniff with Docker Compose and create the first admin |
| [Configuration](configuration.md) | see every setting, its default and when to change it |
| [User guide](user-guide.md) | read the dashboard, the changes, the sources, the history and the configuration |
| [Admin guide](admin-guide.md) | add sources, users, API tokens and a notification channel; set retention |
| [API guide](api-guide.md) | read changes and attach notes from a script, or push a configuration |
| [Operations](operations.md) | check health, back up, restore, upgrade and roll back |
| [Release notes v27.0.0-rc.5](release-notes/v27.0.0-rc.5.md) | see what this candidate contains and what it does not |
| [Release notes v27.0.0-rc.4 (superseded)](release-notes/v27.0.0-rc.4.md) | history only: the label of candidate `63eaa6ad`, never tagged; its application files are those of this candidate |
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

## Setup guides for the controllers

- [Setting up a UniFi source](guides/unifi-setup.md)
- [Setting up a Xen Orchestra source](guides/xo-setup.md)

Neither guide has been checked against a lab controller yet; each one marks the statements about
the vendor side as NOT VERIFIED.

## Reference documents

The engineering notes of each part. They describe how the code works and which tests check it.

| Area | Documents |
|---|---|
| Web interface | [web-interface.md](web-interface.md), [design-direction.md](design-direction.md), [csrf-and-headers.md](csrf-and-headers.md) |
| Sign-in and access | [auth.md](auth.md), [api-access.md](api-access.md), [security-model.md](security-model.md), [secrets-handling.md](secrets-handling.md), [key-management.md](key-management.md), [tls.md](tls.md) |
| Sources and collection | [sources.md](sources.md), [collectors.md](collectors.md), [push.md](push.md), [scheduler.md](scheduler.md), [unifi-client.md](unifi-client.md), [unifi-pack.md](unifi-pack.md), [xo-client.md](xo-client.md), [xo-volatility.md](xo-volatility.md), [vendor-notes/unifi.md](vendor-notes/unifi.md), [vendor-notes/xo.md](vendor-notes/xo.md) |
| Changes and rules | [normaliser.md](normaliser.md), [diff.md](diff.md), [order.md](order.md), [rules.md](rules.md), [snapshots.md](snapshots.md), [changes-service.md](changes-service.md), [history-service.md](history-service.md), [golden-table.md](golden-table.md) |
| Integrations | [enrichment-api.md](enrichment-api.md), [notifications.md](notifications.md), [plugin-api.md](plugin-api.md) |
| Storage and settings | [database.md](database.md), [retention-and-backup.md](retention-and-backup.md), [settings.md](settings.md) |
| Build, test and deploy | [ci-cd.md](ci-cd.md), [ci-baseline.md](ci-baseline.md), [e2e-ci.md](e2e-ci.md), [canary-harness.md](canary-harness.md), [measurements.md](measurements.md), [deploy-development.md](deploy-development.md), [dev-fixture.md](dev-fixture.md), [dev-test-accounts.md](dev-test-accounts.md) |

The Phase 10 design mock-ups are HTML files in the `docs/mockups/` folder of the source
repository. They are kept there as design history and are not part of the published documentation
package; the screenshots in this documentation show the built product.

## Screenshots

All screenshots are in the `images` folder next to this file. Each one is listed in the
[documentation manifest](documentation-manifest.json) with the page, the role that was signed in,
the viewport, the theme, the capture time (Europe/Lisbon) and the documents that use it. Where a
capture shows the names or first characters of the revoked Development test tokens, those entries
are blurred; the manifest marks each blurred capture.
