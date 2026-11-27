# Configuration

For Driftsniff CE 27.0.0. driftsniff reads its settings from `DRIFTSNIFF_` environment
variables at start. An invalid value stops the start with a message that names the setting. No
setting holds a secret: source credentials are entered in the web interface and stored encrypted,
and the master key is a file on the key volume.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DRIFTSNIFF_BASE_URL` | `http://localhost:<port>` | The address people open. Links use it, and the origin check of every write compares with it. |
| `DRIFTSNIFF_TRUSTED_PROXY` | `false` | `true` makes driftsniff trust `X-Forwarded-For` and `X-Forwarded-Proto`. Only behind a proxy you control that overwrites both headers. |
| `DRIFTSNIFF_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` or `critical`. No level writes a password, token, key or secret value. |
| `DRIFTSNIFF_PORT` | `8080` | The port inside the container. `compose.yaml` fixes it. |
| `DRIFTSNIFF_DATA_DIR` | `/data` | The folder of the database, the backups and the CA bundles. `compose.yaml` fixes it. |
| `DRIFTSNIFF_KEY_FILE` | `/keys/master.key` | The master key file, created at the first start. `compose.yaml` fixes it. |
| `DRIFTSNIFF_OLD_KEY_FILE` | unset | The previous master key, only while you change keys. See [key-management.md](key-management.md). Not forwarded by the shipped `compose.yaml`; see below. |
| `DRIFTSNIFF_IMAGE` | `driftsniff:local` | Read by `compose.yaml` only: the image to run or the tag of the local build. |
| `SOURCE_SHA` | `local` | Read by `compose.yaml` only, as the build argument of a source build. The image stores it as `DRIFTSNIFF_COMMIT`, which `/healthz` reports as `commit` and Settings › About shows as the build. |

The shipped `compose.yaml` forwards only `DRIFTSNIFF_BASE_URL`, `DRIFTSNIFF_TRUSTED_PROXY` and
`DRIFTSNIFF_LOG_LEVEL` into the container, and reads `DRIFTSNIFF_IMAGE` and `SOURCE_SHA` itself.
Put them in the shell or in an `.env` file next to `compose.yaml`, then run `docker compose up -d`.

A source build reports the commit `local` unless you pass the commit you built:
`SOURCE_SHA=$(git rev-parse HEAD) docker compose up --build -d`. A published image reports the
commit it was built from.

`DRIFTSNIFF_OLD_KEY_FILE` is **not** forwarded by the shipped `compose.yaml`: a value in the shell
or in `.env` does not reach the container. The rekey in [key-management.md](key-management.md)
passes it to the one-off `rekey` command with `-e`, and adds it to the `environment` list of the
service only until the rekey has finished its clean collection cycle.

## Development-only settings

These settings exist so the maintainers can test the product in a real browser on their
Development site. Leave them unset on every other installation: with
`DRIFTSNIFF_DEV_HOST_SUFFIX` unset, the application never creates test accounts or synthetic data
at start.

| Variable | Default | Meaning |
|---|---|---|
| `DRIFTSNIFF_DEV_HOST_SUFFIX` | unset | The host name of the Development site, or a domain above it, without a scheme, port or path (for example `dev.example.com`). Only when the host of `DRIFTSNIFF_BASE_URL` is that name or ends in `.` and that name does a start create the test accounts below and one labelled push source with synthetic changes. Unset: never. |
| `DRIFTSNIFF_DEV_ADMIN_PASSWORD`, `DRIFTSNIFF_DEV_OPERATOR_PASSWORD`, `DRIFTSNIFF_DEV_VIEWER_PASSWORD` | unset | The passwords (at least 12 characters) of the test accounts `admin`, `operator` and `viewer`. The start creates them only when all three are set and the address passes the check above; an account that already exists is left alone. |
| `DRIFTSNIFF_DEV_SEED` | unset | Must be `development-only` for the manual command `python -m driftsniff seed-dev-accounts [--reset-passwords]`, which also accepts a `localhost` address. Nothing at start reads it. |

When the passwords are set but the address check refuses, the start creates nothing and logs one
warning that names no value. A failure of either step is logged and never stops the application from starting.

## Settings in the web interface

An admin changes these on the Settings page; they are stored in the database and take effect at
once. See the [admin guide](admin-guide.md).

| Setting | Range | Default |
|---|---|---|
| Retention window | 30 to 365 days | 365 days |
| Storage warning size | 1 to 1000 GB | 2 GB |
| Notification channel | one webhook or one SMTP mailbox, from a chosen severity | none |
| Check interval of a source | 1 to 60 minutes | 5 minutes |

## Certificate checks of a source

Each polled source has its own TLS mode, chosen in its form:

| Mode | When to use it |
|---|---|
| Verify with the system trust store | The default. The certificate chains to a public CA and names the host. |
| Verify with your own CA bundle | Your controller has a certificate from your own CA. Put the PEM file (at most 64 KB) in the `ca` folder of the data volume (`/data/ca`) and type its file name in the source form; there is no upload. |
| Pinned certificate | A self-signed certificate. Only the certificate with the SHA-256 you enter is accepted. |
| Insecure, certificate checks off | Never for a real network. Anyone on the path can read the credential. The form asks you to type `I understand the risk` to confirm, and saving writes an audit event. The source carries the Insecure TLS badge and the dashboard lists it under Needs attention. |

The details are in [tls.md](tls.md).
