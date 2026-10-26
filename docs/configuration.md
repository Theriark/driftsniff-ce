# Configuration

For release candidate v27.0.0-rc.1. driftsniff reads its settings from `DRIFTSNIFF_` environment
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
| `DRIFTSNIFF_OLD_KEY_FILE` | unset | The previous master key, only while you change keys. See [key-management.md](key-management.md). |
| `DRIFTSNIFF_ENVIRONMENT_LABEL` | unset | A badge in the header, 1 to 24 ASCII letters, digits, spaces or hyphens, for example `Development`. Unset shows no badge. |
| `DRIFTSNIFF_IMAGE` | `driftsniff:local` | Read by `compose.yaml` only: the image to run or the tag of the local build. |

Put the variables in the shell or in an `.env` file next to `compose.yaml`, then run
`docker compose up -d`.

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
| Verify with your own CA bundle | Your controller has a certificate from your own CA. Put the PEM file (at most 64 KB) in the `ca` folder of the data volume. |
| Pinned certificate | A self-signed certificate. Only the certificate with the SHA-256 you enter is accepted. |
| Insecure, certificate checks off | Never for a real network. Anyone on the path can read the credential. The source carries the Insecure TLS badge and the dashboard lists it under Needs attention. |

The details are in [tls.md](tls.md).
