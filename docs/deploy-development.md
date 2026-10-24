# Development deployment notes

How the Development application of driftsniff CE is configured, how to roll it back and how to check it without changing anything. Development only: Stage and Production use `Promote - Stage` and `Promote - Production` (see `docs/ci-cd.md`), which stay switched off until separately authorised.

Every value below is an example or a public name. No real credential belongs in this file; the four deployment secrets (`DOKPLOY_URL`, `DOKPLOY_API_KEY`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`) live only in GitHub and are never written here.

## Settings of the Development application (D2)

| Setting | Value | Notes |
|---|---|---|
| Image | `ghcr.io/theriark/driftsniff-ce@sha256:<64 hex characters>` | Set by the `deploy-development` job to the digest it pushed. Never a tag. |
| Data volume | mounted at `/data` | Database and stored changes. Separate from the key volume. |
| Key volume | mounted at `/keys` | Holds the master key. Separate from the data volume (see the rule below). |
| `DRIFTSNIFF_BASE_URL` | `https://ce-dev-driftsniff.theriark.dev` | Address users open; used for links. |
| `DRIFTSNIFF_TRUSTED_PROXY` | `true` | Correct only because the application sits behind the Cloudflare and Dokploy reverse proxy. |
| `DRIFTSNIFF_LOG_LEVEL` | `info` | One of debug, info, warning, error, critical. |
| `DRIFTSNIFF_PORT` | `8080` | Fixed by the image. |
| `DRIFTSNIFF_DATA_DIR` | `/data` | Fixed by the image. |
| `DRIFTSNIFF_KEY_FILE` | `/keys/master.key` | Created on the key volume at first start. |
| `DRIFTSNIFF_ENVIRONMENT_LABEL` | `Development` | Text of the environment badge in the page header, so a Development page is never mistaken for another installation. 1 to 24 ASCII letters, digits, spaces or hyphens; the application refuses to start on any other value. Unset shows no badge. Set only on Development. |
| Memory limit | 512 MB | Matches `mem_limit: 512m` in `compose.yaml` and the container smoke test. |

The seven `DRIFTSNIFF_` names above are exactly the first seven in `deploy/dokploy.json`; that file is the source and this table must follow it. None of these is a secret: the master key is generated on the key volume and source credentials are entered in the web page. The manifest adds three generated test-account passwords (`DRIFTSNIFF_DEV_ADMIN_PASSWORD`, `DRIFTSNIFF_DEV_OPERATOR_PASSWORD`, `DRIFTSNIFF_DEV_VIEWER_PASSWORD`, kind `token24`, no value in the repository) and the `browserAccounts` list that names the three accounts; see [dev-test-accounts.md](dev-test-accounts.md). They are used only when the base URL is a `ce-dev-` address.

The container runs as a non-root user with a read-only root file system; only `/tmp` (memory), `/data` and `/keys` are writable.

### Master key rule

The file on the key volume is the data encryption key for stored credentials. Do not delete, regenerate or replace it as cleanup, and do not rebuild the key volume. Losing it makes stored credentials and secret fingerprints unrecoverable. Back it up separately from the data volume.

## Runtime preparation state

The Development runtime was prepared once with the repository's existing `dokploy_prepare` step, which reads `deploy/dokploy.json` and only adds what is missing; it never replaces an existing value. Names only are listed here; no value is recorded in this file.

| Item | State |
|---|---|
| Prepared settings | `DRIFTSNIFF_BASE_URL`, `DRIFTSNIFF_DATA_DIR`, `DRIFTSNIFF_KEY_FILE`, `DRIFTSNIFF_LOG_LEVEL`, `DRIFTSNIFF_PORT`, `DRIFTSNIFF_TRUSTED_PROXY` |
| Not yet applied | `DRIFTSNIFF_ENVIRONMENT_LABEL`. It was added to the manifest afterwards, so the existing Development application does not have it until `dokploy_prepare` runs again (it only adds the missing name) and the application is redeployed. Until then the header shows no badge. |
| Database resource | None. The product declares no database; state lives on the data volume. |
| Switch | The repository variable `DEPLOY_DEVELOPMENT_ENABLED` is set to `true`. While it is unset or not `true`, the `deploy-development` job is skipped. |
| First image | None is published yet. A push to `development` made while the switch was unset skipped the job, so the first image and the first deployment happen on the next merge into `development`. |

One deployment at a time. Workflows of this repository share one concurrency group and a running deployment is never cancelled. Before merging, check that no `CI` run of the repository is queued or running; do not dispatch a workflow by hand, and do not retry a deployment while another is active. After a merge, wait for the `deploy-development` job to finish and confirm the result with the passive smoke check below before the next merge.

## Rollback rule

Redeploy the previous approved digest. Nothing is rebuilt.

1. Find the previous approved digest: the artifact `driftsniff-image-digest` (`image-digest.txt`) and the job summary of the earlier `CI` push run for that commit record `ghcr.io/theriark/driftsniff-ce@sha256:...` and the commit.
2. Set the Development application image to that exact `image@digest` and deploy it, or re-run the earlier successful `CI` push run of that commit (it reuses the image already published for the commit and never overwrites its tag).
3. Check the result with the smoke check below: `commit` must equal the commit of the digest you chose.
4. Stage is rolled back by running `Promote - Stage` again with the inputs of an earlier approved release candidate (its `source_commit`, `image`, `development_run_id`, `documentation_manifest_sha256` and `rc_tag`); the run fails unless that image is the one published for that commit and recorded in the RC tag, and the `stage` branch is then not moved. Production is rolled back by running `Promote - Production` again with an earlier approved `source_sha` and its `digest`; that run fails unless the digest is the image published for that commit.

Data is not rolled back. The `/data` volume keeps whatever the newer image wrote. Before redeploying an older image after a release that changed the stored data format or ran a database migration, confirm that the older image can read the migrated data; if it cannot, the rollback needs a data restore from backup, which is a separate decision. The key volume is never part of a rollback.

## Passive smoke check

`GET /healthz` on the Development host. It reads only, changes no state and needs no login or Cloudflare Access header:

```
curl --fail --silent --show-error https://ce-dev-driftsniff.theriark.dev/healthz
```

Expected: HTTP 200 and a JSON body with `status` equal to `ok`, a non-empty `version` and `commit` equal to the full source commit that was deployed. Anything else is a failed check. The `deploy-development` job runs the same check itself and fails the deployment when it does not pass.
