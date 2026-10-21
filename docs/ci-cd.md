# CI/CD baseline

Four workflows. GitHub Actions builds and deploys; no other controller deploys this repository.

| Workflow | Trigger | What it does |
|---|---|---|
| `CI` (`ci.yml`) | `ci-go` label on a pull request, push to `development`, manual dispatch | Tests and scans; builds one image; scans, smoke-tests and SBOMs that image; on push to `development` pushes that same image as `sha-<12>`, deploys its digest to Development and verifies runtime; `mode=lock` compiles hashed requirements |
| `Promote - Stage` (`promote-stage.yml`) | manual dispatch only | Verifies and consumes an existing reviewed release candidate, then promotes the same image digest to Stage, no rebuild. Fails at its first job until `PROMOTE_STAGE_ENABLED=true` |
| `Finalize Release` (`finalize-release.yml`) | manual dispatch only | After a separately approved release decision, publishes the stable GHCR aliases, the annotated stable tag and the GitHub release of the commit and image that Stage runs, no rebuild and no deployment. Fails at its first job until `FINALIZE_RELEASE_ENABLED=true` |
| `Promote - Production` (`promote-production.yml`) | manual dispatch only | Promotes the image digest that Stage runs to Production, no rebuild. Fails at its first job until `PROMOTE_PRODUCTION_ENABLED=true` |

Rollback is not a workflow. `Promote - Stage` is run again with the inputs of an earlier approved release candidate; `Promote - Production` is run again with an earlier approved `source_sha` and its `digest`. Development rollback is described in `docs/deploy-development.md`.

## Publishing inputs (`Promote - Stage` and `Finalize Release`)

Both workflows take string inputs `request_id`, `version`, `source_commit`, `image`, `development_run_id`, `documentation_manifest_sha256` and `rc_tag`; `Finalize Release` adds `stage_promotion_run_id`. The run name is `publishing:<request_id>`. Both run from `development` or `stage`.

| Input | How it is used |
|---|---|
| `request_id` | Run name and summary only; checked for plain characters |
| `version` | `v27.<minor>.<patch>` (`Promote - Stage` also accepts the RC version); `Finalize Release` creates exactly this tag |
| `source_commit` | Must be in `development` history; its image is `sha-<12>`; `Promote - Stage` advances `stage` to it without force, `Finalize Release` requires it to be the current `stage` |
| `image` | `ghcr.io/theriark/driftsniff-ce@sha256:<digest>`; must equal the digest published for `source_commit` and the digest sealed in the RC tag; this exact reference is deployed and aliased |
| `development_run_id` | Must be a successful `CI` push run on `development` for `source_commit`; must equal `developmentRunId` in the RC tag |
| `documentation_manifest_sha256` | Must equal `documentationManifestSha256` in the RC tag; carried into the stable tag and release notes |
| `rc_tag` | Existing annotated `v27.<minor>.<patch>-rc.<number>` tag on `source_commit` with a non-draft prerelease; it is consumed, never created, moved or deleted. Its JSON message must carry `sourceCommit`, `imageDigest`, `developmentRunId`, `workflowRunId`, `documentationManifestSha256` and `gateCycle`; `workflowRunId` must be a successful run on `development` |
| `stage_promotion_run_id` | `Finalize Release` only: must be a successful `Promote - Stage` run; recorded as `stagePromotionRunId` in the stable tag |

The Dokploy deployment is titled `Stage <full source SHA>` with the description `driftsniff-ce GitHub Actions run <run id>`. `Finalize Release` also re-checks that Stage still runs the exact image and reports the commit on `/healthz`. The stable tag is annotated with the same JSON keys as the RC plus `stagePromotionRunId` and `rcTag`; an existing tag, release or version alias is reconciled and never overwritten.

## Switches and secrets

- `DEPLOY_DEVELOPMENT_ENABLED` (repository variable): the Development publish and deploy job runs only when it is `true`. While it is not, no image is pushed.
- `PROMOTE_STAGE_ENABLED`, `FINALIZE_RELEASE_ENABLED` and `PROMOTE_PRODUCTION_ENABLED` (repository variables): unset until Stage promotion, release publication or Production promotion is authorised. The first job of each of these workflows runs `scripts/guard_enabled.py`, which exits with an error unless the variable is exactly `true`, so a disabled workflow is a failed run before any write, not a skipped job. The guard script has a unit test.
- `DOKPLOY_PRODUCTION_APPLICATION_ID` and `PRODUCTION_HOST` (variables of the `production` environment): the Production target. `Promote - Production` fails when either is missing or equals the Stage target.
- Secrets (never printed): `DOKPLOY_URL`, `DOKPLOY_API_KEY`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`. They are passed only to the jobs and steps that call Dokploy.
- Environments: `development`, `stage`, `production`.

## Image

- Registry name `ghcr.io/theriark/driftsniff-ce`. Tag `sha-<first 12 characters of the commit>`; no `latest` and no mutable tag other than `stage` and `production` (set by the promotion workflows) before a release. Only `Finalize Release` sets the stable alias `<version without v>` and `latest`, both on the released digest. A re-run for the same commit never overwrites the tag.
- The image is built once by the `build` job. `scan`, `smoke` and `sbom` test that image and the Development job pushes exactly it. Deploy and promotion use the digest, not the tag.
- Artifacts: `driftsniff-sbom` (CycloneDX, every CI run) and `driftsniff-image-digest` (`image-digest.txt`, push to `development` only).
- Details and the required checks list: `docs/ci-baseline.md` sections 3 and 7.

## Concurrency

Pull request checks cancel superseded runs of the same branch. Deploy, both promotion workflows and the release workflow share the group `driftsniff-ce-pipeline` with `cancel-in-progress: false`, so a running deployment is never cancelled and two deployments never run together.

## Contract the application and Dockerfile must meet

- Listens on port 8080 and runs as a non-root user; works with a read-only root file system (writable only `/tmp`, `/data`, `/keys`).
- `GET /healthz` returns HTTP 200 with JSON `{"status": "ok", "commit": "<full source SHA>"}`. The commit comes from the `SOURCE_SHA` build argument. Deploy and promotion verify it. The container smoke test also requires a `version` field.
- Environment names are listed in `deploy/dokploy.json`; their Development values are in `docs/deploy-development.md`. The master key lives on the `/keys` volume and must never be regenerated or removed as routine cleanup; source credentials are entered in the web page and encrypted.
- Locked dependencies: `requirements.in` / `requirements-dev.in` compile to hashed `requirements.txt` / `requirements-dev.txt` through `CI` with `mode=lock`. `requirements-dev.in` must include pytest, pytest-cov, hypothesis, ruff, mypy and pip-audit. mypy and coverage targets are configured in `pyproject.toml`.
- `scripts/check_licenses.py` fails on a non-permissive dependency licence.
