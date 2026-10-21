# CI/CD baseline

Four workflows. GitHub Actions builds and deploys; no other controller deploys this repository.

| Workflow | Trigger | What it does |
|---|---|---|
| `CI` (`ci.yml`) | `ci-go` label on a pull request, push to `development`, manual dispatch | Tests and scans; builds one image; scans, smoke-tests and SBOMs that image; on push to `development` pushes that same image as `sha-<12>`, deploys its digest to Development and verifies runtime; `mode=lock` compiles hashed requirements |
| `Promote - Stage` (`promote-stage.yml`) | manual dispatch only | Verifies and consumes an existing reviewed release candidate (RC), then promotes the same image digest to Stage, no rebuild. Fails at its first job until `PROMOTE_STAGE_ENABLED=true` |
| `Finalize release` (`finalize-release.yml`) | manual dispatch only | After the separate release approval, publishes the stable GHCR version alias, the annotated stable tag and the GitHub release of the commit and image that Stage runs. No rebuild, no deployment, no `latest` alias, `main` is not moved |
| `Promote - Production` (`promote-production.yml`) | manual dispatch only | Promotes the image digest that Stage runs to Production, no rebuild. Fails at its first job until `PROMOTE_PRODUCTION_ENABLED=true` |

Rollback is not a workflow. `Promote - Stage` is run again with the inputs of an earlier approved release candidate; `Promote - Production` is run again with an earlier approved `source_sha` and its `digest`. Development rollback is described in `docs/deploy-development.md`.

## Publishing inputs (`Promote - Stage` and `Finalize release`)

Both workflows take the string inputs `request_id`, `version`, `source_commit`, `image`, `development_run_id`, `documentation_manifest_sha256` and `rc_tag`; `Finalize release` adds `stage_promotion_run_id`. The run name is `publishing:<request_id>`. Both run from `development`, or from `stage` when `stage` is at exactly `source_commit`. They are started by the private publisher after the separate native approval; a dispatch by hand has no extra authority.

| Input | How it is used |
|---|---|
| `request_id` | Run name and summary only; checked for plain characters |
| `version` | `27.<minor>.<patch>` or `v27.<minor>.<patch>`; `Promote - Stage` also accepts the RC version `v27.<minor>.<patch>-rc.<number>`. It must belong to `rc_tag`. `Finalize release` writes the version alias `<version>` and the tag `v<version>` |
| `source_commit` | Full SHA; must be in `development` history. Its published image is `sha-<12>`. `Promote - Stage` moves `stage` to it without force; `Finalize release` also requires it to have reached `stage` |
| `image` | `ghcr.io/theriark/driftsniff-ce@sha256:<digest>` or `sha256:<digest>`. The digest must equal the image published for `source_commit` and the digest recorded in the RC tag; that exact reference is deployed and aliased |
| `development_run_id` | A successful `Development` run of this repository on `source_commit`; must equal `developmentRunId` in the RC tag |
| `documentation_manifest_sha256` | Must equal `documentationManifestSha256` in the RC tag; carried into the release notes |
| `rc_tag` | Existing annotated `v27.<minor>.<patch>-rc.<number>` tag on `source_commit`. It is consumed, never created, moved or deleted. Its JSON message must hold `sourceCommit`, `imageDigest`, `developmentRunId` and `documentationManifestSha256` equal to the inputs, and `Promote - Stage` also requires a published (non-draft) GitHub prerelease for it |
| `stage_promotion_run_id` | `Finalize release` only: a successful `Promote - Stage` dispatch run of this repository; recorded as `stagePromotionRunId` in the stable tag |

`Promote - Stage` titles the Dokploy deployment `Stage <full source SHA>` with the description `driftsniff-ce GitHub Actions run <run id>`, sets the `stage` image tag and advances the `stage` branch without force. `Finalize release` re-checks that the `stage` image tag still has the promoted digest, then writes in this order the version alias, the annotated stable tag (the JSON keys of the RC plus `workflowRunId`, `stagePromotionRunId` and `rcTag`) and a non-draft, non-prerelease release. An existing alias, tag or release is reused only when it already matches; anything else fails the run.

## Switches and secrets

- `DEPLOY_DEVELOPMENT_ENABLED` (repository variable): the Development publish and deploy job runs only when it is `true`. While it is not, no image is pushed.
- `PROMOTE_STAGE_ENABLED` and `PROMOTE_PRODUCTION_ENABLED` (repository variables): unset until Stage or Production promotion is authorised. The first job of each promotion workflow runs `scripts/guard_enabled.py`, which exits with an error unless the variable is exactly `true`, so a disabled promotion is a failed run before any deploy step, not a skipped job. The guard script has a unit test. `Finalize release` has no such variable: it writes only the GHCR alias, the tag and the release, and is started only after the separate release approval.
- `DOKPLOY_PRODUCTION_APPLICATION_ID` and `PRODUCTION_HOST` (variables of the `production` environment): the Production target. `Promote - Production` fails when either is missing or equals the Stage target.
- Secrets (never printed): `DOKPLOY_URL`, `DOKPLOY_API_KEY`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`. They are passed only to the jobs and steps that call Dokploy; `Finalize release` uses none of them.
- Environments: `development`, `stage`, `production`. `Finalize release` uses none.

## Image

- Registry name `ghcr.io/theriark/driftsniff-ce`. Tag `sha-<first 12 characters of the commit>`; no `latest` and no mutable tag other than `stage` and `production` (set by the promotion workflows). The only other alias is the stable version `<version>`, written by `Finalize release` on the released digest. A re-run for the same commit never overwrites the tag.
- The image is built once by the `build` job. `scan`, `smoke` and `sbom` test that image and the Development job pushes exactly it. Deploy and promotion use the digest, not the tag.
- Artifacts: `driftsniff-sbom` (CycloneDX, every CI run) and `driftsniff-image-digest` (`image-digest.txt`, push to `development` only).
- Details and the required checks list: `docs/ci-baseline.md` sections 3 and 7.

## Concurrency

Pull request checks cancel superseded runs of the same branch. Deploy, both promotion workflows and `Finalize release` share the group `driftsniff-ce-pipeline` with `cancel-in-progress: false`, so a running deployment is never cancelled and two deployments never run together.

## Contract the application and Dockerfile must meet

- Listens on port 8080 and runs as a non-root user; works with a read-only root file system (writable only `/tmp`, `/data`, `/keys`).
- `GET /healthz` returns HTTP 200 with JSON `{"status": "ok", "commit": "<full source SHA>"}`. The commit comes from the `SOURCE_SHA` build argument. Deploy and promotion verify it. The container smoke test also requires a `version` field.
- Environment names are listed in `deploy/dokploy.json`; their Development values are in `docs/deploy-development.md`. The master key lives on the `/keys` volume and must never be regenerated or removed as routine cleanup; source credentials are entered in the web page and encrypted.
- Locked dependencies: `requirements.in` / `requirements-dev.in` compile to hashed `requirements.txt` / `requirements-dev.txt` through `CI` with `mode=lock`. `requirements-dev.in` must include pytest, pytest-cov, hypothesis, ruff, mypy and pip-audit. mypy and coverage targets are configured in `pyproject.toml`.
- `scripts/check_licenses.py` fails on a non-permissive dependency licence.
