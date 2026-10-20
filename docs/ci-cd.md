# CI/CD baseline

Three workflows only. GitHub Actions builds and deploys; no other controller deploys this repository.

| Workflow | Trigger | What it does |
|---|---|---|
| `CI` (`ci.yml`) | `ci-go` label on a pull request, push to `development`, manual dispatch | Tests and scans; builds one image; scans, smoke-tests and SBOMs that image; on push to `development` pushes that same image as `sha-<12>`, deploys its digest to Development and verifies runtime; `mode=lock` compiles hashed requirements |
| `Promote - Stage` (`promote-stage.yml`) | manual dispatch only | Promotes the same image digest to Stage, no rebuild. Fails at its first job until `PROMOTE_STAGE_ENABLED=true` |
| `Promote - Production` (`promote-production.yml`) | manual dispatch only | Promotes the image digest that Stage runs to Production, no rebuild. Fails at its first job until `PROMOTE_PRODUCTION_ENABLED=true` |

Rollback is not a workflow: it is `Promote - Stage` or `Promote - Production` run again with an earlier approved `source_sha` and its `digest`. Development rollback is described in `docs/deploy-development.md`.

## Switches and secrets

- `DEPLOY_DEVELOPMENT_ENABLED` (repository variable): the Development publish and deploy job runs only when it is `true`. While it is not, no image is pushed.
- `PROMOTE_STAGE_ENABLED` and `PROMOTE_PRODUCTION_ENABLED` (repository variables): unset until Stage or Production promotion is authorised. The first job of each promotion workflow runs `scripts/guard_enabled.py`, which exits with an error unless the variable is exactly `true`, so a disabled promotion is a failed run before any deploy step, not a skipped job. The guard script has a unit test.
- `DOKPLOY_PRODUCTION_APPLICATION_ID` and `PRODUCTION_HOST` (variables of the `production` environment): the Production target. `Promote - Production` fails when either is missing or equals the Stage target.
- Secrets (never printed): `DOKPLOY_URL`, `DOKPLOY_API_KEY`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`. They are passed only to the jobs and steps that call Dokploy.
- Environments: `development`, `stage`, `production`.

## Image

- Registry name `ghcr.io/theriark/driftsniff-ce`. Tag `sha-<first 12 characters of the commit>`; no `latest`, no mutable tag other than `stage` and `production`, which only the promotion workflows set. A re-run for the same commit never overwrites the tag.
- The image is built once by the `build` job. `scan`, `smoke` and `sbom` test that image and the Development job pushes exactly it. Deploy and promotion use the digest, not the tag.
- Artifacts: `driftsniff-sbom` (CycloneDX, every CI run) and `driftsniff-image-digest` (`image-digest.txt`, push to `development` only).
- Details and the required checks list: `docs/ci-baseline.md` sections 3 and 7.

## Concurrency

Pull request checks cancel superseded runs of the same branch. Deploy and both promotion workflows share the group `driftsniff-ce-pipeline` with `cancel-in-progress: false`, so a running deployment is never cancelled and two deployments never run together.

## Contract the application and Dockerfile must meet

- Listens on port 8080 and runs as a non-root user; works with a read-only root file system (writable only `/tmp`, `/data`, `/keys`).
- `GET /healthz` returns HTTP 200 with JSON `{"status": "ok", "commit": "<full source SHA>"}`. The commit comes from the `SOURCE_SHA` build argument. Deploy and promotion verify it. The container smoke test also requires a `version` field.
- Environment names are listed in `deploy/dokploy.json`; their Development values are in `docs/deploy-development.md`. The master key lives on the `/keys` volume and must never be regenerated or removed as routine cleanup; source credentials are entered in the web page and encrypted.
- Locked dependencies: `requirements.in` / `requirements-dev.in` compile to hashed `requirements.txt` / `requirements-dev.txt` through `CI` with `mode=lock`. `requirements-dev.in` must include pytest, pytest-cov, hypothesis, ruff, mypy and pip-audit. mypy and coverage targets are configured in `pyproject.toml`.
- `scripts/check_licenses.py` fails on a non-permissive dependency licence.
