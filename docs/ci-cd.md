# CI/CD baseline

Two workflows only. GitHub Actions builds and deploys; no other controller deploys this repository.

| Workflow | Trigger | What it does |
|---|---|---|
| `CI` (`ci.yml`) | `ci-go` label on a pull request, push to `development`, manual dispatch | Tests and scans; on push to `development` builds one image, deploys its digest to Development and verifies runtime; `mode=lock` compiles hashed requirements |
| `Promote - Stage` (`promote-stage.yml`) | manual dispatch | Promotes the same image digest to Stage, no rebuild. Disabled until `PROMOTE_STAGE_ENABLED=true` |

There is no production workflow yet. Rollback is `Promote - Stage` run again with an earlier approved `source_sha` and its `digest`.

## Switches and secrets

- `DEPLOY_DEVELOPMENT_ENABLED` (repository variable): the Development deploy job runs only when it is `true`.
- `PROMOTE_STAGE_ENABLED` (repository variable): unset until Stage is authorised.
- Secrets (never printed): `DOKPLOY_URL`, `DOKPLOY_API_KEY`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`.
- Environments: `development`, `stage`.

## Concurrency

Pull request checks cancel superseded runs of the same branch. Deploy and promotion jobs share the group `driftsniff-ce-pipeline` with `cancel-in-progress: false`, so a running deployment is never cancelled.

## Contract the application and Dockerfile must meet

- Listens on port 8080 and runs as a non-root user; works with a read-only root file system (writable only `/tmp`, `/data`, `/keys`).
- `GET /healthz` returns HTTP 200 with JSON `{"status": "ok", "commit": "<full source SHA>"}`. The commit comes from the `SOURCE_SHA` build argument. Deploy and promotion verify it.
- Environment names are listed in `deploy/dokploy.json`. The master key lives on the `/keys` volume and must never be regenerated or removed as routine cleanup; source credentials are entered in the web page and encrypted.
- Locked dependencies: `requirements.in` / `requirements-dev.in` compile to hashed `requirements.txt` / `requirements-dev.txt` through `CI` with `mode=lock`. `requirements-dev.in` must include pytest, pytest-cov, hypothesis, ruff, mypy and pip-audit. mypy and coverage targets are configured in `pyproject.toml`.
- `scripts/check_licenses.py` fails on a non-permissive dependency licence.
