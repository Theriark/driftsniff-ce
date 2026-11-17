# CI/CD baseline

Four workflows. GitHub Actions builds and deploys; no other controller deploys this repository.

| Workflow | Trigger | What it does |
|---|---|---|
| `CI` (`ci.yml`) | `ci-go` label on a pull request, push to `development`, manual dispatch | Tests and scans; builds one image; scans, smoke-tests and SBOMs that image; on push to `development` pushes that same image as `sha-<12>`, deploys its digest to Development and verifies runtime; `mode=lock` compiles hashed requirements |
| `Promote - Stage` (`promote-stage.yml`) | one button from `development` (Gate 2), optional `dry_run` | Takes the commit Development runs and its image, requires its successful `CI` push run, runs the test suite at that commit, tags the next release candidate, deploys the same digest to Stage, verifies `/healthz` and tags the image `stage`. No rebuild, no branch move. Fails at its first job until `PROMOTE_STAGE_ENABLED=true` |
| `Release` (`release.yml`) | one button from `development` (Gate 3), optional `dry_run` | Releases what Stage runs: the registry tag `<version>` on the same digest, the annotated tag `v<version>` and a GitHub Release with the pull requests since the last release. No rebuild, no deployment, no branch move |
| `Promote - Production` (`promote-production.yml`) | manual dispatch only | Not part of the release path: Driftsniff-CE has no Production deployment. Fails at its first job until `PROMOTE_PRODUCTION_ENABLED=true` |

`prepare-rc.yml` and `finalize-release.yml` are retired: `Promote - Stage` computes the candidate itself and `Release` replaces `Finalize release`.

## Branches: the gate script moves them

The workflows deploy, tag and publish only. They never push, update, merge or force-move `stage` or `main`: GitHub's Actions token may not move a branch to a commit that changes workflow files, so such a move would fail (the Revrook-CE `Promote - Stage` dry run refused for that reason). The gate script moves both with the operator token:

- `stage`: after a successful `Promote - Stage` run, the gate script fast-forwards `stage` to the new candidate tag. Where `stage` is before the run (behind, ahead or diverged) never stops a promotion; the summary only reports it.
- `main`: right before it dispatches `Release`, the gate script merges `stage` into `main` (a merge commit with Stage's files). `Release` does not read or check `main`.
- `tests/unit/test_publishing_workflows.py` fails CI if either workflow, or a script it calls, could write a branch: every `git push` must push a `refs/tags/` ref, and git ref, commit, merge and branch API calls, `git merge`, `git update-ref` and `gh pr merge` are refused.

## Versions

`scripts/release_version.py` reads the tags; nothing is typed in.

- One line: the first release is `27.0.0`, its candidates `v27.0.0-rc.1`, `v27.0.0-rc.2`, ... Only tags `v27.<minor>.<patch>` and `v27.<minor>.<patch>-rc.<n>` count.
- Until a stable `v27.0.0` exists the line is `27.0.0` and candidates of any other version are ignored. The tag `v27.1.0-rc.1` was created by mistake and is kept; it does not move the line, so the next candidate is `v27.0.0-rc.6`.
- After a release the line is the lowest version above the newest stable tag that already has candidates, else the next feature version `27.<minor + 1>.0` (after `v27.0.0`, the existing `v27.1.0-rc.1` makes the next candidate `v27.1.0-rc.2`).
- A commit that already carries a candidate of the line keeps it, so a re-run never tags a commit twice.
- `Release` takes the version of the line from the candidate at the `stage` head. While the line is unreleased a candidate numbered above it is accepted with a warning (today Stage runs `0c49ea97`, tagged `v27.1.0-rc.1`, and releases as `v27.0.0`). A commit that already has its stable tag keeps that version.
- `tests/unit/test_release_version.py` covers these cases.

## One button: `dry_run` and re-runs

- Rollback: the summary of `Promote - Stage` records the image Stage ran before.
- `dry_run=true` runs every check and writes nothing: no tag, image tag, deployment or release. The job summary lists each check, the computed candidate (`Promote - Stage`) or the stable version (`Release`), and what a real run would create.
- `Release` checks each result first and reuses it when it already matches, so a re-run after a complete release changes nothing. A tag, image tag or release that exists but differs fails the run.
- `Release` never merges `main` into `development`.
- GitHub dispatches only workflows that `main` knows. The pre-flight route `workflow_register` copies reviewed workflow files from `development` to `main`; it must include `release.yml` (see the pull request that introduced this file).

## Switches and secrets

- `DEPLOY_DEVELOPMENT_ENABLED` (repository variable): the Development publish and deploy job runs only when it is `true`. While it is not, no image is pushed.
- `PROMOTE_STAGE_ENABLED` and `PROMOTE_PRODUCTION_ENABLED` (repository variables): unset until Stage or Production promotion is authorised. The first job of each promotion workflow runs `scripts/guard_enabled.py`, which exits with an error unless the variable is exactly `true`, so a disabled promotion is a failed run before any deploy step, not a skipped job. The guard script has a unit test. In a `dry_run` the guard only reports the switch. `Release` has no such variable; it is started by the Gate 3 approval.
- `DOKPLOY_PRODUCTION_APPLICATION_ID` and `PRODUCTION_HOST` (variables of the `production` environment): the Production target. `Promote - Production` fails when either is missing or equals the Stage target.
- Secrets (never printed): `DOKPLOY_URL`, `DOKPLOY_API_KEY`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`. They are passed only to the jobs and steps that call Dokploy; `Release` uses them only to read the Stage application.
- Environments: `development`, `stage`, `production`. `Release` uses `stage` to read the Stage application and deploys nothing.

## Image

- Registry name `ghcr.io/theriark/driftsniff-ce`. Tag `sha-<first 12 characters of the commit>`; no `latest` and no mutable tag other than `stage` and `production` (set by the promotion workflows). The only other alias is the stable version `<version>`, written by `Release` on the released digest. A re-run for the same commit never overwrites the tag.
- The image is built once by the `build` job. `scan`, `smoke` and `sbom` test that image and the Development job pushes exactly it. Deploy and promotion use the digest, not the tag.
- Artifacts: `driftsniff-sbom` (CycloneDX, every CI run) and `driftsniff-image-digest` (`image-digest.txt`, push to `development` only).
- Details and the required checks list: `docs/ci-baseline.md` sections 3 and 7.

## Concurrency

Pull request checks cancel superseded runs of the same branch. Deploy, both promotion workflows and `Release` share the group `driftsniff-ce-pipeline` with `cancel-in-progress: false`, so a running deployment is never cancelled and two deployments never run together.

## Contract the application and Dockerfile must meet

- Listens on port 8080 and runs as a non-root user; works with a read-only root file system (writable only `/tmp`, `/data`, `/keys`).
- `GET /healthz` returns HTTP 200 with JSON `{"status": "ok", "commit": "<full source SHA>"}`. The commit comes from the `SOURCE_SHA` build argument. Deploy and promotion verify it. The container smoke test also requires a `version` field.
- Environment names are listed in `deploy/dokploy.json`; their Development values are in `docs/deploy-development.md`. The master key lives on the `/keys` volume and must never be regenerated or removed as routine cleanup; source credentials are entered in the web page and encrypted.
- Locked dependencies: `requirements.in` / `requirements-dev.in` compile to hashed `requirements.txt` / `requirements-dev.txt` through `CI` with `mode=lock`. `requirements-dev.in` must include pytest, pytest-cov, hypothesis, ruff, mypy and pip-audit. mypy and coverage targets are configured in `pyproject.toml`.
- `scripts/check_licenses.py` fails on a non-permissive dependency licence.
