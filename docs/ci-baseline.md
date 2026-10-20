# CI baseline audit (P1-T1)

Audited ref: `development` at `05d1e5cc1e5d0a9fe445e51f00a1302dedff39c9`. Audit date: 2026-10-20. Task THE-415 (Jira DRS-8 parent). Read-only audit: no workflow, script or application file is changed by this pull request.

The repository holds two workflow files, one helper script and no application code. There is no `AGENTS.md`, no Dockerfile, no `pyproject.toml`, no `LICENSE` and no Dependabot file. `main`, `stage` and `production` all exist and point at the README-only baseline commit `25bd02b0`.

## 1. Workflows

| Workflow (file) | Trigger | Jobs | Concurrency | What it checks or does |
|---|---|---|---|---|
| `CI` (`.github/workflows/ci.yml`) | `pull_request` type `labeled` (the job runs only for label `ci-go`); `push` to `development`; `workflow_dispatch` with input `mode` = `test` (default) or `lock` | `tests` ("Tests and scans"), `deploy-development` ("Build and deploy Development"), `lock-requirements` ("Lock hashed requirements") | Workflow level: group `ci-<event>-<ref>-<label or none>`, cancel-in-progress only for `pull_request`. `deploy-development` job level: group `driftsniff-ce-pipeline`, cancel-in-progress false | see the job rows below |
| `Promote - Stage` (`.github/workflows/promote-stage.yml`) | `workflow_dispatch` only, inputs `source_sha` (required) and `digest` (optional, rollback) | `promote` ("Promote image to Stage") | Workflow level: group `driftsniff-ce-pipeline`, cancel-in-progress false | Disabled: the job runs only when repository variable `PROMOTE_STAGE_ENABLED` is `true` |

Workflow `permissions` default: `ci.yml` is `contents: read`; `promote-stage.yml` is `contents: write` and `packages: write` for the whole workflow.

### 1.1 Jobs in detail

| Job | Runs when | Steps and checks |
|---|---|---|
| `tests` (30 min limit, `ubuntu-24.04`) | label `ci-go` on a pull request, any push to `development`, or dispatch with `mode=test` | 1. Parse every `.github/workflows/*.yml` with `yq`; validate `deploy/dokploy.json` with `jq`. 2. Secret scan: `git grep` for private-key headers, `AKIA`, `ghp_`, `github_pat_`, `xox*-` patterns (excludes `tests/` and `ci.yml`). 3. Detect `pyproject.toml` or `src/` (app) and `Dockerfile`. If there is no app, only steps 1 to 3 run and a notice is printed. 4. With an app: install hashed `requirements-dev.txt` into a venv, `pip check`, `ruff check`, `ruff format --check`, `mypy`, `pytest` (with `--cov` when `pyproject.toml` has `[tool.coverage`), `pip_audit` on `requirements.txt`, `scripts/check_licenses.py` (fails if missing). 5. With a Dockerfile: `docker build` (tag `driftsniff:ci`, build arg `SOURCE_SHA`), then an inline smoke test: image user is non-root, run with `--read-only`, tmpfs `/tmp`, `--cap-drop ALL`, `no-new-privileges`, 512 MB, two named volumes on `/data` and `/keys`, wait up to 60 s for `/healthz` HTTP 200. |
| `deploy-development` (60 min, environment `development`) | push to `development` and repository variable `DEPLOY_DEVELOPMENT_ENABLED` is `true`, after `tests` passes | Verify ref is `development`; checkout the tested SHA; skip everything if there is no Dockerfile; check the four deployment secrets are non-empty; log in to GHCR with `GITHUB_TOKEN`; `docker/build-push-action` pushes tags `development` and `sha-<full 40 char SHA>`; `.github/scripts/dokploy_release.py deploy` sets the Dokploy application image to the pushed digest, deploys, waits for two consecutive `/healthz` answers with status `ok` and the exact commit, then re-reads the application image and requires it to equal the digest; job summary records commit, tag and digest. Job permissions `contents: read`, `packages: write`. |
| `lock-requirements` (15 min) | dispatch with `mode=lock` | Refuses `main`, `development`, `stage`, `production`; runs `pip-compile --generate-hashes --allow-unsafe` for `requirements.in` and `requirements-dev.in`; commits the two `.txt` files to the dispatching branch with `GITHUB_TOKEN` (so no CI run starts). `pip-tools` is pinned to 7.4.1. Permission `contents: write`. |
| `promote` (30 min, environment `stage`) | dispatch and `PROMOTE_STAGE_ENABLED` is `true` | Validates a 40 char `source_sha` and optional `sha256:` digest; requires the run to be on `development`; requires the four secrets; for a normal promotion the SHA must equal current `development` and `development` must contain `main`; for a rollback the SHA must be in `development` history; resolves the digest published as `sha-<SHA>` (never rebuilds) and rejects a mismatching input digest; for a normal promotion asserts Development runs that digest and reports the commit; deploys the digest to the Stage application and verifies health and commit; tags the image `stage`; fast-forwards the `stage` branch to the SHA (no force) and checks it; job summary. |

Third-party actions are pinned to full commit SHAs with the version in a comment (`actions/checkout`, `docker/login-action`, `docker/setup-buildx-action`, `docker/build-push-action`). Dokploy application ids and host names are plain values in the workflow `env` blocks; secrets are only referenced as `secrets.NAME`.

### 1.2 Other tracked files that belong to the pipeline

| File | Content |
|---|---|
| `.github/scripts/dokploy_release.py` | Standard-library helper with subcommands `deploy`, `assert-image`, `health`. Accepts only `ghcr.io/theriark/driftsniff-ce@sha256:<64 hex>` images. `/healthz` must return JSON with `status` = `ok` and `commit` = the 40 char SHA. |
| `deploy/dokploy.json` | `database` null, volumes `/data` and `/keys`, six `DRIFTSNIFF_*` environment entries. Validated by `tests`. |
| `docs/ci-cd.md` | Short description of the two workflows, switches (`DEPLOY_DEVELOPMENT_ENABLED`, `PROMOTE_STAGE_ENABLED`) and the contract the application must meet. Consistent with the two workflows. |

## 2. Gaps against the dev work plan (rev 11, section 2 and P1-T2 to P1-T7)

Each gap is a proposal for the Delivery lead. Owner role in brackets. "Plan" means the dev work plan.

| Id | Gap or conflict | Evidence | Proposal |
|---|---|---|---|
| G1 | `/healthz` contract differs. The workflows and `dokploy_release.py` require JSON with `status` and the full 40 char `commit` (from build arg `SOURCE_SHA`). Plan section 2 and P1-T2 say exactly `status` and `version`, "no other keys". Deployment verification cannot pass with the plan's body. | `ci.yml` (`wait_health`), `docs/ci-cd.md`, Plan P1-T2 acceptance 3 | Delivery asks the R&D Lead to amend the plan: `/healthz` returns `status`, `version` and `commit`. Backend implements it in P1-T2; the Dockerfile (G9) carries `SOURCE_SHA` into the runtime. Until decided P1-T2 and P1-T4 cannot both be accepted. |
| G2 | Workflow file set conflicts. Plan P1-T5 asks for a separate pull request checks workflow and P1-T7 asks for `release.yml`. The company new-project rule allows exactly three workflow files: `ci.yml` (CI), `promote-stage.yml` (Promote - Stage) and `promote-production.yml` (Promote - Production); the approver refuses any other workflow file name. | Plan P1-T5, P1-T7; repository has only the first two | Keep PR checks inside `ci.yml` (extend `tests`, add jobs there). Replace plan's `release.yml` with `promote-production.yml` (skeleton, manual dispatch, guarded, environment `production`, promotes the Stage digest without rebuilding). Rollback is a re-run of the promote workflows with an earlier approved digest, not a workflow. [Platform, P1-T7] |
| G3 | Guard variables and guard script differ. Plan: `STAGE_PROMOTION_ENABLED` and `RELEASE_ENABLED` checked by `scripts/guard_enabled.py` with a unit test, workflow must fail before any deploy step. Actual: `PROMOTE_STAGE_ENABLED` checked in a job-level `if:`, so a disabled run shows as skipped, not failed. | `promote-stage.yml`, `docs/ci-cd.md` | Keep the existing variable name `PROMOTE_STAGE_ENABLED` and add `PROMOTE_PRODUCTION_ENABLED`; update the plan names. Decide whether a skipped job is acceptable (current, simple) or a failing guard step is wanted (plan). Recommendation: failing guard step, tested by a unit test, because a skipped promotion looks like success. [Platform, P1-T7] |
| G4 | Concurrency group name. Plan: `driftsniff-ce-deploy`. Actual: `driftsniff-ce-pipeline`, shared by `deploy-development` and `promote`. | both workflows | Keep `driftsniff-ce-pipeline` (already used consistently, documented); correct the plan. No code change. [Delivery note] |
| G5 | PR checks are one sequential job (`tests`), not separate jobs. Plan P1-T5 lists lint, types, test, audit, secrets, licences, build, scan, smoke as jobs. One job means one required check name (`Tests and scans`) and a failure hides later steps. | `ci.yml` | Acceptable for now. Decide with the Test Engineer whether to split when P2 to P10 add migration, canary, e2e and accessibility jobs; keep the required-check list in this file up to date. [Platform, P1-T5] |
| G6 | Missing checks from P1-T5: `actionlint` (only a YAML parse exists); `gitleaks` (a custom regex scan exists, it covers 5 token shapes and excludes `tests/`); Trivy image scan (none); notices artifact (P1-T3, none); Dockerfile `ARG`/`ENV` credential-name check (P1-T4, none); `scripts/check_licenses.py` is required but does not exist yet. | `ci.yml` steps | Add actionlint, gitleaks, Trivy (HIGH and CRITICAL with a fix) and the credential-name grep to `tests`, pinned by SHA. Keep the existing licence step. [Platform, P1-T5/T4; licence script by Backend, P1-T2/T3] |
| G7 | Smoke test is inline in `ci.yml`. Plan P1-T4 wants `scripts/container-smoke.sh`. The inline test lacks: uid 10001 check (it only checks non-root), write to `/etc` must fail, `/data` and `/keys` writable, `gcc` and `make` absent, image size under 250 MB, always-remove container (it has a trap). | `ci.yml` smoke step | Move the logic into `scripts/container-smoke.sh` with the missing assertions and call it from `ci.yml`. [Platform, P1-T4] |
| G8 | The image that CI tests is not the image that is pushed. `tests` builds `driftsniff:ci` and smoke-tests it; `deploy-development` rebuilds from the same SHA with `build-push-action` (layer cache from GitHub Actions cache). Plan section 2: build once. | `ci.yml` | Build once in one job (load, scan, smoke, then push the same image and digest), or accept a rebuild with a recorded reason. Recommendation: build once with `docker/build-push-action` using `load: true` for tests and push the tested image on `development`. [Platform, P1-T6] |
| G9 | Image tags and artifacts differ from the plan. Actual tags: `development` (mutable) and `sha-<full SHA>`. Plan: `sha-` plus 12 characters, no mutable tag. `promote-stage.yml` resolves `sha-<full SHA>`. No SBOM (Syft), no `image-digest.txt` artifact; the digest is only in the job summary. | `ci.yml`, `promote-stage.yml` | Keep full-SHA tags (promotion depends on them; update the plan). Add Syft SBOM and an `image-digest.txt` artifact. Decide whether the mutable `development` tag stays (useful for people, never used for deploys). [Platform, P1-T6] |
| G10 | Image publication is gated by `DEPLOY_DEVELOPMENT_ENABLED`. Plan P1-T6: a merge to `development` produces an image, digest and SBOM; the controller deploys. Actual: build, push and deploy are one job that is skipped unless the variable is `true`. | `ci.yml` job `if:` | Split build and publish from deploy so an image and SBOM exist for every `development` merge. [Platform, P1-T6] |
| G11 | Hand-off model differs. Plan P1-T6, P1-T8 and dependencies D1, D2 assume a delivery controller dispatch. The repository deploys directly from GitHub Actions to Dokploy with `dokploy_release.py` and verifies the runtime itself. | `ci.yml`, `docs/ci-cd.md` | Delivery decides: keep the direct model (matches the new-project rule: GitHub Actions deploys, no separate controller) and rewrite D1 and P1-T8 as variable and secret preparation. Note G13. [Delivery] |
| G12 | No `promote-production.yml` (see G2). `promote-stage.yml` is `contents: write` and `packages: write` for the whole workflow instead of at job level. | repository tree | Create the skeleton in P1-T7 with job-level permissions; narrow the Stage workflow permissions at the same time. [Platform, P1-T7] |
| G13 | Setup evidence not present. The setup status read for this repository reports no repository secrets and no GitHub environments present (`secretsPresent` and `environmentsPresent` are empty; the four secret names `DOKPLOY_URL`, `DOKPLOY_API_KEY`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET` are missing). `deploy-development` fails at its configuration check as soon as a Dockerfile exists and `DEPLOY_DEVELOPMENT_ENABLED` is `true`. The `production` environment is reported as not created. | `github_repo_status` read, 2026-10-20 | The Project Manager runs the setup broker action `github_repo_setup` (the crew never sees the values). Platform re-reads status before P1-T6. [Project Manager] |
| G14 | Not yet in the repository: Dockerfile and `compose.yaml` (P1-T4), `pyproject.toml` and package (P1-T2), `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, templates, `.gitignore`, `.dockerignore` (P1-T3), Dependabot file for `github-actions` (plan section 2), `AGENTS.md`, `CODEOWNERS` (optional). | repository tree | Already tasks P1-T2 to P1-T4. Platform adds the Dependabot file with P1-T5; `AGENTS.md` is a Delivery decision. |
| G15 | `lock-requirements` installs `pip-tools==7.4.1` without hashes and uses `--allow-unsafe`. Low risk (build tool, short lived, no secrets besides `GITHUB_TOKEN` with `contents: write`). | `ci.yml` | Note only; consider pinning with hashes later. |

Checks that already match the plan: actions pinned by SHA with version comment; pull request runs only on the `ci-go` label; superseded PR runs are cancelled while deployments are never cancelled; deploys use an immutable digest and verify both the Dokploy image and the reported commit; promotion never rebuilds and supports rollback to an earlier approved digest; hashed lock files are produced by CI, not by hand; secrets are referenced only through `secrets.NAME`.

## 3. Required checks list

One pull request check exists today: `CI / Tests and scans` (job `tests`). Later phases add the migration job (P2), canary job (P3) and e2e and accessibility jobs (P10). This file lists them as they appear.

## 4. Settings the crew cannot read or change (for the Delivery lead)

The crew's GitHub tools can read files and refs; they cannot read or write repository settings, so none of the following was verified.

| Setting | Why it matters | Who can act |
|---|---|---|
| Branch protection or rulesets on `development`, `main`, `stage`, `production` (required check `Tests and scans`, pull request required, force-push and deletion blocked) | Plan says never push to these branches; nothing enforces it if no rule exists | Repository admin (founders) |
| Default branch (plan says `main`; the plan's setup record says `main`) | Not read here | Repository admin |
| Environment protection (required reviewers, wait timer) for `development`, `stage`, `production`; `production` environment does not exist yet (G13) | Stage and production promotions should need an approver | Repository admin / setup broker |
| Repository variables `DEPLOY_DEVELOPMENT_ENABLED`, `PROMOTE_STAGE_ENABLED` (current values unknown) | They switch deployments on | Delivery through the controller action; crew cannot read values |
| Repository and environment secrets (names only readable through the setup status; see G13) | Required by deploy and promote | Project Manager (setup broker) |
| Workflow token default permissions and whether Actions may create pull requests | `lock-requirements` pushes with `GITHUB_TOKEN`; workflows declare their own permissions | Repository admin |
| Organisation setting that lets workflows create packages and package visibility (D3 below) | Needed for the first image push and for Dokploy to pull | Organisation admin |
| Private vulnerability reporting (needed by `SECURITY.md`, P1-T3) | `SECURITY.md` will point to it | Repository admin |
| Dependabot alerts and secret scanning push protection | Not required by the plan; useful for a public repository | Repository admin |

## 5. D3 evidence: can the workflow token create the GHCR package?

Status: **unverified, no blocker found yet**. Report only; no credential was created or changed.

1. `deploy-development` already declares `packages: write` and logs in to `ghcr.io` with the workflow `GITHUB_TOKEN` (no personal token). That is the supported way to publish a repository's first package from Actions; the package is created on the first push if the organisation allows it.
2. Nothing has been pushed yet (no Dockerfile exists), so no package `driftsniff-ce` exists to inspect. The crew's tools cannot list organisation packages or read the organisation's package settings.
3. The first real proof is the first successful push after P1-T4 and P1-T6. A `403` or `denied: permission_denied` at that step means an organisation admin must allow package creation by workflows or link the package to the repository; the crew must not create credentials to work around it.
4. The Dockerfile must set the label `org.opencontainers.image.source` to the repository URL so the package links to the repository (plan P1-T4 already lists this label).
5. Dokploy pull: the repository is public. If the package becomes private (organisation default), Dokploy would need registry credentials, which is a credential decision for the Delivery lead and the founders. The rollout of D2 should confirm the package is public or that Dokploy can pull it.

## 6. Reference repositories

The workflow directory of `nowlert-ce` was listed read-only (names only: `ci.yml`, `finalize-release.yml`, `promote-stage.yml`) to confirm the same three-part shape (CI, Stage promotion, release or production promotion). Nothing was copied: no ids, endpoints or credentials. The Theriark Website repository was not needed for this audit.
