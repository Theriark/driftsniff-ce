# Contributing to driftsniff-ce

Thank you for helping. Small, focused changes that are easy to review work best.

## Sign-off rule

Every commit must carry a `Signed-off-by:` line (the Developer Certificate of Origin, <https://developercertificate.org>).
Add it with `git commit -s`. By signing off you confirm that you wrote the change or have the right
to submit it under the MIT licence of this repository.

## Branch flow

1. Create a branch from `development`, named `feat/<short-description>` (or `fix/<short-description>`
   for a bug fix).
2. Keep one change per branch and one pull request per branch.
3. Open the pull request into `development`. Never push to `development`, `stage` or `main`; `main`
   only moves through a release action.
4. Pull request checks run when a maintainer adds the `ci-go` label. All checks must be green, and
   the change needs an independent test and a review before a maintainer merges it.

## Run the tests

You need Python 3.12. From the repository root:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-dev.txt
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
.venv/bin/python -m pytest -q --cov
.venv/bin/python scripts/check_lock_hashes.py
.venv/bin/python scripts/check_licenses.py
.venv/bin/python scripts/gen_notices.py
```

The last command writes `THIRD_PARTY_NOTICES` (generated, never committed). Tests use fakes on
localhost only and must never call a real service.

## Rules for every change

- Write the test first for the core, secrets, rules and sources packages.
- Never commit a secret, token, real address or real account, not even in tests or docs. Canary
  strings in tests start with `CANARY-`.
- Do not copy code from other projects, in particular from AGPL or GPL licensed ones.
- No telemetry and no outbound calls to AI services.
- A change that alters what a user sees or must configure also changes `docs/`.
- A new setting needs a documented default and a test. A new dependency needs an allowed licence
  (see `scripts/check_licenses.py`).

The pull request template lists the full definition of done.
