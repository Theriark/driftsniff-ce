# Browser e2e job (P10-T9 prerequisite, THE-1322)

Job `e2e` (`CI / Browser e2e`) in `ci.yml`. No new workflow file.

| Item | Rule |
|---|---|
| Runs when | The same as the other check jobs: after `gate` (the `ci-go` label, a push to `development`, a manual `mode=test` dispatch) |
| Setup | Checkout, virtual environment, `pip install --require-hashes --no-deps -r requirements-dev.txt`, `pip check`, then `python -m playwright install --with-deps chromium` (the browser build is the one the locked `playwright` version pins) |
| Command | `python -m pytest -q -o addopts="" -p no:cacheprovider tests/e2e` |
| Artifact | `e2e-screenshots`: everything the tests write to `E2E_ARTIFACT_DIR` (screenshots), kept 7 days, uploaded even when a test fails, never committed |
| Deployment | `deploy-development` lists `e2e` in `needs` |
| Unit test job | `CI / Tests` runs `pytest --ignore=tests/e2e`, so it never needs a browser |

Dependencies (development only, in `requirements-dev.in`, hashed in `requirements-dev.txt` by the lock mode): `playwright` (Apache-2.0) and `axe-playwright-python` (MIT). Both licences are on the allow list of `scripts/check_licenses.py`; that script reads the runtime lock only, so development packages are not checked by it. Neither package is in `requirements.in` or the image.

`tests/e2e/test_harness_smoke.py` is a labelled placeholder: it opens a static page at 1440, 768 and 390 pixels, runs axe and saves a screenshot. It needs no application and no network. The Test Engineer authors the real journeys in `tests/e2e` afterwards.

Limits: the browser download comes from the Playwright CDN on every run (no cache); `CI / Browser e2e` is not a required check until a repository admin adds it to the branch protection of `development`.
