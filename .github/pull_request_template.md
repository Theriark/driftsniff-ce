## Summary

What changes and why. Link the issue it closes, if there is one.

## Acceptance checks

One line per acceptance check (at most seven), each with the command run or an artifact link.

1. 

## Definition of done

A change is done only when every line is true and this description shows the evidence.

- [ ] 1. The acceptance checks above each have a command run or an artifact link.
- [ ] 2. Tests were written first for core, secrets, rules and sources, and all pull request
      checks are green: lint, types, tests with coverage gate, audit, secrets, licences, build,
      scan, smoke, migration, canary and browser jobs.
- [ ] 3. No secret, token, real address, real account or real certificate in code, tests,
      fixtures, docs, logs or this text. Canaries start with `CANARY-`.
- [ ] 4. Docs under `docs/` changed together with any behaviour a user sees or must configure.
- [ ] 5. New settings have a documented default and a test; new dependencies have an approved
      licence check entry.
- [ ] 6. The change was tested independently and reviewed; both results are recorded on this
      pull request.
- [ ] 7. UI changes carry screenshots at 1440, 768 and 390 pixels wide and a review against the
      UI standard (write n/a if there is no UI change).
- [ ] 8. Every commit has a `Signed-off-by:` line; the branch is `feat/<short-description>` (or
      `fix/<short-description>`) from `development`; a maintainer merges the pull request.
- [ ] 9. Rollback is stated for any deployed change: redeploy the previous approved digest.

## Rollback

Not deployed, or: redeploy the previous approved digest.
