## Summary

What changes and why. Jira key: DRS-

## Acceptance checks

One line per acceptance check of the task (at most seven), each with the command run or an
artifact link.

1. 

## Definition of done

A task is done only when every line is true and this description shows the evidence.

- [ ] 1. The acceptance checks above each have a command run or an artifact link.
- [ ] 2. Tests were written first for core, secrets, rules and sources, and all pull request
      checks are green: lint, types, tests with coverage gate, audit, secrets, licences, build,
      scan, smoke, plus the migration and canary jobs once they exist.
- [ ] 3. No secret, token, real address, real account or real certificate in code, tests,
      fixtures, docs, logs or this text. Canaries start with `CANARY-`.
- [ ] 4. Docs under `docs/` changed together with any behaviour a user sees or must configure.
- [ ] 5. New settings have a documented default and a test; new dependencies have an approved
      licence check entry.
- [ ] 6. The Test Engineer verified independently and the Code Reviewer reviewed freshly; both
      results are recorded on this pull request.
- [ ] 7. UI changes carry screenshots at 1440, 768 and 390 pixels wide, the Frontend Developer
      critique and the reviewer verdict against the UI standard (write n/a if there is no UI change).
- [ ] 8. Every commit has a `Signed-off-by:` line; the title carries the Jira key; the branch is
      `feature/DRS-NN-short-slug` from `development`; the merge is a squash merge by pull request.
- [ ] 9. The Jira item holds a short result, this pull request link, the evidence and, for
      deployed work, commit SHA, digest, controller completion record, URL and time. It is moved
      to the board QA stage by the owner. Human QA stays pending until it is recorded by the
      human tester; nobody else records or imitates it.
- [ ] 10. Rollback is stated for any deployed change: redeploy the previous approved digest.

## Rollback

Not deployed, or: redeploy the previous approved digest.
