# driftsniff-ce

driftsniff Community Edition (CE) is a self-hosted tool that records changes to UniFi Network and
Xen Orchestra configuration, keeps the before and after values, and gives each change an
explainable risk label.

> **Pre-release.** driftsniff has no release yet. This repository is under construction:
> interfaces and the stored data format can change without notice, and it is not ready for
> production use.
>
> **No warranty.** The software is provided "as is" under the MIT licence, without warranty of any
> kind. See [LICENSE](LICENSE).

## What it is meant to do

This is the plan for the first release, not a description of what works today.

- Read the configuration of UniFi Network and Xen Orchestra with read-only access, on a schedule.
- Store only what changes, with the before and after values.
- Keep secret values out of storage: secrets are recorded as keyed fingerprints only.
- Label each change with a risk level, the rule that produced it and the reason.
- Never claim to know who made a change.

## Quick start

Coming in P11 (documentation and hardening phase). There is nothing to install yet.

## Develop

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch flow, the sign-off rule and how to run the
tests.

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Licence

MIT, Copyright (c) 2026 Theriark. The licences of the packages driftsniff uses are listed in
`THIRD_PARTY_NOTICES`, which `scripts/gen_notices.py` generates from the lock files.
