# Security policy

## Supported versions

driftsniff has no release yet. Once it has releases, only the latest release receives security
fixes. Until the first release, only the `development` branch is maintained.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub
private vulnerability reporting:

1. Open the **Security** tab of this repository.
2. Choose **Report a vulnerability** (direct link:
   <https://github.com/Theriark/driftsniff-ce/security/advisories/new>).
3. Describe the problem: affected version or commit, steps to reproduce, and the impact you expect.

Use synthetic data only. Never send real credentials, API keys, tokens, controller addresses or
exports of real configuration.

## What to expect

- We aim to acknowledge your report within 5 working days.
- We will tell you whether we can reproduce it and keep you informed until a fix is released.
- With your agreement we credit you in the release notes. There is no bug bounty.

## Scope

In scope: the code in this repository and the container image built from it.

Out of scope: vulnerabilities in UniFi Network or Xen Orchestra themselves (report those to their
vendors), and problems that come only from how a deployment is exposed. driftsniff stores
configuration history, which is sensitive even when secret values are redacted: keep the data and
key volumes private and back them up separately.
