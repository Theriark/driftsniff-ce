# Development fixture: labelled synthetic changes

Why: the Development site (`https://ce-dev-driftsniff.theriark.dev`) had one push source and no change, so the change list, the dashboard and the history could not be judged with data. The fixture fills them with synthetic changes across several resource types and all four severities. Development only: nothing here runs on Stage or Production. Code: `driftsniff/devfixture.py`, the start-up call in `driftsniff/cli.py`; tests: `tests/unit/test_devfixture.py`. Task: THE-1130 (gap G8 of the UI revision plan).

## What it makes

One push source named `DEV-FIXTURE synthetic (removable)` and four pushed documents, run through the real run pipeline with the shipped rules, dated 6 h, 4 h, 2 h and 30 min before the start:

| Step | Result | What changes (all synthetic) |
|---|---|---|
| 1 baseline | the first snapshot, no event | 3 networks, 2 WiFi broadcasts, 2 firewall zones, 2 DNS policies, 1 VPN server, 1 RADIUS profile, 2 devices |
| 2 secrets and exposure | event, highest severity `critical` | a WiFi passphrase and a VPN key replaced (fingerprints only), client isolation off, a zone gains a network |
| 3 routine changes | event, highest severity `medium` | a VLAN, a firmware version, a DNS policy switched off, two names |
| 4 objects added and removed | event with additions and removals | a network added, a DNS policy and the RADIUS profile removed, a device offline, a network management mode |

Resource types: `unifi-networks`, `unifi-wifi-broadcasts`, `unifi-firewall-zones`, `unifi-dns-policies`, `unifi-vpn-servers`, `unifi-radius-profiles`, `unifi-devices`.

## Why it is safe

- **Synthetic values only.** Ids start with `fx-`, names with `FIXTURE`, domains end in `.fixture.example`, there is no IP address, and every secret is a `CANARY-` value that the pipeline stores as a fingerprint (the tests check that no `CANARY` text is stored or logged).
- **No credential.** The source has no sender key (`push_token_hash` stays empty), so nothing can push to it from outside. The existing push source of the site and its key are not touched.
- **No notification.** The fixture runs through its own pipeline that has no notifier, so no channel is told about its events.
- **Development only.** It runs at start-up only for a `ce-dev-<name>.theriark.dev` address with no other environment badge (the same guard as the test accounts, `docs/dev-test-accounts.md`). Stage, Production and localhost do nothing and log nothing.
- **Never blocks start-up.** A failure is logged (`development fixture not seeded: ...`, no value) and the application starts.

## Running it again

A second start changes nothing. The steps that ended `ok` are counted from the run records and are not run again; a step that failed is tried again at the next start.

## Removing it

Delete the source `DEV-FIXTURE synthetic (removable)` on the Sources page (an admin). That removes the source, its runs, snapshots, objects, events and items (`SourceService.delete`). A later start sees the `source.delete` audit event that names the fixture and does not make it again. To bring it back, restore the Development data volume from a backup that still has it or remove the audit event by hand.

## Rollback

Remove the call `seed_fixture_at_startup` from `_serve` in `cli.py` (and the module); nothing else depends on it and no migration is involved.

## Not covered

- It adds no ordered resources (firewall policies, ACL rules) and no Xen Orchestra resources.
- The dates are fixed offsets from the first start, so after some days the changes look older; delete the source and restore it only if fresh timestamps are needed.
