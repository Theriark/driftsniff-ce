# UniFi Drive vendor notes (wave 2)

driftsniff's own notes on UniFi Drive, the storage application of the UniFi NAS (UNAS) consoles.
They explain why the source type `unifi_drive` has **no collector yet**. Nothing here is copied from
the vendor; every statement is in our own words, with its source and the date it was read.

## Status in one paragraph

Ubiquiti publishes **no documented API for UniFi Drive**. The vendor's developer site lists six
APIs (Network, Protect, Mobility, InnerSpace, Site Manager, Carrier Fabric); Drive is not one of
them, and no Drive endpoint, OpenAPI file or API key scope is described anywhere in it. The only
programmatic Drive access seen is community software that calls undocumented local UniFi OS
endpoints. driftsniff does not build collectors on guessed private endpoints, so no collector, type
table or rule pack was written. Receiving Drive *notifications* (email or webhook, as Nowlert does)
is an event feed, not a configuration API, and does not change this.

## Sources

All sources were read on **2026-11-12**.

| Id | Source | What it showed |
|---|---|---|
| V1 | Ubiquiti developer site index, https://developer.ui.com/llms.txt | The complete list of documented APIs: Network v11.0.97, Protect v7.4.99, Mobility v1.0.0, InnerSpace v1.3.23, Site Manager v1.0.0, Carrier Fabric v1.0.0. "Drive" and "UNAS" appear nowhere (case-insensitive search of the whole file). |
| V2 | Ubiquiti developer site map, https://developer.ui.com/sitemap.xml | Path prefixes are only `/network`, `/protect`, `/mobility`, `/innerspace`, `/site-manager`, `/carrier-fabric`. No URL contains "drive" or "unas". |
| V3 | Site Manager OpenAPI, https://developer.ui.com/site-manager/v1.0.0/openapi.json | Paths: hosts, sites, devices, ISP metrics, SD-WAN configs and the console connector `/v1/connector/consoles/{id}/*path`. The connector forwards to `http://127.0.0.1/proxy/[path]` on the console and names Network, Protect and InnerSpace as the applications documented behind it. Drive is not named, and no other path covers storage. |
| V4 | Home Assistant community post "UniFi Drive/UNAS for Home Assistant", https://community.home-assistant.io/t/custom-integration-unifi-drive-unas-for-home-assistant-local-api-monitoring-and-controls/1010371 (posted 2026-05-14) | A third-party integration labelled "(Unofficial)" that uses "local UniFi OS / UniFi Drive endpoints"; the post lists no paths and says behaviour varies by firmware and model. Evidence that only undocumented endpoints are in use. |
| V5 | Ubiquiti help centre, Drive section, https://help.ui.com/hc/en-us/sections/28300885539479-Drive | Could not be read (HTTP 403 to an automated reader). Not relied on either way. |
| C1 | driftsniff `src/driftsniff/collectors/unifi/resources.py` | The existing UniFi collector reaches the documented Network integration API at `/integration` or `/proxy/network/integration` with an `X-API-KEY` header. That works because Network is a documented API (V1); the same pattern has no documented Drive counterpart to point at. |

## What was not done, and why

- No collector, factory branch, `resources_of` branch, resource labels, type table or rule pack.
  The resources the task asked for (storage pools and volumes, shared drives and member
  permissions, users with access, backup and sync tasks, SMB/NFS service settings) have no
  documented endpoint, field name, answer shape or auth scope to verify against.
- No fake API. A fake would have to invent the vendor's paths and shapes, and it is meant to become
  the Mock Platform simulation, so an invented surface would spread.
- The placeholder `src/driftsniff/rules/packs/unifi_drive/.gitkeep` and the shared lists that name
  `unifi_drive` (base commit) were left untouched; removing the type from them is the integrator's
  decision.

## What would unblock a collector

Any one of these, checked again at the time:

1. Ubiquiti adds a Drive API to developer.ui.com (an entry in V1, ideally with an OpenAPI file),
   or the Site Manager connector (V3) names Drive as a documented application.
2. Ubiquiti documents a Drive integration API elsewhere (for example in the console's Integrations
   page or a release note) with paths, answer shapes and a read-only API key scope.
3. The founder explicitly accepts a collector on undocumented local endpoints, with a lab UNAS to
   verify every path and field, every statement marked UNVERIFIED, and a firmware version floor.
   Without that decision this note's default holds.

Re-check V1 and V2 first; they are the vendor's own complete index.
