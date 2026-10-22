# UniFi vendor notes (P7-T1)

These are driftsniff's own notes on the UniFi Network application interface that the UniFi
collector will read (P7). They are written for the people who build and review the collector and
the type table `src/driftsniff/rules/types/unifi.yaml`. Nothing here is copied or vendored from the
vendor; every statement is in our own words, with its source and the date it was read.

## Status in one paragraph

Dependency D5 (the vendor API reference) is still open and no lab controller has been used, so
**nothing in this file is lab-verified**. The founder waived Gate A for development work (THE-359,
comment e8aa0805), which allows the type table to be written now, with every UniFi fact labelled
below. The vendor's own reference was not read for this task; the facts come from the third party
descriptions listed under Sources. Where this file says *unverified*, the name or behaviour must be
checked against the vendor reference (D5) or a lab result before it is relied on. No lab result is
claimed anywhere in this repository.

## Sources

All sources were read on **2026-10-21**. They are secondary: a client library description and two
tool descriptions written by third parties. None is the vendor's own reference.

| Id | Source | What it was used for |
|---|---|---|
| S1 | Art-of-WiFi, "unifi network application api client", https://github.com/Art-of-WiFi/unifi-network-application-api-client | Version range, endpoint groups, some field names |
| S2 | "unifi get firewall policy ordering", https://glama.ai/mcp/servers/owine/unifi-network-mcp/tools/unifi_get_firewall_policy_ordering | Shape of the policy ordering answer |
| S3 | Search result summaries (the pages themselves were not opened) for https://glama.ai/mcp/servers/owine/unifi-network-mcp/tools/unifi_list_firewall_policies and https://docs.rs/crate/unifly/0.9.0 | Field list of a firewall policy, endpoint paths |
| S4 | driftsniff dev work plan part B, section 12 (task THE-411, document analysis-1, revision 11) | The list of resources and the fields to keep, the collection modes, the version floor |

## Statements

Status values: **plan** (decided by our own plan, not a vendor fact), **unverified** (reported by a
secondary source, not checked against the vendor reference or a lab), **unknown** (no source at all;
the table makes a placeholder choice).

| # | Statement | Source | Date read | Status |
|---|---|---|---|---|
| 1 | The interface is the integration API of the UniFi Network application, with paths below a `/v1/` prefix. | S1, S3 | 2026-10-21 | unverified |
| 2 | The client library states it covers application version 10.1.84 and later and was tested against newer versions. Our supported floor is 10.1.84. | S1; S4 for the floor | 2026-10-21 | floor: plan; library claim: unverified |
| 3 | Access uses an API key created in the application (settings, integrations), not a user name and password. | S1 | 2026-10-21 | unverified |
| 4 | The key travels in a request header named in the plan as X-API-KEY. | S4 (the plan says "confirmed from D5") | 2026-10-21 | unverified: S1 names no header |
| 5 | Resources exist for sites, networks, WiFi broadcasts, firewall zones, firewall policies, ACL rules and devices; DNS policies, traffic matching lists, WANs, VPN tunnels and servers, RADIUS profiles and device tags are named by the plan. | S1 (sites, networks, WiFi broadcasts, firewall zones and policies, ACL rules, devices), S4 (all) | 2026-10-21 | unverified |
| 6 | Networks have, at least, `management`, `name`, `enabled` and `vlanId`. | S1 | 2026-10-21 | unverified |
| 7 | WiFi broadcasts have, at least, `type`, `name`, `securityConfiguration` (with a security mode such as a WPA2/WPA3 personal mode) and `broadcastingFrequenciesGHz`. | S1 | 2026-10-21 | unverified |
| 8 | A firewall policy has `id`, `name`, `enabled`, an `action` object with a `type`, `source` and `destination` objects holding a zone id and a traffic filter, `ipProtocolScope`, `connectionStateFilter`, `ipsecFilter`, a schedule, `loggingEnabled`, `index`, `description` and metadata with an origin. | S3 | 2026-10-21 | unverified (search summary only) |
| 9 | Firewall policy order is given per pair of (source zone, destination zone). The answer holds two lists of policy ids: those evaluated before the system defined rules and those after them. | S2 | 2026-10-21 | unverified |
| 10 | ACL rules come in an address based kind and a MAC based kind and have `type`, `name`, `action`, `sourceFilter`, `destinationFilter` and `protocolFilter`, and an ordering list. | S1 | 2026-10-21 | unverified |
| 11 | Devices can be listed, with filterable `name`, `model`, `state` and `features`; separate calls return statistics. | S1 | 2026-10-21 | unverified |
| 12 | Firewall policies and ACL rules are first match lists, so their order is part of the configuration. | S4 (design decision) | 2026-10-21 | plan |
| 13 | DNS server lists are ordered. | S4 (design decision) | 2026-10-21 | plan |
| 14 | Secret fields: the WiFi passphrase and the RADIUS shared secret. Whether VPN keys are returned in clear is not known. | S4 for the first two; none for VPN | 2026-10-21 | WiFi and RADIUS: plan; VPN: unknown |
| 15 | A key inherits the role of its creator, and a view only role is enough to read every resource above. | S4 (setup guide, tests U2 and U3) | 2026-10-21 | unverified, not tested |
| 16 | The ordering of firewall policies is asked per pair of zones with the query names `sourceFirewallZoneId` and `destinationFirewallZoneId` at `<site>/firewall/policies/ordering`, and answers with an object `orderedFirewallPolicyIds` that holds the lists `beforeSystemDefined` and `afterSystemDefined`. | S2 for the shape (two lists per pair); the query and field names: no source was read for them | 2026-10-22 | unverified |
| 17 | The ordering of ACL rules is one list per site at `<site>/acl-rules/ordering`, in an object `orderedAclRuleIds`. | S1 (an ordering list exists), names: no source | 2026-10-22 | unverified |
| 18 | A radio channel of a device moves by itself under automatic channel selection, so it is volatile. The field is assumed to sit in a list `interfaces.radios` with the member field `channel`. | S4 (golden row 5 says radio channel, ignore class); the path: no source | 2026-10-22 | plan for volatility; path unverified |

## The type table

The table `rules/types/unifi.yaml` holds fifteen resources, all with the prefix `unifi-` (a resource
may be defined once across all files and the Xen Orchestra tables already use `networks` and
`users`). Names that appear in a statement above carry that statement's number. A name with no
number is a placeholder chosen from the plan's field list and has **no source**.

| Resource | Collection | Kept fields (class config unless noted) | Name status |
|---|---|---|---|
| `unifi-sites` | set | `id`, `name`, `internalReference` | `id`, `name`: unverified (5); `internalReference`: no source |
| `unifi-site-settings` | set | `id` only | The plan says "where the API offers them"; no endpoint is confirmed, see below |
| `unifi-networks` | set | `name`, `enabled`, `management`, `vlanId` (6); `internetAccessEnabled`, `dhcpGuarding.trustedDhcpServerIpAddresses` (set), `dhcpConfig.dnsServers` (ordered scalar) | the three last names: no source |
| `unifi-wifi-broadcasts` (floor high) | set | `name`, `enabled`, `type`, `securityConfiguration.type`, `broadcastingFrequenciesGHz` (set), `network.networkId`, `hideName`, `clientIsolationEnabled`; `securityConfiguration.passphrase` is **secret** | first four unverified (7); `enabled`, `network.networkId`, `hideName`, `clientIsolationEnabled`, `securityConfiguration.passphrase`: no source |
| `unifi-firewall-zones` (floors) | set | `name`, `networkIds` (set) | no source |
| `unifi-firewall-policies` (floors) | **ordered-keyed, first match** | `name`, `description`, `enabled`, `action.allowReturnTraffic`, `source.zoneId`, `destination.zoneId`, `ipProtocolScope`, `connectionStateFilter` (set), `ipsecFilter`, `loggingEnabled`, and the derived `actionType`; `action.type` and `index` are ignore | unverified (8); `action.allowReturnTraffic`: no source |
| `unifi-acl-rules` (floors) | **ordered-keyed, first match** | `name`, `description`, `type`, `enabled`, `action`; `index` is ignore | `name`, `type`, `action` unverified (10); others no source |
| `unifi-dns-policies` | set | `type`, `enabled`, `domain` | no source |
| `unifi-traffic-matching-lists` | set | `name`, `type`, `items` (set) | no source |
| `unifi-wans` | set | `name`, `dnsServers` (ordered scalar) | no source |
| `unifi-vpn-site-to-site-tunnels` (floor high) | set | `name`, `type`, `enabled`; `preSharedKey` is **secret** | no source |
| `unifi-vpn-servers` (floor high) | set | `name`, `type`, `enabled`; `preSharedKey` is **secret** | no source |
| `unifi-radius-profiles` (floor high) | set | `name`; `sharedSecret` is **secret** | no source |
| `unifi-device-tags` | set | `name`, `deviceIds` (set) | no source |
| `unifi-devices` | set | `name`, `model`, `firmwareVersion`, `state` (adoption state); `uptimeSec`, `lastHeartbeatAt`, `statistics` are ignore | `name`, `model`, `state` unverified (11); the rest: no source |

"Floors" means the security floors of the plan (P5-T2): `added`, `modified` and `moved` are high
and `removed` is critical. A resource marked "(floor high)" has high for all four kinds. A field
that is not in the table is **unclassified** (a change shows as a fingerprint only) until the
Backend Developer classifies it and the Code Reviewer agrees.

### Decisions the table makes, for the collector task (P7-T4)

1. **Action of a firewall policy.** The vendor object nests the action (`action.type`, statement 8)
   but the order check of the engine reads a flat top level field. The table therefore names a
   derived field `actionType` as the action field and marks `action.type` ignore. The collector
   must copy `action.type` to `actionType` on the raw object before it hands it to the normaliser;
   without that copy a move over a block rule is only HIGH, not CRITICAL. The blocking values are
   written `block` and `reject`; the real names of the values are unverified.
2. **One position list per resource.** The vendor orders firewall policies per pair of zones
   (statement 9), while the engine stores one position list for the resource. How the per pair
   lists become one list was left to P7-T4; see "Decisions of P7-T4" below. A policy that moves from one
   zone pair to another changes `source.zoneId` or `destination.zoneId`, which the table tracks.
3. **Nested filter objects.** The traffic filters of a policy, the source, destination and protocol
   filters of an ACL rule and the other nested objects are **not classified** because their field
   names are not known. Their changes show as a fingerprint only. This is the largest gap of the
   table and the first thing to fix once D5 exists.
4. **Golden table names.** The test only tables under `tests/golden/types` use names such as
   `unifi-wlans` and `guest_portal.title` that are not the names here. P7-T4 must map the golden
   rows 3, 5, 7, 9, 16, 17, 21 and 22 to the shipped resources (for example
   `unifi-wifi-broadcasts` for the WiFi rows).

## Decisions of P7-T4 (collection, ordering, rules)

1. **Position list.** The engine stores one position list for a resource. For firewall policies it
   is the lists of all zone pairs, pairs sorted, each pair "before the system defined policies"
   then "after". Sorting keeps the list stable between runs. ACL rules: the one list per site.
   Sites one after the other.
2. **Mismatch.** An object that no ordering names is appended and an id without an object is
   dropped; the run is partial with the class `ordering_mismatch`. An ordering that cannot be read
   fails the resource and keeps the previous state.
3. **Action field.** The collector copies `action.type` to `actionType` (decision 1 above).
4. **Golden rows.** Row 3 maps to `unifi-networks` `name`, row 5 to `unifi-devices`
   `interfaces.radios.channel` (statement 18, unverified), rows 16 and 17 to
   `unifi-wifi-broadcasts` `securityConfiguration.type` and `securityConfiguration.passphrase`,
   rows 21 and 22 to `unifi-firewall-policies`. Rows 7 and 9 name site settings fields; the table
   has none, so they are not run.
5. **Values.** The values of the security type (`OPEN`, `WPA2_PERSONAL` and so on) and of the
   action (`ALLOW`, `BLOCK`, `REJECT`) are unverified. The rules list upper and lower case spellings.

## Site settings

The plan asks for site level settings "where the API offers them". None of the sources names a site
settings endpoint, so there is nothing to classify. The table holds only the key so that golden row
7 can later be pointed at it. Status: unknown. If D5 shows no such endpoint, delete the resource in
the same change that maps row 7.

## What is needed from the Research Analyst (D5)

The plan assigns the vendor reference (D5) to the Research Analyst. Needed, in this order:

1. The vendor reference page or file for each of the fifteen resources, with its date, so that
   every name marked *no source* or *unverified* above can be checked. The most important are the
   nested traffic filter objects of firewall policies and ACL rules.
2. Which header carries the key (statement 4) and which base path answers the information call.
3. Whether the credential fields of WiFi broadcasts, RADIUS profiles and VPN tunnels and servers
   are returned in clear, and under which field names (statement 14).
4. The lab tests U2 and U3 of the plan (statement 15), recorded in `docs/lab-evidence.md` when that
   file exists.

Until then the independent work in P7 uses synthetic fixtures with the `CANARY-` prefix.

## Carried over, not settled here

- `ALLOWED_OPTIONS` of the source options grows when the collector needs a new option; P7-T1 adds
  none.
- `serve` has no scheduler until the collector factory exists. P7-T1 builds neither; whoever
  builds the factory in P7 or P8 must say so.
- The scheduler test gap of THE-628 (a timer firing while a run now run is in progress) is
  untouched.
- The decision about the derived resource `backup-job-settings` is needed before P8-T2 and is not
  settled here.
