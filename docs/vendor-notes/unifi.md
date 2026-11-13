# UniFi vendor notes (P7-T1)

These are driftsniff's own notes on the UniFi Network application interface that the UniFi
collector will read (P7). They are written for the people who build and review the collector and
the type table `src/driftsniff/rules/types/unifi.yaml`. Nothing here is copied or vendored from the
vendor; every statement is in our own words, with its source and the date it was read.

## Status in one paragraph

On **2026-11-13** driftsniff read a real controller for the first time: a UDM Pro Max running UniFi
Network **10.6.109**, through the integration API with an API key (source S5). Every statement
marked **verified 10.6.109** below was checked against what that controller returned. The field
paths of the type table now come from that reading. What it could not settle stays labelled:
resources the controller had no objects of (ACL rules, device tags), versions other than 10.6.109,
and the rights of a View Only key (the key used was made by an owner account). Dependency D5 (the
vendor's own reference) is still open; this is one controller, not the reference.

## Sources

All sources were read on **2026-10-21**. They are secondary: a client library description and two
tool descriptions written by third parties. None is the vendor's own reference.

| Id | Source | What it was used for |
|---|---|---|
| S1 | Art-of-WiFi, "unifi network application api client", https://github.com/Art-of-WiFi/unifi-network-application-api-client | Version range, endpoint groups, some field names |
| S2 | "unifi get firewall policy ordering", https://glama.ai/mcp/servers/owine/unifi-network-mcp/tools/unifi_get_firewall_policy_ordering | Shape of the policy ordering answer |
| S3 | Search result summaries (the pages themselves were not opened) for https://glama.ai/mcp/servers/owine/unifi-network-mcp/tools/unifi_list_firewall_policies and https://docs.rs/crate/unifly/0.9.0 | Field list of a firewall policy, endpoint paths |
| S4 | driftsniff dev work plan part B, section 12 (task THE-411, document analysis-1, revision 11) | The list of resources and the fields to keep, the collection modes, the version floor |
| S5 | First real reading, 2026-11-13: a UDM Pro Max running UniFi Network 10.6.109, read by a local driftsniff stack through the integration API with an API key made by an owner account. A field path list with value types, enum values and counts was written from it; no values of free text fields were recorded | Header, paths, shapes, ordering behaviour, which secrets are returned |

## Statements

Status values: **verified 10.6.109** (checked against the real controller of S5 on 2026-11-13),
**plan** (decided by our own plan, not a vendor fact), **unverified** (reported by a secondary
source, not checked), **unknown** (no source at all; the table makes a placeholder choice).

| # | Statement | Source | Date read | Status |
|---|---|---|---|---|
| 1 | The interface is the integration API of the UniFi Network application, with paths below a `/v1/` prefix. | S1, S3, S5 | 2026-11-13 | verified 10.6.109 |
| 2 | The client library states it covers application version 10.1.84 and later and was tested against newer versions. Our supported floor is 10.1.84. | S1; S4 for the floor | 2026-10-21 | floor: plan; library claim: unverified |
| 3 | Access uses an API key created in the application (settings, integrations), not a user name and password. | S1, S5 | 2026-11-13 | verified 10.6.109 |
| 4 | The key travels in a request header named `X-API-KEY`. | S4, S5 | 2026-11-13 | verified 10.6.109 |
| 5 | Resources exist for sites, networks, WiFi broadcasts, firewall zones, firewall policies, ACL rules, DNS policies, traffic matching lists, WANs, site-to-site VPN tunnels, VPN servers, RADIUS profiles, device tags and devices. | S1, S4, S5 | 2026-11-13 | verified 10.6.109: all fourteen paths answered 200 |
| 6 | Networks have `name`, `enabled`, `default`, `management` (seen: `GATEWAY`, a text, not a flag), `vlanId`, `zoneId` and `metadata.origin` / `metadata.configurable`. The list answer has no DHCP or DNS server fields. | S1, S5 | 2026-11-13 | verified 10.6.109 |
| 7 | WiFi broadcasts have `type` (seen: `STANDARD`, `IOT_OPTIMIZED`), `name`, `enabled`, `network.type` and `network.networkId`, `securityConfiguration.type` (seen: `WPA2_PERSONAL`, `WPA2_WPA3_PERSONAL`), `broadcastingFrequenciesGHz` and `metadata.origin`. | S1, S5 | 2026-11-13 | verified 10.6.109; other security type names unverified |
| 8 | A firewall policy has `id`, `name`, `description`, `enabled`, an `action` object with `type` (seen: `ALLOW`, `BLOCK`) and `allowReturnTraffic`, `source` and `destination` objects holding a `zoneId` and a `trafficFilter` (kinds seen: IP address, network, port, site-to-site tunnel; on the source also MAC address and VPN server), `ipProtocolScope`, `connectionStateFilter`, `ipsecFilter`, `loggingEnabled` and `metadata.origin` (seen: `USER_DEFINED`, `SYSTEM_DEFINED`, `DERIVED`). No `index` and no schedule were returned. | S3, S5 | 2026-11-13 | verified 10.6.109 |
| 9 | Firewall policy order is given per pair of (source zone, destination zone). The answer holds two lists of policy ids: those evaluated before the system defined rules and those after them. **The lists name only the policies whose origin is `USER_DEFINED`** (72 of 265 on the S5 controller); `SYSTEM_DEFINED` and `DERIVED` policies are never listed. | S2, S5 | 2026-11-13 | verified 10.6.109 |
| 10 | ACL rules come in an address based kind and a MAC based kind and have `type`, `name`, `action`, `sourceFilter`, `destinationFilter` and `protocolFilter`, and an ordering list. | S1 | 2026-10-21 | unverified |
| 11 | The device list has `name`, `model`, `macAddress`, `ipAddress`, `firmwareVersion`, `firmwareUpdatable`, `state` (seen: `ONLINE`), `supported`, and `features` and `interfaces` as lists of words. It has no statistics, uptime or radio channel. | S1, S5 | 2026-11-13 | verified 10.6.109 |
| 12 | Firewall policies and ACL rules are first match lists, so their order is part of the configuration. | S4 (design decision) | 2026-10-21 | plan |
| 13 | DNS server lists are ordered. | S4 (design decision) | 2026-10-21 | plan |
| 14 | No credential is returned in clear: WiFi broadcasts carry only the security type and no passphrase; RADIUS profiles carry no shared secret; VPN servers and tunnels carry no key. The table keeps secret entries for those three kinds anyway, in case another version returns them. | S5 | 2026-11-13 | verified 10.6.109 for an owner made key |
| 15 | A key inherits the role of its creator, and a view only role is enough to read every resource above. | S4 (setup guide, tests U2 and U3) | 2026-11-13 | unverified: the S5 key was made by an owner account, so View Only was not tried |
| 16 | The ordering of firewall policies is asked per pair of zones with the query names `sourceFirewallZoneId` and `destinationFirewallZoneId` at `<site>/firewall/policies/ordering`, and answers with an object `orderedFirewallPolicyIds` that holds the lists `beforeSystemDefined` and `afterSystemDefined`. | S2, S5 | 2026-11-13 | verified 10.6.109 |
| 17 | The ordering of ACL rules is one list per site at `<site>/acl-rules/ordering`, in an object `orderedAclRuleIds`. | S1 (an ordering list exists), names: no source | 2026-10-22 | unverified: the S5 controller had no ACL rules |
| 18 | Device fields that change by themselves: `state` and `firmwareUpdatable` (ignore class). The radio channel of golden row 5 is not in the device list. | S4, S5 | 2026-11-13 | verified 10.6.109 for the fields; volatility: plan |

## The type table

The table `rules/types/unifi.yaml` holds fifteen resources, all with the prefix `unifi-` (a resource
may be defined once across all files and the Xen Orchestra tables already use `networks` and
`users`). Since 2026-11-13 every path the S5 controller returned is classified, and
`tests/contract/test_unifi_real_shapes.py` walks real-shaped objects through the table and fails on
any unclassified path. Paths the old table had but the real API does not return were removed
(network DHCP and DNS fields, WAN DNS servers, WiFi `hideName` and `clientIsolationEnabled`, tunnel
`enabled`, the device statistics, uptime and radio channel, the policy `index`).

| Resource | Collection | What the table keeps | Status |
|---|---|---|---|
| `unifi-sites` | set | `id`, `name`, `internalReference` | verified 10.6.109 |
| `unifi-site-settings` | set | `id` only | placeholder, see below |
| `unifi-networks` | set | statement 6 | verified 10.6.109 |
| `unifi-wifi-broadcasts` (added and removed high) | set | statement 7; the frequency list is a set; a passphrase field would be **secret** | verified 10.6.109 |
| `unifi-firewall-zones` (floors) | set | `name`, `networkIds` (set), `metadata.origin`, `metadata.configurable` | verified 10.6.109 |
| `unifi-firewall-policies` (added, removed, moved) | **ordered-keyed, first match** | statement 8, every nested filter field of both sides; the lists of filter members, network ids, MAC addresses, VPN server ids and connection states are sets; the derived `actionType` is the action field and `action.type` is ignore | verified 10.6.109 |
| `unifi-acl-rules` (floors) | **ordered-keyed, first match** | `name`, `description`, `type`, `enabled`, `action`; `index` is ignore | unverified (no objects on S5) |
| `unifi-dns-policies` | set | `type` (seen `A_RECORD`), `enabled`, `domain`, `ipv4Address`, `ttlSeconds`, `metadata.origin` | verified 10.6.109 |
| `unifi-traffic-matching-lists` | set | `name`, `type` (seen `IPV4_ADDRESSES`, `PORTS`), `items` (a set of objects with `type` and `value`) | verified 10.6.109 |
| `unifi-wans` | set | `name` (the list answer has nothing else) | verified 10.6.109 |
| `unifi-vpn-site-to-site-tunnels` (floor high) | set | `name`, `type` (seen `WIREGUARD`), `metadata.origin`, `metadata.source`; a key field would be **secret** | verified 10.6.109 |
| `unifi-vpn-servers` (floor high) | set | `name`, `type`, `enabled`, `metadata.origin`; a key field would be **secret** | verified 10.6.109 |
| `unifi-radius-profiles` (floor high) | set | `name`, `metadata.origin`, `metadata.configurable`; a shared secret field would be **secret** | verified 10.6.109 |
| `unifi-device-tags` | set | `name`, `deviceIds` (set) | unverified (no objects on S5) |
| `unifi-devices` | set | statement 11; `state` and `firmwareUpdatable` are ignore; `features` and `interfaces` are sets | verified 10.6.109 |

"Floors" means the security floors of the plan (P5-T2): `added`, `modified` and `moved` are high
and `removed` is critical. Firewall policies and WiFi broadcasts have no floor for a modified object
(since 2026-11-13), so that their packs can rate a rename low or medium; every field that changes
what traffic or which clients are allowed has its own high rule. A floor applies to the kind of the
item, so a member removed from a list inside a policy (a port, an address) is critical by the
removed floor. A field that is not in the table is **unclassified** (a change shows as a
fingerprint only).

### Decisions the table makes, for the collector task (P7-T4)

1. **Action of a firewall policy.** The vendor object nests the action (`action.type`, statement 8)
   but the order check of the engine reads a flat top level field. The table therefore names a
   derived field `actionType` as the action field and marks `action.type` ignore. The collector
   copies `action.type` to `actionType` on the raw object before it hands it to the normaliser;
   without that copy a move over a block rule is only HIGH, not CRITICAL. The blocking values are
   `block` and `reject` (compared without case); `BLOCK` is verified, `REJECT` is not.
2. **One position list per resource.** The vendor orders firewall policies per pair of zones
   (statement 9), while the engine stores one position list for the resource; see "Decisions of
   P7-T4" below. A policy that moves from one zone pair to another changes `source.zoneId` or
   `destination.zoneId`, which the table tracks.
3. **Nested filter objects.** Since 2026-11-13 the traffic filters of firewall policies are
   classified field by field. The filters of ACL rules are still not, because no ACL rule was seen.
4. **Golden table names.** The test only tables under `tests/golden/types` use names such as
   `unifi-wlans` and `guest_portal.title` that are not the names here; the shipped rows are mapped
   in `tests/golden/test_golden_unifi_shipped.py`.

## Decisions of P7-T4 (collection, ordering, rules)

1. **Position list.** The engine stores one position list for a resource. For firewall policies it
   is the lists of all zone pairs, pairs sorted, and inside each pair: the "before the system
   defined policies" list, then the policies the controller made itself, then the "after" list.
   ACL rules: the one list per site. Sites one after the other.
2. **Policies the controller made itself.** The ordering lists name only `USER_DEFINED` policies
   (statement 9). A policy whose `metadata.origin` is anything else (`SYSTEM_DEFINED`, `DERIVED`) is
   expected to be absent and is not counted as a mismatch. It is placed inside its zone pair between
   the two lists, which is where the controller evaluates the system defined policies, so a user
   policy that moves from "before" to "after" is seen to jump over them. Inside that group the
   policies are sorted by id, a key that never changes, so the place never depends on the order the
   controller returned them in. One without a usable zone pair goes after every pair, sorted by id.
   A policy the lists name anyway keeps its listed place. ACL rules have no origin in the table and
   keep the rule below. Code: `firewall_orderings` in `collectors/unifi/normalize.py`.
3. **Mismatch.** A policy with origin `USER_DEFINED`, or without an origin, that no ordering names
   is appended, and an id without an object is dropped; the run is partial with the class
   `ordering_mismatch`. An ordering that cannot be read fails the resource and keeps the previous
   state. Before 2026-11-13 every real run was partial ("193 appended") because of statement 9.
4. **Action field.** The collector copies `action.type` to `actionType` (decision 1 above).
5. **Golden rows.** Row 3 maps to `unifi-networks` `name`, row 5 to the volatile device fields of
   statement 18 (the real device list has no radio channel), rows 16 and 17 to
   `unifi-wifi-broadcasts` `securityConfiguration.type` and `securityConfiguration.passphrase`
   (the latter hypothetical, statement 14), rows 21 and 22 to `unifi-firewall-policies`. Rows 7 and
   9 name site settings fields; the table has none, so they are not run.
6. **Values.** The rules use the upper case values the controller returned. Security type names
   other than the two seen (statement 7) and the action `REJECT` follow the same spelling and are
   unverified; a value that differs simply does not match its rule.
7. **Not expressible.** "A change to a system defined policy is low unless its action changes"
   cannot be written as a rule: a rule sees one field, not the origin of its object.

## Site settings

The plan asks for site level settings "where the API offers them". None of the sources names a site
settings endpoint, so there is nothing to classify. The table holds only the key so that golden row
7 can later be pointed at it. Status: unknown. If D5 shows no such endpoint, delete the resource in
the same change that maps row 7.

## Still open

1. The vendor reference (D5) for the fields of ACL rules and device tags, and for versions other
   than 10.6.109 (the floor band of the tests assumes the 10.6.109 shapes).
2. The lab tests U2 and U3 of the plan (statement 15): a key made by a View Only account, and
   whether it reads every resource. The S5 key was made by an owner account.
3. Which base path answered on S5 (direct or console proxy) was not recorded with the field list.

The contract tests use synthetic fixtures in the 10.6.109 shapes with the `CANARY-` prefix.

## Carried over, not settled here

- `ALLOWED_OPTIONS` of the source options grows when the collector needs a new option; P7-T1 adds
  none.
- `serve` has no scheduler until the collector factory exists. P7-T1 builds neither; whoever
  builds the factory in P7 or P8 must say so.
- The scheduler test gap of THE-628 (a timer firing while a run now run is in progress) is
  untouched.
- The decision about the derived resource `backup-job-settings` was taken by Core on THE-359
  (2026-10-22): there is no derived resource, the settings are nested fields of `backup-jobs`
  (see docs/vendor-notes/xo.md).
