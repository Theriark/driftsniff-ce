# The shipped UniFi tables and pack (P7-T4)

`rules/types/unifi.yaml` holds the type tables of the UniFi resources (all names prefixed
`unifi-`) and `rules/packs/unifi/*.yaml` holds 43 rules: `network.yaml` (sites, networks, DNS
policies, traffic matching lists, WANs, device tags), `wifi.yaml`, `firewall.yaml` (zones,
policies, ACL rules), `vpn.yaml` (tunnels, servers, RADIUS) and `devices.yaml`. Each rule has a one
sentence rationale and a test with one matching and one near-miss input
(`tests/unit/test_rules_unifi_pack.py`, cases in `tests/fixtures/unifi/rule_cases.json`).

- WiFi broadcasts, firewall zones, firewall policies, ACL rules, VPN tunnels and servers and RADIUS
  profiles have the object floor `high` (a removed zone, policy or ACL rule is `critical`). A rule
  on one of them is at least `high`, so it is always the reason shown; a test enforces this.
- The critical rules are: a secured WiFi becoming open, a changed WiFi passphrase, VPN key or
  RADIUS secret (the rule only asks whether the fingerprint changed), and a policy or ACL rule
  that stopped traffic and now allows it. A move needs no rule: the first match floor of the
  engine makes it high and critical when it jumped over a blocking entry.
- The names of the WiFi security types and the action values are **unverified**; the rules spell
  the likely ones in upper and lower case. A value that is not listed does not match the critical
  rule and the change falls back to the next rule or to the object floor, never to nothing.
- Golden rows 3, 5, 16, 17, 21 and 22 run against the shipped tables
  (`tests/golden/test_golden_unifi_shipped.py`). Rows 7 and 9 are not run: site settings have no
  endpoint and no collected field.

See [rules.md](rules.md) for the file formats and [unifi-client.md](unifi-client.md) for the collector.
