# Rules: schema and loader

This page explains the files that tell driftsniff how serious a change is, and how they are read.
It is for people who write or review rule packs and type tables. The code is
`src/driftsniff/rules/` (`schema.py`, `predicates.py`, `loader.py`, `engine.py`). The first half
of this page covers what is loaded and checked; the section "The engine" at the end explains how a
change item gets its severity.

## Where the files are

```text
rules/packs/unifi/*.yaml   rule packs of the UniFi collector
rules/packs/xo/*.yaml      rule packs of the Xen Orchestra collector
rules/types/*.yaml         type tables, one entry per resource
```

`load_rules(root)` reads every such file, validates it and returns an index. `root` defaults to
the `driftsniff.rules` package folder. A folder or file that is missing is not an error: a root
without files gives an empty index. Only `*.yaml` directly in those folders is read. A `.yml` file
or a nested folder is ignored without a message and is not part of the pack version, so name every
file `*.yaml`. A file larger than 1,000,000 bytes is refused.

Any problem stops the load with `RuleLoadError`, which names the file and the line
(`packs/xo/a.yaml:12: rules.1.severity: Input should be 'low', 'medium', 'high' or 'critical'`).
Nothing is skipped and nothing is repaired. The loader is not yet called by the application at
start; the engine is not called either. The run pipeline (P6-T2) will load the rules, and a load
error must then stop the start.

Booleans are only `true` and `false` (also `True`, `TRUE`, `False`, `FALSE`), as in YAML 1.2. The
loader does not use the YAML 1.1 rule of PyYAML, so the bare words `yes`, `no`, `on`, `off`, `y` and
`n` stay text: `from: [on]` is the text `on`, which is what a vendor sends. A quoted `'on'` is text
too, and `value: yes` for `boolean_flips_to` is refused because it is not a boolean. The same
holds in type tables, so a field called `on` needs no quotes. Quote a path that is only `*` or `**`
(`path: "**"`), because an unquoted `*` starts a YAML alias. A file may hold one document, a key
may appear once, and only text, numbers, booleans and null are accepted as values.

## A rule pack

```yaml
version: 1
rules:
  - id: xo.users.permission_to_admin
    resource: users
    path: permission
    when: {name: enum_transition, from: [none], to: [admin]}
    severity: critical
    rationale: A user became an administrator.
  - id: xo.users.other
    resource: users
    path: "**"
    severity: medium
    rationale: A user setting changed.
```

| Key | Meaning |
|---|---|
| `id` | Unique over all packs. Lower case letters, digits, `.`, `_` and `-`. |
| `resource` | The resource type the rule is for. It must have a type table. |
| `path` | The field, dot separated. See below. |
| `when` | Optional. A predicate name, or a mapping with `name` and the arguments. |
| `severity` | `low`, `medium`, `high` or `critical`. |
| `rationale` | One sentence that explains the severity. Required. |

Unknown keys are refused.

### Paths

Every literal segment is turned into lower case snake case, in the rule and in the path of the
change item it is compared with: `secureBoot` becomes `secure_boot`, `HTTPProxy` becomes
`http_proxy`, `other-config` becomes `other_config`. A segment `*` matches exactly one segment. A
segment `**` is only allowed last and matches the rest of the path, which can be empty, so `**`
alone matches every field of the resource and the empty path of an added or removed object. A path
that comes from an ordered scalar list ends in the index (`dns.servers.0`). A field name that
itself contains a dot or other symbols (a map key such as `a.b`) cannot be written as one segment:
the diff joins keys with plain dots, so the path is split and snake-cased. Only `*` and `**` reach
such a field, so a pack author who needs to treat it separately must say so in the rationale.

### Specificity and ties

Specificity is twice the number of literal segments, plus one when the rule has a `when`.

| Path | `when` | Specificity |
|---|---|---|
| `**` | none | 0 |
| `settings.*` | none | 2 |
| `settings.exportRetention` | none | 4 |
| `settings.exportRetention` | `decreases_below` | 5 |

`RuleIndex.candidates(resource, path)` returns the rules whose path matches, the most specific
first. The engine takes the first one whose predicate is true, or that has none.

Two rules of one resource that can apply to the same field and have the same specificity are a
load error, `RuleTieError`. The error names both rules. It is never broken silently. Two rules
only tie when their paths overlap (some path matches both) and their predicates are not known to
exclude each other. Known exclusions: two `boolean_flips_to` or two `any_to_value` with different
values, and two `enum_transition` whose `from` lists or whose `to` lists have nothing in common.
Everything else on the same path with the same specificity is a tie, so make one rule more
specific.

## Predicates

A predicate compares the value of the field before and after the change. Null and a missing field
are the same. Values are compared as canonical JSON: `1` equals `1.0`, `true` does not equal `1`.
A value of the wrong type never matches.

| Predicate | Arguments | True when |
|---|---|---|
| `changed` | none | the value differs |
| `becomes_empty` | none | after is null, `""`, `[]` or `{}` and before was not |
| `boolean_flips_to` | `value` (true or false) | before and after are booleans, after is `value` and before is the opposite |
| `decreases_below` | `n` (number) | before and after are numbers, after is below `n` and below before |
| `increases_above` | `n` (number) | before and after are numbers, after is above `n` and above before |
| `enum_transition` | `from`, `to` (non-empty lists) | before is in `from`, after is in `to` and the value changed |
| `cidr_broadens` | none | before and after are networks of the same IP version (IPv4 or IPv6) and after strictly contains before |
| `any_to_value` | `value` (text, number, true or false) | after is `value` and before was not |

`when: becomes_empty` and `when: {name: decreases_below, n: 2}` are the two forms. Unknown names,
missing arguments, extra arguments and arguments of the wrong type are refused at load.
`cidr_broadens` reads a plain address as a one-address network and ignores host bits (`10.1.2.3/16`
is `10.1.0.0/16`).

## A type table

```yaml
version: 1
types:
  - resource: firewall_policies
    collection: ordered-keyed
    key_field: id
    name_field: name
    floor: high
    fields:
      name: config
      action: config
      stats.packets: ignore
      secret_hint: secret
    lists:
      destination.ports:
        mode: set
        key_field: port
      dns.servers: ordered-scalar
```

| Key | Meaning |
|---|---|
| `resource` | The resource type name. Defined once over all files. |
| `collection` | How the objects of this resource are compared: `set` (default), `ordered-keyed`, `ordered-scalar` or `vendor-index`. `ordered-keyed` needs `key_field`. |
| `key_field`, `name_field` | The field that identifies an object, and the one that names it. |
| `fields` | The class of each field path: `config`, `secret`, `ignore` or `unclassified`. A field that is not listed is `unclassified`. |
| `lists` | The mode of each list inside an object, and optionally the field that keys its members (`mode` and `key_field`), and `first_match: true` for an `ordered-keyed` list where the first matching entry wins. A list that is not listed keeps its order (`ordered-scalar`). |
| `floor` | The lowest severity of an added, removed, modified or moved object of this type. |
| `floors` | The same per kind of change (`added`, `removed`, `modified`, `moved`). Use `floor` or `floors`, not both. |
| `first_match` | `true` when the objects of this ordered-keyed collection are an ordered list where the first matching entry wins (a firewall policy list). Default `false`. |
| `action_field` | The field of an object, or of a list member, that holds what it does (its verdict). Read by `core/order.py` to put the actions into the order detail of a move. It must have the class `config` wherever a first-match order uses it. Required when `first_match` is set on the table or on any of its lists (the load fails with `first_match needs an action_field`); optional otherwise. |
| `blocking_actions` | The values of the action field that stop traffic or access. Compared without case or surrounding spaces. Default `deny` and `drop`. Needs `action_field`. |

The four collection modes are those of `core/normalize.py`; `core/order.py` and `core/diff.py`
read them unchanged. A loaded type table is a `ResourceTable`, a `StaticTypeTable` with the
resource name, the collection mode and the floors added, so it is passed to `normalize_object`,
`compare` and `compare_order` as it is. Its paths are the vendor field names exactly as the diff
walks them, with their original case (`secureBoot`), because that is how the diff looks them up.
`RuleIndex.type_tables` maps each resource to its table.

## The rule pack version

`RuleIndex.pack_version` (also `compute_pack_version(root)`) is the first 12 lower case hex
characters of one SHA-256. The hash is fed, for each pack and type file in the order of their
paths relative to the root, the path in UTF-8, a zero byte, the bytes of the file and a zero byte.
Every CRLF and every lone CR in the file is turned into LF first, because YAML reads them all as the
same line break; a checkout with Windows line endings therefore has the same version. It changes
when any file changes, is added, is removed or is renamed, and does not depend on where the root
is. A root without files gives `e3b0c44298fc`.

Type tables are part of it on purpose: object floors decide severities too, so a change to a floor
is a change to the rules. The version is meant to be stored with each change event in
`change_events.rule_pack_version`. That column already exists (migration 0001); nothing writes
change events yet (P6-T2), so the version is not stored anywhere today and no migration is needed.

## The engine

`RuleEngine(index).classify(item)` gives a severity, a rule id and a rationale for one change item
of `core/diff.py` or `core/order.py`; `apply(item)` returns a copy of the item with the three
fields filled in. The engine knows no vendor: every rule, floor and action comes from the packs
and the type tables.

1. A `schema_drift` item keeps the classification the diff gave it (LOW, `builtin.schema_drift`).
2. The most specific rule that applies wins: the first of `RuleIndex.candidates` whose predicate
   holds (or that has none). A predicate reads the shown value of a `config` field before and
   after, and the fingerprint of a `secret` or `unclassified` field, so `changed` holds for a secret
   that changed and a predicate about numbers or networks never holds for it. An added or removed
   whole object has no value on either side.
3. No rule applies: MEDIUM, rule id `builtin.unclassified`, rationale `unclassified field, not
   reviewed`.
4. Floors only raise. The final severity is the maximum of the rule and of the floors below. When a
   floor is higher than the rule it is the result (`floored` is true, and `matched_rule_id` keeps
   the rule that matched); when the rule is as high as the floor, the rule is the result.

| Floor | When | Severity | Rule id |
|---|---|---|---|
| Object floor | the type table of the resource has `floor` or `floors` for this kind of change (`added`, `removed`, `modified`, `moved`; an `order_changed` item counts as `moved`) | as declared | `builtin.floor.<kind>` |
| Move | a `moved` or `order_changed` item in a first-match order (`first_match` on the resource for its own order, or on the list for a list inside an object) | HIGH | `builtin.move.first_match` |
| Move across a block | a `moved` item whose `moved_actions` or `jumped_actions` hold a blocking action of the table | CRITICAL | `builtin.move.blocking` |

The security sensitive objects (zones, policies and ACL rules, roles, users and permissions, auth
providers, WiFi security, RADIUS profiles, VPN servers and tunnels, XO servers, backup
repositories) are marked by `floor: high` in their type tables, and the removal of a firewall or
ACL object by `floors: {removed: critical}`. The other CRITICAL cases are rules of the packs, for
example `enum_transition` from `none` to `admin`, `boolean_flips_to: false` on the TLS verification
field, `enum_transition` from the WPA family to `open`, and `boolean_flips_to: false` on the enabled
flag of a firewall rule. The engine only implements the mechanism. The shipped tables and packs
(P5-T3, P7, P8) say which fields these are.

An `order_changed` item (a list of more than 5,000 entries) has no detail, so its floor is HIGH and
never CRITICAL. A first-match table always has an `action_field` (the load refuses one without), so
a move across a deny rule is CRITICAL whenever the order detail was computed.

Every result has a rule id and a rationale that are not empty, and the same item always gives the
same result.

### Mutes

`is_muted(severity, resource, path, mutes)` and `item_is_muted(item, mutes)` are the check for the
list views, with `PathMute(resource, path_pattern)` standing for one row of `path_mutes`. A mute
hides an item from a list; the item is still stored with its real severity. A mute never applies to
a CRITICAL item, and an item without a severity is never muted. The pattern is read like the path of
a rule (snake case, `*` for one segment, `**` for the rest); an empty pattern matches only the empty
path of a whole object.

## The shipped Xen Orchestra tables and pack

`rules/types/xo.yaml` holds the type tables of the XO collections and `rules/packs/xo/*.yaml` holds
47 rules (`compute.yaml` for virtual machines, hosts, pools and storage, `network.yaml`,
`backup.yaml` and `access.yaml` for servers, users and groups). Each rule has a one sentence
rationale and a test with one matching and one near-miss input
(`tests/unit/test_rules_xo_pack.py`, cases in `tests/fixtures/xo/rule_cases.json`).

- XO servers, backup repositories, users, groups and ACL roles have the object floor `high`.
  A rule on one of them only matters when it is `critical` (a user who becomes an administrator, a
  server that stops checking certificates, a change of the access roles of a group).
- A field that is classed but has no rule is MEDIUM, `builtin.unclassified`, until it is reviewed.
  There is no catch-all `**` rule: the engine matches on the path only, so one would also swallow
  the fields that are not in the table.
- The setting map of a backup job is keyed by schedule id, and a type table names only fixed field
  paths. The table therefore describes a derived resource, `backup-job-settings`, with one object
  per key of the map (object id: job id, a colon, then the schedule id or `default`), and ignores
  `settings` on the backup job itself. The XO collector (P8-T2) has to produce that resource.
- The field names are those of the plan and are not yet checked against a live Xen Orchestra
  (P8-T1). A field that is not in the table is unclassified and shows as a fingerprint only.
