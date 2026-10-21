# Rules: schema and loader

This page explains the files that tell driftsniff how serious a change is, and how they are read.
It is for people who write or review rule packs and type tables. The code is
`src/driftsniff/rules/` (`schema.py`, `predicates.py`, `loader.py`). The engine that applies the
rules to change items is a later task (P5-T2); this page covers what is loaded and checked.

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
start: the engine task wires it in, and a load error must then stop the start.

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
| `lists` | The mode of each list inside an object, and optionally the field that keys its members (`mode` and `key_field`). A list that is not listed keeps its order (`ordered-scalar`). |
| `floor` | The lowest severity of an added, removed, modified or moved object of this type. |
| `floors` | The same per kind of change (`added`, `removed`, `modified`, `moved`). Use `floor` or `floors`, not both. |

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
