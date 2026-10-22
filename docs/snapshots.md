# States, manifests and snapshots

This page explains how driftsniff stores what it reads, and why the database grows only when
your configuration changes. It is for people who run or change driftsniff.

## What is stored

- **State.** One normalised object (one network, one firewall rule, one virtual machine) as
  canonical JSON (see [normaliser.md](normaliser.md)), compressed with zstd level 3 and addressed by
  the SHA-256 of that JSON. The same content is stored once, however many snapshots or sources
  contain it.
- **Manifest.** The list of everything one collection saw: for each resource, the map of object key
  to state hash; for an ordered collection (firewall rules, resolver order) also the list of keys in
  their order; and the controller and normaliser versions.
- **Snapshot.** A stored manifest with the time it was taken. Its `kind` is `baseline` for the first
  snapshot of a source and for the first one after the normaliser version changes (the diff starts
  from a baseline instead of comparing across the change), and `normal` otherwise.

## When something is stored

After each collection the manifest is hashed and compared with the last stored one of that source.

| Collection result | Snapshot | New states | Run record | Source |
|---|---|---|---|---|
| Nothing changed | none | none | written | `last_checked_at` and `last_success_at` move forward |
| Something changed | one | only the changed or new objects | written | same |
| Partial run (some resources failed) | as above | as above | written, status `partial` | only `last_checked_at` moves |

A manifest that returns to an older state is a new snapshot: it is still a change from the last one.
A change of the controller version alone is also a change, because the diff needs it to recognise
schema drift.

## What each run records

Every run row holds `bytes_fetched` (what the controller sent), `new_state_bytes` and
`manifest_bytes` (the compressed bytes this run added to the database), `object_count` and
`stored_new_snapshot`. Use them to check that growth follows your change rate.

## Object rows

`objects` keeps `first_seen_at`, `last_seen_at` and `removed_at` per object. They are updated when a
snapshot is stored, not on every check: `last_seen_at` is the time of the last snapshot the object was
part of, and `removed_at` is the time of the first snapshot it was missing from. An object that
returns is no longer marked removed. A resource that is missing from a manifest altogether is left
alone; a resource that is present but empty removes all of its objects.

## Cleaning up

`gc_unreferenced_states()` deletes states that no stored snapshot refers to. It reads and checks every
manifest first; if one is damaged it stops without deleting anything. States that any snapshot still
refers to are never removed.

## Schema revision

Migration `0002` adds the two size columns to `runs`. The session table of the authentication
phase is migration `0003` (see [auth.md](auth.md)).
