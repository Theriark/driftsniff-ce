# Xen Orchestra volatility, coverage and canary tests (P8-T4)

Three claims about the Xen Orchestra (XO) collector are tested through the whole run pipeline (the
real `XoClient`, the real `RunPipeline`, a migrated database, the shipped rule pack), against the
fake XO of `tests/contract/fake_xo.py`.

**Nothing the fake serves is verified.** No lab XO exists and the vendor reference was not read
(docs/vendor-notes/xo.md; Phase 0 tests X1 to X4 are open). Every collection name, field name and
value in `tests/fixtures/xo/pool.json` is the plan's or our own reading of the interface. The tests
show that the collector behaves as the plan says for those names; they do not show that a real XO
answers with them.

## The fixture

`tests/fixtures/xo/pool.json` is one small pool as an admin session sees it: all 20 collections the
collector reads (38 objects, one of them a built in template that the collector drops). It holds no
secret value. `@canary:<label>` and `@shape:<kind>:<label>` are placeholders;
`tests/contract/xo_pool.py` replaces each one when a test loads the file (a fresh synthetic value
for the canary test, a plain word for the others). A shape is a credential shaped text (url, token,
jwt, pem or remote) that is built in code from pieces, so no scanner sees a credential in the
repository.

The file also holds a simulated backup run in two steps, `during` and `after`. A backup run
snapshots the VMs, copies the disks and deletes the snapshots again. `during` creates snapshot
objects (served from `vm-snapshots`, `vdi-snapshots` and `tasks`, which the collector must never
request), changes the snapshot lists of VMs and disks, the VDI lists of the storage, the parents of
disks and VBDs, power state, start times, memory usage, storage usage, current operations, guest
addresses and server status; `after` removes the snapshots and moves the parents again. No
configuration changes in either step.

## What is tested

| Claim | Test |
|---|---|
| The simulated backup run produces zero change items over six collections in a row (base, during, after, base, during, after), and no snapshot, task or log collection is requested | `tests/contract/test_xo_volatility.py::test_a_simulated_backup_run_produces_zero_change_items` |
| The test can fail: the three phases really differ, and a configuration change made during the run (a rename, a promoted user, a shorter retention) is the only change reported | `test_the_simulated_backup_run_changes_the_pool_but_not_its_configuration`, `test_a_real_change_made_during_a_backup_run_is_the_only_change_reported` |
| Admin mode covers every collection, each with its object count | `test_admin_mode_covers_every_collection` |
| In the read-only fixture `users`, `groups`, `servers` and `backup-repositories` (the plan's remotes) show 403 with no objects, and the other 16 collections are fresh | `test_the_read_only_fixture_shows_403_on_the_admin_only_collections` |
| A credential that loses its admin rights keeps the objects of the four collections, goes stale from the last good read, reports nothing as removed, and recovers | `test_a_credential_that_loses_its_admin_rights_goes_stale_and_removes_nothing` |
| One unreadable collection (404, a line that is not JSON) goes stale alone | `test_one_unreadable_collection_goes_stale_alone` |
| Zero canary hits in the database file, its rows and decompressed states, the log output, the text of errors and run records, standard output and error, and the request lines (the credential travels only in the cookie) | `tests/security/test_xo_canaries.py` |

The canary test uses 20 placeholders: the sign in methods of users and the device configuration of
storage connections (secret class), the user and password part of two remote addresses, a server
address and proxy, and free text (notes, descriptions, `PV_args`, `otherConfig` maps, cloud style
text) of VMs, templates, hosts, pools and networks. It runs the base pool, the backup run, a server
that repeats the cookie in its error answers while the credential can only read part of the pool, a
collection that breaks inside a line that holds a canary, and a refused credential. It first checks
that every canary reached the pipeline (except the two remote address canaries, which the collector
removes before anything else sees them, and the broken line, which is never parsed).

## What this does not show

- **A volatile field that is not classified.** The fake returns every field of an object whatever
  the request asks for, the worst case for the normaliser, and every volatile field of the fixture
  is ignore class in `rules/types/xo.yaml`. A real XO may add a volatile field the table does not
  name; it would be unclassified and a change would show as a fingerprint (open item 5 of the
  notes). Only a lab or the vendor reference closes that.
- **A plain secret in an unclassified field.** The scanner recognises credential shaped values. A
  plain word in a field the table does not name (for example a server password that XO should hide)
  is stored as received, so the canary test seeds credential shaped values there. The type table
  classes `authProviders` and `device_config` as secret for that reason. The collector does not ask
  for a field that is not in the table, so a real XO that honours the field list never returns it;
  the fake does not.
- **The read-only role.** The four 403 collections are the plan's expectation. Test X2 is open.
