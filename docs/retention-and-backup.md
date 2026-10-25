# Retention and backup

driftsniff keeps its history in one SQLite file (`/data/driftsniff.db`). Two things keep that file
small and safe: a **daily retention job** that deletes old history, and a **backup command** that
writes a checked copy.

## Retention

`driftsniff.sources.retention`. The application runs the job once a day at **03:30 UTC** (the
next 03:30 after it starts). One run does three things, in this order:

1. **Old change events are deleted.** The retention window is **365 days** by default and can be
   set from **30 to 365** days. An event, its items, acknowledgements, notes, enrichments and
   notification deliveries all go together.
2. **Manifests older than 90 days are thinned** to the last manifest of each UTC day, per source.
   A manifest that a retained change event points to (as its snapshot or its previous snapshot)
   is never removed, and the newest manifest of a source is always kept, even for a source that
   has been idle for months.
3. **Unreferenced states are deleted.** An object state that no remaining manifest refers to is
   removed (see `snapshots.md`).

Steps 1 and 2 are one transaction; step 3 and the audit event are another. A crash between them
leaves unreferenced states that the next run collects. It never leaves a manifest without its
states. If a stored manifest is damaged, step 3 stops before it deletes anything.

Every run writes one audit event `retention.run` (actor `system`) with counts only: the window
used, events deleted, manifests thinned, states removed and bytes freed.

### The window setting

The window is the `retention_days` row of the `settings` table (value: a whole number). A
missing value gives 365. A value that is not a whole number from 30 to 365 also gives 365, the
longest window, so a mistake never deletes more than the default would; the run logs a warning
that names the setting but not its value. An admin changes it with `POST /settings/retention`
(30 to 365, audited as `settings.retention_days_changed`; see `settings.md`); the settings screen
that calls the route is built after it.

### Limits

- The job runs at the next 03:30 UTC after the application starts. An application that is
  stopped at every 03:30 never prunes, and a missed run is not made up.
- A run that is inside its worker thread when the application stops finishes by itself.
- Rows of `runs`, `audit_events` and removed `objects` are not pruned in this version.
- A failed run is logged by the class of its error only and the job tries again the next day.

## Backup

```
python -m driftsniff backup [TARGET]
```

- Writes a consistent copy of the database to **TARGET**, which must not exist yet. Without a
  target the file is `/data/backups/driftsniff-<UTC time>.db` (the folder is created with mode
  0700).
- It uses the SQLite online backup API, so the application can keep running; the copy includes
  what is still in the write-ahead log. The copy is one file with no `-wal` or `-shm` neighbour,
  with mode 0600 (it holds encrypted credentials and fingerprints).
- It then runs `PRAGMA integrity_check` on the copy. If the copy or the check fails the file is
  removed again, so a file that exists after a successful run is a good backup.
- It **never overwrites** a file and never follows a link at the target. Exit code 1 and a
  message when the target exists, the database is missing or the copy fails.
- It prints a warning that the **key volume is not part of the backup.** Back it up separately
  and keep it apart from the database backup (see `key-management.md`). A restored database
  without its master key cannot decrypt the stored credentials, and the application will not
  start (exit code 4).

### Restore

1. Stop the application.
2. Copy the backup file to `/data/driftsniff.db` (remove an old `-wal` or `-shm` file next to it).
3. Restore the key volume that belongs to that backup.
4. Start the application. It migrates the database if it is older than the program.

## Tests

`tests/unit/test_retention.py` and `tests/unit/test_backup.py`. Time is injected, so no test waits
for 03:30. Run with `pytest tests/unit/test_retention.py tests/unit/test_backup.py`.
