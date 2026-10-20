# Database

driftsniff keeps everything in one SQLite file, `driftsniff.db`, inside the data directory
(`DRIFTSNIFF_DATA_DIR`, default `/data`).

## Settings of the connections

- Write-ahead logging (WAL) is on. The mode is stored in the file.
- Foreign keys are enforced, the busy timeout is 5000 ms and `synchronous` is `NORMAL`.
- There is one writer. Every write takes one process-wide lock, so writers never wait on each
  other inside SQLite. Reads use up to four read-only connections.

## Migrations

The schema is created and upgraded by numbered Alembic revisions that ship inside the package
(`driftsniff/db/migrations/versions`).

- `python -m driftsniff migrate` upgrades the database to the newest revision (it creates the
  file when it does not exist). The upgrade runs in one transaction: it is applied completely
  or not at all.
- `python -m driftsniff serve` does the same before it starts listening.
- A database whose revision is newer than the installed version is never touched. The command
  prints a message and exits with code **3**. Start the newer version again, or restore a
  database backup made by this version.
- Downgrades are not supported.

## Stored configuration

States, manifests and snapshots, and how little a run without changes stores, are described in
[snapshots.md](snapshots.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid setting or database error (the message says which) |
| 2 | Command not implemented yet, or usage error |
| 3 | The database is newer than this version of driftsniff |
