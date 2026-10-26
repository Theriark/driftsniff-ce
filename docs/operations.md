# Operations

For release candidate v27.0.0-rc.1. How to check that driftsniff runs, keep its data safe, upgrade
it and roll it back. The commands assume the `compose.yaml` of this repository; the service is
called `driftsniff`.

## Health

```
curl --fail http://localhost:8080/healthz
```

The answer is `{"status": "ok", "version": "...", "commit": "<full source commit>"}`. It needs no
sign-in and changes nothing. The container's own health check calls the same route every 10
seconds, so `docker compose ps` shows `healthy` when it answers.

The Settings page (admins) shows the same version and build under **About**, with the database
schema, the database size and the last clean-up.

## Logs

```
docker compose logs driftsniff
```

`DRIFTSNIFF_LOG_LEVEL` sets the detail. Passwords, tokens, keys, setup codes and secret values are
never written to the log; a failed check is logged by the class of its error.

## The two volumes

| Volume | Holds | Rule |
|---|---|---|
| `data` (`/data`) | the database `driftsniff.db`, the backups, the CA bundles | back it up with the command below |
| `keys` (`/keys`) | the master key `master.key` | back it up once, separately, and keep it apart from the database backups |

Do not delete, regenerate or replace the master key. Without it the stored credentials and the
secret fingerprints cannot be read, and the application does not start on a database that needs
it. Changing the key on purpose is a separate procedure in [key-management.md](key-management.md).

## Back up

```
docker compose exec driftsniff python -m driftsniff backup
```

The command writes a consistent copy to `/data/backups/driftsniff-<UTC time>.db` while the
application keeps running, checks the copy with SQLite's integrity check and removes it again if
the check fails. It never overwrites a file. Copy the file off the host with your usual backup
tool. The key volume is not part of this backup. Details: [retention-and-backup.md](retention-and-backup.md).

## Restore

1. Stop the application: `docker compose stop driftsniff`.
2. Copy the backup file to `/data/driftsniff.db` on the data volume and remove any
   `driftsniff.db-wal` or `driftsniff.db-shm` file next to it.
3. Make sure the key volume holds the master key that belongs to that backup.
4. Start the application: `docker compose start driftsniff`. It migrates an older database at
   start.

## Retention

Each night at 03:30 UTC driftsniff deletes changes older than the retention window (365 days by
default, 30 to 365, set on the Settings page), thins old snapshots and removes states nothing
refers to. A run that is missed because the application was stopped at 03:30 is not made up. The
result of the last run is on the Settings page and in the dashboard's Activity.

## Upgrade

1. Take a backup.
2. Set `DRIFTSNIFF_IMAGE` to the new image digest (or pull the new source and build) and run
   `docker compose up -d`.
3. Check `/healthz`: `commit` must be the new build.

## Roll back

Run the previous image digest again with `docker compose up -d`. Nothing is rebuilt. The data is
not rolled back: if the newer image migrated the database to a format the older image cannot read,
restore the backup you took before the upgrade, with its master key.

The Development, Stage and Production installations that Theriark runs follow the same rule with
their own workflows; see [deploy-development.md](deploy-development.md) and [ci-cd.md](ci-cd.md).
