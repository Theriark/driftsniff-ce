# Development test accounts

How the crew gets sign-in accounts on the Development site (`https://ce-dev-driftsniff.theriark.dev`) so every flow can be tested in a real browser. Development only: nothing here runs on Stage or Production. Code: `driftsniff/devseed.py` and the `seed-dev-accounts` command in `driftsniff/cli.py`; tests: `tests/unit/test_devseed.py`. Sign-in and roles are described in [auth.md](auth.md).

## What it creates

One account per role of the product. The user name is the account's identifier; the passwords are made when the command runs.

| Role | User name | May |
|---|---|---|
| `admin` | `dev-admin@theriark.dev` | everything |
| `operator` | `dev-operator@theriark.dev` | acknowledge, write notes, run a source now, mute paths |
| `viewer` | `dev-viewer@theriark.dev` | read |

The names are role labels, not people; no mail is ever sent to them. Each password has 32 random characters from letters, digits and `- _ . +` (it starts with a letter or digit, so a command line takes it) and is never reused: a new run or a reset makes new ones.

## The Development-only switch

The command refuses to do anything (exit code 1, no database change, no file written) unless all three hold:

1. `DRIFTSNIFF_DEV_SEED=development-only` is set in the environment of the command. Nothing in the repository sets it: it is not in `deploy/dokploy.json`, `compose.yaml`, the `Dockerfile` or a workflow (a test checks this), so Stage, which is prepared from the same files, never has it.
2. `DRIFTSNIFF_BASE_URL` is `https://ce-dev-<name>.theriark.dev` or a local address (`localhost`, `127.0.0.1`). A Stage address (`ce-stg-...`), a production address or any other host is refused even when the switch is set.
3. `DRIFTSNIFF_ENVIRONMENT_LABEL`, when set, names Development (it contains `dev`).

## How Platform runs it in the Development container

Run it as a one-off command in the running Development container, with the switch set for that command only (do not store the switch in the application's settings):

```
driftsniff seed-dev-accounts
```

with `DRIFTSNIFF_DEV_SEED=development-only` in the command's environment (for example `docker exec -e DRIFTSNIFF_DEV_SEED=development-only <container> driftsniff seed-dev-accounts`, or the Dokploy terminal of the Development application). The container's own `DRIFTSNIFF_DATA_DIR` and `DRIFTSNIFF_BASE_URL` apply, so it works on the same database as the running application.

The command prints, per role, `created`, `password replaced` or `already exists, unchanged`, together with the user name. It never prints a password and never logs one. New passwords are written to `DATA_DIR/dev-seed-credentials.json` (mode 0600, readable only by the container user; change the place with `--credentials-file`). The file looks like this (values here are shapes only):

```
{"version": 1, "accounts": {"admin": {"username": "dev-admin@theriark.dev", "password": "<32 characters>"}, ...}}
```

Then, by whoever read the file, one registration per role with the crew's task client (run on the crew side, not inside the container), so the crew's browser tests find the pair under its secret names (the names are `DRIFTSNIFF_DEV_ADMIN_EMAIL` / `DRIFTSNIFF_DEV_ADMIN_PASSWORD` and the same for `OPERATOR` and `VIEWER`; write only the names in comments and documents):

```
python3 /opt/pi-crews/shared/theriark_crew_task_client.py --action browser_account --repo driftsniff-ce --env dev --label admin --email <user name> --password <value from the file>
```

Repeat for `operator` and `viewer`. When all three are registered, **delete the file** (`rm /data/dev-seed-credentials.json`). Whoever reads the file handles the passwords; they must not be pasted into a task, a comment, a document, a pull request or a log.

## Running it again

- **Second run, nothing changed.** An account that exists is left alone (its password is stored only as a hash, so there is nothing to write for it). The command says `already exists, unchanged` and writes no file.
- **A missing account** is created with a new password; only that account gets an entry in the file. An entry from an earlier run that was never registered stays in the file for the accounts it covers.
- **Lost or unknown passwords:** `driftsniff seed-dev-accounts --reset-passwords` gives all three accounts new passwords, clears a lock and a disabled flag, ends their sessions and writes an audit event `user.credentials_reset` for each. Register the new pairs again (the task client replaces the old ones).
- **A seed user name that exists with another role** stops the run before any change.

## Relation to first-run setup

An admin created here ends first-run setup: `/setup` answers 404 once any admin exists, as described in [auth.md](auth.md). The one-time setup code in the container log is not needed and is never used or printed by this command.

## Not covered

- The command has no effect on the web interface; accounts appear on the Users screen only when that screen exists.
- It does not run on its own. Nothing starts it at deployment; a person or Platform runs it once after a fresh Development data volume.
- The registered pairs are test credentials for Development only. They are not valid on Stage, which has its own accounts prepared separately at Stage promotion.

## Rollback

Remove the command (`cli.py`, `devseed.py`); nothing else depends on it and no migration is involved. To remove the accounts from a Development database, disable them in the web interface once the Users screen exists, or restore the data volume from a backup.
