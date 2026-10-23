# Development test accounts

How the crew gets sign-in accounts on the Development site (`https://ce-dev-driftsniff.theriark.dev`) so every flow can be tested in a real browser. Development only: nothing here runs on Stage or Production. Code: `driftsniff/devseed.py`, the start-up call in `driftsniff/cli.py` and its `seed-dev-accounts` command; tests: `tests/unit/test_devseed.py`. Sign-in and roles are described in [auth.md](auth.md).

## What it creates

One account per role of the product. The user name is the role itself, and the password is the one the deployment controller generated for that role.

| Role | User name | Password variable | May |
|---|---|---|---|
| `admin` | `admin` | `DRIFTSNIFF_DEV_ADMIN_PASSWORD` | everything |
| `operator` | `operator` | `DRIFTSNIFF_DEV_OPERATOR_PASSWORD` | acknowledge, write notes, run a source now, mute paths |
| `viewer` | `viewer` | `DRIFTSNIFF_DEV_VIEWER_PASSWORD` | read |

The names are role labels, not people; no mail is ever sent to them. The browser sign-in form takes the user name in its first field, which is why the manifest below calls it `email`.

## How the accounts get there (no operator step)

1. `deploy/dokploy.json` declares the three passwords in `env` with kind `token24` and **no** `value`, and lists the accounts in `browserAccounts`; each entry has only `email`, `label` and `passwordEnv`:

   ```
   {"email": "admin", "label": "admin", "passwordEnv": "DRIFTSNIFF_DEV_ADMIN_PASSWORD"}
   ```

   `email` is the user name the application creates (`username_for` in `devseed.py`), `label` is the role, and `passwordEnv` is the variable that holds that role's password. A test compares the manifest with the code, so they cannot drift apart. The six earlier settings, the volumes and `database` are unchanged.
2. The Platform step `dokploy_prepare` generates each `token24` value privately (or reuses the existing one), writes it to the Development application's settings, and registers the browser secret **names** (for the admin: `DRIFTSNIFF_DEV_ADMIN_EMAIL` and `DRIFTSNIFF_DEV_ADMIN_PASSWORD`; the same for `OPERATOR` and `VIEWER`). It runs no command in the container. No password is in the repository, a workflow, a comment or a log.
3. When the Development container starts (`driftsniff serve`), it runs the seed after the database migration and before the first-run setup code: it creates each of the three accounts that does not exist yet, with the password from its variable.

The Test Engineer then signs in with the registered names in the real browser; registering the accounts is not the same as a passed sign-in.

## The Development-only guard

The start-up seed runs only when **both** hold:

1. All three password variables are set. With none set (every Production start) it does nothing and logs nothing.
2. `DRIFTSNIFF_BASE_URL` is a `ce-dev-<name>.theriark.dev` address. Stage and Production are prepared from the same manifest and may receive the same variables, so the address decides: a Stage address (`ce-stg-...`), a production address, `localhost` or any other host is refused with one warning that names no value, and nothing is created. A `DRIFTSNIFF_ENVIRONMENT_LABEL` that does not name Development (it must contain `dev`) also refuses.

An incomplete configuration (some variables missing, or a password shorter than 12 characters) creates nothing and logs an error that names the variables only. A failure of the seed is logged and never stops the application from starting.

The marker `DRIFTSNIFF_DEV_SEED=development-only` is not used at start-up: nothing in the repository may set it (`deploy/dokploy.json`, `compose.yaml`, the `Dockerfile` and the workflow are checked by a test), and the controller interface declares only generated passwords. It stays the extra guard of the manual command below.

## The manual command

```
driftsniff seed-dev-accounts [--reset-passwords]
```

For a local installation or to replace passwords. It refuses (exit code 1, no database change) unless `DRIFTSNIFF_DEV_SEED=development-only` is in its environment, the address is a Development one (`ce-dev-<name>.theriark.dev`, `localhost` or `127.0.0.1`), the badge does not name another environment and all three password variables are set. It prints, per role, `created`, `password replaced` or `already exists, unchanged` with the user name, never a password, and writes no file.

## Running it again

- **Second start or second run, nothing changed.** An account that exists is left alone (its password is stored only as a hash). Other users and all data are preserved; only the three seed user names are ever touched.
- **A missing account** is created; the others are not changed.
- **An existing account with another password** (for example a person created `admin` in first-run setup, or the generated value was replaced) is left alone and reported: the start-up log and the command say that the stored password is not the configured one. `driftsniff seed-dev-accounts --reset-passwords` then puts the configured password on all three accounts, clears a lock and a disabled flag, ends their sessions and writes an audit event `user.credentials_reset` for each.
- **A seed user name that exists with another role** stops the seed before any change (logged at start-up, which continues).

## Relation to first-run setup

An admin created here ends first-run setup: `/setup` answers 404 once any admin exists, as described in [auth.md](auth.md). On Development the one-time setup code is therefore not printed after the seed has run.

## Not covered

- The seed has no effect on the web interface; accounts appear on the Users screen only when that screen exists.
- It does not make Stage accounts. Stage has its own accounts prepared separately at Stage promotion.
- The values are test credentials for Development only. They are not valid anywhere else.

## Rollback

Remove the three password entries and `browserAccounts` from `deploy/dokploy.json` and the start-up call in `cli.py` (`seed_at_startup`); nothing else depends on them and no migration is involved. To remove the accounts from a Development database, disable them in the web interface once the Users screen exists, or restore the data volume from a backup.
