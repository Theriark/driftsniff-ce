# Admin settings

P10-T8, slice A (the services and routes). The settings page that shows them is slice B
(`docs/web-interface.md` section 12): a browser that asks `GET /settings` for a page gets it. Code:
`driftsniff/web/settings_service.py` (the service), `driftsniff/web/settings_store.py` (the two
setting rows and their rules), `driftsniff/web/routes_settings.py` (the routes) and the user
methods of `driftsniff/web/auth.py`.

Every route needs the **admin** role: no session gives 401, a viewer or an operator gives 403. A
write also needs the session CSRF value and the configured origin (`docs/csrf-and-headers.md`).
The routes take a form post or a JSON object and answer with JSON, like the token and notification
routes.

## What can be changed

| Setting | Field | Rule | Stored as | Read by |
|---|---|---|---|---|
| Retention window | `retention_days` | a whole number of days from 30 to 365 | row `retention_days` of `settings` | the nightly retention job (`docs/retention-and-backup.md`) |
| Storage warning size | `storage_warning_gb` | a whole number of gigabytes from 1 to 1000 | row `storage_warning_gb` | the storage card of the start page |

A missing or invalid stored value reads as the default: 365 days and 2 GB. A value is checked
before anything is written, so a refused entry changes nothing. The answer for a refused entry is
**422** with `detail` (the rule) and `field` (the form field to mark); it never repeats the typed
value. A sign, a space inside the number, a decimal point, an exponent, a non-ASCII digit or more
than six digits is refused.

## Routes

| Route | Does | Answers |
|---|---|---|
| `GET /settings` | the retention window, the storage warning size, the users and the About data | 200 JSON |
| `POST /settings/retention` | sets `retention_days` | 200 `{"retention_days": n}`, 422 |
| `POST /settings/storage-warning` | sets `storage_warning_gb` | 200 `{"storage_warning_gb": n}`, 422 |
| `POST /settings/users` | adds a user: `username`, `password`, `role` (viewer, operator or admin) | 201 `{"user": {...}}`, 409 name taken, 422 |
| `POST /settings/users/{user_id}/disable` | disables a user and ends their sessions | 200, 404, 409 |
| `POST /settings/users/{user_id}/enable` | enables a disabled user | 200, 404 |

A field the route does not know is refused with 422, so a misspelt name is never ignored. Without
the service (`create_app(admin_settings=None)`) every route answers 503. The security route table
(`tests/security/routekit.py`) lists every row as admin only.

`GET /settings` answers one object:

* `retention`: `days`, `default`, `min`, `max`, `runs_at_utc` (the time of the nightly job).
* `storage_warning`: `gb`, `default`, `min`, `max`, `used_bytes` (the database and its write-ahead
  log).
* `users`: for each user `id`, `username`, `role`, `disabled`, `locked` (a sign-in lock is
  running) and `created_at`. Never a password hash.
* `about`: `version`, `commit`, `schema_revision`, `database_bytes`, `sources`, `users` and
  `last_retention_run` (`at`, the window used and the counts of the last run, or `null`).

## Users

* A new user's name is trimmed and lower case, 3 to 64 characters; the password has 12 to 256
  characters and is hashed with argon2id like every other. The answer holds the user as listed and
  never the password.
* A name that is taken (whatever its case) answers **409**.
* An admin cannot disable **their own** account (409); the last enabled admin cannot be disabled by
  anyone (409, checked in the same transaction as the change). A disabled admin does not count.
* Disabling a user deletes their sessions at once; their API tokens stop working too, because the
  token check reads the user.
* Not in this slice: changing a role, resetting a password, deleting a user and unlocking a locked
  user. The lock ends by itself after 15 minutes (`docs/auth.md`).

## Audit

Every accepted write writes one audit event; a refused entry writes none.

| Action | Actor | Target | Detail |
|---|---|---|---|
| `settings.retention_days_changed` | the admin's user name | none | `{"from": old, "to": new}` (days) |
| `settings.storage_warning_changed` | the admin's user name | none | `{"from": old, "to": new}` (gigabytes) |
| `user.created` | the admin's user name | the new user name | `{"role": ...}` |
| `user.disabled`, `user.enabled` | the admin's user name | the user name | none |

`old` is the value in force before the change (the default when none was stored). An audit event
never holds a password, a hash or a typed value that was refused. The activity timeline of the
start page words the two settings actions (`AUDIT_VERBS` in `web/dashboard.py`).

## Tests

`tests/unit/test_settings_service.py` (the service on a real database), `tests/security/
test_settings_routes.py` (roles, CSRF, input rules, audit, 503) and `tests/security/
test_settings_canaries.py` (a planted password and refused values reach no answer, database row or
log line). Run with `pytest tests/unit/test_settings_service.py tests/security`.

## Already existed before this slice

`AuthService.create_user` and `set_user_disabled`, the `retention_days` row read by the nightly
job, the `RunPipeline` notifier wiring (`serve` passes `NotificationService.notify_event` as the
notifier of `build_collection`), and the token and notification routes. What was missing, and is
built here: a route to add, list, disable and enable users, a write for the retention window, a
storage warning setting (the start page used a constant of 2 GB) and the About data.
