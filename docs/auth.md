# Users, sign-in and sessions

How people sign in to driftsniff CE (P9-T1). The code is in `driftsniff/web/auth.py` (rules and
storage), `driftsniff/web/deps.py` (role checks for routes) and `driftsniff/web/routes_ui.py`
(the three posts). Migration `0003` adds the `sessions` table.

## Roles

| Role | May |
|---|---|
| `viewer` | read |
| `operator` | acknowledge, write notes, run a source now, mute paths |
| `admin` | manage sources, users, API tokens and settings |

Each role may do everything the lower ones may. A route asks for a role with
`Depends(require_viewer)`, `Depends(require_operator)` or `Depends(require_admin)`
(`driftsniff.web.deps`): no session gives **401**, a role that ranks lower gives **403**, an
application built without the sign-in service gives **503**.

## Passwords and user names

- Hashed with argon2id: 64 MiB of memory, 3 passes, 1 lane. A stored hash with weaker settings
  is replaced by one with the current settings at the next successful sign-in.
- 12 to 256 characters, counted as characters. There is no other composition rule.
- User names are 3 to 64 characters of letters, digits and `. _ @ + -`, start with a letter or a
  digit, and are stored in lower case.

## Signing in

`POST /login` takes a form post or a JSON object with `username` and `password` (at most 16 KB).
Success answers **303** to `/` and sets the session cookie. Every failure (unknown user, wrong
password, disabled user, locked user) answers **401** with the same text, and an unknown user
costs the same hashing work as a known one.

| Limit | Rule |
|---|---|
| Per user name and per client address | 5 failures inside a minute, then the next attempts are refused with **429** and a `Retry-After` header; the wait starts at 1 second and doubles with every further failure (2, 4, 8 ... at most 60 seconds). A refused attempt is not checked and does not count. A quiet minute starts the count again. |
| Per user | 10 failures in a row lock the user for 15 minutes (a `user.locked` audit event is written). Attempts during the lock fail like a wrong password and do not extend it. A good sign-in clears the count. |

The per-name and per-address counters are kept in memory (the application runs one worker), so a
restart clears them; the lock is stored with the user and survives a restart.

## Sessions

- The cookie is named `ds_session`: 32 random bytes, `HttpOnly`, `SameSite=Lax`, `Secure` when the
  request arrived over HTTPS. A forwarded `X-Forwarded-Proto: https` counts only when
  `DRIFTSNIFF_TRUSTED_PROXY=true`.
- The database keeps only the SHA-256 of the cookie value, so a copy of the `sessions` table
  cannot be turned back into a cookie. The row also holds the per-session CSRF value that P9-T2
  checks.
- A session ends after **8 hours without a request**, **7 days after sign-in** whatever its use,
  at logout (`POST /logout`, which deletes the row and clears the cookie), and when its user is
  disabled (all sessions of that user are deleted in the same transaction as the change).
  The last-seen time is written at most once a minute.
- Ended sessions are deleted when they are noticed and at every sign-in.

## First admin

1. At the first start with no admin, `serve` prints a one-time **setup code** to the container
   log, once. `driftsniff create-admin-code` prints a new one (and replaces an unused one); it
   refuses when an admin exists.
2. `POST /setup` with `code`, `username` and `password` creates the first admin and signs them in
   (**303** and the cookie). A wrong code answers **403**, a rule-breaking name or password
   **422** with the rule (the code stays valid), repeated wrong codes **429**.
3. Only the SHA-256 of the code is stored. Using the code deletes it in the same transaction that
   creates the admin, so a second use fails.
4. As soon as any user with the role `admin` exists (a disabled admin still counts), `/setup`
   answers **404** like an unknown route.

## Logs and audit

Passwords, cookie values and setup codes are never written to a log. The audit log records
`setup.completed`, `user.created`, `user.locked`, `user.disabled` and `user.enabled` (actor and
target are user names; no secret).

## Not built yet

| Part | Status |
|---|---|
| The setup and login pages, the user menu | P10-T3 / P10-T2; only the posts exist |
| CSRF value check, Origin check, security headers | built in P9-T2, see `docs/csrf-and-headers.md` |
| API tokens (`/api/v1`, Bearer) | built in P9-T3, see `docs/api-access.md`; a session cookie is not an API credential |
| Admin screens to add, change and disable users | P10; `AuthService.create_user` and `set_user_disabled` exist |
| Route table test that every route states its role | P9-T6 |

## Limits

- Anyone who knows a user name can lock that user for 15 minutes with ten wrong passwords; the
  address limit slows this down but does not stop it. There is no unlock command in CE v1: the lock
  ends by itself.
- A disabled last admin cannot be replaced through `/setup` (an admin row still exists).
- Throttle state is per process (see above).
- The per-address counter uses the client address of the connection. With
  `DRIFTSNIFF_TRUSTED_PROXY=true`, `serve` starts uvicorn with proxy headers on, and uvicorn then
  takes the client address from `X-Forwarded-For`, so each person behind the proxy has their own
  counter; that setting trusts the header from any sender (`forwarded_allow_ips="*"`), so the
  proxy must overwrite the header and the container port must not be reachable except through it.
  With `DRIFTSNIFF_TRUSTED_PROXY=false` behind a proxy, all clients share the proxy's address and
  therefore one per-address counter (the per-name counter and the lock still work). This follows
  from the uvicorn setting in `cli.py`; no test here runs a proxy.
