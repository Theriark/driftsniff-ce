# CSRF, security headers and browser hardening

How driftsniff CE protects the browser interface (P9-T2). The code is `driftsniff/web/csrf.py`
(one middleware, added in `driftsniff/main.py`); the tests are `tests/unit/test_web_csrf.py` and
`tests/security/test_template_scan.py`. The sign-in side is described in [auth.md](auth.md).

## What is checked

| Request | Rule | Refusal |
|---|---|---|
| POST, PUT, PATCH or DELETE outside `/api/v1/` | If the browser sends an `Origin` header it must be the origin of `DRIFTSNIFF_BASE_URL` (scheme, host and port; `http://host` equals `http://host:80`). `Origin: null` and any other value are refused. | **403** |
| The same, from a signed-in session | It must also carry the session's CSRF value, compared in constant time. | **403** (**413** for a form post over 16 KB) |
| `POST /login`, `POST /setup` | Origin check only. They create the session, so there is no per-session value to show yet. | **403** |
| Anything under `/api/v1/` | Exempt from the CSRF value (it is authenticated by a key or token in a request header). A request that carries the `ds_session` cookie is refused, so a browser session never acts on the API. | **403** |
| GET, HEAD, OPTIONS | Not checked (they must not change anything). | |

A request without a session (or with an ended one) has no CSRF value to check; the route's own
role check answers **401**.

## Sending the CSRF value

The value is created with the session (`Principal.csrf_token`, stored in the `sessions` row). The
templates built in P10 send it in one of two places:

- a hidden form field named `csrf_token` in every form that posts (also works without JavaScript);
- the request header `X-CSRF-Token` on every HTMX request (`hx-headers` on the body element).

A value in a JSON body does not count. The value is never logged, never put in a URL and never
repeated in an answer.

## Headers on every response

Every response, including errors and refusals, carries:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` (no inline script, no inline style, no eval) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `same-origin` (see below) |
| `Cache-Control` | `no-store`, on every route except `/static/` (a route that sets its own value keeps it) |

There is no CORS middleware and no `Access-Control-*` header on any response, and a preflight
request gets none.

### Why `same-origin` and not `no-referrer`

With `Referrer-Policy: no-referrer` a browser sends `Origin: null` on every plain form post (Fetch
standard, "serializing a request origin"). The origin check refuses `Origin: null`, so first-run
setup, sign-in, sign-out and every other form of the product failed with a 403 (found on
Development, THE-862). `same-origin` keeps the referrer private: it sends the page address only
to this site and nothing to any other site, and the form post carries the real `Origin`. The check
itself is unchanged: `Origin: null` (also sent from sandboxed frames and some cross-site redirects)
and every foreign origin are still refused. `tests/unit/test_web_csrf.py` covers both.

## Rules for the templates (P10)

- Jinja autoescape is on. `tests/security/test_template_scan.py` fails on `| safe`, on an
  `{% autoescape false %}` (or `off`) block in any file under `web/templates/`, and on
  `autoescape=False` anywhere in the package.
- No inline script and no `style` attribute: the policy blocks them.
- HTMX is vendored with eval disabled and `selfRequestsOnly` on (set in P10-T2; not part of this
  task).

## Limits

- A browser that sends no `Origin` header on a write is accepted when its session value is right;
  `POST /login` and `POST /setup` then rely on `SameSite=Lax` alone. Current browsers send
  `Origin` on every cross-site POST.
- The headers are added by middleware. A crash that the server itself turns into a plain 500
  (outside the application) carries none of them.
- The origin is compared with `DRIFTSNIFF_BASE_URL` only. Behind a reverse proxy the base address
  must be the public address people type, or every browser write is refused.
- The per-address sign-in counter uses the connection's address. Behind a proxy that is the
  proxy's address unless `DRIFTSNIFF_TRUSTED_PROXY=true`, which makes `serve` read the forwarded
  address (details and the proxy requirement in `docs/auth.md`, "Limits").

## Rollback

Remove the `add_middleware(BrowserHardeningMiddleware)` line in `main.py`; nothing is stored, no
migration is involved. Redeploying the previous approved digest does the same.
