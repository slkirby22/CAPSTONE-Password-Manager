# Route and error acceptance inventory (bounded P0-019/P0-023)

This inventories the actual Flask application after the web-first item-access
milestone and the bounded diagnostic sanitization change. It is a review and
regression contract for a disposable, synthetic-data-only prototype. It does not
complete Phase 0, approve deployment, or establish a v2 cryptographic, account
lifecycle, or abuse-prevention policy. The historical capstone on `main` and the
separate mobile source are outside this change.

## Scope and interpretation

The runtime `app.url_map` contains **31 rules**: 29 declared in `app.py`, Flask's
static rule, and Flask-Bootstrap's static rule. The table below includes every
rule, including automatically supported methods. There is no replacement API
vault, API reveal, registration, password-reset, or token-refresh route.

The following access labels describe view-level checks, after shared middleware:

- **Public**: no authenticated identity required.
- **Web**: current database user matching the cookie's integer `user_id` and
  32-character lowercase hexadecimal `auth_identity`. Missing, malformed,
  deleted, legacy, or mismatched bindings fail closed; a stale bound session is
  cleared. Cached role/username values are only refreshed display state.
- **Manager**: Web plus current database role `admin` or `manager` and the target
  rules below. Ordinary role denial redirects to `/dashboard?error=...` (302),
  with a best-effort `UNAUTHORIZED_ACTION` audit; missing identity redirects to
  `/` (302).
- **Admin**: Web plus current database role `admin`.
- **JWT**: bearer header only, signature/expiry/blocklist validation plus a
  current database account matching string numeric `sub` and `auth_identity`.
  A cookie alone never grants API access. JWT authorization does not require an
  administrator role.

Unless a row says otherwise, Web identity denial is a 302 redirect to `/`.
All explicit POST/PATCH/DELETE web methods require CSRF. The four API mutation
view functions are explicitly CSRF-exempt; JWT bearer authentication protects
all of them except public `/api/login`. GET and HEAD do not require CSRF.

## Complete registered-route matrix

`OPTIONS` is Flask's automatic response and does not invoke the view or its
identity/role decorator; shared middleware still runs. `HEAD` invokes the GET
view, including its side effects, but returns no body. “No vault mutation” does
not exclude a refreshed session cookie, a CSRF token in the session, limiter
state, or a specifically listed legacy audit write.

| Rule / endpoint | Registered methods | Access / CSRF | Normal result and error or mutation contract |
|---|---|---|---|
| `/` / `index_route` | GET, HEAD, OPTIONS | Public | 200 index HTML; no account/vault write. |
| `/healthz` / `healthz` | GET, HEAD, OPTIONS | Public | GET/HEAD run item-schema validation and zero-row selects for all mapped tables; 200 `{"status":"ok"}` or 503 `{"status":"unavailable"}`. No schema creation/migration. Automatic OPTIONS does not run these checks. |
| `/favicon.ico` / `favicon` | GET, HEAD, OPTIONS | Public | Serve local favicon (200, or conditional file response). Missing file normally raises HTTP 404; the legacy `FileNotFoundError` branch, if reached, attempts an audit and returns 204. No authentication or vault access. |
| `/static/<path:filename>` / `static` | GET, HEAD, OPTIONS | Public | Flask application static files; existing file/conditional response or 404. No authentication or vault access. |
| `/static/bootstrap/<path:filename>` / `bootstrap.static` | GET, HEAD, OPTIONS | Public | Flask-Bootstrap extension static files; existing file/conditional response or 404. The extension rule is distinct from the application's broader static rule. |
| `/login` / `login_route` | GET, HEAD, OPTIONS, POST | Public; POST CSRF | GET/HEAD 200 form, or 302 `/dashboard` for an already current user. POST success 302 `/dashboard`; failed credentials/locked account/verifier failure render 200 with `Invalid username or password`. Missing required form key is HTTP 400. Success resets counter and establishes a permanent bound cookie after counter commit; failed existing-account verification increments counter; legacy login audits are best effort. Route limited to 10/minute. |
| `/logout` / `logout_route` | GET, HEAD, OPTIONS | Public, optional current Web user; no CSRF | GET/HEAD clear session and redirect `/` (302); current-user logout attempts an audit. Stale cookie must not attribute an event to a recycled account ID. Unsafe GET/HEAD mutation remains open. |
| `/dashboard` / `dashboard_route` | GET, HEAD, OPTIONS | Web | 200 HTML with only owned/shared item metadata; no decrypt. Local metadata failure: 500 `Vault unavailable.`. |
| `/select_password_for_edit` / `select_password_for_edit_route` | GET, HEAD, OPTIONS, POST | Web; POST CSRF | Authenticated legacy service-name route returns text 410; no selector translation, decrypt, or vault mutation. |
| `/create_user` / `create_user_route` | GET, HEAD, OPTIONS, POST | Manager; POST CSRF | GET/HEAD 200 form. POST successful create 302 `/dashboard`; invalid role/password or duplicate username renders 200 validation message; missing required form key 400. New user and best-effort separate success audit; see role/transaction caveats. |
| `/view_users` / `view_users_route` | GET, HEAD, OPTIONS, POST | Manager; POST CSRF | 200 account-list/selection HTML; allowed selection attempts `USER_VIEW` audit even on GET/HEAD. POST reads `selected_user_id`; unavailable target renders list, forbidden target redirects `/view_users?error=...` (302). No target account mutation. |
| `/select_user_for_edit` / `select_user_for_edit_route` | GET, HEAD, OPTIONS, POST | Manager; POST CSRF | Alias to the working `view_users` helper with the same list/selection, target checks, and audit behavior. |
| `/update_user/<user_id>` / `update_user_route` | OPTIONS, POST | Manager; CSRF | Permitted other-user update renders 200; self-update redirects `/logout` (302), with role preserved. Missing/forbidden target or invalid role assignment redirects `/view_users` (302, with error where applicable); invalid password or taken username renders 200. Missing required form key 400. Commits username/password/role before separate audit and final rendering. |
| `/delete_user/<user_id>` / `delete_user_route` | OPTIONS, POST | Manager; CSRF | Permitted target deletion commits target's owned vault rows and user deletion, then separate audit; 302 `/view_users`. Missing or forbidden target also 302 with error. Self-deletion denied. Retention/offboarding policy remains open. |
| `/lock_account/<user_id>` / `lock_account_route` | OPTIONS, POST | Manager; CSRF | Permitted change sets failed-login counter to 4, commits, attempts audit, and renders 200. Already locked renders 200 without counter change. Missing/forbidden target 302 `/view_users?error=...`; self-lock denied. Does not revoke existing auth. |
| `/unlock_account/<user_id>` / `unlock_account_route` | OPTIONS, POST | Manager; CSRF | Permitted change sets counter to 0, commits, attempts audit, and renders 200. Not locked renders 200 without counter change. Missing/forbidden target 302 `/view_users?error=...`; self-unlock denied. |
| `/search_user` / `search_user_route` | GET, HEAD, OPTIONS | Web; special anonymous response | Anonymous, empty query, no match, or self match: 200 `{"found":false}`. Another current exact uppercase username: 200 with `found`, `username`, and `auth_identity`. No account/vault mutation; authenticated user enumeration is intentional current behavior, not a policy approval. |
| `/add_password` / `add_password_route` | OPTIONS, POST | Web; CSRF | Owner comes from current user. Required service/username/password fields; caller `item_id`/`pw_id`/`id` rejected. Invalid shape/recipient: text 400. Success creates encrypted item and share list with staged `PASSWORD_ADD` audit in one commit; 302 `/dashboard`. Local failure rolls back and returns 500 `Unable to add password.`. |
| `/update_password/<service>` / `legacy_update_password_route` | OPTIONS, POST | Web; CSRF | Authenticated text 410; no service-name translation or vault mutation. |
| `/delete_password/<service>` / `legacy_delete_password_route` | OPTIONS, POST | Web; CSRF | Authenticated text 410; no service-name translation or vault mutation. |
| `/passwords/<item_id>` / `item_detail_route` | GET, HEAD, OPTIONS | Web; owner or current explicit share | 200 metadata-only detail; owner gets recipient metadata/edit controls. Malformed, missing, deleted, or unrelated item: text 404 `Item unavailable.`. No decrypt; local failure 500 `Vault unavailable.`. |
| `/passwords/<item_id>/reveal` / `reveal_password_route` | OPTIONS, POST | Web JSON; owner or current explicit share; CSRF | Anonymous 401 `{"error":"Authentication required"}`. Allowed exact item: 200 `{"item_id":...,"password":...}` after one decrypt. Invalid/unavailable/unauthorized item: 404 `{"error":"Item unavailable"}`. Local failure 500 `{"error":"Unable to reveal item"}`; no vault mutation. |
| `/passwords/<item_id>/update` / `update_password_route` | OPTIONS, POST | Web; current owner only; CSRF | Path is sole selector. Malformed form/body identity/recipient: text 400. Item unavailable/unauthorized: text 404, after shape validation. Success updates metadata, replaces shares, optionally replaces ciphertext and stages `PASSWORD_SHARE` audit in one commit; 302 `/dashboard`. Local failure rollback and 500 `Unable to update password.`. |
| `/passwords/<item_id>/delete` / `delete_password_route` | OPTIONS, POST | Web; current owner only; CSRF | Body identity rejected with text 400. Item unavailable/unauthorized text 404. Success deletes item with staged `PASSWORD_DELETE` audit in one commit; 302 `/dashboard`. Local failure rollback and 500 `Unable to delete password.`. |
| `/audit_log_viewer` / `audit_log_viewer_route` | GET, HEAD, OPTIONS | Admin HTML | Anonymous 302 `/`; non-admin 302 `/dashboard?error=...`. Allowed 200 HTML of recent logs, after best-effort `AUDIT_LOG_VIEW` audit. GET/HEAD have this audit side effect. |
| `/get_audit_logs` / `get_audit_logs_route` | GET, HEAD, OPTIONS | Admin JSON | Anonymous 401 `{"error":"Authentication required"}`; non-admin 403 `{"error":"Administrator access required"}`. Allowed 200 array with `id`, `event_time`, `event_message`, `event_type`, `user_id`; optional start/end filters applied directly to query. No audit write by this view. |
| `/api/login` / `api_login` | OPTIONS, POST | Public; CSRF-exempt | 200 exactly `access_token` and integer `user_id`; 400 for non-JSON, non-object/malformed JSON, or absent/empty/non-string credential fields; identical 401 `{"error":"Invalid credentials"}` for unknown/wrong/locked account. Updates shared login counter and best-effort login audit. Route limited to 10/minute. |
| `/api/logout` / `api_logout` | OPTIONS, POST | JWT; CSRF-exempt | Valid current token: adds its JTI/expiry to blacklist, commits, 200 `{"message":"Successfully logged out"}`. Subsequent ordinary reuse is rejected by blocklist with 401 before helper execution. See duplicate/race caveat below. Does not clear a separate web cookie. |
| `/api/dashboard` / `api_dashboard` | GET, HEAD, OPTIONS | JWT | Valid current JWT: 410 retired-vault JSON. No vault metadata, decrypt, selector lookup, or mutation. |
| `/api/passwords` / `api_add_password` | OPTIONS, POST | JWT; CSRF-exempt | Valid current JWT: 410 retired-vault JSON regardless of payload shape; no vault creation or payload parsing. |
| `/api/passwords/<password_id>` / `api_retired_password` | DELETE, OPTIONS, PATCH | JWT; CSRF-exempt | Valid current JWT: 410 retired-vault JSON; selector is not resolved and payload is not parsed; no vault update/delete. |

## Shared request, authentication, and method contracts

1. Flask-WTF CSRF runs before Limiter and the application readiness gate. Missing,
   invalid, expired, or mismatched CSRF yields 400 before the web view/auth check.
   HTTPS unsafe requests also require the configured same-origin referrer.
   Forms or the `X-CSRFToken` header supply the token; this change does not weaken
   these checks. Unmatched routes/methods do not become a CSRF-protected view.
2. Limiter runs before readiness. Only `/login` and `/api/login` have declared
   limits: 10/minute per remote address, independently scoped by endpoint, with
   no per-method split or explicit method restriction. Do not treat form GETs,
   HEAD, or OPTIONS as a guaranteed free login budget. Other routes have no
   application/default limit. A breach is 429, not a login failure counter write.
   Rate-limit response headers are disabled in the current configuration.
3. Except `/healthz` and requests already carrying a routing exception, every
   matched request goes through `User.query.limit(1)` and item-schema validation.
   This includes public pages, both static endpoints, and automatic OPTIONS.
   Readiness failure returns 503 `{"error":"Service unavailable"}` before view
   authorization; it neither initializes nor migrates a database. `/healthz`
   performs its own more comprehensive checks for GET/HEAD.
4. The protected Web account-lookup wrapper returns the same generic 503 on
   lookup failure. `/login` and `/logout` call current-user resolution directly;
   unexpected failures outside a local catch reach the generic 500 boundary.
   JWT account/blocklist lookup failures likewise reach that boundary.
5. Missing bearer authentication returns 401 `{"msg":"Authentication required"}`;
   malformed/invalid token returns 422 `{"msg":"Invalid token"}` without decoder
   text. Expired token retains 401 `{"msg":"Token has expired"}`. Revoked token
   is 401 `{"error":"Token revoked"}`; unknown/stale account is 401
   `{"error":"Authentication required"}`. Valid JWT is required before a retired
   API response. Automatic OPTIONS is not an authenticated vault operation.
6. Methods absent from the table return 405 and preserve the `Allow` header;
   unmatched paths return 404. No API reveal route exists. HEAD inherits GET
   side effects; automatic OPTIONS does not execute login/logout/audit/vault
   views. These distinctions are part of review, not assertions that every
   historically unsafe GET has been repaired.
7. All application responses, including redirects, 4xx/5xx and static responses,
   receive `Cache-Control: no-store`, `Pragma: no-cache`, and the existing security
   headers. CORS is limited to the configured localhost mobile origin for
   `/api/*`, allowed methods/headers, with credentials disabled. CORS does not
   replace authentication or CSRF. Existing CSP allows inline and specified
   third-party scripts; this is not a hardened script policy.

## Fixed diagnostic and response boundary

The application `Exception` handler catches an unexpected request failure before
Flask's default unhandled-exception traceback logger can emit SQL parameters or
other exception content. It attempts rollback without logging rollback exception
text and returns **500 `{"error":"Request could not be completed"}`**. Operational
logging uses the fixed event `operation_failed event=request_failed`, followed
only by a bounded code-registered endpoint name and an allowlisted HTTP method
(or `none`); request paths, selectors, and arbitrary method strings are excluded.

HTTP exceptions preserve their status and protocol headers while replacing the
body with JSON `error` containing the trusted Werkzeug status-code default
description from `default_exceptions[code]`, not its instance-specific diagnostic
or an arbitrary exception subclass description. CSRF retains an explicit allowlist of
fixed library reasons; other descriptions fall back to `Invalid CSRF request.`.
Thus 400, 404, 405 and 429 remain distinguishable and a 405 retains `Allow`.
This deliberately does not rewrite existing explicit route returns such as
validation HTML, redirects, item 404 text, or retirement 410 responses.

`diagnostics.py` permits only a fixed event vocabulary: `request_failed`,
`rollback_failed`, `web_login_failed`, `audit_write_failed`, and
`database_reset_failed`. Unknown event strings map to `request_failed`.
The corrected web-login catch clears any partially established cookie,
attempts rollback, emits only `web_login_failed`, and preserves the generic
failed-login form. The best-effort audit writer emits only `audit_write_failed`
and attempts rollback. The reset utility's error print is sanitized; the utility is outside this
review's execution scope. Existing vault/readiness/account
lookup catches already log fixed literal messages rather than exception text.

Forbidden application diagnostic content includes exception text/tracebacks,
request bodies, form/query values, passwords, ciphertext, SQL parameters,
cookies, bearer tokens, encryption keys, connection strings, and account/item
identifiers. Tests should use conspicuous synthetic sentinels and inspect
responses, captured stdout/stderr, and application logs. A failure after a
confirmed database commit cannot be undone by an error handler; a generic 500
is not evidence that no earlier mutation occurred.

The shipped Gunicorn start command restricts each access-log record to fixed
`request_complete` text, response status, and duration. It omits method, path,
query, headers, bodies, referer, user-agent, cookies, and client/account data.
`scripts/smoke_wsgi.py` exercises the real start command with synthetic query,
Authorization, Cookie, User-Agent, and Referer sentinels, then inspects the flushed
combined server output. This does not certify every upstream proxy, hosting log,
library debug logger, crash collector, or future logging configuration. Those
sinks and their retention still need separate review. In particular, Gunicorn
can log exception strings for malformed HTTP rejected before Flask, and server
failures outside Flask can log a URI and traceback. Those transport/server-level
error sinks are outside route-handler sanitization acceptance; changing the
access-log format does not sanitize them. Limiter breach diagnostics can retain
remote-address and fixed-endpoint metadata; they are not a no-personal-data
logging claim. Its default `swallow_errors=False` avoids its optional
traceback-logging fallback branch. Never submit real secrets through this
prototype to validate the boundary.

## Preserved role, item, and transaction boundaries

- Administrators may manage other recognized-role accounts. Managers may manage
  employee or peer-manager accounts, never administrators. Managers can create
  employees only, and can assign employee or retain an existing peer's manager
  role; they cannot promote employees to manager/admin. Unknown actor/target
  roles fail privileged checks. Administrator/manager self profile edits preserve
  the current role; self-delete/lock/unlock are denied.
- Role elevation never grants another user's vault plaintext. Owner and current
  explicit share may list/read/reveal; only current owner may update/delete/change
  sharing. Item IDs are immutable lowercase UUID4 hex selectors, not authority.
  Malformed, absent, deleted, and unauthorized items share an unavailable 404
  once applicable request-shape validation succeeds.
- Sharing uses current `auth_identity` values, rejecting malformed, missing,
  or stale recipients before mutation. Duplicates collapse. Submitted shares
  replace the list; omission removes shares. Crafted owner fields do not transfer
  ownership. Create/update/delete reject supplied alternate item identifiers.
- Update requires a username. Only `replace_password=1` with a present password
  field replaces ciphertext; otherwise existing bytes remain unchanged, even
  when a password field is posted. Explicit empty stored passwords remain
  allowed. Metadata edits do not reveal or decrypt an existing password.
- Vault create/update/delete and their success audit commit together. Legacy
  account mutations, login, logout, and viewer audits use the separate
  best-effort committing writer. They do not acquire a new atomic-audit promise
  from this diagnostic change. A rendering/post-commit failure can coexist with
  a successful prior account write; retries require checking current state.

## Deliberately open policy and lifecycle decisions

These are recorded gaps, not accidental claims of completed acceptance:

- **Logout method and revocation:** Web logout still mutates on GET/HEAD without
  CSRF; POST logout is 405. Clearing the local signed cookie does not centrally
  revoke an already copied cookie, and web logout does not revoke JWTs. API
  logout revokes only the presented JTI, not all tokens or web sessions.
- **Duplicate API logout/races:** Ordinary sequential replay is blocked with 401.
  The legacy helper's already-revoked branch returns a tuple which the route
  wraps in `jsonify`; a race reaching it does not have a repaired 400 contract.
  Concurrent duplicate insertion may instead hit the unique constraint and
  generic 500. This patch does not introduce idempotency or race serialization.
- **Existing-auth lifecycle:** Locking or changing a password does not rotate
  `auth_identity` or revoke already issued cookies/JWTs. Self-update merely
  redirects the current browser to logout; it is not global reset revocation.
  Account deletion/recreation binding and next-request role/share checks exist,
  but no serializable concurrent authorization guarantee is added.
- **Last administrator and deletion:** No minimum-admin invariant, approved
  offboarding/retention semantics, immutable historical identity tombstones, or
  backup-rollback reconciliation. Deleting an account retains the legacy
  deletion of its owned vault entries. These need separate product/security
  decisions rather than a diagnostic patch.
- **Lockout/throttling:** The fourth failed credential verification locks future
  login; no timed unlock, recovery policy, device/account-aware distributed
  throttle, or durable shared limiter is added. Storage is `memory://`, keyed
  by remote address. Web failure increments and cross-web/API races do not gain
  a complete concurrency model. Unknown/locked users skip password verification,
  so identical login failure bodies are not a constant-time guarantee.
- **Session lifetime:** Permanent cookie lifetime defaults to 15 minutes,
  configurable from 1 to 1440; Flask refreshes permanent sessions each request.
  JWT access expiry defaults to 15 minutes. There is no refresh route, absolute
  session-age cap, centralized session registry, or lock-triggered invalidation.
- **Input/enumeration policy:** Account target paths remain string selectors over
  numeric database IDs. Account forms do not gain a comprehensive schema, size,
  empty-name, or normalization policy. Audit date inputs are not parsed into a
  strict date schema and queries are not paginated. Authenticated exact-name
  search reveals existence and current share identity. `MAX_CONTENT_LENGTH`
  remains unset; framework defaults for form memory/parts do not define a full
  abuse or stored-field-length policy. Returning generic errors does not validate
  those inputs or approve existing enumeration behavior.
- **Crypto/platform scope:** Server-held Fernet, plaintext metadata, existing
  recipient/account deletion semantics, old-client cached secrets, browser
  plaintext limitations, migration/backup/restore, non-SQLite compatibility,
  hosting logs, and independent security review remain separate work.

## Evidence and acceptance execution

Source inspection covers `app.py`, `functions.py`, `authorization.py`,
`api_functions.py`, `vault_access.py`, `audit_events.py`, `diagnostics.py`,
`models.py`, configuration, templates, and existing tests. A read-only runtime
inspection with the repository's dependency interpreter and the public
`tests/conftest.py` environment confirmed all 31 URL rules, middleware order,
CSRF exemptions, JWT/session defaults, form limits, and rate-header settings.
Unmatched-route probes confirmed generic JSON 404 and `no-store`. Those probes
are not an execution claim for the acceptance suite below.

The new `test_route_error_contracts.py` uses the actual application, real
password login, enabled CSRF, and in-memory synthetic data. It covers the exact
31-rule inventory drift guard, anonymous web/API boundaries, malformed forms/JSON,
login/hash/account-commit/query/audit/rollback failures, JWT parser/blocklist/logout
failures, readiness/current-user failures, safe HTTP exception descriptions, and
method-error `Allow` preservation. It captures response/headers, logs and standard
output/error to reject secret/token/source sentinels and attached tracebacks.
The fixture disables rate limiting to isolate most tests; one dedicated case
reenables and resets the actual limiter, verifies ten requests and the generic
eleventh-request 429, then resets storage. This is not a durable/distributed or
live-host throttling acceptance claim.

Other targeted evidence includes:

- `test_role_authorization.py`, `test_vault_authorization.py`, and
  `test_audit_authorization.py`: actor/target/current-role and object-access
  boundaries, including denial-before-data access and mutation checks.
- `test_account_identity.py` and migration tests: bound cookies/JWTs, legacy
  identity denial, deletion/recreation safety, and stale logout attribution.
- `test_real_api_login.py`: actual production login routes, CSRF, real verifier,
  response shapes, counter policy, corrupt hashes, and oversized passwords.
- `test_item_reveal.py`, `test_web_update_atomicity.py`, and
  `test_api_passwords.py`: metadata/reveal limits, retired APIs, item identity,
  CSRF, recipient staleness, and atomic vault rollback.
- `test_deployment_config.py`, `test_security_headers.py`, and
  `test_session_lifetime.py`: configuration/readiness/headers/lifetime. Some
  older tests build helper applications; they are not substitutes for testing
  the actual production routes and registered middleware.

For this change, actual-route diagnostic tests should establish real login and
CSRF, inject synthetic failures after readiness/authentication where relevant,
verify fixed responses and diagnostics without secret sentinels, preserve
protocol errors/headers, cover every route/method rule, and compare relevant
account/vault/audit state on denied or failed writes. Explicitly exercise cookie
absence after login commit failure and audit-writer rollback failure. Keep
injection separate from authentication bypasses.

Record final commands and their actual results in the change's verification
report. Listing these acceptance commands is not a statement that they passed:

```sh
python -m pytest -q
python scripts/smoke_wsgi.py
node --check static/js/functions.js
node --check static/js/item-reveal.js
python -m pip check
python -m pip_audit -r requirements/runtime.txt
git diff --check
```

The Chromium smoke described in [web-first item access](web-first-item-access.md)
remains useful regression coverage when the required test-only browser packages
are available. Neither route tests nor browser smoke constitute production
approval or independent security review. Historical milestone documents describe
their own point-in-time routes; this inventory describes the current URL map.
