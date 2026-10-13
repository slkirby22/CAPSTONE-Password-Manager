# Web-first item access milestone

This Phase 0 security correction is intentionally breaking. It does not implement
v2 cryptography or complete Phase 0. Use disposable synthetic data only. The
historical capstone and separate mobile source remain unchanged; this development
version supports the web interface. See [API retirement](web-first-api-retirement.md).

## Route contract

- `GET /dashboard`: authorized item metadata only.
- `GET /passwords/<item_id>`: the exact authorized item's metadata and owner-only
  sharing controls. No password decrypt, ciphertext field or ORM vault object is
  passed to the template. Metadata is an explicit SQL/DTO allowlist.
- `POST /passwords/<item_id>/reveal`: requires current account-bound cookie and
  CSRF. Looks up the exact immutable identity with current owner/share permission,
  then decrypts one field and returns `{item_id, password}`. GET never reveals.
- `POST /passwords/<item_id>/update` and `/delete`: current owner only. No global
  role bypass. Path is the sole selector; body `item_id`, `pw_id`, `id` rejected.
- Old service-name selection and mutation routes return authenticated HTTP 410.
  They never translate a historical name/integer into a current row.
- All legacy API vault endpoints return authenticated machine-readable HTTP 410.
  There is no new API reveal or mobile feature expansion. Login/logout remain.

UUID4 IDs are opaque selectors, not authorization tokens. The current database
account incarnation is checked on every protected request, including reveal.
Missing, malformed, deleted and unauthorized item references receive the same
404. Unauthenticated reveal receives JSON 401. Decryption/database failures return
generic 500 without exception text or secret-bearing diagnostics. Readiness and
current-account lookup failures return generic 503. All application
responses, including redirects/errors, carry `Cache-Control: no-store`.

Sharing forms/search now use existing account `auth_identity` values. Every
recipient must still exist under that identity when the write executes; stale
forms cannot grant a replacement account that reuses the numeric primary key.
Underlying owner/share foreign keys remain internal integers. This does not alter
legacy account deletion semantics or introduce a cryptographic identity protocol.

## Replacement and atomic writes

Metadata editing never requires revealing the old password. Replacement input
starts blank/disabled; only explicit `replace_password=1` replaces it. The
password field is required with that intent, and an explicit empty value remains
allowed by the existing stored-secret policy. Otherwise ciphertext is preserved
byte-for-byte even if a password field is posted. Username is required; notes are
optional. The submitted share list replaces shares, including an empty list.
Owner fields cannot transfer ownership. Create rejects supplied item identities.

Validate recipients and encrypt any replacement before changing fields. Credential,
sharing and success audit mutations commit together. Failures roll back together;
no secret values enter success audit messages. Create and delete use the same
transactional audit discipline in this milestone.

## Browser plaintext lifetime

Only an explicit reveal button fetches the current secret, using CSRF,
`cache: no-store` and redirect rejection. It is displayed in a dedicated text
node, never initial HTML, URLs, storage or generic list state. Hide clears the
node rather than masking it. Navigation/links, pagehide, pageshow/back-forward,
background visibility, logout link, form submission and a 30-second timeout clear
revealed state. Pending requests are aborted and generation-checked; stale JSON
responses cannot restore a hidden or switched item. Shared recipients get reveal
but no update/delete controls. Replacement stays independently user-entered.

The timeout bounds the entire request/display interval to 30 seconds, so slow
requests leave less display time. JavaScript strings, browser caches/snapshots,
OS memory and already delivered values cannot be reliably erased. No-store and
cleanup are exposure reduction, not zeroization, revoked-secret recall or a
malicious-client defense. Browser/device app-switcher guarantees are not claimed.

## Migration and remaining limits

Read [item identity upgrade](item-identity-upgrade.md) and the earlier
[account identity upgrade](account-identity-upgrade.md). Only an explicit offline
disposable SQLite migration is provided. Old/partial schema readiness fails;
startup never migrates. Non-SQLite readiness intentionally fails closed pending
separately reviewed equivalent constraints. Historical SQL scripts are not an
upgrade path. Never run mixed-version writers or migrate a real vault here.

This remains server-held Fernet encryption. Usernames, service names and notes
remain plaintext metadata. Initial vault rendering avoids password contents, not
all sensitive information. Existing inline/third-party scripts and server
compromise remain risks. An authorized malicious client can deliberately reveal
each item. Permission checks reflect the database when checked; no serializable
concurrent revocation guarantee, lock-triggered revocation or backup rollback
reconciliation is introduced. A later [password-change session
binding](password-session-revocation.md) does enforce password-reset revocation
at the next authentication check. UUIDs have active uniqueness checks but no historic
tombstone registry. Mobile builds may retain secrets fetched from an old backend;
this change cannot remove those copies.

## Acceptance commands

```sh
python -m pytest -q
python scripts/smoke_wsgi.py
node --check static/js/functions.js
node --check static/js/item-reveal.js
python -m pip check
python -m pip_audit -r requirements/runtime.txt
```

Tests use production routes and disposable data: role/owner/shared matrices,
metadata zero-decrypt projections, duplicate names, numeric reuse, revoked shares,
account deletion, CSRF, retired JWT API, malformed selectors, corrupt ciphertext,
atomic write failures, omission/replacement semantics, stale recipient forms,
SQLite migration rollback, and Node DOM interruption tests. Node DOM tests are
not a substitute for a native mobile/device test or external security review.


The CI test job also installs pinned Playwright from `tests/browser/package-lock.json`,
installs Chromium, then runs `python scripts/smoke_item_browser.py`. This uses a
fresh browser context, temporary public-fixture SQLite database and real Gunicorn
routes/CSRF; external page requests are blocked. For an equivalent local run,
install those test-only packages and Chromium, then set `NODE_PATH` to the absolute
`tests/browser/node_modules` directory before invoking the script. The installation
sequence follows [Playwright's CI instructions](https://playwright.dev/docs/ci).
These tools are not included in the runtime container. Browser launch may be
restricted in some sandboxes; an unexecuted smoke must not be reported as passing.
