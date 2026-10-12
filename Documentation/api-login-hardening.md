# API login regression hardening

This bounded change is for the legacy, synthetic-data-only prototype. It does
not make the application production-ready or authorize deployment.

## Actual `/api/login` contract

- Success remains HTTP 200 with exactly `access_token` and integer `user_id`.
  The JWT identity remains the string form of that ID. Usernames remain
  case-insensitive through uppercase lookup.
- Unknown account, wrong password, and locked account now all return HTTP 401
  with the identical JSON object `{"error": "Invalid credentials"}`. No token
  or user ID is returned. This fixes the actual route's previous serialization
  of a locked-account helper tuple as a successful HTTP 200 JSON array.
- Non-JSON requests remain HTTP 400 with `{"error": "JSON required"}`.
- Malformed JSON or a top-level value other than an object returns HTTP 400 with
  `{"error": "JSON object required"}`.
- Missing, empty, or non-string username/password values return HTTP 400 with
  `{"error": "Username and password must be non-empty strings"}`. Rejected
  request shapes do not change login counters or create authentication logs.
- Unsupported/corrupt stored hashes and passwords exceeding the verifier's
  supported size fail closed using the generic HTTP 401 response.

## Existing counter policy preserved

The web and API login interfaces use the same `failed_login_attempts` column.
API password failures now increment it, with a database-side increment to avoid
lost increments between concurrent API failures. A counter of 0 through 3 still
permits verification; the fourth failure reaches 4 and locks subsequent login
attempts. Locked attempts do not reset or increment the counter. A successful
unlocked login resets it to 0 on either interface.

API failures for existing accounts record `FAILED_LOGIN`, locked attempts record
`ACCOUNT_LOCKED`, and successful API logins retain `API_LOGIN`. Submitted
passwords are not included in these log messages.

This change introduces no timed unlock, lockout duration, new threshold, or
rate-limit configuration. The existing 10-per-minute route limit is unchanged.
Temporary lockout and the wider P0-014 authentication-abuse policy remain open.
Database-side increment alone is not a complete concurrent authentication or
web/API race-safety design.

## Privacy boundary

The generic authentication failure status and JSON body do not disclose whether
an account exists or is locked. This is a response-contract guarantee, not a
constant-time guarantee: missing or locked users skip password verification,
and existing-account failures perform different database/audit work. Timing
oracles and other authentication-abuse controls remain outside this bounded fix.

## Verification

`tests/test_real_api_login.py` contains 34 cases against the actual `app.py`
routes, including the real password verifier, API CSRF exemption, and web login
with valid CSRF tokens. Tests cover the success/JWT contract, identical failures,
fourth-failure lockout, counter reset and accumulation across both interfaces,
malformed input, corrupt hashes, and oversized passwords. The fixture asserts
that the database is in-memory SQLite before creating or dropping synthetic
tables.

Together with the three existing helper-route tests in `tests/test_api_login.py`,
the focused login run passed all 37 tests using Python 3.12 and the upgraded
dependency environment. `pip check`, WSGI smoke, and `git diff --check` also
passed. Run the final full suite after integrating parallel changes; these
focused counts do not substitute for that integration check.

```sh
python -m pytest -q tests/test_real_api_login.py tests/test_api_login.py
python -m pip check
python scripts/smoke_wsgi.py
git diff --check
```
