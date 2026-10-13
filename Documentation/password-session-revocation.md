# Password change session revocation (synthetic development only)

Every successfully committed, nonblank account-password replacement through
`POST /update_user/<user_id>` invalidates all previously issued web sessions and
JWTs for that account. This covers the existing permitted self-update and
administrator/manager reset flows; it does not create a new password-reset route
or broaden who may update an account. Even entering the same password re-salts
the stored scrypt hash and requires reauthentication. A blank password remains a
profile-only edit and preserves the password and other existing sessions.

## Binding and atomicity

A separate `credential_binding` claim is now required in signed web cookies and
JWTs, in addition to the existing immutable `auth_identity`. The claim is an
HMAC-SHA256 over a versioned domain, transport, account identity, and stored
password hash. It uses the existing transport signing secret (`SECRET_KEY` for
web; `JWT_SECRET_KEY` for JWT). It is not the password hash, an unkeyed password
fingerprint, a new persisted credential, or a vault encryption key. Claims from
one transport are not valid in the other, even if the configured keys match.
The password/hash itself must never be included in cookies, JWT claims or logs.

Both authentication paths compare the signed claim against the current database
record on every protected request. Malformed, missing, or mismatched claims fail
closed; stale web authentication is cleared. No time-based cutoff, in-process
revocation cache, extra database column, or second revocation transaction is
used. Replacing the salted hash and invalidating old authentication therefore
have the same database commit point. A failed hash operation, validation failure,
constraint failure, or rollback does not invalidate previously valid sessions.

`auth_identity` remains unchanged, preserving account-incarnation protection and
sharing-recipient references. Numeric IDs alone can never authenticate a
replacement account. The password-change initiator's cookie is also cleared
immediately on a successful self change, before the existing logout redirect.

The legacy account-update audit remains a separate best-effort write. A rendering
or audit failure after the password commit does not undo that committed change
or resurrect sessions; the HTTP response alone is not proof of transaction state.
This milestone does not claim atomic account-mutation/audit delivery.

## Concurrency contract

Login captures the binding from the same in-memory hash it is about to verify,
before any audit/counter commit can expire and reload that account. A reset
committed while the old password is being verified, after the web login audit,
or after the counter commit cannot give that old proof a current binding. Such
a login may return a cookie/token, but that credential is already invalid and
cannot authorize a subsequent request. The new password must be used again.

Each reset hashes with a fresh salt. Sequential or concurrent replacements do
not lose an integer generation increment: the binding follows whichever
password hash finally commits. A second reset invalidates credentials issued
between resets. Account password writes retain the legacy last-writer behavior;
this does not add a general optimistic-concurrency contract for account edits.

Revocation takes effect at the next authentication check after the commit. An
already authenticated in-flight request may finish, and plaintext already shown
or copied by a client cannot be remotely recalled. There is no push channel to
clear all open pages immediately. Existing reveal/hide/navigation cleanup stays
in force; a stale page's next reveal request is denied without decryption.

## Upgrade and operational limits

No schema migration is added. Existing required account/item identity migrations
remain required for old disposable fixtures. New claims can be computed from
existing account rows. Existing cookies/JWTs without `credential_binding` sign
out intentionally; users must sign in again. There is no automatic legacy-token
upgrade and no startup database rewrite.

All serving processes must run this version. Do not leave old workers serving
alongside new ones: old validators do not enforce credential bindings. A rollback
to old validation similarly removes this protection. Restoring an older database
snapshot can restore an older hash/binding; restoring environments requires a
separately reviewed signing-key/session invalidation procedure. No live rollout,
real-data migration, signing-key rotation, or deployment is authorized here.

The following policies are unchanged and remain separate decisions:

- Manual lock/unlock changes future-login eligibility, not existing sessions
- Fourth-failure indefinite lockout and the in-process rate limiter
- GET/HEAD web logout clears its local cookie only; copied cookies can remain
  valid, and separate JWTs are unaffected
- API logout blacklists only the presented JWT JTI, not all account sessions
- Legacy vault API routes remain authenticated HTTP 410; no mobile changes
- Current roles, owner/shared item access, deliberate reveal, and audit limits

## Verification

`tests/test_password_session_revocation.py` exercises actual routes with real CSRF,
multiple cookies/JWTs, copied-cookie replay, self/admin and same-password resets,
rollback after flush, invalid input and hash failures, unchanged account/sharing
identity, malformed/legacy claims, fresh login, repeated resets, and unchanged
lock/logout boundaries. `tests/test_password_login_races.py` deterministically
interleaves actual app requests on a temporary file-backed SQLite database with
separate SQLAlchemy sessions/connections. No timing sleeps or real data are used.

The Chromium smoke now includes an actual administrator reset while a shared
account retains its page/CSRF token, cookie and JWT; stale reveal and replay are
rejected, while fresh login restores the same authorized shared item access.
Existing migration, deletion/recreation, access-control, route/error, and browser
cleanup regressions also remain applicable. These checks are not production
approval, zero-knowledge assurance, or professional security certification.
