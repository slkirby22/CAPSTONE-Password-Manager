# Web credential update atomicity (Phase 0)

This is a bounded legacy-v1 correction for `POST /update_password/<service>`.
It uses disposable synthetic data only and does not establish production
readiness, zero knowledge, or completion of Phase 0.

## Defect and transaction contract

Previously, the route changed the credential username, notes and sharing before
validating/encrypting the supplied password. Calling the general `log_event`
helper committed the shared SQLAlchemy session. A missing password or encryption
failure then left an apparently failed update's metadata/sharing persisted,
possibly granting a new recipient access to the old secret. Audit insertion
failures were also swallowed, allowing a success response without its audit.

The corrected route:

1. Requires `pw_id`, `username`, and `password`; validates positive decimal IDs.
   Notes remain optional. Empty credential usernames/passwords remain accepted;
   this change does not apply account-password complexity rules to stored items.
2. Resolves the authenticated owner and all submitted share recipients before
   mutation. Invalid/nonexistent share recipients return generic HTTP 400 without
   changes. Duplicate recipients are collapsed. An empty list removes sharing.
   Nonexistent credentials and non-owner requests retain the dashboard redirect.
3. Encrypts the password before changing credential fields or relationships.
4. Stages the existing `PASSWORD_SHARE` audit through `stage_event`, which never
   commits or catches errors. The route commits fields, ciphertext, sharing, and
   the success audit together exactly once.
5. Rolls back on encryption, audit, or database failures and returns a generic
   HTTP 500. Diagnostics omit exception text and submitted credentials.

A malformed request returns generic HTTP 400. A successful update retains the
HTTP 302 dashboard redirect. The existing success audit type is preserved and
uses the current authenticated database identity. No plaintext enters that audit.

The old best-effort, committing `log_event` interface remains for other legacy
callers. It must not be used inside an operation requiring atomic audited writes.
This fix does **not** claim to repair transactions in other routes, redesign
credential selection, alter Fernet formats, or define concurrent sharing and
account-deletion policies. As with ordinary database transactions, failures after
an externally confirmed database commit cannot be undone by rollback; the tests
exercise failures before commit completes.

## Synthetic actual-route evidence

Run with the repository's test dependencies installed:

```sh
python -m pytest -q tests/test_web_update_atomicity.py
python -m pytest -q tests/test_vault_authorization.py tests/test_audit_authorization.py
python -m pytest -q
```

The new tests log in through the actual web login route, invoke the production
update route with CSRF disabled only in the disposable test app, and independently
read the database using a fresh session after each request. Existing vault tests
retain CSRF and owner/shared/unrelated role coverage.

The 17 atomicity regressions initially produced **14 failures and 3 passes**
against the pre-fix update/audit code, then **17 passes** after the fix. Coverage:

- Missing required fields and malformed/nonexistent identifiers leave ciphertext,
  fields, sharing, and audits unchanged.
- Invalid encryption keys, injected encryption failures, actual SQL audit-insert
  and credential-update failures, and a commit failure after flush roll back.
- Success updates every field, replaces/removes/deduplicates sharing, preserves
  ciphertext decryptability, writes one success audit, and commits once.
- Existing empty-credential and optional-notes behavior is preserved.

This is Flask/SQLAlchemy/SQLite route-level verification, not full browser testing
or live MySQL/SQL Server verification. The broader suite must be rerun after
integrating the separate identity-binding fixture updates; intermediate missing-
binding failures are not an atomicity test pass.
