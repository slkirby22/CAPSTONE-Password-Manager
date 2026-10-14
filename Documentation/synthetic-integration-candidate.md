# Synthetic integration candidate

This candidate preserves the commits from draft PRs 31–34 and adds one bounded
audit-reporting correction. Its review target is the existing development branch
at e688a6b, not historical main. It proposes a combined integration for review;
creating this branch does not merge the target or authorize deployment. Existing
individual drafts remain available and should not also be merged blindly after
adopting a cumulative candidate.

## Included work

- PR 31: disposable SQLite upgrade and backup/restore verification.
- PR 32: offline owner-operated synthetic administrator bootstrap.
- PR 33: same-origin CSP, unambiguous local Bootstrap assets, desktop/mobile
  screenshot verification and small responsive corrections.
- PR 34: account-form bounds checked before hashing or mutation.
- Audit reliability: latest request wins after JSON resolution; old success or
  failure cannot replace newer data. Loading/error rows are safe to filter and
  excluded from CSV. Refresh reapplies current text/type filters. Clear All
  Filters now clears both date bounds as its label promises.

## Date contract correction

The audit UI selects calendar dates, inclusive of both endpoints, in the existing
stored timestamp's source calendar. The server now validates canonical YYYY-MM-DD
values and includes the selected end day's final microsecond. The former SQL
comparison against a date-only string excluded the end day, while browser UTC/
local Date mixing could exclude another day depending on timezone. Browser filters
now compare the canonical date portion directly. No historical timestamp rewrite
or timezone migration is included.

Malformed, repeated or reversed date filters return safe HTTP 400 JSON after the
existing administrator authorization checks. This intentionally changes invalid
query behavior and corrects tests that formerly preserved end-day exclusion.

## Acceptance evidence and limits

The combined suite includes real-CSRF account errors, copied-session revocation,
CSP enforcement, metadata/reveal/sharing behavior, desktop/mobile screenshots,
synthetic migration/recovery, container readiness and runtime dependency auditing.
Audit tests cover day boundaries, invalid dates, three browser timezones, delayed
JSON success/error ordering, retained filters and filtered CSV. A real Chromium
scenario fetches actual historical fixture rows, delays response bodies and checks
same-day inclusion plus CSV contents under America/New_York.

This remains a synthetic-only legacy hardening milestone. It does not decide
manual lock/logout/cooldown policies, restore-session invalidation, personal/team
recovery or v2 cryptographic architecture. Server-held Fernet decryption remains;
there is no zero-knowledge, production-readiness or professional-certification
claim. No live data, new credentials, paid hosting, DNS, deployment, branch
protection or automatic merge configuration is part of this candidate.

CSV display exports prefix formula-shaped values with visible `Text: `, then
escape quoted field structure. Leading formula characters, controls and their
full-width variants are covered. Original audit storage and on-screen text stay
unchanged; this export is not a byte-for-byte archival format. Current invalid-
password audit messages can begin with manager/admin-chosen usernames, and old
stored text is not assumed trustworthy. This is a preventive export boundary,
not a demonstrated remote-code exploit in the current event format or a claim
of testing every spreadsheet application. The visible prefix deliberately avoids
relying on apostrophe escaping surviving spreadsheet save/reopen. See
[OWASP CSV Injection](https://community.owasp.org/attacks/CSV_Injection).
