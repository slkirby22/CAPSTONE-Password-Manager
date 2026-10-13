# Account mutation input bounds

A disposable real-route reproduction found two failures: an administrator could
save an empty username, and an oversized password reached the hash adapter and
returned HTTP 500. Creation and update now validate their scalar username/password
fields before hashing or modifying account state. Invalid technical inputs render
safe HTTP 400 form errors without echoing submitted passwords.

Username length is checked after the existing uppercase conversion against the
model's 255-character limit. Empty/whitespace-only names are rejected; otherwise
names are not trimmed or Unicode-normalized. Password text is never trimmed,
normalized or truncated. The maximum is the installed Passlib adapter's existing
4096-character bound, not 4096 UTF8 bytes: supported non-ASCII passwords remain
valid. Both values must encode as valid UTF8. Existing complexity, role assignment,
blank-password-on-update, authentication and all-session invalidation behavior
remain unchanged. Missing or repeated username/password fields fail closed.

Tests cover real CSRF form submissions, no mutation or hashing on invalid input,
normalization expansion, exact boundaries, Unicode preservation, unchanged hash
on blank update and browser-visible form errors. Synthetic browser form checks
run in the isolated visual fixture so they don't alter the auth smoke's rate
budget. There is no live account or credential setup in this change.

This does not migrate historical malformed usernames, redesign username syntax,
change login compatibility or add account lifecycle policy. Concurrent uniqueness
races and broader transactional account/audit handling remain separate work.
