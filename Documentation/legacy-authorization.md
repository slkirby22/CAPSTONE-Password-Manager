# Legacy authorization hardening (P0-011/P0-012)

This is Phase 0 stabilization of the existing prototype, stacked on dependency
remediation draft #21. It is not v2 team-vault ownership, recovery, or a new
administrative access model. The original capstone remains on main; all work
is draft, synthetic-only and non-production.

## Current identity

Protected web helpers use the shared `require_web_user` policy. Each request
resolves the session user ID against the current database; cached role/name
values are refreshed for display only. Missing/deleted identities are denied
before target lookup, rendering or mutation. Manager and administrator checks
use the current database role, including after demotion. Audit HTML/JSON remain
administrator-only, with their prior redirect/401/403 contracts.

JWT-protected routes also resolve the token subject to a current account. A
signed token for a deleted/missing account receives generic HTTP 401, before
any credential mutation. This closes the orphan-row creation path. This does
not introduce lock-triggered revocation: locking continues to deny subsequent
login, not revoke existing sessions. The later
[password-change binding](password-session-revocation.md) revokes cookies/JWTs
when the account password replacement commits.

## Legacy actor/target matrix

| Operation | Administrator | Manager | Employee/unknown role |
|---|---|---|---|
| Create account | Any of the three recognized roles | Employee only | Denied |
| Update other account | Recognized target roles | Manager/employee targets only | Denied |
| Assign role on update | Any recognized role | Employee, or retain target's existing manager role | Denied |
| Update own profile | Allowed, role unchanged | Allowed, role unchanged | Denied |
| Lock/unlock/delete other account | Recognized target roles | Manager/employee targets only | Denied |
| Lock/unlock/delete self | Denied | Denied | Denied |
| Audit records | Allowed | Denied | Denied |

The manager-to-manager scope preserves the prior selection UI; managers cannot
create managers, promote employees, or touch administrators. Self-destructive
operations were already omitted from the UI and are now denied server-side.
Unknown role assignments fail closed before username/password/role mutation.
Denied web role gates and denied target/assignment changes retain structured
`UNAUTHORIZED_ACTION` audit records attributed to the current database identity.
Self profile requests ignore a crafted role field and keep the current role.
Unknown targets return safely without partial mutation or a server error.

Account selection is checked server-side. The broken legacy
`/select_user_for_edit` URL delegates to the existing working user-selection
view. The form uses current display roles and correct target variables; retaining
a manager peer's role no longer requires an invisible option.

## Credential ownership remains separate

Owners can read, update, delete, and change sharing of their own credentials.
Explicit sharing permits reading, not update/delete. Unrelated users have no
credential access. Administrator or manager status does not grant access to
other users' credential plaintext. Account deletion retains the prototype's
existing behavior of deleting the target account's owned entries; this is not
an approved team offboarding/retention model.

## Evidence and limits

The real-route matrix covers every recognized actor/target role combination,
unknown actor/assignment roles, malformed elevated assignments, unchanged state
on denial, current-role demotion, stale display roles, self-role preservation,
anonymous/deleted web identities, unknown targets, and CSRF rejection. Separate
object-level tests cover web/JWT ownership/sharing and missing JWT identities.
Existing audit authorization regression tests remain required.

Still open: the broader P0-023 route review (enumeration, unsafe logout method,
error contracts and schema/input limits), last-administrator lifecycle rules,
concurrent authorization changes, durable distributed throttling, temporary
lockout, token/session invalidation policy, immutable item selectors, plaintext
reveal behavior, migration/backup/restore, and independent security review.
No claim that P0 or v2 is complete follows from this matrix. Admins still operate
a server holding the legacy Fernet key, despite route-level access restrictions.
