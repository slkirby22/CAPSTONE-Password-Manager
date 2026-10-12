# Browser password generation (P0-020)

## Bounded change

The browser generator in `static/js/functions.js` now uses only Web Crypto
`crypto.getRandomValues` with unsigned 32-bit samples. There is no `Math.random`
or other insecure fallback. This replaces the legacy non-cryptographic generator
and fixes its mismatch with the existing Python password policy. It does not
change the server policy, stored credentials, authentication, or vault encryption.

For each alphabet or shuffle choice, rejection sampling discards values in the
incomplete upper tail of the 32-bit range before taking the remainder. This
makes each bounded choice unbiased. A Fisher–Yates shuffle uses the same sampler,
including the current position as a possible swap destination. Guaranteeing one
character per category before filling and shuffling is not a claim of uniform
sampling over every possible policy-compliant password.

## Input and policy contract

- `generatePassword()` defaults to 12 characters, as does the existing UI call.
- Integer lengths below eight are clamped to eight, the existing server minimum.
  Fractional, nonnumeric, nonfinite, and unsafe-integer lengths fail explicitly.
- Every generated value includes uppercase, lowercase, a digit, and a special.
  Lowercase remains an additional generator guarantee, not a new server rule.
- The special alphabet is exactly `!@#$%^&*(),.?":{}|<>`, matching
  `password_meets_requirements` in `functions.py` and client strength feedback.
  The complete alphabet consists of ASCII uppercase, lowercase, digits, and that
  special alphabet. The previous extra punctuation can no longer be selected as
  the sole supposedly policy-satisfying special character.
- The existing server minimum and default UI length are retained as compatibility
  choices; this change is not a new password-strength policy or security audit.

If Web Crypto is absent, lacks `getRandomValues`, or raises an error, generation
fails without returning a partial value. The Generate button preserves the
existing input and displays an availability message beside it. There is no
fallback to predictable randomness. This failure presentation has a deterministic
DOM-contract test; it has not been verified in a full browser during this change.

## Deterministic acceptance

`tests/test_js_password_generation.py` loads the actual JavaScript in Node's VM
with a synthetic `getRandomValues` provider. The fixtures are public test data,
never credentials. `Math.random` is replaced with a throwing function. No test
uses real randomness or real vault values, and no stochastic rerun is needed to
obtain a green result.

Coverage includes:

- Existing Python policy assertions, category guarantees, default/minimum and
  explicit lengths, and invalid lengths.
- Every special character and every combined-alphabet position, including both
  endpoints of each category and the combined alphabet.
- The entire rejected modulo-bias tail for a bound of ten, the highest accepted
  sample, zero, a power-of-two bound, one, and the full uint32 bound.
- Invalid bounds and exact Fisher–Yates outcomes for zero and self-swap indexes.
- Absent or malformed crypto providers, provider failures, and a UI failure that
  leaves the existing synthetic input untouched.

Focused verification on 12 October 2026: **37 passed**, with one pre-existing
Passlib/Python `crypt` deprecation warning. `node --check static/js/functions.js`
and `git diff --check` passed. The default shell Python lacked pytest, so the
focused run used the existing sibling `.venv-upgraded` Python 3.12 environment.
A combined-suite run and broader Phase 0 acceptance belong to the coordinating
review; these focused results do not establish full application security.
