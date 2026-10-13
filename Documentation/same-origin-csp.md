# Same-origin browser resources and CSP

The legacy templates loaded external jQuery even though application scripts use
native DOM APIs and bundled Bootstrap 5.3.5 does not require jQuery. Those unused
loads are removed rather than copying another library into the application.
The old /static/bootstrap URLs were shadowed by Flask-Bootstrap routes and
actually served Bootstrap 3.3.7. The templates now use an unambiguous versioned
vendor path for the repository's existing Bootstrap 5.3.5 CSS/JS. A real HTTP
regression compares served bytes against those files. Check visual layout during
manual acceptance because the accidentally served legacy CSS is replaced.
Bootstrap CSS/JS are local; asset-manifest.json records their existing hashes
and header version. This is change detection, not an upstream provenance audit or
claim of a vulnerability-free vendor bundle. No vendor bytes were changed.

All responses now enforce self-only scripts/styles/connections/fonts/forms,
no inline scripts/event handlers/eval, no inline style attributes, no object
embeds, no base tag overrides and no framing. Images allow same-origin and data
URLs for Bootstrap's embedded SVG controls. No search/CDN origins are allowlisted.
Current DOM property style updates (feedback colors and audit row filtering) are
covered by browser compatibility checks; do not replace them with HTML style
attributes or weaken the policy when adding UI.

The real Chromium smoke visits login/item views and administrator account/audit
views, exercises existing reveal/edit/share/reset flows, rejects external network
attempts and unexpected CSP violations, then verifies an injected inline script
is actually blocked. The policy is enforced, not merely report-only. All tests
use disposable public fixtures; no hosting or live configuration is changed.

This reduces external executable dependencies and common injection paths. It
cannot protect against compromised same-origin scripts, server delivery, browser
extensions or a hostile device. Existing server-side vault decryption remains
unchanged; this is not a zero-knowledge or release-readiness claim.

CI also saves seven-day synthetic screenshot artifacts for desktop, narrow desktop,
and touch/mobile-emulated login, vault, owner sharing and admin views. A separate
fresh fixture process prevents visual navigation from consuming the authentication
smoke's rate limit. Initial captures exposed missing viewport metadata and shared
username/control overflow; device-width metadata and bounded wrapping fix these
without changing the workflow. Assertions check mobile viewport width, page
horizontal overflow and selected-item control containment. Screenshots contain
public fixtures only, captured with vault values hidden; no cookies/storage-state
files are uploaded. Manual taste/accessibility review remains useful.
