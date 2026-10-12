# Audit log text rendering

The audit table's JSON refresh previously interpolated all five event fields
into `row.innerHTML`. Persisted audit messages can include user-supplied strings
such as usernames and service names. Reading those records must not turn that
text into HTML in an administrator's browser. Authorization alone does not
remove this rendering risk.

`static/js/audits.js` now constructs rows and cells with `createElement` and
assigns every field through `textContent`. Loading and error rows use the same
DOM-construction approach. The original column order, event-type class, status
cell's five-column span, and string conversion (including numeric IDs and
nullable user IDs) are preserved. Filters, event-type options, and CSV export
continue to consume literal cell text. Existing server-rendered Jinja cells
remain unchanged and retain their normal autoescaping.

## Regression evidence

Run from the repository root with the test dependencies and Node installed:

```sh
python -m pytest -q tests/test_js_audit_rendering.py
node --check static/js/audits.js
```

The tests load and execute the actual shipped script using Node's VM, following
the repository's existing Python-to-Node test pattern. A small DOM double
implements the text/children operations used by this page and rejects nonempty
`innerHTML` assignments. Assertions check rendered structure and values, rather
than searching the source for an API name:

- Synthetic hostile strings in each of the five fields remain exact text in
  five plain cells, with no nested elements.
- Event-type options preserve literal text and deduplicate values; message and
  event-type filtering still work.
- CSV export preserves the visible text and existing quote escaping.
- Repeated updates and empty results remove previous rows and stale options.
- Fetches show a five-column loading row, then data or an error row for HTTP,
  network, and JSON failures.

Before the fix, all 10 cases failed on attempted HTML parsing. After the fix,
all 10 passed. Only synthetic local data was used. This is executable DOM-contract
coverage, not a full browser parser or an active script-execution test; it does
not claim browser-engine or production-vault validation.

This bounded correction does not change audit authorization, storage, CSV
formula handling, or deployment settings. It requires review and deliberate
adoption before affecting an existing installation.
