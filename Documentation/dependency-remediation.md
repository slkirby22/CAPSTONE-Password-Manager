# Runtime dependency remediation (P0-030)

Status: isolated draft, 2026-10-12. Based on CI-preparation draft #20 at
`9e3170afebcbf2088ac5039850c98053f44bf1e0`, itself stacked on audit-fix draft
#19. This is Phase 0 legacy stabilization in support of v2, not a v2 encryption
implementation or permission to merge/deploy. Original main is unchanged.

## Changes and rationale

The baseline [PR #20 audit run](https://github.com/slkirby22/CAPSTONE-Password-Manager/actions/runs/38298832118)
reported 54 advisory entries across eight packages. The raw report includes
repeated advisory IDs; 54 is not a unique vulnerability or exploit count.
Upgrade the affected packages to current stable releases verified against PyPI
and upstream changelogs on 2026-10-12:

| Package | Previous | Proposed |
|---|---|---|
| cryptography | 44.0.1 | 50.0.2 |
| Flask | 3.1.0 | 3.1.3 |
| flask-cors | 5.0.1 | 6.0.5 |
| Jinja2 | 3.1.5 | 3.1.6 |
| PyJWT | 2.10.1 | 2.15.1 |
| Pygments | 2.19.1 | 2.21.0 |
| Werkzeug | 3.1.3 | 3.1.9 |
| python-dotenv | 1.0.1 | 1.2.4 |
| cffi (required compatibility dependency) | 1.17.1 | 2.0.0 |

`cryptography` 50.0.2 requires cffi >=2.0.0 on CPython. This is the only
additional dependency changed. Runtime/test/optional-driver separation is
preserved. The audit job, scanner version and blocking exit behavior are
unchanged: no ignored IDs, skipped dependencies, or `continue-on-error`.

Primary upstream references:
- [cryptography changelog](https://cryptography.io/en/latest/changelog/)
- [PyJWT changelog](https://pyjwt.readthedocs.io/en/stable/changelog.html)
- [Flask changelog](https://flask.palletsprojects.com/en/stable/changes/)
- [Flask-CORS releases](https://github.com/corydolphin/flask-cors/releases)
- [Jinja changelog](https://jinja.palletsprojects.com/en/stable/changes/)
- [Werkzeug changelog](https://werkzeug.palletsprojects.com/en/stable/changes/)
- [Pygments changelog](https://pygments.org/docs/changelog/)
- [python-dotenv changelog](https://github.com/theskumar/python-dotenv/blob/main/CHANGELOG.md)

## Compatibility and evidence

Supported verification target remains Python 3.12 on Linux with SQLite, the
same scope as #20. Cryptography upstream has removed Intel macOS and 32-bit
Windows support in 49.0.0; those platforms are not newly certified by this PR.
MySQL, SQL Server, mobile clients and every OS/CPU combination remain untested.

The added real-application tests cover:
- Scrypt account login using a public synthetic hash created with the baseline.
- Reading a synthetic Fernet ciphertext created under cryptography 44.0.1
  through the actual JWT-authenticated dashboard route after upgrading.
- Rejection of corrupted ciphertext and the wrong Fernet key.
- Actual token creation, protected access, logout and rejection after revocation.
- Rejection of expired, incorrectly signed, unsigned and malformed JWTs.
- CORS preflight for the exact configured localhost mobile origin; rejection of
  unrelated/lookalike/null origins and no CORS grant outside the API.

These tests intentionally preserve the current server-readable Fernet format.
They do not establish zero knowledge, compatibility with every historical record,
complete route authorization, or safe use with real credentials.

Local clean Python 3.12.14 environment results (Node 24.19.0 for the generator
test; CI retains Node 22): 75 existing baseline tests passed; 12 added
compatibility tests also passed under baseline dependencies; all 87 tests passed
under upgraded dependencies. `pip check` and the real Gunicorn synthetic smoke
passed. Runtime `pip-audit==2.10.1` resolved 37 packages with no known advisories
at check time. Existing deprecation warnings remain visible. Docker verification
is delegated to the unchanged container CI job because Docker is unavailable in
the local executor. Exact published-commit CI must be checked before adoption.

Reproduce (use separate virtual environments for scanner and runtime):

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements/test.txt
python -m pip check
python -m pytest -q
python scripts/smoke_wsgi.py
python3.12 -m venv /tmp/capstone-audit
/tmp/capstone-audit/bin/python -m pip install pip-audit==2.10.1
/tmp/capstone-audit/bin/python -m pip_audit -r requirements/runtime.txt
```

## Remaining gates and rollback

A clean package audit is a dated check against known Python package advisories,
not an application audit or proof that dependencies are trustworthy. It does
not scan vendored browser libraries, the OS/base image, optional database drivers,
or all development tools. Legacy Flask-Bootstrap/passlib and other aging code
remain modernization work; absence of a known advisory is not a maintenance
endorsement. Hash-locked builds, a pinned container digest, SBOM, static analysis,
and broader dependency coverage remain separate work.

No schema, secret, stored key, recovery workflow, role, or API contract is changed.
For a synthetic-only local compatibility investigation, use the baseline commit
and its isolated environment; do not recommend vulnerable dependencies for a
published service. Do not rotate the Fernet key as part of this upgrade.

Phase 0 remains incomplete, including role/ownership matrix review, API login
lockout consistency and response handling, route/error review, first-run setup,
migration/backup/restore, and disclosure documentation. All deployment gates in
[render-testing.md](render-testing.md) still apply. Real credentials remain out
of scope, and production mode remains unsupported.
