# CI and Render preparation: legacy v1, synthetic data only

Status: preparation draft, not deployed. Baseline: audit-authorization PR #19,
commit `3825a1de94300a44513d721307b508cb8499aee1`. That draft must be reviewed
and adopted first, or this work reviewed as a stack. No main merge, Render
resources, keys, DNS records, repository settings, or live vault changes are
part of this preparation. `oldcapstone-synthetic` is a proposed service name;
a test subdomain under skirby.net remains an owner decision.

## Recommendation and cost

Start with one Free Render Docker web service, SQLite, and a single Gunicorn
worker. This preserves the tested SQLite path without claiming compatibility
with PostgreSQL. It is an explicitly disposable demonstration: data disappears
on deploy/restart and idle spin-down. It sleeps after 15 minutes; waking can
take about a minute. Never import real vault contents or reuse real passwords.
Render's Free workspace allowance is 750 instance-hours per month.

If retaining synthetic test data matters, choose the $7/month 0.5c-512mb web
plan plus a 1 GB disk at $0.25/GB/month: approximately $7.25/month before tax,
usage overages, or extra services. Mount the disk at `/data`; only files beneath
that mount persist. Disks require a paid instance, allow only one instance,
and remove zero-downtime deploys. Verify the quoted total at setup time.

Render provides managed Postgres, but this patch intentionally rejects it:
v1's schema/queries/drivers/migrations need their own integration work first.
Free Postgres expires after 30 days and has no provider backup/recovery.
MySQL on Render is a self-managed private Docker service plus paid disk,
adding operations and expense unnecessary for this demonstration.

Sources checked 2026-10-12: [Free instances](https://render.com/docs/free),
[Pricing](https://render.com/pricing), [Compute names](https://render.com/docs/compute-plans),
[Disks](https://render.com/docs/disks), [MySQL](https://render.com/docs/deploy-mysql).

## What is prepared

- CI tests Python 3.12 (the supported version for this preparation), including
  the existing Node-based password-generator check, and runs an actual Gunicorn
  smoke test. Container CI builds and checks the non-root image and readiness.
- A blocking runtime dependency audit runs independently. Existing vulnerable
  dependencies must be fixed in a reviewed follow-up, not ignored to turn CI green.
- Runtime, test, and optional legacy database drivers are separated. SQLite
  CI/container builds need neither MySQL development libraries nor SQL Server ODBC.
- Startup validates distinct explicit session/JWT secrets, a Fernet key,
  database backend, timeout and trusted hosts. No default database credentials,
  JWT fallback, random-per-restart session key, or debug server is used.
- Synthetic startup creates only empty tables. It never runs `SQL/setup_*`,
  `refreshdb.py`, or seed scripts and creates no default administrator.
- `/healthz` returns 200 only when all mapped tables/columns can be queried; errors return
  a generic 503. This is a bounded readiness probe, not a full schema/security audit.
- Docker uses an allowlist of application files, runs as UID 10001, excludes
  `.env`, keys, test databases, legacy SQL and maintenance scripts.

## Verify locally without a deployment

Use Python 3.12 and Node 22:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements/test.txt
python -m pip check
python -m pytest -q
python scripts/smoke_wsgi.py
```

Tests use public deterministic synthetic fixtures, create disposable SQLite
state and require no real keys. The WSGI smoke test invokes the real startup
script and verifies readiness, the index, anonymous audit denial and zero
seeded users/passwords. It binds only to 127.0.0.1 on local port 18080. Container CI uses port 18081.

The Docker build is `docker build -t capstone-synthetic:test .`. The workflow
contains the exact disposable-container smoke command. No registry publish,
deploy action, privileged secrets, scheduled runs, or paid resources are used.
The Docker base uses a floating Python 3.12 patch tag; image digest/SBOM pinning
remains a release-hardening task, not a reproducible-release claim.

## Configuration contract and compatibility changes

`.env.example` contains placeholders and intentionally cannot start. Do not
put real values in Git, chat, screenshots or CI. Configure the distinct session
secret, JWT secret and Fernet key through the hosting provider's secure UI when
setup is approved. Keep the same Fernet key with any retained database; replacing
it loses access to that database's encrypted values. Preserve signing secrets
across restarts. Existing JWT fallback users must invalidate old sessions/tokens.

`APP_ENV=production` is intentionally rejected: this application is a prototype.
`synthetic` requires `SYNTHETIC_DATA_ONLY=true`, SQLite with an absolute path,
and explicit `TRUSTED_HOSTS`. On Render set trusted hosts to the exact assigned
onrender.com hostname and, later, the approved custom hostname (comma-separated,
no scheme or paths). There is no wildcard or automatic trust of request headers.

For legacy local MySQL/MSSQL development, `APP_ENV=development` accepts explicit
`DATABASE_URL`, or all DB_USER/DB_PASSWORD/DB_HOST/DB_NAME/DB_TYPE fields. Install
`requirements.txt` and the appropriate native client/ODBC libraries yourself.
Fernet may be read from `secret.key` only in development. SQL Server no longer
implicitly trusts the server certificate; fix certificate trust explicitly.
The SQLite image has no MySQL/ODBC drivers, and neither backend was integration-
tested in this patch. Secure cookies require HTTPS for interactive login even
locally. Never import the legacy known-admin SQL seeds for hosted testing.

## Launch gates: not cleared by this patch

Do not connect the Blueprint or publish a domain until these are reviewed:

1. Review/merge the audit fix and this proposed change, then run all CI jobs on
   the exact approved deployed branch commit. Repository protection/required
   status settings still need the owner's deliberate configuration.
2. Remediate dependency-audit failures; review the broader route authorization
   and role hierarchy, API-login response wrapper, API lockout consistency,
   error disclosure and audit-message rendering. The actual API-login route returns
   HTTP 200 with a JSON error tuple for locked accounts; existing helper tests
   reconstruct the route and mask this bug. The app still decrypts
   credentials on the server and sends plaintext to clients. It is not zero knowledge.
3. Decide the access boundary for the demonstration. An obscure subdomain is
   not authentication. Internet exposure is blocked pending security review
   and an approved authentication/access-control plan.
4. Add/review a one-time administrator initialization workflow with no default
   credentials. Currently the hosted schema is empty: there is deliberately no
   login credential and no account-creation bypass. This is a launch blocker.
5. Decide disposable or persistent SQLite, allowed spend, test subdomain, and
   service lifetime. If disposable, add a visible reset/synthetic-data notice
   before making the interactive demo available.
6. Review reverse-proxy/rate-limit behavior. Single-worker memory limiting is
   only a test constraint; it resets on restart and may group clients behind
   the proxy. This preparation does not blindly trust forwarded client headers.
7. For retained data, add migrations and tested consistent backup/restore.
   `create_all()` creates absent tables; it never upgrades an existing schema.

## Eventual approved setup sequence

1. Approve launch scope and limits, resolve the launch gates, and retain a green
   reviewed commit. Create the service in the personal Render account, not the
   knowledge-portal environment. Do not share either app's database or secrets.
2. Use `deployment/render.yaml.example` only after that approval. It is deliberately
   not root `render.yaml`. Creating a Blueprint launches resources even when
   `autoDeployTrigger: 'off'`; Blueprint Auto Sync is a separate setting, on by
   default. Set Auto Sync to No until configuration sync is approved.
3. Supply secrets through the secure provider UI. `sync: false` prompts during
   initial Blueprint creation only. No keys are generated by this patch.
4. Validate HTTPS, readiness, no sample/default accounts, bootstrap, authorization,
   login/logout, CRUD/sharing and reset behavior using synthetic values.
5. Once explicitly approved, add the custom domain in Render and a DNS CNAME
   to the assigned onrender.com host. Render verifies and provisions TLS. The
   default hostname remains accessible unless deliberately disabled; apply the
   same access boundary to both. No DNS values are guessed in this plan.
6. After the first manually reviewed deployment, switch to
   `autoDeployTrigger: checksPass` if desired. Render accepts successful, neutral
   and skipped checks, so required jobs must actually run and must not use
   `continue-on-error` or path skips. Zero checks or failed checks blocks auto
   deployment. Manual deployment is a separate bypass needing operator review.

Sources: [Blueprint lifecycle](https://render.com/docs/infrastructure-as-code),
[Blueprint specification](https://render.com/docs/blueprint-spec),
[CI gating](https://render.com/docs/deploys),
[Health checks](https://render.com/docs/health-checks),
[Secrets](https://render.com/docs/configure-environment-variables),
[Custom domains](https://render.com/docs/custom-domains),
[DNS](https://render.com/docs/configure-other-dns),
[Gunicorn on Render](https://render.com/docs/deploy-flask).

## Recovery and rollback boundaries

For disposable mode, the recovery policy is intentional reset: stop the service,
redeploy the reviewed code and recreate empty tables. No important data may rely
on it. No seed account is recreated. Code rollback cannot restore deleted data.

For durable SQLite, stop writes and use SQLite's backup API/online backup tool
for a consistent copy; retain its corresponding Fernet key separately and test
restoration into an isolated instance. Render's daily disk snapshots (at least
seven days) do not replace database-consistent backups. Never blindly copy a live
SQLite file or assume snapshots are safe database recovery. Define a restore
drill and retention policy before choosing persistent mode. Roll back code only
when schema compatibility is verified; there is no migration rollback system yet.

## Roadmap alignment

This is bounded progress on P0-031, P0-040, P0-046 and P0-048, plus configuration
preparation related to P0-015/017/018/025. It does not complete P0-016 (bootstrap),
P0-038 (migrations), the Phase 0 gate or any production/release gate. Secret
scanning, static security analysis, full database/browser integration tests,
coverage, supply-chain attestation and automatic release remain future work.

## Verification snapshot (2026-10-12)

- Baseline audit branch: 48 tests passed using the earlier dependency environment.
- Clean Python 3.12 environment: full `requirements/test.txt` install succeeded;
  75 tests passed, 11 existing deprecation warnings; actual Gunicorn smoke,
  `pip check`, compile checks and `git diff --check` passed.
- Independent review reproduced the initial suite and found loopback/readiness
  gaps, corrected with additional regressions before packaging.
- `pip-audit==2.10.1 -r requirements/runtime.txt` completed and FAILED as intended:
  54 reported advisories across cryptography 44.0.1, Flask 3.1.0,
  flask-cors 5.0.1, PyJWT 2.10.1, Pygments 2.19.1, Jinja2 3.1.5,
  Werkzeug 3.1.3 and python-dotenv 1.0.1. Advisory counts are tool findings,
  not an independently deduplicated exploit count. Remediation needs its own
  compatibility/security review; these pins were not silently upgraded here.
- Docker is unavailable in this workspace: container build/run has NOT been
  executed. The prepared CI job must prove this from a clean runner.
- At initial local packaging, no remote CI run or publication had occurred.
  The owner subsequently approved a separate stacked draft PR and CI execution.
  Check the PR for remote verification; no deployment or DNS changes are authorized.
  The known dependency-audit findings prevent a green-pipeline claim.
