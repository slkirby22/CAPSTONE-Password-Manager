/* Real Chromium smoke with pinned test-only Playwright. Public fixtures only. */
'use strict';
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const base = process.env.BROWSER_SMOKE_BASE;
const fixture = JSON.parse(process.env.BROWSER_SMOKE_FIXTURE);
const firstSecret = 'Public-item-one-123!';
const secondSecret = 'Public-item-two-123!';
const replacement = 'Public-replacement-456!';
function ciphertext() {
    return execFileSync(process.env.BROWSER_SMOKE_PYTHON, ['-c',
        "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); v=c.execute('select password from password where item_id=?',(sys.argv[2],)).fetchone()[0]; print(v.decode() if isinstance(v,bytes) else v)",
        process.env.BROWSER_SMOKE_DB, fixture.first], {encoding: 'utf8'}).trim();
}
(async () => {
    const options = {headless: true};
    if (process.env.BROWSER_SMOKE_CHROMIUM) options.executablePath = process.env.BROWSER_SMOKE_CHROMIUM;
    const browser = await chromium.launch(options);
    const externalRequests = [];
    const policyViolations = [];
    async function prepareContext(ctx) {
        await ctx.exposeBinding('recordPolicyViolation', (_, directive) => policyViolations.push(directive));
        await ctx.addInitScript(() => {
            document.addEventListener('securitypolicyviolation', event => window.recordPolicyViolation(event.effectiveDirective));
        });
        await ctx.route('**/*', route => {
            if (new URL(route.request().url()).origin === base) return route.continue();
            externalRequests.push(route.request().url());
            return route.abort();
        });
    }
    const context = await browser.newContext({timezoneId: 'America/New_York'});
    await prepareContext(context);
    // This smoke makes no external network requests; app scripts/styles are local.

    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    // Install before page scripts create any timers; later fastForward controls them.
    await page.clock.install();
    const failures = [];
    page.on('pageerror', error => failures.push(error.message));
    let logoutCount = 0;
    page.on('request', request => { if (new URL(request.url()).pathname === '/logout') logoutCount++; });
    let revealCount = 0;
    page.on('request', request => { if (request.url().endsWith('/reveal')) revealCount++; });
    async function hidden() {
        assert.equal(await page.locator('#revealed-password').textContent(), '');
        assert.equal(await page.locator('#revealed-password').isVisible(), false);
        assert.equal(await page.locator('#reveal-password').getAttribute('aria-expanded'), 'false');
    }
    async function select(id) {
        const response = await page.goto(`${base}/passwords/${id}`);
        assert.equal(response.status(), 200);
        assert.equal(response.headers()['cache-control'], 'no-store');
        const html = await response.text();
        for (const value of [firstSecret, secondSecret, replacement, fixture.ciphertext]) assert(!html.includes(value));
        await hidden();
    }
    async function reveal(value) {
        const pending = page.waitForResponse(response => response.url().endsWith('/reveal'));
        await page.locator('#reveal-password').click();
        const response = await pending;
        assert.equal(response.status(), 200);
        assert.equal(response.headers()['cache-control'], 'no-store');
        await page.waitForFunction(value => document.querySelector('#revealed-password').textContent === value, value);
        assert.equal(await page.locator('#replacement-password').count() ? await page.locator('#replacement-password').inputValue() : '', '');
    }
    async function login(name, password = 'Public-login-fixture-123!') {
        await page.goto(`${base}/login`);
        assert(await page.locator('[name=csrf_token]').inputValue());
        await page.locator('#username').fill(name);
        await page.locator('#password').fill(password);
        await Promise.all([page.waitForURL('**/dashboard'), page.getByRole('button', {name: 'Login', exact: true}).click()]);
        const cookie = (await context.cookies()).find(cookie => cookie.name === 'session');
        assert(cookie && cookie.secure && cookie.httpOnly && cookie.sameSite === 'Lax');
    }
    async function holdRealJson() {
        await page.evaluate(() => {
            const nativeFetch = window.fetch;
            window.__held = [];
            window.fetch = async (...args) => {
                const response = await nativeFetch(...args);
                if (String(args[0]).endsWith('/reveal')) {
                    const value = await response.clone().json();
                    response.json = () => new Promise(resolve => window.__held.push(() => resolve(value)));
                }
                return response;
            };
        });
    }
    async function releaseHeld() {
        await page.evaluate(() => window.__held.shift()());
        await page.waitForTimeout(75);
    }
    const screenshotDir = process.env.BROWSER_SMOKE_VISUAL_ONLY === '1' ? process.env.BROWSER_SMOKE_SCREENSHOTS : null;
    const layoutReports = [];
    async function capture(target, name) {
        if (!screenshotDir) return;
        fs.mkdirSync(screenshotDir, {recursive: true});
        const previous = target.viewportSize();
        for (const [size, viewport] of Object.entries({desktop: {width: 1440, height: 1000}, narrow: {width: 390, height: 844}})) {
            await target.setViewportSize(viewport);
            await target.evaluate(() => document.fonts.ready);
            await target.screenshot({path: path.join(screenshotDir, `${name}-${size}.png`), fullPage: true});
            layoutReports.push(await target.evaluate(({name, size}) => ({name, size,
                viewport: innerWidth, scrollWidth: document.documentElement.scrollWidth,
                viewportMeta: document.querySelector('meta[name="viewport"]')?.content || null,
                controls: [...document.querySelectorAll('button,input:not([type="hidden"]),select,a.btn')].filter(el => el.getClientRects().length).map(el => {
                    const r = el.getBoundingClientRect();
                    return {label: el.textContent.trim() || el.getAttribute('aria-label') || el.id || el.name,
                        x: r.x, y: r.y, width: r.width, height: r.height};
                })}), {name, size}));
        }
        await target.setViewportSize(previous);
        const mobileContext = await browser.newContext({viewport: {width: 390, height: 844},
            isMobile: true, hasTouch: true, deviceScaleFactor: 1,
            storageState: await target.context().storageState()});
        await prepareContext(mobileContext);
        try {
            const mobile = await mobileContext.newPage();
            mobile.on('pageerror', error => failures.push(error.message));
            await mobile.goto(target.url());
            await mobile.evaluate(() => document.fonts.ready);
            await mobile.screenshot({path: path.join(screenshotDir, `${name}-mobile.png`), fullPage: true});
            layoutReports.push(await mobile.evaluate(name => ({name, size: 'mobile-emulated',
                viewport: innerWidth, scrollWidth: document.documentElement.scrollWidth,
                viewportMeta: document.querySelector('meta[name="viewport"]')?.content || null}), name));
            const geometry = layoutReports[layoutReports.length - 1];
            assert.equal(geometry.viewport, 390, 'Mobile layout must use the device viewport');
            assert(geometry.scrollWidth <= 390, 'Mobile page must not overflow horizontally');
            const overflow = await mobile.locator('.password-form input:not([type=hidden]), .password-form button, .password-form li').evaluateAll(elements => elements.filter(el => {
                const outer = el.closest('.password-form').getBoundingClientRect();
                const inner = el.getBoundingClientRect();
                return el.getClientRects().length && (inner.left < outer.left - 1 || inner.right > outer.right + 1);
            }).length);
            assert.equal(overflow, 0, 'Item controls must remain inside their card');
        } finally { await mobileContext.close(); }
        fs.writeFileSync(path.join(screenshotDir, 'layout-report.json'), JSON.stringify(layoutReports, null, 2));
    }
    try {
        if (process.env.BROWSER_SMOKE_VISUAL_ONLY === '1') {
            assert(screenshotDir, 'Visual-only run requires an artifact directory');
            await page.goto(`${base}/login`);
            await capture(page, 'login');
            await login('BROWSEROWNER');
            await capture(page, 'vault');
            await select(fixture.first);
            await capture(page, 'owner-share');
            await page.goto(`${base}/logout`);
            await login('BROWSERADMIN');
            await page.goto(`${base}/view_users`);
            await capture(page, 'admin-users');
            await page.goto(`${base}/create_user`);
            await page.locator('#username').fill('PUBLIC-INVALID-BOUND');
            await page.locator('#password').fill('A1!' + 'x'.repeat(4096));
            let submitted = page.waitForResponse(response => new URL(response.url()).pathname === '/create_user' && response.request().method() === 'POST');
            await page.getByRole('button', {name: 'Create User', exact: true}).click();
            assert.equal((await submitted).status(), 400);
            await page.locator('.error').waitFor();
            assert((await page.locator('.error').textContent()).includes('4096'));
            assert.equal(await page.locator('#password').inputValue(), '');
            await page.goto(`${base}/view_users`);
            await page.locator('#selected_user_id').selectOption(String(fixture.shared_id));
            await Promise.all([page.waitForNavigation(), page.getByRole('button', {name: 'Edit Selected User', exact: true}).click()]);
            await page.locator('input[name=username]').fill('');
            await page.locator('input[name=username]').evaluate(element => element.removeAttribute('required'));
            submitted = page.waitForResponse(response => new URL(response.url()).pathname === `/update_user/${fixture.shared_id}`);
            await page.getByRole('button', {name: 'Update User', exact: true}).click();
            assert.equal((await submitted).status(), 400);
            await page.locator('.error').waitFor();
            assert((await page.locator('.error').textContent()).includes('Username'));
            assert.equal(await page.locator('input[name=username]').inputValue(), 'BROWSERSHARED');
            await page.goto(`${base}/audit_log_viewer`);
            await page.waitForFunction(() => [...document.querySelectorAll('#audit-logs-table tbody tr')].some(row => row.cells.length === 5));
            // Hold actual server JSON after it arrives, then release in reverse order.
            await page.evaluate(() => {
                const original = window.fetch;
                window.__auditHeld = [];
                window.fetch = async (...args) => {
                    const response = await original(...args);
                    if (String(args[0]).startsWith('/get_audit_logs')) {
                        const body = await response.json();
                        return {ok: response.ok, json: () => new Promise((resolve, reject) => window.__auditHeld.push({body, resolve, reject}))};
                    }
                    return response;
                };
            });
            // Set both fields without implicit input/change events producing extra requests.
            async function exactAuditRange(day) {
                await page.evaluate(day => {
                    document.querySelector('#start-date').value = day;
                    document.querySelector('#end-date').value = day;
                    document.querySelector('#end-date').dispatchEvent(new Event('change'));
                }, day);
            }
            await exactAuditRange('2025-01-01');
            await page.waitForFunction(() => window.__auditHeld.length === 1);
            await page.locator('#message-filter').fill('second day');
            await exactAuditRange('2025-01-02');
            await page.waitForFunction(() => window.__auditHeld.length === 2);
            await page.evaluate(() => {const next = window.__auditHeld[1]; next.resolve(next.body);});
            await page.waitForFunction(() => document.querySelectorAll('#audit-logs-table tbody tr').length === 3);
            const visibleAudit = page.locator('#audit-logs-table tbody tr:visible');
            assert.equal(await visibleAudit.count(), 2);
            assert((await visibleAudit.allTextContents()).every(text => text.includes('second day')));
            await page.locator('#event-type-filter').selectOption('FIXTURE');
            await page.evaluate(() => {const old = window.__auditHeld[0]; old.resolve(old.body);});
            await page.waitForTimeout(75);
            assert.equal(await visibleAudit.count(), 2);
            assert(!(await page.locator('#audit-logs-table tbody').textContent()).includes('first day'));
            // A late failure must not erase a successful newer range either.
            await exactAuditRange('2025-01-01');
            await page.waitForFunction(() => window.__auditHeld.length === 3);
            await page.locator('#message-filter').fill('second day');
            await exactAuditRange('2025-01-02');
            await page.waitForFunction(() => window.__auditHeld.length === 4);
            await page.evaluate(() => {const next = window.__auditHeld[3]; next.resolve(next.body);});
            await page.waitForFunction(() => document.querySelectorAll('#audit-logs-table tbody tr').length === 3);
            await page.evaluate(() => window.__auditHeld[2].reject(new Error('Synthetic late response failure')));
            await page.waitForTimeout(75);
            assert.equal(await page.locator('#event-type-filter').inputValue(), 'FIXTURE');
            assert.equal(await visibleAudit.count(), 2);
            const downloaded = page.waitForEvent('download');
            await page.locator('#export-csv').click();
            const download = await downloaded;
            const csv = fs.readFileSync(await download.path(), 'utf8');
            assert(csv.includes('second day midnight') && csv.includes('second day late'));
            assert(!csv.includes('first day') && !csv.includes('excluded message') && !csv.includes('Loading...'));
            console.log('PASS real audit same-day range, latest-response wins, loading filters, preserved text/type filters and filtered CSV under America/New_York');
            assert.deepEqual(failures, []);
            assert.deepEqual(externalRequests, []);
            assert.deepEqual(policyViolations, []);
            console.log('PASS actual-CSRF browser forms show safe errors for oversized password and empty username; existing user retained');
            console.log('PASS isolated synthetic desktop, narrow and mobile visual capture');
            return;
        }
        await page.goto(`${base}/`);
        // Dispatch deterministically while the document is alive: a real unload
        // may cancel its fetch before the test sees it, hiding the cookie race.
        const unloadLogouts = await page.evaluate(async () => {
            const nativeFetch = window.fetch;
            const pending = [];
            window.fetch = (...args) => {
                const response = nativeFetch(...args);
                if (new URL(String(args[0]), location.href).pathname === '/logout') {
                    pending.push(response);
                }
                return response;
            };
            try {
                window.dispatchEvent(new Event('beforeunload'));
                await Promise.all(pending);
                return pending.length;
            } finally { window.fetch = nativeFetch; }
        });
        assert.equal(unloadLogouts, 0, 'Landing-page unload must not issue a background logout');
        console.log('PASS landing-page unload does not issue a session-clearing request');
        await login('BROWSEROWNER');
        assert.equal(logoutCount, 0, 'Landing-to-login navigation must not issue logout');
        const metadata = await page.content();
        assert(!metadata.includes(firstSecret) && !metadata.includes(secondSecret));
        assert.equal(revealCount, 0);
        assert.equal(await page.locator('nav a').count(), 2);
        await page.locator(`nav a[href="/passwords/${fixture.second}"]`).click();
        assert.equal(new URL(page.url()).pathname, `/passwords/${fixture.second}`);
        assert.equal(await page.locator('#username').inputValue(), 'second-login');
        await reveal(secondSecret);
        await page.locator('#hide-password').click();
        await hidden();
        await select(fixture.first);
        await reveal(firstSecret);
        await page.locator('#hide-password').click();
        await hidden();
        console.log('PASS metadata-only initial views, duplicate-name exact selection, owner reveal/hide, Secure/HttpOnly/SameSite cookie, no-store');
        assert.equal(ciphertext(), fixture.ciphertext);
        await page.locator('#username').fill('first-login-edited');
        await page.locator('#notes').fill('edited public notes');
        await Promise.all([page.waitForURL('**/dashboard'), page.getByRole('button', {name: 'Update', exact: true}).click()]);
        assert.equal(ciphertext(), fixture.ciphertext);
        await select(fixture.first);
        assert.equal(await page.locator('#username').inputValue(), 'first-login-edited');
        await page.locator('#replace-password').check();
        await page.locator('#replacement-password').fill(replacement);
        await Promise.all([page.waitForURL('**/dashboard'), page.getByRole('button', {name: 'Update', exact: true}).click()]);
        assert.notEqual(ciphertext(), fixture.ciphertext);
        await select(fixture.first);
        await reveal(replacement);
        console.log('PASS actual-CSRF metadata edit preserves ciphertext; explicit replacement changes secret');
        await page.locator(`nav a[href="/passwords/${fixture.second}"]`).click();
        await hidden();
        await page.goBack();
        await hidden();
        await reveal(replacement);
        await page.clock.fastForward(30001);
        await hidden();
        await page.clock.resume();
        console.log('PASS navigation/back cleanup; browser-clock 30-second automatic hide');
        await holdRealJson();
        await page.locator('#reveal-password').click();
        await page.waitForFunction(() => window.__held.length === 1);
        await page.locator('#hide-password').click();
        await releaseHeld();
        await hidden();
        await page.locator('#reveal-password').click();
        await page.waitForFunction(() => window.__held.length === 1);
        await page.locator('#hide-password').click();
        await page.locator('#reveal-password').click();
        await page.waitForFunction(() => window.__held.length === 2);
        await releaseHeld();
        await hidden();
        await releaseHeld();
        await page.waitForFunction(value => document.querySelector('#revealed-password').textContent === value, replacement);
        await page.locator('#hide-password').click();
        await hidden();
        await page.locator('#reveal-password').click();
        await page.waitForFunction(() => window.__held.length === 1);
        await page.locator(`nav a[href="/passwords/${fixture.second}"]`).click();
        await hidden();
        await page.goBack();
        await hidden();
        console.log('PASS actual server JSON delayed after fetch: hide, repeated stale responses, and navigation/back cannot restore plaintext');
        await select(fixture.first);
        await reveal(replacement);
        await Promise.all([
            page.waitForURL(base + '/'),
            page.getByRole('link', {name: 'Logout', exact: true}).click()
        ]);
        assert(!(await page.content()).includes(replacement));
        await page.goBack();
        assert(!(await page.content()).includes(replacement));
        await page.goto(`${base}/login`);
        const anonymousCsrf = await page.locator('[name=csrf_token]').inputValue();
        assert.equal(logoutCount, 1, 'Only the explicit logout action may issue logout');
        const missingCsrf = await page.evaluate(async id => {
            const response = await fetch(`/passwords/${id}/reveal`, {
                method: 'POST', credentials: 'same-origin'
            });
            return {status: response.status, body: await response.json()};
        }, fixture.first);
        assert.deepEqual(missingCsrf, {status: 400, body: {error: 'The CSRF token is missing.'}});
        const denied = await page.evaluate(async ({id, csrf}) => {
            const response = await fetch(`/passwords/${id}/reveal`, {
                method: 'POST', headers: {'X-CSRFToken': csrf}, credentials: 'same-origin'
            });
            return {status: response.status, body: await response.json()};
        }, {id: fixture.first, csrf: anonymousCsrf});
        assert.deepEqual(denied, {status: 401, body: {error: 'Authentication required'}});
        await login('BROWSERSHARED');
        assert.equal(await page.locator('nav a').count(), 1);
        await select(fixture.first);
        assert.equal(await page.locator(`form[action$="/update"],form[action$="/delete"],#replace-password`).count(), 0);
        await reveal(replacement);
        const csrf = await page.locator('#item-reveal').getAttribute('data-csrf-token');
        const mutation = await page.evaluate(async ({id, csrf}) => {
            const response = await fetch(`/passwords/${id}/update`, {
                method: 'POST', credentials: 'same-origin',
                body: new URLSearchParams({csrf_token: csrf, username: 'forbidden'})
            });
            return response.status;
        }, {id: fixture.first, csrf});
        assert.equal(mutation, 404);
        const unshared = await page.evaluate(async id => (await fetch(`/passwords/${id}`, {credentials: 'same-origin'})).status, fixture.second);
        assert.equal(unshared, 404);
        console.log('PASS logout/back cleanup; shared reveal, absent mutation controls, real-CSRF mutation rejection, unshared item rejection');
        // Reset a disposable shared account while retaining its actual browser
        // cookie, page CSRF token, and independently issued JWT.
        await page.locator('#hide-password').click();
        await hidden();
        const sharedToken = await page.evaluate(async () => {
            const response = await fetch('/api/login', {method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: 'BROWSERSHARED', password: 'Public-login-fixture-123!'})});
            if (response.status !== 200) throw new Error('Synthetic API login failed');
            return (await response.json()).access_token;
        });
        const oldCookies = await context.cookies();
        const adminContext = await browser.newContext();
        await prepareContext(adminContext);
        const adminPage = await adminContext.newPage();
        adminPage.on('pageerror', error => failures.push(error.message));
        try {
            await adminPage.goto(`${base}/login`);
            await adminPage.locator('#username').fill('BROWSERADMIN');
            await adminPage.locator('#password').fill('Public-login-fixture-123!');
            await Promise.all([adminPage.waitForURL('**/dashboard'), adminPage.getByRole('button', {name: 'Login', exact: true}).click()]);
            assert.equal((await adminPage.goto(`${base}/create_user`)).status(), 200);
            assert.equal((await adminPage.goto(`${base}/audit_log_viewer`)).status(), 200);
            await adminPage.waitForFunction(() => [...document.querySelectorAll('#audit-logs-table tbody tr')].some(row => row.cells.length === 5 && row.querySelector('.event-type')));
            await adminPage.locator('#message-filter').fill('NO-SUCH-PUBLIC-AUDIT-FIXTURE');
            assert.equal(await adminPage.locator('#audit-logs-table tbody tr:visible').count(), 0);
            await adminPage.locator('#clear-filters').click();
            await adminPage.goto(`${base}/view_users`);
            const resetCsrf = await adminPage.locator('[name=csrf_token]').first().inputValue();
            const resetStatus = await adminPage.evaluate(async ({id, csrf}) => (await fetch(`/update_user/${id}`, {
                method: 'POST', body: new URLSearchParams({csrf_token: csrf,
                    username: 'BROWSERSHARED', password: 'Public-reset-fixture-456!', role: 'employee'})
            })).status, {id: fixture.shared_id, csrf: resetCsrf});
            assert.equal(resetStatus, 200);
            const pending = page.waitForResponse(response => response.url().endsWith('/reveal'));
            await page.locator('#reveal-password').click();
            assert.equal((await pending).status(), 401);
            await page.waitForFunction(() => document.querySelector('#reveal-status').textContent.includes('Password unavailable.'));
            await hidden();
            assert(!(await page.content()).includes(replacement));
            // Replay the copied pre-reset cookie, not just the browser's cleared copy.
            await context.addCookies(oldCookies);
            const replay = await page.evaluate(async ({id, csrf, token}) => {
                const reveal = await fetch(`/passwords/${id}/reveal`, {method: 'POST', headers: {'X-CSRFToken': csrf}});
                const api = await fetch('/api/dashboard', {headers: {Authorization: 'Bearer ' + token}});
                return {web: reveal.status, jwt: api.status};
            }, {id: fixture.first, csrf, token: sharedToken});
            assert.deepEqual(replay, {web: 401, jwt: 401});
            assert.equal((await adminPage.goto(`${base}/view_users`)).status(), 200);
        } finally { await adminContext.close(); }
        await login('BROWSERSHARED', 'Public-reset-fixture-456!');
        await select(fixture.first);
        await reveal(replacement);
        await page.locator('#hide-password').click();
        await hidden();
        console.log('PASS committed admin reset invalidates copied browser cookie, stale-page reveal and JWT; fresh login restores authorized shared reveal');
        assert.deepEqual(failures, [], 'Application scripts must run without ignored jQuery errors');
        assert.deepEqual(externalRequests, [], 'UI must not depend on external resources');
        assert.deepEqual(policyViolations, [], 'Normal UI must satisfy the enforced CSP');
        await page.evaluate(() => {
            document.addEventListener('securitypolicyviolation', event => {
                if (event.effectiveDirective === 'script-src-elem') window.syntheticInlineCspViolation = true;
            });
            const script = document.createElement('script');
            script.textContent = 'window.syntheticInlineCspProbe = true';
            document.body.appendChild(script);
        });
        await page.waitForFunction(() => window.syntheticInlineCspViolation === true);
        const blocked = await page.evaluate(() => window.syntheticInlineCspProbe !== true);
        assert.equal(blocked, true, 'Real browser must block injected inline scripts');
        console.log('PASS same-origin assets, zero normal CSP violations, actual inline-script blocking');
        console.log(JSON.stringify({status: 'passed', browser: browser.version(), headless: true, server: 'Gunicorn single worker, real app routes', csrf: 'enabled; actual form tokens', cookie: 'production Secure flag unchanged; Chromium localhost exception', externalNetwork: 'blocked', applicationErrors: failures.length, externalRequests: externalRequests.length, cspInlineScriptBlocked: blocked, limitation: 'single browser/local synthetic data; Playwright default disables BFCache; no deployment or security-readiness claim'}));
    } finally { await context.close(); await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
