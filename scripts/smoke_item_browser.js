/* Real Chromium smoke with pinned test-only Playwright. Public fixtures only. */
'use strict';
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
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
    const context = await browser.newContext();
    // This smoke makes no external network requests; app scripts/styles are local.
    await context.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort());
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    // Install before page scripts create any timers; later fastForward controls them.
    await page.clock.install();
    const failures = [];
    page.on('pageerror', error => failures.push(error.message));
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
    async function login(name) {
        await page.goto(`${base}/login`);
        assert(await page.locator('[name=csrf_token]').inputValue());
        await page.locator('#username').fill(name);
        await page.locator('#password').fill('Public-login-fixture-123!');
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
    try {
        await login('BROWSEROWNER');
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
        await page.getByRole('link', {name: 'Logout', exact: true}).click();
        assert(!(await page.content()).includes(replacement));
        await page.goBack();
        assert(!(await page.content()).includes(replacement));
        await page.goto(`${base}/login`);
        const anonymousCsrf = await page.locator('[name=csrf_token]').inputValue();
        const denied = await page.evaluate(async ({id, csrf}) => {
            const response = await fetch(`/passwords/${id}/reveal`, {
                method: 'POST', headers: {'X-CSRFToken': csrf}, credentials: 'same-origin'
            });
            return response.status;
        }, {id: fixture.first, csrf: anonymousCsrf});
        assert.equal(denied, 401);
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
        // Bootstrap expects external jQuery, intentionally blocked in this local-only smoke.
        assert(failures.every(message => /jQuery/.test(message)), JSON.stringify(failures));
        console.log(JSON.stringify({status: 'passed', browser: browser.version(), headless: true, server: 'Gunicorn single worker, real app routes', csrf: 'enabled; actual form tokens', cookie: 'production Secure flag unchanged; Chromium localhost exception', externalNetwork: 'blocked', expectedExternalJqueryErrors: failures.length, limitation: 'single browser/local synthetic data; Playwright default disables BFCache; no deployment or security-readiness claim'}));
    } finally { await context.close(); await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
