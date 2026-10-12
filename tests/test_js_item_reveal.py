"""Run shipped reveal behavior in Node with a strict event-driven DOM double.

Only synthetic credentials are used. This checks visible DOM and interrupted
fetch/json completions, not real browser memory zeroization or snapshots.
"""
import json
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'static/js/item-reveal.js'
HARNESS = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
    constructor() {
        this.listeners = {}; this.dataset = {}; this.attributes = {};
        this.textContent = ''; this.hidden = false; this.disabled = false;
        this.value = ''; this.checked = false; this.isLink = false;
    }
    addEventListener(name, callback) {
        (this.listeners[name] ||= []).push(callback);
    }
    emit(name, event = {}) {
        for (const callback of this.listeners[name] || []) callback({target: this, ...event});
    }
    setAttribute(name, value) { this.attributes[name] = value; }
    closest(selector) { assert.equal(selector, 'a'); return this.isLink ? this : null; }
    matches(selector) { assert.equal(selector, '[data-item-selector]'); return !!this.isSelector; }
    set innerHTML(value) { throw new Error('HTML parsing is forbidden'); }
}
const ids = ['item-reveal', 'reveal-password', 'hide-password', 'revealed-password',
    'reveal-status', 'replace-password', 'replacement-password', 'strength-replacement-password'];
const elements = Object.fromEntries(ids.map(id => [id, new Element()]));
const root = elements['item-reveal'];
const item = 'a'.repeat(32);
root.dataset = {itemId: item, csrfToken: 'synthetic-csrf'};
const document = new Element();
document.visibilityState = 'visible';
document.getElementById = id => elements[id] || null;
const window = new Element();
const timers = new Map();
let nextTimer = 0;
const requests = [];
const context = vm.createContext({
    document, window, AbortController,
    setTimeout(callback, delay) { assert.equal(delay, 30000); const id = ++nextTimer; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch(url, options) { return new Promise((resolve, reject) => requests.push({url, options, resolve, reject})); },
    // Fail if any future reveal implementation persists or logs credentials.
    localStorage: {setItem() { throw new Error('Storage forbidden'); }},
    sessionStorage: {setItem() { throw new Error('Storage forbidden'); }},
    console: {log() { throw new Error('Logging forbidden'); }, error() { throw new Error('Logging forbidden'); }}
});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
document.emit('DOMContentLoaded');
const reveal = elements['reveal-password'];
const hide = elements['hide-password'];
const output = elements['revealed-password'];
const status = elements['reveal-status'];
const flush = () => new Promise(resolve => setImmediate(resolve));
function reply(index = requests.length - 1, password = 'synthetic-secret', itemId = item) {
    requests[index].resolve({ok: true, json: async () => ({item_id: itemId, password})});
}
function assertCleared() {
    assert.equal(output.textContent, ''); assert.equal(output.hidden, true);
    assert.equal(hide.hidden, true); assert.equal(reveal.disabled, false);
    assert.equal(reveal.attributes['aria-expanded'], 'false');
    assert.equal(output.value, '');
}
function interrupt(reason) {
    if (reason === 'hide') hide.emit('click');
    else if (reason === 'visibility') { document.visibilityState = 'hidden'; document.emit('visibilitychange'); }
    else if (reason === 'selection') { const target = new Element(); target.isSelector = true; document.emit('change', {target}); }
    else if (reason === 'navigation' || reason === 'logout') { const target = new Element(); target.isLink = true; document.emit('click', {target}); }
    else if (reason === 'submit' || reason === 'delete') document.emit('submit');
    else if (reason === 'timeout') [...timers.values()][0]();
    else window.emit(reason);
}
'''


def run_script(body):
    script = HARNESS + '\n(async () => {\n' + body + '\n})().catch(e => {console.error(e); process.exitCode = 1;});'
    result = subprocess.run(['node', '-e', script, str(SCRIPT)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_explicit_fetch_csrf_no_store_and_repeated_reveal_hide():
    run_script(r'''
        assert.equal(requests.length, 0); assertCleared();
        for (let i = 0; i < 3; i++) {
            reveal.emit('click'); reveal.emit('click');
            assert.equal(requests.length, i + 1);
            const request = requests[i];
            assert.equal(request.url, `/passwords/${item}/reveal`);
            assert.equal(request.options.method, 'POST');
            assert.equal(request.options.headers['X-CSRFToken'], 'synthetic-csrf');
            assert.equal(request.options.cache, 'no-store');
            assert.equal(request.options.credentials, 'same-origin');
            assert.equal(request.options.redirect, 'error');
            const password = '<img src=x onerror=throw> synthetic-' + i;
            reply(i, password); await flush();
            assert.equal(output.textContent, password); assert.equal(output.hidden, false);
            assert.equal(reveal.attributes['aria-expanded'], 'true');
            assert.equal(elements['replacement-password'].value, '');
            hide.emit('click'); assertCleared(); assert.equal(timers.size, 0);
        }
    ''')


@pytest.mark.parametrize('reason', ['hide', 'selection', 'navigation', 'logout', 'submit', 'delete',
                                   'visibility', 'pagehide', 'pageshow', 'beforeunload', 'popstate', 'timeout'])
@pytest.mark.parametrize('stage', ['pending', 'visible', 'json'])
def test_interruption_clears_dom_and_suppresses_late_response(reason, stage):
    run_script(f'const reason = {json.dumps(reason)}; const stage = {json.dumps(stage)};\n' + r'''
        reveal.emit('click');
        let finishJson;
        if (stage === 'visible') { reply(); await flush(); assert.equal(output.hidden, false); }
        if (stage === 'json') {
            requests[0].resolve({ok: true, json: () => new Promise(resolve => { finishJson = resolve; })});
            await flush();
        }
        interrupt(reason); assertCleared();
        if (stage !== 'visible') assert.equal(requests[0].options.signal.aborted, true);
        if (stage === 'pending') reply();
        if (stage === 'json') finishJson({item_id: item, password: 'late synthetic-secret'});
        await flush(); assertCleared();
    ''')


def test_old_request_cannot_replace_new_visible_secret_or_error():
    run_script(r'''
        reveal.emit('click'); hide.emit('click'); reveal.emit('click');
        reply(1, 'new synthetic-secret'); await flush();
        reply(0, 'stale synthetic-secret'); await flush();
        assert.equal(output.textContent, 'new synthetic-secret');
        hide.emit('click'); reveal.emit('click'); hide.emit('click'); reveal.emit('click');
        reply(3, 'newest synthetic-secret'); await flush();
        requests[2].reject(new Error('Late synthetic failure')); await flush();
        assert.equal(output.textContent, 'newest synthetic-secret');
    ''')


@pytest.mark.parametrize('failure', ['401', '404', '500', 'network', 'json', 'wrong-item', 'wrong-type'])
def test_failures_clear_and_remain_generic(failure):
    run_script(f'const failure = {json.dumps(failure)};\n' + r'''
        reveal.emit('click');
        if (failure === 'network') requests[0].reject(new Error('sensitive synthetic diagnostics'));
        else if (failure === 'json') requests[0].resolve({ok: true, json: async () => {throw new Error('sensitive synthetic diagnostics');}});
        else if (failure === 'wrong-item') reply(0, 'synthetic-secret', 'b'.repeat(32));
        else if (failure === 'wrong-type') reply(0, {secret: 'synthetic-secret'});
        else requests[0].resolve({ok: false, status: Number(failure)});
        await flush(); assertCleared();
        assert.equal(status.textContent, 'Password unavailable. Please select the item again or sign in.');
    ''')


def test_changed_item_without_event_never_displays_old_response():
    run_script(r'''
        reveal.emit('click'); root.dataset.itemId = 'b'.repeat(32);
        reply(); await flush(); assert.equal(output.textContent, ''); assert.equal(output.hidden, true);
    ''')


def test_hidden_page_cannot_request_and_restored_page_requires_click():
    run_script(r'''
        document.visibilityState = 'hidden'; reveal.emit('click'); assert.equal(requests.length, 0);
        document.visibilityState = 'visible'; window.emit('pageshow'); assert.equal(requests.length, 0);
        reveal.emit('click'); reply(); await flush(); window.emit('pageshow'); assertCleared();
        assert.equal(requests.length, 1);
    ''')


def test_replacement_requires_explicit_intent_and_never_receives_reveal():
    run_script(r'''
        const intent = elements['replace-password']; const input = elements['replacement-password'];
        assert.equal(input.disabled, true); assert.equal(input.value, '');
        intent.checked = true; intent.emit('change'); assert.equal(input.disabled, false);
        input.value = 'synthetic-replacement'; document.emit('submit');
        assert.equal(input.value, 'synthetic-replacement');
        intent.checked = false; intent.emit('change'); assert.equal(input.value, ''); assert.equal(input.disabled, true);
        intent.checked = true; intent.emit('change'); input.value = 'synthetic-replacement';
        window.emit('pageshow'); assert.equal(input.value, ''); assert.equal(intent.checked, false);
        assert.equal(input.disabled, true);
    ''')
