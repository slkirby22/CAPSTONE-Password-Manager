"""Deterministic public fixtures only; these tests never generate real credentials."""
import json
from pathlib import Path
import subprocess

import pytest

from functions import password_meets_requirements


JS_PATH = Path(__file__).resolve().parents[1] / 'static' / 'js' / 'functions.js'
SPECIALS = '!@#$%^&*(),.?":{}|<>'
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' + SPECIALS


def run_js(body):
    script = f"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
let calls = 0;
let samples = [];
let fallback = 0;
const fakeCrypto = {{
    getRandomValues(array) {{
        assert.equal(Object.prototype.toString.call(array), '[object Uint32Array]');
        assert.equal(array.length, 1);
        calls++;
        array[0] = samples.length ? samples.shift() : fallback;
        return array;
    }}
}};
const context = vm.createContext({{
    crypto: fakeCrypto,
    document: {{ addEventListener() {{}}, querySelectorAll() {{ return []; }} }},
    module: {{ exports: {{}} }}
}});
vm.runInContext('Math.random = () => {{ throw new Error("Insecure fallback used"); }}', context);
vm.runInContext(fs.readFileSync({json.dumps(str(JS_PATH))}, 'utf8'), context);
const {{ generatePassword, secureRandomInt }} = context.module.exports;
{body}
"""
    result = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout) if result.stdout.strip() else None


@pytest.mark.parametrize('length', [-10, 0, 1, 4, 7, 8, 12, 64])
def test_js_generate_password_meets_requirements(length):
    pw = run_js(f'console.log(JSON.stringify(generatePassword({length})));')
    assert len(pw) == max(8, length)
    assert password_meets_requirements(pw)
    assert any(c.islower() for c in pw)
    assert set(pw) <= set(ALPHABET)


def test_default_length():
    assert len(run_js('console.log(JSON.stringify(generatePassword()));')) == 12


@pytest.mark.parametrize('length', ['NaN', 'Infinity', '-Infinity', '8.5', '"12"', 'null', '{}', '9007199254740992'])
def test_invalid_lengths_fail_before_randomness(length):
    run_js(f'assert.throws(() => generatePassword({length}), /length must be an integer/); assert.equal(calls, 0);')


def test_every_special_character_satisfies_unchanged_server_policy():
    passwords = run_js(f"""
const results = [];
for (let index = 0; index < {len(SPECIALS)}; index++) {{
    samples = [0, 0, 0, index, 0, 0, 0, 0, 7, 6, 5, 4, 3, 2, 1];
    results.push(generatePassword(8));
    assert.equal(samples.length, 0);
}}
console.log(JSON.stringify(results));
""")
    for special, pw in zip(SPECIALS, passwords):
        assert pw[3] == special
        assert password_meets_requirements(pw)


def test_category_and_combined_alphabet_endpoints():
    pw = run_js(f"""
samples = [25, 25, 9, {len(SPECIALS) - 1}, {len(ALPHABET) - 1}, 0, {len(ALPHABET) - 1}, 0,
           7, 6, 5, 4, 3, 2, 1];
console.log(JSON.stringify(generatePassword(8)));
assert.equal(calls, 15);
assert.equal(samples.length, 0);
""")
    assert pw == 'Zz9>>A>A'
    assert password_meets_requirements(pw)


def test_every_combined_alphabet_character_is_reachable():
    length = 4 + len(ALPHABET)
    pw = run_js(f"""
samples = [0, 0, 0, 0,
           ...Array.from({{length: {len(ALPHABET)}}}, (_, i) => i),
           ...Array.from({{length: {length - 1}}}, (_, i) => {length - 1} - i)];
console.log(JSON.stringify(generatePassword({length})));
assert.equal(samples.length, 0);
""")
    assert pw == 'Aa0!' + ALPHABET
    assert password_meets_requirements(pw)


def test_rejection_sampling_discards_entire_biased_tail():
    run_js("""
samples = [4294967290, 4294967291, 4294967292, 4294967293, 4294967294, 4294967295, 4294967289];
assert.equal(secureRandomInt(10), 9);
assert.equal(calls, 7);
samples = [0];
assert.equal(secureRandomInt(10), 0);
assert.equal(calls, 8);
""")


def test_random_bounds_include_full_uint32_range():
    run_js("""
samples = [4294967295, 4294967295, 4294967295];
assert.equal(secureRandomInt(1), 0);
assert.equal(secureRandomInt(256), 255);
assert.equal(secureRandomInt(4294967296), 4294967295);
assert.equal(calls, 3);
""")


@pytest.mark.parametrize('bound', ['0', '-1', '1.5', 'NaN', 'Infinity', '4294967297', '"10"'])
def test_invalid_random_bound(bound):
    run_js(f'assert.throws(() => secureRandomInt({bound}), /Random bound/); assert.equal(calls, 0);')


def test_shuffle_moves_guaranteed_categories_with_zero_swap_indexes():
    pw = run_js('console.log(JSON.stringify(generatePassword(8))); assert.equal(calls, 15);')
    assert pw == 'a0!AAAAA'
    assert password_meets_requirements(pw)


def test_shuffle_accepts_its_last_index_and_preserves_characters():
    pw = run_js("""
samples = [0, 0, 0, 0, 0, 0, 0, 0, 7, 6, 5, 4, 3, 2, 1];
console.log(JSON.stringify(generatePassword(8)));
assert.equal(samples.length, 0);
""")
    assert pw == 'Aa0!AAAA'


@pytest.mark.parametrize('provider', ['undefined', 'null', '{}', '{getRandomValues: 123}'])
def test_unavailable_crypto_fails_closed(provider):
    run_js(f'context.crypto = {provider}; assert.throws(() => generatePassword(), /requires Web Crypto/); assert.equal(calls, 0);')


def test_crypto_provider_error_has_no_insecure_fallback():
    run_js("""
context.crypto = {getRandomValues() { throw new Error('Synthetic crypto failure'); }};
assert.throws(() => generatePassword(), /Synthetic crypto failure/);
assert.equal(calls, 0);
""")


def test_ui_reports_crypto_failure_without_changing_existing_input():
    run_js("""
let ready;
let click;
const target = {id: 'new-password', value: 'public synthetic existing fixture'};
const feedback = {textContent: '', style: {}};
context.crypto = undefined;
context.document = {
    addEventListener(event, callback) { ready = callback; },
    querySelectorAll() { return []; },
    getElementById(id) {
        if (id === 'generate-password') return {addEventListener(event, callback) { click = callback; }};
        if (id === 'new-password') return target;
        if (id === 'strength-new-password') return feedback;
        return null;
    }
};
vm.runInContext(fs.readFileSync(""" + json.dumps(str(JS_PATH)) + """, 'utf8'), context);
ready();
click();
assert.equal(target.value, 'public synthetic existing fixture');
assert.match(feedback.textContent, /Secure password generation is unavailable/);
assert.equal(feedback.style.color, 'red');
assert.equal(calls, 0);
""")
