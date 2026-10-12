"""Run the shipped audit script against a small, strict DOM test double.

The double models the text/child semantics used by the audit view and refuses
HTML parsing. It deliberately does not execute synthetic hostile markup.
"""

import json
from pathlib import Path
import subprocess

import pytest


AUDIT_SCRIPT = Path(__file__).resolve().parents[1] / "static/js/audits.js"

DOM_HARNESS = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
    constructor(tagName) {
        this.tagName = tagName.toUpperCase();
        this.children = [];
        this.style = {};
        this.className = '';
        this.value = '';
        this._text = '';
    }
    set textContent(value) {
        this._text = value == null ? '' : String(value);
        this.children = [];
    }
    get textContent() {
        return this._text + this.children.map(child => child.textContent).join('');
    }
    set innerHTML(value) {
        if (value !== '') {
            throw new Error('HTML parsing is forbidden in the audit renderer');
        }
        this.textContent = '';
    }
    appendChild(child) {
        this.children.push(child);
        return child;
    }
    removeChild(child) {
        this.children.splice(this.children.indexOf(child), 1);
    }
    get cells() {
        return this.children.filter(child => child.tagName === 'TD');
    }
    get options() {
        return this.children;
    }
    remove(index) {
        this.children.splice(index, 1);
    }
    addEventListener() {}
    click() {
        this.clicked = true;
    }
    querySelectorAll(selector) {
        if (selector === 'td') return this.cells;
        throw new Error(`Unsupported element selector: ${selector}`);
    }
}

const tbody = new Element('tbody');
const table = new Element('table');
const headers = ['Audit ID', 'Event Time', 'Event Message', 'Event Type', 'User ID']
    .map(value => {
        const th = new Element('th');
        th.textContent = value;
        return th;
    });
table.querySelectorAll = selector => {
    if (selector === 'tbody tr') return tbody.children;
    if (selector === 'thead tr:first-child th') return headers;
    throw new Error(`Unsupported table selector: ${selector}`);
};
const elements = {'audit-logs-table': table};
for (const id of ['id-filter', 'message-filter', 'user-id-filter', 'start-date',
    'end-date', 'clear-filters', 'export-csv']) {
    elements[id] = new Element('input');
}
const eventTypeFilter = new Element('select');
const allOption = new Element('option');
allOption.value = 'all';
allOption.textContent = 'All';
eventTypeFilter.appendChild(allOption);
eventTypeFilter.value = 'all';
elements['event-type-filter'] = eventTypeFilter;
const created = [];
const document = {
    body: new Element('body'),
    addEventListener() {},
    createElement(tagName) {
        const element = new Element(tagName);
        created.push(element);
        return element;
    },
    getElementById(id) {
        assert.ok(elements[id], `Unexpected element ID: ${id}`);
        return elements[id];
    },
    querySelector(selector) {
        assert.equal(selector, '#audit-logs-table tbody');
        return tbody;
    },
    querySelectorAll(selector) {
        assert.equal(selector, '.event-type');
        return tbody.children.flatMap(row => row.cells)
            .filter(cell => cell.className === 'event-type');
    }
};
const requests = [];
const errors = [];
const downloads = [];
const context = vm.createContext({
    assert, document, tbody, table, elements, eventTypeFilter, created,
    requests, errors, downloads, Blob,
    console: {error: (...args) => errors.push(args)},
    URL: {createObjectURL: blob => {
        downloads.push(blob);
        return 'blob:synthetic-local-download';
    }},
    fetch: url => new Promise((resolve, reject) => requests.push({url, resolve, reject})),
    flush: () => new Promise(resolve => setImmediate(resolve))
});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
"""


def run_audit_script(scenario):
    script = DOM_HARNESS + "\nvm.runInContext(" + json.dumps(
        f"(async () => {{\n{scenario}\n}})()"
    ) + ", context).catch(error => {console.error(error); process.exitCode = 1;});"
    result = subprocess.run(
        ["node", "-e", script, str(AUDIT_SCRIPT)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "field", ["id", "event_time", "event_message", "event_type", "user_id"]
)
def test_audit_fields_are_literal_text_in_five_cells(field):
    log = {
        "id": 7,
        "event_time": "2026-10-12 12:34:56",
        "event_message": "Synthetic user changed a password",
        "event_type": "UPDATE",
        "user_id": 12,
    }
    log[field] = (
        '</td><td><img src="synthetic-invalid" onerror="auditExecuted=true">'
        '<svg onload="auditExecuted=true"></svg><script>auditExecuted=true</script>'
        ' & <b>literal</b> "quotes"\nnext line'
    )
    run_audit_script(
        f"const log = {json.dumps(log)};\n"
        r"""
        updateTable([log]);
        assert.equal(tbody.children.length, 1);
        const row = tbody.children[0];
        assert.equal(row.tagName, 'TR');
        assert.equal(row.children.length, 5);
        const fields = ['id', 'event_time', 'event_message', 'event_type', 'user_id'];
        fields.forEach((field, index) => {
            const cell = row.children[index];
            assert.equal(cell.tagName, 'TD');
            assert.equal(cell.textContent, String(log[field]));
            assert.equal(cell.children.length, 0);
            assert.equal(cell.className, index === 3 ? 'event-type' : '');
        });
        assert.equal(typeof auditExecuted, 'undefined');
        """
    )


def test_refresh_filters_and_export_preserve_literal_text():
    run_audit_script(r"""
        const type = '<img src="synthetic" onerror="auditExecuted=true">';
        const message = 'literal <b>markup</b>, "quoted" & content';
        const first = {id: 1, event_time: '2026-10-12 12:34:56',
            event_message: message, event_type: type, user_id: null};
        const second = {...first, id: 2, event_message: 'Other message'};
        updateTable([first, second]);
        populateEventTypeFilter();
        assert.equal(eventTypeFilter.options.length, 2);
        const option = eventTypeFilter.options[1];
        assert.equal(option.value, type);
        assert.equal(option.textContent, type);
        assert.equal(option.children.length, 0);
        assert.equal(tbody.children[0].cells[4].textContent, 'null');

        elements['message-filter'].value = '<b>MARKUP</b>';
        eventTypeFilter.value = type;
        filterTable();
        assert.equal(tbody.children[0].style.display, '');
        assert.equal(tbody.children[1].style.display, 'none');
        exportToCSV();
        assert.equal(downloads.length, 1);
        const csv = await downloads[0].text();
        assert.equal(csv,
            'Audit ID,Event Time,Event Message,Event Type,User ID\n' +
            '"1","2026-10-12 12:34:56","literal <b>markup</b>, ""quoted"" & content",' +
            '"<img src=""synthetic"" onerror=""auditExecuted=true"">","null"');
        const link = created.find(element => element.tagName === 'A');
        assert.equal(link.download, 'audit_logs.csv');
        assert.equal(link.clicked, true);
        assert.equal(document.body.children.length, 0);

        updateTable([{...first, id: 3, event_type: 'LOGIN'}]);
        populateEventTypeFilter();
        assert.equal(tbody.children.length, 1);
        assert.equal(tbody.children[0].cells[0].textContent, '3');
        assert.equal(eventTypeFilter.options.length, 2);
        assert.equal(eventTypeFilter.options[1].textContent, 'LOGIN');
        updateTable([]);
        populateEventTypeFilter();
        assert.equal(tbody.children.length, 0);
        assert.equal(eventTypeFilter.options.length, 1);
        assert.equal(eventTypeFilter.options[0].value, 'all');
    """)


def test_fetch_renders_loading_then_literal_data():
    run_audit_script(r"""
        elements['start-date'].value = '2026-10-01';
        elements['end-date'].value = '2026-10-12';
        fetchAndUpdateLogs();
        assert.equal(tbody.children.length, 1);
        assert.equal(tbody.children[0].cells.length, 1);
        assert.equal(tbody.children[0].cells[0].colSpan, 5);
        assert.equal(tbody.textContent, 'Loading...');
        assert.equal(requests[0].url,
            '/get_audit_logs?start_date=2026-10-01&end_date=2026-10-12');
        const log = {id: 42, event_time: '2026-10-12 12:34:56',
            event_message: '<img src="synthetic" onerror="auditExecuted=true">',
            event_type: '<b>LOGIN</b>', user_id: 0};
        requests[0].resolve({ok: true, json: () => Promise.resolve([log])});
        await flush();
        assert.equal(tbody.children.length, 1);
        assert.equal(tbody.children[0].cells.length, 5);
        assert.equal(tbody.children[0].cells[2].textContent, log.event_message);
        assert.equal(eventTypeFilter.options[1].textContent, log.event_type);
        assert.equal(errors.length, 0);
    """)


@pytest.mark.parametrize("failure", ["http", "network", "json"])
def test_fetch_error_replaces_loading_with_five_column_status(failure):
    run_audit_script(
        f"const failure = {json.dumps(failure)};\n" + r"""
        fetchAndUpdateLogs();
        if (failure === 'network') {
            requests[0].reject(new Error('Synthetic network failure'));
        } else if (failure === 'json') {
            requests[0].resolve({ok: true, json: () => Promise.reject(
                new Error('Synthetic malformed response'))});
        } else {
            requests[0].resolve({ok: false});
        }
        await flush();
        assert.equal(tbody.children.length, 1);
        assert.equal(tbody.children[0].cells.length, 1);
        assert.equal(tbody.children[0].cells[0].colSpan, 5);
        assert.equal(tbody.textContent, 'Error loading data');
        assert.equal(errors.length, 1);
        """
    )
