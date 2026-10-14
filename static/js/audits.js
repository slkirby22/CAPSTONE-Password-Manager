let auditRequestVersion = 0;

document.addEventListener('DOMContentLoaded', function() {
    initializeAuditLog();
});

function initializeAuditLog() {
    populateEventTypeFilter();
    setupEventListeners();
    
    // Load initial data if start date is set
    const startDate = document.getElementById('start-date').value;
    if (startDate) {
        fetchAndUpdateLogs();
    }
}

function setupEventListeners() {
    // Regular filters (client-side only)
    document.getElementById('id-filter').addEventListener('input', filterTable);
    document.getElementById('message-filter').addEventListener('input', filterTable);
    document.getElementById('user-id-filter').addEventListener('input', filterTable);
    document.getElementById('event-type-filter').addEventListener('change', filterTable);
    
    // Date filters (server-side)
    document.getElementById('start-date').addEventListener('change', handleDateChange);
    document.getElementById('end-date').addEventListener('change', handleDateChange);
    
    // Buttons
    document.getElementById('clear-filters').addEventListener('click', clearAllFilters);
    document.getElementById('export-csv').addEventListener('click', exportToCSV);
}

function handleDateChange() {
    fetchAndUpdateLogs();
}

function fetchAndUpdateLogs() {
    const version = ++auditRequestVersion;
    const startDate = document.getElementById('start-date').value;
    const endDate = document.getElementById('end-date').value;
    
    // Show loading state
    const tbody = document.querySelector('#audit-logs-table tbody');
    showAuditStatus(tbody, 'Loading...');
    
    fetch(`/get_audit_logs?start_date=${startDate}&end_date=${endDate}`)
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            if (version !== auditRequestVersion) return;
            updateTable(data);
            // Re-populate event types with new data
            populateEventTypeFilter();
            filterTable();
        })
        .catch(error => {
            if (version !== auditRequestVersion) return;
            console.error('Error fetching logs:', error);
            showAuditStatus(tbody, 'Error loading data');
        });
}

function showAuditStatus(tbody, message) {
    tbody.textContent = '';
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 5;
    cell.textContent = message;
    row.appendChild(cell);
    tbody.appendChild(row);
}

function updateTable(logs) {
    const tbody = document.querySelector('#audit-logs-table tbody');
    tbody.textContent = ''; // Clear existing rows

    logs.forEach(log => {
        const row = document.createElement('tr');
        const fields = ['id', 'event_time', 'event_message', 'event_type', 'user_id'];
        fields.forEach(field => {
            const cell = document.createElement('td');
            // Audit values are untrusted text, never HTML.
            cell.textContent = String(log[field]);
            if (field === 'event_type') {
                cell.className = 'event-type';
            }
            row.appendChild(cell);
        });
        tbody.appendChild(row);
    });
}

function populateEventTypeFilter() {
    const eventTypes = new Set();
    const eventTypeCells = document.querySelectorAll('.event-type');
    const eventTypeFilter = document.getElementById('event-type-filter');
    const selectedType = eventTypeFilter.value;
    
    // Clear existing options except "All"
    while (eventTypeFilter.options.length > 1) {
        eventTypeFilter.remove(1);
    }
    
    // Collect unique event types
    eventTypeCells.forEach(cell => {
        eventTypes.add(cell.textContent.trim());
    });
    
    // Keep an explicit filter selected even when the new range has no matches.
    if (selectedType && selectedType !== 'all') eventTypes.add(selectedType);

    // Add options to select
    eventTypes.forEach(type => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type;
        eventTypeFilter.appendChild(option);
    });
    eventTypeFilter.value = selectedType || 'all';
}

function filterTable() {
    const table = document.getElementById('audit-logs-table');
    const rows = table.querySelectorAll('tbody tr');
    
    // Get filter values
    const auditIdFilter = document.getElementById('id-filter').value.toLowerCase();
    const eventMessageFilter = document.getElementById('message-filter').value.toLowerCase();
    const eventTypeFilter = document.getElementById('event-type-filter').value;
    const userIdFilter = document.getElementById('user-id-filter').value.toLowerCase();
    const startDate = document.getElementById('start-date').value;
    const endDate = document.getElementById('end-date').value;

    rows.forEach(row => {
        // Loading/error status rows span five columns but have only one cell.
        if (row.cells.length !== 5) return;
        const auditId = row.cells[0].textContent.toLowerCase();
        const eventTime = row.cells[1].textContent.trim();
        const eventMessage = row.cells[2].textContent.toLowerCase();
        const eventType = row.cells[3].textContent.trim();
        const userId = row.cells[4].textContent.toLowerCase();

        let showRow = true;

        // Apply filters
        if (auditIdFilter && !auditId.includes(auditIdFilter)) {
            showRow = false;
        }
        if (eventMessageFilter && !eventMessage.includes(eventMessageFilter)) {
            showRow = false;
        }
        if (eventTypeFilter !== 'all' && eventType !== eventTypeFilter) {
            showRow = false;
        }
        if (userIdFilter && !userId.includes(userIdFilter)) {
            showRow = false;
        }

        // Dates are in the audit source's calendar, not the browser's timezone.
        // The API uses the same inclusive YYYY-MM-DD range. Avoid Date parsing,
        // which treats date-only inputs as UTC but event timestamps as local.
        const eventDate = eventTime.slice(0, 10);
        if (startDate && eventDate < startDate) showRow = false;
        if (endDate && eventDate > endDate) showRow = false;

        // Toggle row visibility
        row.style.display = showRow ? '' : 'none';
    });
}

function clearAllFilters() {
    // Reset all input fields
    document.getElementById('id-filter').value = '';
    document.getElementById('message-filter').value = '';
    document.getElementById('user-id-filter').value = '';
    document.getElementById('start-date').value = '';
    document.getElementById('end-date').value = '';
    document.getElementById('event-type-filter').value = 'all';

    // Re-filter the table to show all rows
    filterTable();
    handleDateChange(); // Fetch logs with cleared filters
}

function auditCsvCell(text) {
    let value = text.trim();
    // CSV quoting escapes structure, not spreadsheet formulas. A visible literal
    // prefix avoids relying on spreadsheet-specific apostrophe interpretation.
    // This is a display export; stored/rendered audit text remains unchanged.
    if (/^[=+\-@\u0000-\u001f\u007f＝＋－＠]/.test(value)) value = 'Text: ' + value;
    return `"${value.replace(/"/g, '""')}"`;
}

function exportToCSV() {
    const table = document.getElementById('audit-logs-table');
    const rows = table.querySelectorAll('tbody tr');
    const csvContent = [];

    // Add headers
    const headers = [];
    table.querySelectorAll('thead tr:first-child th').forEach(header => {
        headers.push(header.textContent.trim());
    });
    csvContent.push(headers.join(','));

    // Add visible rows
    rows.forEach(row => {
        if (row.cells.length === 5 && row.style.display !== 'none') {
            const rowData = [];
            row.querySelectorAll('td').forEach(cell => {
                rowData.push(auditCsvCell(cell.textContent));
            });
            csvContent.push(rowData.join(','));
        }
    });

    // Create CSV file
    const csvString = csvContent.join('\n');
    const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'audit_logs.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
