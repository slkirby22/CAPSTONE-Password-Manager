document.addEventListener('DOMContentLoaded', () => {
    populateEventTypeFilter();

    document.getElementById('clear-filters').addEventListener('click', clearAllFilters);
    document.getElementById('export-csv').addEventListener('click', exportToCSV);

    document.getElementById('start-date').addEventListener('change', fetchLogs);
    document.getElementById('end-date').addEventListener('change', fetchLogs);
});

function fetchLogs() {
    const startDate = document.getElementById('start-date').value;
    const endDate = document.getElementById('end-date').value;

    fetch(`/get_audit_logs?start_date=${startDate}&end_date=${endDate}`)
        .then(response => response.json())
        .then(data => {
            // Update the table with the new logs
            updateTable(data);
        });
}

function updateTable(logs) {
    const tbody = document.querySelector('#audit-logs-table tbody');
    tbody.innerHTML = ''; // Clear existing rows

    logs.forEach(log => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${log.id}</td>
            <td>${log.event_time}</td>
            <td>${log.event_message}</td>
            <td>${log.event_type}</td>
            <td>${log.user_id}</td>
        `;
        tbody.appendChild(row);
    });
}

function populateEventTypeFilter() {
    const table = document.getElementById('audit-logs-table');
    const rows = table.querySelectorAll('tbody tr');
    const eventTypeFilter = document.getElementById('event-type-filter');
    const eventTypes = new Set();

    rows.forEach(row => {
        const eventType = row.cells[3].textContent; // Event Type is in the 4th column (index 3)
        eventTypes.add(eventType);
    });

    eventTypes.forEach(type => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type;
        eventTypeFilter.appendChild(option);
    });
}

function filterTable() {
    const table = document.getElementById('audit-logs-table');
    const rows = table.querySelectorAll('tbody tr');

    // Get filter values
    const auditIdFilter = document.querySelector('thead input[placeholder="Filter by ID"]').value.toLowerCase();
    const eventMessageFilter = document.querySelector('thead input[placeholder="Filter by Message"]').value.toLowerCase();
    const eventTypeFilter = document.getElementById('event-type-filter').value;
    const userIdFilter = document.querySelector('thead input[placeholder="Filter by User ID"]').value.toLowerCase();

    // Get start and end date values
    const startDate = document.getElementById('start-date').value;
    const endDate = document.getElementById('end-date').value;

    rows.forEach(row => {
        const auditId = row.cells[0].textContent.toLowerCase();
        const eventTime = row.cells[1].textContent.trim();
        const eventMessage = row.cells[2].textContent.toLowerCase();
        const eventType = row.cells[3].textContent;
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

        // Apply date range filter
        const eventDate = new Date(eventTime);
        if (startDate) {
            const start = new Date(startDate);
            if (eventDate < start) {
                showRow = false;
            }
        }
        if (endDate) {
            const end = new Date(endDate);
            if (eventDate > end) {
                showRow = false;
            }
        }

        // Display or hide row based on all filters
        row.style.display = showRow ? '' : 'none';
    });
}

function clearAllFilters() {
    // Reset all input fields
    document.querySelector('thead input[placeholder="Filter by ID"]').value = '';
    document.querySelector('thead input[placeholder="Filter by Message"]').value = '';
    document.querySelector('thead input[placeholder="Filter by User ID"]').value = '';
    document.getElementById('end-date').value = '';
    document.getElementById('event-type-filter').value = 'all';

    // Re-filter the table to show all rows
    filterTable();
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
        if (row.style.display !== 'none') {
            const rowData = [];
            row.querySelectorAll('td').forEach(cell => {
                rowData.push(cell.textContent.trim());
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
    link.click();
}