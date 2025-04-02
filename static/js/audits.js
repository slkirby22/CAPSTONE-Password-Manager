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
    const startDate = document.getElementById('start-date').value;
    const endDate = document.getElementById('end-date').value;
    
    // Show loading state
    const tbody = document.querySelector('#audit-logs-table tbody');
    tbody.innerHTML = '<tr><td colspan="5">Loading...</td></tr>';
    
    fetch(`/get_audit_logs?start_date=${startDate}&end_date=${endDate}`)
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            updateTable(data);
            // Re-populate event types with new data
            populateEventTypeFilter();
        })
        .catch(error => {
            console.error('Error fetching logs:', error);
            tbody.innerHTML = '<tr><td colspan="5">Error loading data</td></tr>';
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
            <td class="event-type">${log.event_type}</td>
            <td>${log.user_id}</td>
        `;
        tbody.appendChild(row);
    });
}

function populateEventTypeFilter() {
    const eventTypes = new Set();
    const eventTypeCells = document.querySelectorAll('.event-type');
    const eventTypeFilter = document.getElementById('event-type-filter');
    
    // Clear existing options except "All"
    while (eventTypeFilter.options.length > 1) {
        eventTypeFilter.remove(1);
    }
    
    // Collect unique event types
    eventTypeCells.forEach(cell => {
        eventTypes.add(cell.textContent.trim());
    });
    
    // Add options to select
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
    const auditIdFilter = document.getElementById('id-filter').value.toLowerCase();
    const eventMessageFilter = document.getElementById('message-filter').value.toLowerCase();
    const eventTypeFilter = document.getElementById('event-type-filter').value;
    const userIdFilter = document.getElementById('user-id-filter').value.toLowerCase();
    const startDate = document.getElementById('start-date').value;
    const endDate = document.getElementById('end-date').value;

    rows.forEach(row => {
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

        // Apply date range filter
        if (startDate || endDate) {
            const eventDate = new Date(eventTime);
            
            if (startDate) {
                const start = new Date(startDate);
                if (eventDate < start) {
                    showRow = false;
                }
            }
            
            if (endDate) {
                const end = new Date(endDate);
                end.setHours(23, 59, 59); // Include entire end day
                if (eventDate > end) {
                    showRow = false;
                }
            }
        }

        // Toggle row visibility
        row.style.display = showRow ? '' : 'none';
    });
}

function clearAllFilters() {
    // Reset all input fields
    document.getElementById('id-filter').value = '';
    document.getElementById('message-filter').value = '';
    document.getElementById('user-id-filter').value = '';
    document.getElementById('end-date').value = '';
    document.getElementById('event-type-filter').value = 'all';

    // Re-filter the table to show all rows
    filterTable();
    handleDateChange(); // Fetch logs with cleared filters
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
                rowData.push(`"${cell.textContent.trim().replace(/"/g, '""')}"`);
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