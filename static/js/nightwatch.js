// Constants
const REFRESH_INTERVALS = {
    '30s': 30000,
    '1m': 60000,
    '5m': 300000,
    'off': null
};

// State
let currentRefreshInterval = null;
let currentFilters = {
    timeRange: '24h',
    severity: 'all',
    status: 'all'
};

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
    // Initialize date range picker with dark theme
    flatpickr('#dateRange', {
        mode: 'range',
        maxDate: 'today',
        defaultDate: [new Date(Date.now() - 24*60*60*1000), new Date()],
        theme: 'dark',
        onChange: function(selectedDates) {
            if (selectedDates.length === 2) {
                currentFilters.timeRange = 'custom';
                updateAlerts();
            }
        }
    });

    // Initialize filter listeners
    document.querySelector('#severityFilter').addEventListener('change', function(e) {
        currentFilters.severity = e.target.value;
        updateAlerts();
    });

    document.querySelector('#statusFilter').addEventListener('change', function(e) {
        currentFilters.status = e.target.value;
        updateAlerts();
    });

    document.querySelector('#timeRangeFilter').addEventListener('change', function(e) {
        currentFilters.timeRange = e.target.value;
        updateAlerts();
    });

    // Initialize auto-refresh
    document.querySelector('#autoRefresh').addEventListener('change', function(e) {
        const interval = e.target.value;
        setAutoRefresh(interval);
    });

    // Initial data load
    updateStats();
    updateAlerts();
});

// Update alert statistics
async function updateStats() {
    try {
        const response = await fetch('/api/alert_stats');
        if (!response.ok) throw new Error('Failed to fetch alert stats');
        
        const stats = await response.json();
        
        // Update statistics cards
        document.querySelector('#totalAlerts').textContent = stats.total_alerts;
        document.querySelector('#activeAlerts').textContent = stats.active_alerts;
        document.querySelector('#triggeredAlerts').textContent = stats.triggered_last_24h;
        document.querySelector('#criticalAlerts').textContent = stats.critical_alerts;
        
    } catch (error) {
        console.error('Error updating stats:', error);
        showToast('Error updating statistics', 'error');
    }
}

// Update alerts table
async function updateAlerts() {
    try {
        // Construct query parameters
        const params = new URLSearchParams();
        
        if (currentFilters.timeRange === 'custom') {
            const dates = document.querySelector('#dateRange')._flatpickr.selectedDates;
            if (dates.length === 2) {
                params.append('from_date', dates[0].toISOString());
                params.append('to_date', dates[1].toISOString());
            }
        } else {
            const hours = {
                '1h': 1,
                '6h': 6,
                '24h': 24,
                '7d': 168
            }[currentFilters.timeRange] || 24;
            
            params.append('from_date', new Date(Date.now() - hours*60*60*1000).toISOString());
        }
        
        params.append('severity', currentFilters.severity);
        params.append('status', currentFilters.status);
        
        const response = await fetch(`/api/triggered_alerts?${params.toString()}`);
        if (!response.ok) throw new Error('Failed to fetch alerts');
        
        const alerts = await response.json();
        
        // Update table
        const tbody = document.querySelector('#alertsTable tbody');
        tbody.innerHTML = '';
        
        alerts.forEach(alert => {
            const tr = document.createElement('tr');
            tr.className = alert.severity === 'critical' ? 'table-danger' : '';
            
            const timestamp = new Date(alert.timestamp).toLocaleString();
            const value = Number(alert.value).toFixed(2);
            const threshold = Number(alert.threshold).toFixed(2);
            
            tr.innerHTML = `
                <td>${timestamp}</td>
                <td>${alert.alert_name}</td>
                <td>${alert.alert_description}</td>
                <td>${value}</td>
                <td>${threshold}</td>
                <td>${alert.status}</td>
                <td>
                    ${alert.status !== 'acknowledged' ? 
                        `<button class="btn btn-sm btn-primary" onclick="acknowledgeAlert('${alert.id}')">
                            Acknowledge
                        </button>` : 
                        `<span class="text-muted">Acknowledged by ${alert.acknowledged_by}</span>`
                    }
                </td>
            `;
            
            tbody.appendChild(tr);
        });
        
        // Update empty state
        const emptyState = document.querySelector('#emptyState');
        if (alerts.length === 0) {
            emptyState.style.display = 'block';
        } else {
            emptyState.style.display = 'none';
        }
        
    } catch (error) {
        console.error('Error updating alerts:', error);
        showToast('Error updating alerts table', 'error');
    }
}

// Acknowledge an alert
async function acknowledgeAlert(alertId) {
    try {
        const modal = new bootstrap.Modal(document.querySelector('#acknowledgeModal'));
        const form = document.querySelector('#acknowledgeForm');
        
        form.onsubmit = async (e) => {
            e.preventDefault();
            
            const notes = document.querySelector('#acknowledgmentNotes').value;
            
            const response = await fetch(`/api/alerts/${alertId}/acknowledge`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ notes })
            });
            
            if (!response.ok) throw new Error('Failed to acknowledge alert');
            
            modal.hide();
            showToast('Alert acknowledged successfully', 'success');
            updateAlerts();
            updateStats();
        };
        
        modal.show();
        
    } catch (error) {
        console.error('Error acknowledging alert:', error);
        showToast('Error acknowledging alert', 'error');
    }
}

// Set auto-refresh interval
function setAutoRefresh(interval) {
    if (currentRefreshInterval) {
        clearInterval(currentRefreshInterval);
        currentRefreshInterval = null;
    }
    
    const milliseconds = REFRESH_INTERVALS[interval];
    if (milliseconds) {
        currentRefreshInterval = setInterval(() => {
            updateStats();
            updateAlerts();
        }, milliseconds);
    }
}

// Show toast notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast align-items-center border-0 nightwatch-dark`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    // Adjust background color for dark theme
    let bgClass = 'bg-primary';
    switch(type) {
        case 'success':
            bgClass = 'bg-success';
            break;
        case 'error':
            bgClass = 'bg-danger';
            break;
        case 'warning':
            bgClass = 'bg-warning';
            break;
    }
    toast.classList.add(bgClass);
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body text-white">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    document.querySelector('#toastContainer').appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
} 