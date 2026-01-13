/**
 * Analytical-Intelligencel-Intelligence v1 - Frontend JavaScript
 * Handles polling and real-time updates
 */

// Configuration
const POLL_INTERVAL = 1000; // 1 second
const API_BASE = '';

// State
let lastUpdateTime = null;
let pollTimer = null;

/**
 * Format a timestamp for display
 */
function formatTime(isoString) {
    if (!isoString) return '--';
    const date = new Date(isoString);
    return date.toLocaleTimeString();
}

/**
 * Update the last update indicator
 */
function updateLastUpdateTime() {
    lastUpdateTime = new Date();
    const el = document.getElementById('last-update');
    if (el) {
        el.textContent = `Last update: ${formatTime(lastUpdateTime.toISOString())}`;
    }
}

/**
 * Fetch dashboard stats and update the UI
 */
async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/api/v1/stats`);
        if (!response.ok) throw new Error('Failed to fetch stats');

        const stats = await response.json();

        // Update stat cards
        updateElement('total-events', stats.total_events);
        updateElement('total-detections', stats.total_detections);
        updateElement('detections-24h', stats.detections_24h);
        updateElement('total-devices', stats.total_devices);

        updateLastUpdateTime();
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

/**
 * Fetch recent detections and update the table
 */
async function fetchRecentDetections() {
    try {
        const response = await fetch(`${API_BASE}/api/v1/recent-detections?limit=10`);
        if (!response.ok) throw new Error('Failed to fetch detections');

        const detections = await response.json();

        const tbody = document.querySelector('#recent-alerts tbody');
        if (!tbody) return;

        if (detections.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No recent alerts</td></tr>';
            return;
        }

        tbody.innerHTML = detections.map(d => `
            <tr class="severity-row-${d.severity.toLowerCase()}">
                <td class="timestamp">${d.ts ? d.ts.substring(0, 19) : '--'}</td>
                <td><span class="severity-badge ${d.severity.toLowerCase()}">${d.severity}</span></td>
                <td><span class="model-badge ${d.model_name}">${d.model_name}</span></td>
                <td class="label-cell" title="${escapeHtml(d.label)}">${escapeHtml(d.label.substring(0, 50))}${d.label.length > 50 ? '...' : ''}</td>
                <td>${escapeHtml(d.device_id || '--')}</td>
                <td>${d.score.toFixed(2)}</td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error fetching detections:', error);
    }
}

/**
 * Update an element's text content
 */
function updateElement(id, value) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = value;
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Start polling for updates
 */
function startPolling() {
    // Initial fetch
    fetchStats();
    fetchRecentDetections();

    // Set up interval
    pollTimer = setInterval(() => {
        fetchStats();
        fetchRecentDetections();
    }, POLL_INTERVAL);
}

/**
 * Stop polling
 */
function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

/**
 * Initialize the application
 */
function init() {
    // Only poll on dashboard page
    const isDashboard = window.location.pathname === '/' || window.location.pathname === '';

    if (isDashboard) {
        startPolling();
    }

    // Handle visibility change to pause/resume polling
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            stopPolling();
        } else if (isDashboard) {
            startPolling();
        }
    });

    // Update time on any page
    updateLastUpdateTime();
}

// Start when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
