/**
 * Analytical-Intelligence v1 - Frontend JavaScript
 * Professional dashboard with analytics charts and real-time updates
 * 
 * @version 1.0.0
 * @author Analytical Intelligence Team
 */

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ═══════════════════════════════════════════════════════════════
    
    const CONFIG = {
        API_BASE: '',
        POLL_INTERVAL: 30000,      // 30 seconds
        CHART_ANIMATION: 750,      // Chart animation duration
        DEBOUNCE_DELAY: 250        // Resize debounce
    };

    // ═══════════════════════════════════════════════════════════════
    // STATE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════
    
    const State = {
        pollTimer: null,
        charts: {},
        isLoading: false,
        isDashboard: false
    };

    // ═══════════════════════════════════════════════════════════════
    // UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Safely update element text content
     */
    function updateElement(id, value) {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = value ?? '--';
        }
    }

    /**
     * Format number with locale-specific separators
     */
    function formatNumber(num) {
        if (num == null) return '--';
        return new Intl.NumberFormat().format(num);
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
     * Show/hide loading state for a chart
     */
    function setChartLoading(chartId, isLoading) {
        const loader = document.getElementById(`loading-${chartId}`);
        if (loader) {
            loader.classList.toggle('hidden', !isLoading);
        }
    }

    /**
     * Show empty state for a chart
     */
    function setChartEmpty(chartId, isEmpty) {
        const empty = document.getElementById(`empty-${chartId}`);
        const canvas = document.getElementById(`chart-${chartId}`);
        if (empty) {
            empty.classList.toggle('hidden', !isEmpty);
        }
        if (canvas) {
            canvas.style.display = isEmpty ? 'none' : 'block';
        }
    }

    /**
     * Debounce function for resize handling
     */
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // THEME-AWARE CHART COLORS
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Get chart colors based on current theme
     */
    function getChartColors() {
        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
        
        return {
            // Text & Grid
            text: isDark ? 'rgba(240, 240, 240, 0.9)' : 'rgba(26, 26, 46, 0.9)',
            textMuted: isDark ? 'rgba(136, 136, 136, 0.8)' : 'rgba(74, 85, 104, 0.8)',
            grid: isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)',
            
            // Primary Colors
            primary: isDark ? '#00ff41' : '#00875a',
            primaryBg: isDark ? 'rgba(0, 255, 65, 0.15)' : 'rgba(0, 135, 90, 0.15)',
            secondary: isDark ? '#00d4ff' : '#0066cc',
            secondaryBg: isDark ? 'rgba(0, 212, 255, 0.15)' : 'rgba(0, 102, 204, 0.15)',
            
            // Severity Colors
            critical: isDark ? '#ff0040' : '#dc2626',
            high: isDark ? '#ff6600' : '#ea580c',
            medium: isDark ? '#ffaa00' : '#ca8a04',
            low: isDark ? '#00ff41' : '#16a34a',
            
            // Accent
            purple: isDark ? '#bf00ff' : '#6b47dc',
            purpleBg: isDark ? 'rgba(191, 0, 255, 0.15)' : 'rgba(107, 71, 220, 0.15)'
        };
    }

    /**
     * Get severity color by name
     */
    function getSeverityColor(severity) {
        const colors = getChartColors();
        const map = {
            'CRITICAL': colors.critical,
            'HIGH': colors.high,
            'MEDIUM': colors.medium,
            'LOW': colors.low
        };
        return map[severity] || colors.secondary;
    }

    // ═══════════════════════════════════════════════════════════════
    // API FUNCTIONS
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Fetch dashboard stats
     */
    async function fetchStats() {
        try {
            const response = await fetch(`${CONFIG.API_BASE}/api/v1/stats`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const stats = await response.json();
            
            updateElement('total-events', formatNumber(stats.total_events));
            updateElement('total-detections', formatNumber(stats.total_detections));
            updateElement('detections-24h', formatNumber(stats.detections_24h));
            updateElement('total-devices', formatNumber(stats.total_devices));
            
        } catch (error) {
            console.error('[AI] Failed to fetch stats:', error);
        }
    }

    /**
     * Fetch recent detections for table
     */
    async function fetchRecentDetections() {
        try {
            const response = await fetch(`${CONFIG.API_BASE}/api/v1/recent-detections?limit=10`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const detections = await response.json();
            const tbody = document.querySelector('#recent-alerts tbody');
            if (!tbody) return;

            if (!detections || detections.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="empty-state">
                            <span class="empty-icon">✓</span>
                            <span>No recent alerts — system is secure</span>
                        </td>
                    </tr>`;
                return;
            }

            tbody.innerHTML = detections.map(d => `
                <tr class="severity-row-${(d.severity || 'low').toLowerCase()}">
                    <td class="cell-timestamp">${d.ts ? d.ts.substring(0, 19) : '--'}</td>
                    <td><span class="severity-badge ${(d.severity || 'low').toLowerCase()}">${d.severity || 'LOW'}</span></td>
                    <td><span class="model-badge ${d.model_name || ''}">${d.model_name || '--'}</span></td>
                    <td class="cell-label" title="${escapeHtml(d.label || '')}">${escapeHtml((d.label || '').substring(0, 40))}${(d.label || '').length > 40 ? '...' : ''}</td>
                    <td class="cell-device">${escapeHtml(d.device_id || '—')}</td>
                    <td class="cell-score">${d.score ? (d.score * 100).toFixed(1) + '%' : '--'}</td>
                </tr>
            `).join('');

        } catch (error) {
            console.error('[AI] Failed to fetch detections:', error);
        }
    }

    /**
     * Fetch dashboard analytics data
     */
    async function fetchDashboardAnalytics() {
        if (State.isLoading) return;
        State.isLoading = true;

        // Show loading states
        ['timeseries', 'severity', 'top-labels', 'top-attackers', 'by-device'].forEach(id => {
            setChartLoading(id, true);
        });

        try {
            const response = await fetch(`${CONFIG.API_BASE}/api/v1/dashboard/analytics?window=24h`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();

            // Update summary KPIs
            if (data.summary) {
                updateElement('summary-high-critical', formatNumber(data.summary.high_critical_24h));
                updateElement('summary-intensity', data.summary.intensity);
            }

            // Render charts
            renderTimeseriesChart(data.timeseries);
            renderSeverityChart(data.severity);
            renderTopLabelsChart(data.top_labels);
            renderTopAttackersChart(data.top_attackers);
            renderByDeviceChart(data.by_device);

        } catch (error) {
            console.error('[AI] Failed to fetch analytics:', error);
        } finally {
            State.isLoading = false;
            // Hide all loading states
            ['timeseries', 'severity', 'top-labels', 'top-attackers', 'by-device'].forEach(id => {
                setChartLoading(id, false);
            });
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // CHART RENDERING FUNCTIONS
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Common chart configuration
     */
    function getBaseChartOptions() {
        const colors = getChartColors();
        return {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: CONFIG.CHART_ANIMATION
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.85)',
                    titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
                    bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
                    padding: 10,
                    cornerRadius: 6
                }
            },
            scales: {
                x: {
                    ticks: { 
                        color: colors.textMuted, 
                        font: { family: "'JetBrains Mono', monospace", size: 10 } 
                    },
                    grid: { color: colors.grid, drawBorder: false }
                },
                y: {
                    ticks: { 
                        color: colors.textMuted, 
                        font: { family: "'JetBrains Mono', monospace", size: 10 } 
                    },
                    grid: { color: colors.grid, drawBorder: false },
                    beginAtZero: true
                }
            }
        };
    }

    /**
     * V1: Detections Over Time (Area Chart)
     */
    function renderTimeseriesChart(data) {
        const ctx = document.getElementById('chart-timeseries');
        if (!ctx || !data?.labels) return;

        const colors = getChartColors();
        const chartData = {
            labels: data.labels,
            datasets: [{
                label: 'Detections',
                data: data.values,
                borderColor: colors.primary,
                backgroundColor: colors.primaryBg,
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: colors.primary
            }]
        };

        if (State.charts.timeseries) {
            State.charts.timeseries.data = chartData;
            State.charts.timeseries.options.scales.x.ticks.color = colors.textMuted;
            State.charts.timeseries.options.scales.y.ticks.color = colors.textMuted;
            State.charts.timeseries.options.scales.x.grid.color = colors.grid;
            State.charts.timeseries.options.scales.y.grid.color = colors.grid;
            State.charts.timeseries.update('none');
            return;
        }

        State.charts.timeseries = new Chart(ctx, {
            type: 'line',
            data: chartData,
            options: {
                ...getBaseChartOptions(),
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                scales: {
                    ...getBaseChartOptions().scales,
                    x: {
                        ...getBaseChartOptions().scales.x,
                        ticks: {
                            ...getBaseChartOptions().scales.x.ticks,
                            maxRotation: 0,
                            autoSkip: true,
                            maxTicksLimit: 12
                        }
                    }
                }
            }
        });
    }

    /**
     * V2: Severity Breakdown (Doughnut Chart)
     */
    function renderSeverityChart(data) {
        const ctx = document.getElementById('chart-severity');
        if (!ctx || !data?.labels) return;

        const colors = getChartColors();
        const backgroundColors = data.labels.map(l => getSeverityColor(l));

        const chartData = {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: backgroundColors,
                borderColor: 'transparent',
                borderWidth: 0,
                hoverOffset: 8
            }]
        };

        if (State.charts.severity) {
            State.charts.severity.data = chartData;
            State.charts.severity.update('none');
            return;
        }

        State.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom',
                        labels: {
                            color: colors.text,
                            font: { family: "'JetBrains Mono', monospace", size: 10 },
                            padding: 15,
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }
                    }
                }
            }
        });
    }

    /**
     * V3: Top Attack Types (Horizontal Bar Chart)
     */
    function renderTopLabelsChart(data) {
        const ctx = document.getElementById('chart-top-labels');
        if (!ctx || !data?.labels) return;

        const colors = getChartColors();
        const chartData = {
            labels: data.labels.map(l => l.length > 25 ? l.substring(0, 25) + '...' : l),
            datasets: [{
                data: data.values,
                backgroundColor: colors.secondary,
                borderColor: 'transparent',
                borderWidth: 0,
                borderRadius: 4,
                barThickness: 16
            }]
        };

        if (State.charts.topLabels) {
            State.charts.topLabels.data = chartData;
            State.charts.topLabels.update('none');
            return;
        }

        State.charts.topLabels = new Chart(ctx, {
            type: 'bar',
            data: chartData,
            options: {
                ...getBaseChartOptions(),
                indexAxis: 'y',
                scales: {
                    x: {
                        ...getBaseChartOptions().scales.x,
                        beginAtZero: true
                    },
                    y: {
                        ...getBaseChartOptions().scales.y,
                        grid: { display: false }
                    }
                }
            }
        });
    }

    /**
     * V4: Top Attacker IPs (Horizontal Bar Chart)
     */
    function renderTopAttackersChart(data) {
        const ctx = document.getElementById('chart-top-attackers');
        if (!ctx) return;

        // Handle empty state
        if (!data?.labels || data.labels.length === 0) {
            setChartEmpty('top-attackers', true);
            return;
        }
        setChartEmpty('top-attackers', false);

        const colors = getChartColors();
        const chartData = {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: colors.critical,
                borderColor: 'transparent',
                borderWidth: 0,
                borderRadius: 4,
                barThickness: 16
            }]
        };

        if (State.charts.topAttackers) {
            State.charts.topAttackers.data = chartData;
            State.charts.topAttackers.update('none');
            return;
        }

        State.charts.topAttackers = new Chart(ctx, {
            type: 'bar',
            data: chartData,
            options: {
                ...getBaseChartOptions(),
                indexAxis: 'y',
                scales: {
                    x: {
                        ...getBaseChartOptions().scales.x,
                        beginAtZero: true
                    },
                    y: {
                        ...getBaseChartOptions().scales.y,
                        grid: { display: false }
                    }
                }
            }
        });
    }

    /**
     * V5: Alerts by Device (Vertical Bar Chart)
     */
    function renderByDeviceChart(data) {
        const ctx = document.getElementById('chart-by-device');
        if (!ctx || !data?.labels) return;

        const colors = getChartColors();
        const chartData = {
            labels: data.labels.map(l => l.length > 12 ? l.substring(0, 12) + '...' : l),
            datasets: [{
                data: data.values,
                backgroundColor: colors.purple,
                borderColor: 'transparent',
                borderWidth: 0,
                borderRadius: 4,
                barThickness: 24
            }]
        };

        if (State.charts.byDevice) {
            State.charts.byDevice.data = chartData;
            State.charts.byDevice.update('none');
            return;
        }

        State.charts.byDevice = new Chart(ctx, {
            type: 'bar',
            data: chartData,
            options: {
                ...getBaseChartOptions(),
                scales: {
                    x: {
                        ...getBaseChartOptions().scales.x,
                        grid: { display: false }
                    },
                    y: {
                        ...getBaseChartOptions().scales.y,
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // POLLING & LIFECYCLE
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Start polling for updates
     */
    function startPolling() {
        // Initial fetch
        fetchStats();
        fetchRecentDetections();
        fetchDashboardAnalytics();

        // Set up interval
        State.pollTimer = setInterval(() => {
            fetchStats();
            fetchRecentDetections();
            fetchDashboardAnalytics();
        }, CONFIG.POLL_INTERVAL);
    }

    /**
     * Stop polling
     */
    function stopPolling() {
        if (State.pollTimer) {
            clearInterval(State.pollTimer);
            State.pollTimer = null;
        }
    }

    /**
     * Update charts on theme change
     */
    function handleThemeChange() {
        // Recreate charts with new colors
        Object.keys(State.charts).forEach(key => {
            if (State.charts[key]) {
                State.charts[key].destroy();
                State.charts[key] = null;
            }
        });
        
        // Re-fetch analytics to redraw charts
        if (State.isDashboard) {
            fetchDashboardAnalytics();
        }
    }

    /**
     * Handle window resize
     */
    const handleResize = debounce(() => {
        Object.values(State.charts).forEach(chart => {
            if (chart) chart.resize();
        });
    }, CONFIG.DEBOUNCE_DELAY);

    // ═══════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Initialize the application
     */
    function init() {
        // Check if we're on a dashboard page (/ or /dashboard) or have chart canvases
        const path = window.location.pathname;
        const hasDashboardCharts = document.getElementById('chart-timeseries') !== null;
        State.isDashboard = path === '/' || path === '' || path === '/dashboard' || hasDashboardCharts;

        if (State.isDashboard) {
            startPolling();
        }

        // Visibility change handler
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                stopPolling();
            } else if (State.isDashboard) {
                startPolling();
            }
        });

        // Resize handler
        window.addEventListener('resize', handleResize);

        // Theme change observer
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.attributeName === 'data-theme') {
                    handleThemeChange();
                }
            });
        });
        observer.observe(document.documentElement, { attributes: true });

        console.log('[AI] Dashboard initialized');
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
