/**
 * Network Security Dashboard Charts
 * Chart management and data visualization components
 * 
 * @author Hirotoshi Uchida
 * @version 1.0.0
 * @project Network Security App
 */

/**
 * Chart configuration and management
 */
class SecurityCharts {
    constructor() {
        this.charts = new Map();
        this.defaultColors = {
            primary: '#007bff',
            success: '#28a745',
            danger: '#dc3545',
            warning: '#ffc107',
            info: '#17a2b8',
            secondary: '#6c757d'
        };
        this.animationDuration = 750;
        this.maxDataPoints = 20;
    }

    /**
     * Initialize all charts
     */
    initializeCharts() {
        try {
            this.createTrafficChart();
            this.createProtocolChart();
            this.createThreatChart();
            this.createPerformanceChart();
            console.log('All charts initialized successfully');
        } catch (error) {
            console.error('Chart initialization failed:', error);
        }
    }

    /**
     * Create network traffic chart
     */
    createTrafficChart() {
        const canvas = document.getElementById('trafficChart');
        if (!canvas) {
            console.warn('Traffic chart canvas not found');
            return null;
        }

        const config = {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Incoming Traffic (MB/s)',
                    data: [],
                    borderColor: this.defaultColors.primary,
                    backgroundColor: this.hexToRgba(this.defaultColors.primary, 0.1),
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    pointBackgroundColor: this.defaultColors.primary,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                }, {
                    label: 'Outgoing Traffic (MB/s)',
                    data: [],
                    borderColor: this.defaultColors.success,
                    backgroundColor: this.hexToRgba(this.defaultColors.success, 0.1),
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    pointBackgroundColor: this.defaultColors.success,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Traffic (MB/s)',
                            font: {
                                weight: 'bold'
                            }
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        },
                        ticks: {
                            callback: function(value) {
                                return value.toFixed(2) + ' MB/s';
                            }
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time',
                            font: {
                                weight: 'bold'
                            }
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            usePointStyle: true,
                            padding: 20
                        }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        borderColor: this.defaultColors.primary,
                        borderWidth: 1,
                        cornerRadius: 6,
                        displayColors: true,
                        callbacks: {
                            title: function(tooltipItems) {
                                return 'Time: ' + tooltipItems[0].label;
                            },
                            label: function(context) {
                                return context.dataset.label + ': ' + context.parsed.y.toFixed(2) + ' MB/s';
                            }
                        }
                    }
                },
                animation: {
                    duration: this.animationDuration,
                    easing: 'easeInOutQuart'
                },
                elements: {
                    line: {
                        capBezierPoints: false
                    }
                }
            }
        };

        const chart = new Chart(canvas, config);
        this.charts.set('traffic', chart);
        return chart;
    }

    /**
     * Create protocol distribution chart
     */
    createProtocolChart() {
        const canvas = document.getElementById('protocolChart');
        if (!canvas) {
            console.warn('Protocol chart canvas not found');
            return null;
        }

        const config = {
            type: 'doughnut',
            data: {
                labels: ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'SMTP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        this.defaultColors.primary,
                        this.defaultColors.success,
                        this.defaultColors.warning,
                        this.defaultColors.danger,
                        this.defaultColors.info,
                        this.defaultColors.secondary,
                        '#e83e8c'
                    ],
                    borderWidth: 3,
                    borderColor: '#fff',
                    hoverBorderWidth: 4,
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom',
                        labels: {
                            usePointStyle: true,
                            padding: 15,
                            generateLabels: function(chart) {
                                const data = chart.data;
                                if (data.labels.length && data.datasets.length) {
                                    return data.labels.map((label, i) => {
                                        const value = data.datasets[0].data[i];
                                        const total = data.datasets[0].data.reduce((a, b) => a + b, 0);
                                        const percentage = total > 0 ? ((value * 100) / total).toFixed(1) : 0;
                                        
                                        return {
                                            text: `${label} (${percentage}%)`,
                                            fillStyle: data.datasets[0].backgroundColor[i],
                                            strokeStyle: data.datasets[0].backgroundColor[i],
                                            lineWidth: 0,
                                            pointStyle: 'circle',
                                            hidden: isNaN(data.datasets[0].data[i]) || data.datasets[0].data[i] === 0,
                                            index: i
                                        };
                                    });
                                }
                                return [];
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        borderColor: this.defaultColors.primary,
                        borderWidth: 1,
                        cornerRadius: 6,
                        callbacks: {
                            title: function(tooltipItems) {
                                return tooltipItems[0].label;
                            },
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((context.parsed * 100) / total).toFixed(1) : 0;
                                return `Packets: ${context.parsed} (${percentage}%)`;
                            }
                        }
                    }
                },
                animation: {
                    animateRotate: true,
                    animateScale: true,
                    duration: 1000,
                    easing: 'easeInOutQuart'
                },
                onHover: (event, activeElements) => {
                    event.native.target.style.cursor = activeElements.length > 0 ? 'pointer' : 'default';
                }
            }
        };

        const chart = new Chart(canvas, config);
        this.charts.set('protocol', chart);
        return chart;
    }

    /**
     * Create security threat chart
     */
    createThreatChart() {
        const canvas = document.getElementById('threatChart');
        if (!canvas) {
            console.warn('Threat chart canvas not found - this is optional');
            return null;
        }

        const config = {
            type: 'bar',
            data: {
                labels: ['Port Scans', 'Brute Force', 'DDoS Attempts', 'Malware', 'Unauthorized Access'],
                datasets: [{
                    label: 'Threat Count',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        this.hexToRgba(this.defaultColors.danger, 0.8),
                        this.hexToRgba(this.defaultColors.warning, 0.8),
                        this.hexToRgba(this.defaultColors.info, 0.8),
                        this.hexToRgba(this.defaultColors.secondary, 0.8),
                        this.hexToRgba(this.defaultColors.primary, 0.8)
                    ],
                    borderColor: [
                        this.defaultColors.danger,
                        this.defaultColors.warning,
                        this.defaultColors.info,
                        this.defaultColors.secondary,
                        this.defaultColors.primary
                    ],
                    borderWidth: 2,
                    borderRadius: 4,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Threats',
                            font: {
                                weight: 'bold'
                            }
                        },
                        ticks: {
                            stepSize: 1
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Threat Types',
                            font: {
                                weight: 'bold'
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        callbacks: {
                            label: function(context) {
                                return `${context.label}: ${context.parsed.y} threats detected`;
                            }
                        }
                    }
                },
                animation: {
                    duration: this.animationDuration,
                    easing: 'easeInOutQuart'
                }
            }
        };

        const chart = new Chart(canvas, config);
        this.charts.set('threat', chart);
        return chart;
    }

    /**
     * Create system performance chart
     */
    createPerformanceChart() {
        const canvas = document.getElementById('performanceChart');
        if (!canvas) {
            console.warn('Performance chart canvas not found - this is optional');
            return null;
        }

        const config = {
            type: 'radar',
            data: {
                labels: ['CPU Usage', 'Memory Usage', 'Network Load', 'Disk I/O', 'Response Time', 'Throughput'],
                datasets: [{
                    label: 'Current Performance',
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: this.defaultColors.primary,
                    backgroundColor: this.hexToRgba(this.defaultColors.primary, 0.2),
                    borderWidth: 2,
                    pointBackgroundColor: this.defaultColors.primary,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            stepSize: 20,
                            callback: function(value) {
                                return value + '%';
                            }
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        },
                        angleLines: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        callbacks: {
                            label: function(context) {
                                return `${context.label}: ${context.parsed.r}%`;
                            }
                        }
                    }
                },
                animation: {
                    duration: this.animationDuration,
                    easing: 'easeInOutQuart'
                }
            }
        };

        const chart = new Chart(canvas, config);
        this.charts.set('performance', chart);
        return chart;
    }

    /**
     * Update traffic chart with new data
     */
    updateTrafficChart(data) {
        const chart = this.charts.get('traffic');
        if (!chart || !data) return;

        const now = new Date().toLocaleTimeString();
        
        // Add new data point
        chart.data.labels.push(now);
        chart.data.datasets[0].data.push(this.bytesToMB(data.rx_bytes || 0));
        chart.data.datasets[1].data.push(this.bytesToMB(data.tx_bytes || 0));

        // Keep only last maxDataPoints
        if (chart.data.labels.length > this.maxDataPoints) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
            chart.data.datasets[1].data.shift();
        }

        chart.update('none');
    }

    /**
     * Update protocol chart with new data
     */
    updateProtocolChart(data) {
        const chart = this.charts.get('protocol');
        if (!chart || !data) return;

        const protocols = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'SMTP', 'Other'];
        chart.data.datasets[0].data = protocols.map(protocol => 
            data[protocol] || data[protocol.toLowerCase()] || 0
        );

        chart.update();
    }

    /**
     * Update threat chart with new data
     */
    updateThreatChart(data) {
        const chart = this.charts.get('threat');
        if (!chart || !data) return;

        const threats = ['port_scans', 'brute_force', 'ddos_attempts', 'malware', 'unauthorized_access'];
        chart.data.datasets[0].data = threats.map(threat => data[threat] || 0);

        chart.update();
    }

    /**
     * Update performance chart with new data
     */
    updatePerformanceChart(data) {
        const chart = this.charts.get('performance');
        if (!chart || !data) return;

        const metrics = ['cpu_usage', 'memory_usage', 'network_load', 'disk_io', 'response_time', 'throughput'];
        chart.data.datasets[0].data = metrics.map(metric => {
            const value = data[metric] || 0;
            return Math.min(Math.max(value, 0), 100); // Clamp between 0-100
        });

        chart.update();
    }

    /**
     * Get chart by ID
     */
    getChart(chartId) {
        return this.charts.get(chartId);
    }

    /**
     * Destroy chart
     */
    destroyChart(chartId) {
        const chart = this.charts.get(chartId);
        if (chart) {
            chart.destroy();
            this.charts.delete(chartId);
            console.log(`Chart ${chartId} destroyed`);
        }
    }

    /**
     * Resize all charts
     */
    resizeAllCharts() {
        this.charts.forEach((chart, id) => {
            try {
                chart.resize();
            } catch (error) {
                console.error(`Error resizing chart ${id}:`, error);
            }
        });
    }

    /**
     * Update all charts with dashboard data
     */
    updateAllCharts(data) {
        if (!data) return;

        try {
            if (data.traffic) {
                this.updateTrafficChart(data.traffic);
            }
            
            if (data.protocols) {
                this.updateProtocolChart(data.protocols);
            }
            
            if (data.threats) {
                this.updateThreatChart(data.threats);
            }
            
            if (data.performance) {
                this.updatePerformanceChart(data.performance);
            }
        } catch (error) {
            console.error('Error updating charts:', error);
        }
    }

    /**
     * Set chart theme
     */
    setTheme(theme) {
        const isDark = theme === 'dark';
        const textColor = isDark ? '#fff' : '#333';
        const gridColor = isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';

        this.charts.forEach(chart => {
            // Update text colors
            if (chart.options.scales) {
                Object.keys(chart.options.scales).forEach(scaleKey => {
                    if (chart.options.scales[scaleKey].title) {
                        chart.options.scales[scaleKey].title.color = textColor;
                    }
                    if (chart.options.scales[scaleKey].ticks) {
                        chart.options.scales[scaleKey].ticks.color = textColor;
                    }
                    if (chart.options.scales[scaleKey].grid) {
                        chart.options.scales[scaleKey].grid.color = gridColor;
                    }
                });
            }

            // Update legend colors
            if (chart.options.plugins && chart.options.plugins.legend && chart.options.plugins.legend.labels) {
                chart.options.plugins.legend.labels.color = textColor;
            }

            chart.update();
        });
    }

    /**
     * Export chart as image
     */
    exportChart(chartId, filename) {
        const chart = this.charts.get(chartId);
        if (!chart) {
            console.error(`Chart ${chartId} not found`);
            return;
        }

        try {
            const canvas = chart.canvas;
            const link = document.createElement('a');
            link.download = filename || `${chartId}-chart.png`;
            link.href = canvas.toDataURL('image/png');
            link.click();
        } catch (error) {
            console.error(`Error exporting chart ${chartId}:`, error);
        }
    }

    /**
     * Get chart statistics
     */
    getChartStats(chartId) {
        const chart = this.charts.get(chartId);
        if (!chart) return null;

        const data = chart.data.datasets[0].data;
        const validData = data.filter(value => typeof value === 'number' && !isNaN(value));

        if (validData.length === 0) return null;

        return {
            count: validData.length,
            min: Math.min(...validData),
            max: Math.max(...validData),
            average: validData.reduce((a, b) => a + b, 0) / validData.length,
            sum: validData.reduce((a, b) => a + b, 0)
        };
    }

    /**
     * Reset chart data
     */
    resetChart(chartId) {
        const chart = this.charts.get(chartId);
        if (!chart) return;

        chart.data.labels = [];
        chart.data.datasets.forEach(dataset => {
            dataset.data = [];
        });

        chart.update();
    }

    /**
     * Helper: Convert hex color to rgba
     */
    hexToRgba(hex, alpha) {
        const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
        if (!result) return hex;

        const r = parseInt(result[1], 16);
        const g = parseInt(result[2], 16);
        const b = parseInt(result[3], 16);

        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }

    /**
     * Helper: Convert bytes to MB
     */
    bytesToMB(bytes) {
        return parseFloat((bytes / (1024 * 1024)).toFixed(2));
    }

    /**
     * Helper: Format number with appropriate suffix
     */
    formatNumber(num) {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
    }

    /**
     * Get all chart instances
     */
    getAllCharts() {
        return Array.from(this.charts.entries()).map(([id, chart]) => ({
            id,
            chart,
            type: chart.config.type,
            data: chart.data
        }));
    }

    /**
     * Destroy all charts
     */
    destroyAllCharts() {
        this.charts.forEach((chart, id) => {
            chart.destroy();
        });
        this.charts.clear();
        console.log('All charts destroyed');
    }
}

// Global chart manager instance
let chartManager = null;

// Initialize charts when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    if (typeof Chart !== 'undefined') {
        chartManager = new SecurityCharts();
        chartManager.initializeCharts();
        
        // Make chartManager globally available
        window.chartManager = chartManager;
        
        console.log('Chart manager initialized');
    } else {
        console.error('Chart.js library not loaded');
    }
});

// Handle window resize
window.addEventListener('resize', () => {
    if (chartManager) {
        chartManager.resizeAllCharts();
    }
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityCharts;
}
