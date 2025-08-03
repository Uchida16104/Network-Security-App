/**
 * Network Security Dashboard JavaScript
 * Real-time network monitoring and visualization
 * 
 * @author Hirotoshi Uchida
 * @version 1.0.0
 * @project Network Security App
 */

class NetworkSecurityDashboard {
    constructor() {
        this.isOnline = navigator.onLine;
        this.updateInterval = 5000; // 5 seconds
        this.charts = {};
        this.websocket = null;
        this.deviceData = [];
        this.trafficData = [];
        this.alertsData = [];
        this.networkTopology = null;
        
        this.init();
    }
    
    /**
     * Initialize the dashboard
     */
    init() {
        this.setupEventListeners();
        this.initializeCharts();
        this.startRealTimeUpdates();
        this.loadInitialData();
        this.setupWebSocket();
        this.initializeNetworkTopology();
        
        console.log('Network Security Dashboard initialized');
    }
    
    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Refresh button
        const refreshBtn = document.querySelector('[onclick="refreshData()"]');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshData());
        }
        
        // Navigation links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => this.handleNavigation(e));
        });
        
        // Device table actions
        document.addEventListener('click', (e) => {
            if (e.target.matches('.scan-device-btn')) {
                this.scanDevice(e.target.dataset.ip);
            }
            if (e.target.matches('.block-device-btn')) {
                this.blockDevice(e.target.dataset.ip);
            }
        });
        
        // Online/offline detection
        window.addEventListener('online', () => {
            this.isOnline = true;
            this.showNotification('Connection restored', 'success');
            this.startRealTimeUpdates();
        });
        
        window.addEventListener('offline', () => {
            this.isOnline = false;
            this.showNotification('Connection lost - working offline', 'warning');
            this.stopRealTimeUpdates();
        });
        
        // Window resize
        window.addEventListener('resize', () => {
            this.resizeCharts();
            this.updateNetworkTopology();
        });
    }
    
    /**
     * Initialize charts
     */
    initializeCharts() {
        this.initTrafficChart();
        this.initProtocolChart();
    }
    
    /**
     * Initialize traffic chart
     */
    initTrafficChart() {
        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;
        
        this.charts.traffic = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Incoming Traffic (MB/s)',
                    data: [],
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }, {
                    label: 'Outgoing Traffic (MB/s)',
                    data: [],
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
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
                            text: 'Traffic (MB/s)'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                animation: {
                    duration: 750,
                    easing: 'easeInOutQuart'
                }
            }
        });
    }
    
    /**
     * Initialize protocol distribution chart
     */
    initProtocolChart() {
        const ctx = document.getElementById('protocolChart');
        if (!ctx) return;
        
        this.charts.protocol = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#007bff',
                        '#28a745',
                        '#ffc107',
                        '#dc3545',
                        '#17a2b8',
                        '#6c757d'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((context.parsed * 100) / total).toFixed(1) : 0;
                                return `${context.label}: ${context.parsed} (${percentage}%)`;
                            }
                        }
                    }
                },
                animation: {
                    animateRotate: true,
                    duration: 1000
                }
            }
        });
    }
    
    /**
     * Initialize network topology visualization
     */
    initializeNetworkTopology() {
        const container = document.getElementById('network-topology');
        if (!container) return;
        
        this.networkTopology = {
            container: container,
            nodes: [],
            links: [],
            svg: null
        };
        
        // Create SVG element
        const svg = d3.select(container)
            .append('svg')
            .attr('width', '100%')
            .attr('height', '100%');
        
        this.networkTopology.svg = svg;
        
        // Add zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.5, 3])
            .on('zoom', (event) => {
                svg.select('g').attr('transform', event.transform);
            });
        
        svg.call(zoom);
        
        // Create main group
        const g = svg.append('g');
        
        // Add links group
        g.append('g').attr('class', 'links');
        
        // Add nodes group
        g.append('g').attr('class', 'nodes');
    }
    
    /**
     * Update network topology
     */
    updateNetworkTopology(data) {
        if (!this.networkTopology || !data) return;
        
        const { svg } = this.networkTopology;
        const width = this.networkTopology.container.clientWidth;
        const height = this.networkTopology.container.clientHeight;
        
        // Update SVG dimensions
        svg.attr('viewBox', `0 0 ${width} ${height}`);
        
        // Prepare data
        const nodes = data.nodes || [];
        const links = data.links || [];
        
        // Create force simulation
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(30));
        
        // Update links
        const link = svg.select('.links')
            .selectAll('line')
            .data(links);
        
        link.enter()
            .append('line')
            .attr('class', 'topology-link')
            .attr('stroke', 'rgba(255, 255, 255, 0.6)')
            .attr('stroke-width', 2)
            .merge(link);
        
        link.exit().remove();
        
        // Update nodes
        const node = svg.select('.nodes')
            .selectAll('circle')
            .data(nodes);
        
        const nodeEnter = node.enter()
            .append('g')
            .attr('class', 'topology-node')
            .call(d3.drag()
                .on('start', (event, d) => {
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                })
                .on('drag', (event, d) => {
                    d.fx = event.x;
                    d.fy = event.y;
                })
                .on('end', (event, d) => {
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }));
        
        nodeEnter.append('circle')
            .attr('r', 20)
            .attr('fill', d => this.getNodeColor(d.type))
            .attr('stroke', '#fff')
            .attr('stroke-width', 2);
        
        nodeEnter.append('text')
            .attr('dy', '.35em')
            .attr('text-anchor', 'middle')
            .attr('fill', '#fff')
            .attr('font-size', '10px')
            .attr('font-weight', 'bold')
            .text(d => d.label.substring(0, 3));
        
        node.exit().remove();
        
        // Update simulation
        simulation.on('tick', () => {
            svg.selectAll('.topology-link')
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            svg.selectAll('.topology-node')
                .attr('transform', d => `translate(${d.x},${d.y})`);
        });
        
        // Add tooltips
        nodeEnter.append('title')
            .text(d => `${d.label}\nIP: ${d.ip}\nMAC: ${d.mac || 'Unknown'}`);
    }
    
    /**
     * Get node color based on type
     */
    getNodeColor(type) {
        const colors = {
            'gateway': '#28a745',
            'server': '#007bff',
            'device': '#17a2b8',
            'suspicious': '#dc3545',
            'unknown': '#6c757d'
        };
        return colors[type] || colors.unknown;
    }
    
    /**
     * Start real-time updates
     */
    startRealTimeUpdates() {
        if (!this.isOnline) return;
        
        this.updateTimer = setInterval(() => {
            this.updateDashboard();
        }, this.updateInterval);
        
        console.log('Real-time updates started');
    }
    
    /**
     * Stop real-time updates
     */
    stopRealTimeUpdates() {
        if (this.updateTimer) {
            clearInterval(this.updateTimer);
            this.updateTimer = null;
        }
        console.log('Real-time updates stopped');
    }
    
    /**
     * Setup WebSocket connection
     */
    setupWebSocket() {
        if (!this.isOnline) return;
        
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
            
            this.websocket = new WebSocket(wsUrl);
            
            this.websocket.onopen = () => {
                console.log('WebSocket connected');
                this.showNotification('Real-time monitoring active', 'success');
            };
            
            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketData(data);
                } catch (error) {
                    console.error('WebSocket data parsing error:', error);
                }
            };
            
            this.websocket.onclose = () => {
                console.log('WebSocket disconnected');
                this.showNotification('Real-time connection lost', 'warning');
                
                // Attempt to reconnect after 5 seconds
                setTimeout(() => {
                    if (this.isOnline) {
                        this.setupWebSocket();
                    }
                }, 5000);
            };
            
            this.websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
            
        } catch (error) {
            console.error('WebSocket setup error:', error);
        }
    }
    
    /**
     * Handle WebSocket data
     */
    handleWebSocketData(data) {
        switch (data.type) {
            case 'dashboard':
                this.updateDashboardData(data.data);
                break;
            case 'alert':
                this.addSecurityAlert(data.data);
                break;
            case 'device_update':
                this.updateDeviceData(data.data);
                break;
            case 'traffic_update':
                this.updateTrafficData(data.data);
                break;
            default:
                console.log('Unknown WebSocket data type:', data.type);
        }
    }
    
    /**
     * Load initial data
     */
    async loadInitialData() {
        try {
            this.showLoading(true);
            
            const response = await this.fetchAPI('/api/dashboard');
            if (response.success) {
                this.updateDashboardData(response.data);
            } else {
                throw new Error(response.error || 'Failed to load dashboard data');
            }
            
        } catch (error) {
            console.error('Failed to load initial data:', error);
            this.showNotification('Failed to load dashboard data', 'danger');
        } finally {
            this.showLoading(false);
        }
    }
    
    /**
     * Update dashboard data
     */
    updateDashboardData(data) {
        // Update status cards
        this.updateStatusCards(data);
        
        // Update device table
        this.updateDeviceTable(data.devices || []);
        
        // Update charts
        this.updateCharts(data);
        
        // Update network topology
        this.updateNetworkTopology(data.topology);
        
        // Update security alerts
        this.updateSecurityAlerts(data.alerts || []);
        
        console.log('Dashboard data updated');
    }
    
    /**
     * Update status cards
     */
    updateStatusCards(data) {
        const elements = {
            'active-devices': data.devices ? data.devices.length : 0,
            'network-traffic': this.formatTrafficValue(data.traffic?.total_bytes || 0),
            'security-events': data.alerts ? data.alerts.length : 0,
            'system-status': data.system_status?.status || 'Unknown'
        };
        
        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
                element.classList.add('animate-zoom-in');
                setTimeout(() => element.classList.remove('animate-zoom-in'), 400);
            }
        });
    }
    
    /**
     * Update device table
     */
    updateDeviceTable(devices) {
        const tbody = document.getElementById('device-table-body');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        devices.forEach(device => {
            const row = document.createElement('tr');
            row.className = this.getDeviceRowClass(device);
            
            row.innerHTML = `
                <td>${device.ip}</td>
                <td>${device.mac || 'Unknown'}</td>
                <td>${device.hostname || 'Unknown'}</td>
                <td>${device.os || 'Unknown'}</td>
                <td>
                    <span class="badge ${this.getStatusBadgeClass(device.status)}">
                        ${device.status || 'Unknown'}
                    </span>
                </td>
                <td>${this.formatTimestamp(device.last_seen)}</td>
                <td>
                    <button class="btn btn-sm btn-primary scan-device-btn" data-ip="${device.ip}">
                        <i class="fas fa-search"></i> Scan
                    </button>
                    <button class="btn btn-sm btn-danger block-device-btn" data-ip="${device.ip}">
                        <i class="fas fa-ban"></i> Block
                    </button>
                </td>
            `;
            
            tbody.appendChild(row);
        });
        
        this.deviceData = devices;
    }
    
    /**
     * Update charts with new data
     */
    updateCharts(data) {
        this.updateTrafficChart(data.traffic);
        this.updateProtocolChart(data.protocols);
    }
    
    /**
     * Update traffic chart
     */
    updateTrafficChart(trafficData) {
        if (!this.charts.traffic || !trafficData) return;
        
        const now = new Date().toLocaleTimeString();
        const chart = this.charts.traffic;
        
        // Add new data point
        chart.data.labels.push(now);
        chart.data.datasets[0].data.push(trafficData.rx_bytes / 1024 / 1024 || 0);
        chart.data.datasets[1].data.push(trafficData.tx_bytes / 1024 / 1024 || 0);
        
        // Keep only last 20 data points
        if (chart.data.labels.length > 20) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
            chart.data.datasets[1].data.shift();
        }
        
        chart.update('none');
    }
    
    /**
     * Update protocol chart
     */
    updateProtocolChart(protocolData) {
        if (!this.charts.protocol || !protocolData) return;
        
        const chart = this.charts.protocol;
        const protocols = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'Other'];
        
        chart.data.datasets[0].data = protocols.map(protocol => 
            protocolData[protocol] || 0
        );
        
        chart.update();
    }
    
    /**
     * Update security alerts
     */
    updateSecurityAlerts(alerts) {
        const container = document.getElementById('security-alerts');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (alerts.length === 0) {
            container.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-shield-alt alert-icon"></i>
                    <div class="alert-content">
                        <div class="alert-title">All Clear</div>
                        <div class="alert-description">No security threats detected</div>
                    </div>
                </div>
            `;
            return;
        }
        
        alerts.forEach(alert => {
            const alertElement = document.createElement('div');
            alertElement.className = `alert alert-${this.getAlertSeverityClass(alert.severity)}`;
            alertElement.innerHTML = `
                <i class="fas ${this.getAlertIcon(alert.type)} alert-icon"></i>
                <div class="alert-content">
                    <div class="alert-title">${alert.type.replace(/_/g, ' ').toUpperCase()}</div>
                    <div class="alert-description">${alert.description}</div>
                    <div class="alert-details">
                        ${alert.ip ? `<span class="detail-item"><strong>IP:</strong> ${alert.ip}</span>` : ''}
                        ${alert.mac ? `<span class="detail-item"><strong>MAC:</strong> ${alert.mac}</span>` : ''}
                        ${alert.port ? `<span class="detail-item"><strong>Port:</strong> ${alert.port}</span>` : ''}
                    </div>
                    <div class="alert-timestamp">${this.formatTimestamp(alert.timestamp)}</div>
                </div>
            `;
            
            container.appendChild(alertElement);
        });
        
        this.alertsData = alerts;
    }
    
    /**
     * Refresh all dashboard data
     */
    async refreshData() {
        try {
            this.showLoading(true);
            
            const response = await this.fetchAPI('/api/dashboard');
            if (response.success) {
                this.updateDashboardData(response.data);
                this.showNotification('Dashboard refreshed', 'success');
            } else {
                throw new Error(response.error || 'Failed to refresh data');
            }
            
        } catch (error) {
            console.error('Failed to refresh data:', error);
            this.showNotification('Failed to refresh dashboard', 'danger');
        } finally {
            this.showLoading(false);
        }
    }
    
    /**
     * Update dashboard periodically
     */
    async updateDashboard() {
        if (!this.isOnline) return;
        
        try {
            const response = await this.fetchAPI('/api/websocket-data', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ type: 'dashboard' })
            });
            
            if (response.success) {
                this.updateDashboardData(response.data);
            }
            
        } catch (error) {
            console.error('Dashboard update error:', error);
        }
    }
    
    /**
     * Scan specific device
     */
    async scanDevice(ip) {
        try {
            this.showNotification(`Scanning device ${ip}...`, 'info');
            
            const response = await this.fetchAPI(`/api/device-details/${ip}`);
            if (response.success) {
                this.showDeviceDetails(response.data);
                this.showNotification(`Device scan completed for ${ip}`, 'success');
            } else {
                throw new Error(response.error || 'Scan failed');
            }
            
        } catch (error) {
            console.error('Device scan error:', error);
            this.showNotification(`Failed to scan device ${ip}`, 'danger');
        }
    }
    
    /**
     * Block specific device
     */
    async blockDevice(ip) {
        if (!confirm(`Are you sure you want to block device ${ip}?`)) {
            return;
        }
        
        try {
            const response = await this.fetchAPI(`/api/block-device/${ip}`, {
                method: 'POST'
            });
            
            if (response.success) {
                this.showNotification(`Device ${ip} has been blocked`, 'success');
                this.refreshData();
            } else {
                throw new Error(response.error || 'Block failed');
            }
            
        } catch (error) {
            console.error('Device block error:', error);
            this.showNotification(`Failed to block device ${ip}`, 'danger');
        }
    }
    
    /**
     * Show device details modal
     */
    showDeviceDetails(deviceData) {
        // Create modal HTML
        const modalHTML = `
            <div class="modal fade" id="deviceDetailsModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Device Details - ${deviceData.ip}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6>Basic Information</h6>
                                    <table class="table table-borderless table-sm">
                                        <tr><td><strong>IP Address:</strong></td><td>${deviceData.ip}</td></tr>
                                        <tr><td><strong>MAC Address:</strong></td><td>${deviceData.mac || 'Unknown'}</td></tr>
                                        <tr><td><strong>Hostname:</strong></td><td>${deviceData.hostname || 'Unknown'}</td></tr>
                                        <tr><td><strong>OS:</strong></td><td>${deviceData.os || 'Unknown'}</td></tr>
                                        <tr><td><strong>Status:</strong></td><td>
                                            <span class="badge ${this.getStatusBadgeClass(deviceData.status)}">
                                                ${deviceData.status || 'Unknown'}
                                            </span>
                                        </td></tr>
                                    </table>
                                </div>
                                <div class="col-md-6">
                                    <h6>Network Information</h6>
                                    <table class="table table-borderless table-sm">
                                        <tr><td><strong>Ping Response:</strong></td><td>${deviceData.ping_response ? 'Yes' : 'No'}</td></tr>
                                        <tr><td><strong>Last Seen:</strong></td><td>${this.formatTimestamp(deviceData.last_seen)}</td></tr>
                                    </table>
                                </div>
                            </div>
                            
                            ${deviceData.ports && deviceData.ports.length > 0 ? `
                                <div class="mt-3">
                                    <h6>Open Ports</h6>
                                    <div class="table-responsive">
                                        <table class="table table-sm">
                                            <thead>
                                                <tr>
                                                    <th>Port</th>
                                                    <th>Protocol</th>
                                                    <th>Service</th>
                                                    <th>State</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                ${deviceData.ports.map(port => `
                                                    <tr>
                                                        <td>${port.port}</td>
                                                        <td>${port.protocol || 'tcp'}</td>
                                                        <td>${port.service || 'Unknown'}</td>
                                                        <td><span class="badge bg-success">${port.state || 'open'}</span></td>
                                                    </tr>
                                                `).join('')}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            ` : ''}
                            
                            ${deviceData.traceroute && deviceData.traceroute.length > 0 ? `
                                <div class="mt-3">
                                    <h6>Network Route</h6>
                                    <div class="table-responsive">
                                        <table class="table table-sm">
                                            <thead>
                                                <tr>
                                                    <th>Hop</th>
                                                    <th>IP Address</th>
                                                    <th>Hostname</th>
                                                    <th>RTT (ms)</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                ${deviceData.traceroute.map(hop => `
                                                    <tr>
                                                        <td>${hop.hop}</td>
                                                        <td>${hop.ip}</td>
                                                        <td>${hop.hostname || 'Unknown'}</td>
                                                        <td>${hop.rtt}</td>
                                                    </tr>
                                                `).join('')}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-primary" onclick="dashboard.scanDevice('${deviceData.ip}')">
                                <i class="fas fa-sync-alt"></i> Rescan
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal
        const existingModal = document.getElementById('deviceDetailsModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        // Add modal to DOM
        document.body.insertAdjacentHTML('beforeend', modalHTML);
        
        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('deviceDetailsModal'));
        modal.show();
    }
    
    /**
     * Handle navigation
     */
    handleNavigation(e) {
        e.preventDefault();
        
        // Update active nav link
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        e.target.classList.add('active');
        
        // Handle navigation logic here
        const href = e.target.getAttribute('href');
        console.log('Navigation to:', href);
    }
    
    /**
     * Resize charts
     */
    resizeCharts() {
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.resize === 'function') {
                chart.resize();
            }
        });
    }
    
    /**
     * Show loading state
     */
    showLoading(show) {
        const elements = document.querySelectorAll('.card-body');
        elements.forEach(element => {
            if (show) {
                element.classList.add('loading');
            } else {
                element.classList.remove('loading');
            }
        });
    }
    
    /**
     * Show notification
     */
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} position-fixed`;
        notification.style.cssText = `
            top: 20px;
            right: 20px;
            z-index: 9999;
            max-width: 300px;
            animation: slideInRight 0.3s ease-out;
        `;
        notification.innerHTML = `
            <i class="fas ${this.getNotificationIcon(type)}"></i>
            ${message}
            <button type="button" class="btn-close" onclick="this.parentElement.remove()"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'fadeOut 0.3s ease-out';
                setTimeout(() => notification.remove(), 300);
            }
        }, 5000);
    }
    
    /**
     * Fetch API helper
     */
    async fetchAPI(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        };
        
        const response = await fetch(url, { ...defaultOptions, ...options });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    }
    
    /**
     * Helper methods for UI formatting
     */
    formatTrafficValue(bytes) {
        if (bytes < 1024) return `${bytes} B/s`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
        return `${(bytes / 1024 / 1024).toFixed(1)} MB/s`;
    }
    
    formatTimestamp(timestamp) {
        if (!timestamp) return 'Never';
        const date = new Date(timestamp);
        return date.toLocaleString();
    }
    
    getDeviceRowClass(device) {
        switch (device.status) {
            case 'online': return 'table-success';
            case 'offline': return 'table-secondary';
            case 'suspicious': return 'table-danger';
            default: return '';
        }
    }
    
    getStatusBadgeClass(status) {
        switch (status) {
            case 'online': return 'bg-success';
            case 'offline': return 'bg-secondary';
            case 'suspicious': return 'bg-danger';
            default: return 'bg-warning';
        }
    }
    
    getAlertSeverityClass(severity) {
        switch (severity) {
            case 'critical': return 'danger';
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'info';
        }
    }
    
    getAlertIcon(type) {
        const icons = {
            'port_scan': 'fa-search',
            'suspicious_activity': 'fa-exclamation-triangle',
            'unauthorized_device': 'fa-ban',
            'potential_ddos': 'fa-shield-alt',
            'high_traffic_volume': 'fa-chart-line'
        };
        return icons[type] || 'fa-info-circle';
    }
    
    getNotificationIcon(type) {
        const icons = {
            'success': 'fa-check-circle',
            'danger': 'fa-exclamation-circle',
            'warning': 'fa-exclamation-triangle',
            'info': 'fa-info-circle'
        };
        return icons[type] || 'fa-info-circle';
    }
}

// Network monitoring utilities
class NetworkMonitor {
    constructor() {
        this.isMonitoring = false;
        this.monitoringInterval = null;
    }
    
    /**
     * Start continuous network monitoring
     */
    startMonitoring() {
        if (this.isMonitoring) return;
        
        this.isMonitoring = true;
        console.log('Network monitoring started');
        
        // Monitor every 10 seconds
        this.monitoringInterval = setInterval(() => {
            this.performNetworkCheck();
        }, 10000);
    }
    
    /**
     * Stop network monitoring
     */
    stopMonitoring() {
        if (!this.isMonitoring) return;
        
        this.isMonitoring = false;
        
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
        }
        
        console.log('Network monitoring stopped');
    }
    
    /**
     * Perform network connectivity check
     */
    async performNetworkCheck() {
        try {
            // Check if we can reach our API
            const response = await fetch('/api/health-check', {
                method: 'HEAD',
                timeout: 5000
            });
            
            if (!response.ok) {
                throw new Error('API not responding');
            }
            
            // Update network status
            this.updateNetworkStatus(true);
            
        } catch (error) {
            console.warn('Network check failed:', error);
            this.updateNetworkStatus(false);
        }
    }
    
    /**
     * Update network status indicator
     */
    updateNetworkStatus(isOnline) {
        const indicators = document.querySelectorAll('.realtime-indicator');
        indicators.forEach(indicator => {
            if (isOnline) {
                indicator.classList.remove('offline', 'warning');
                indicator.classList.add('online');
            } else {
                indicator.classList.remove('online');
                indicator.classList.add('offline');
            }
        });
    }
}

// Charts utility class
class ChartManager {
    constructor() {
        this.charts = new Map();
    }
    
    /**
     * Create a new chart
     */
    createChart(canvasId, config) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) {
            console.error(`Canvas element not found: ${canvasId}`);
            return null;
        }
        
        const chart = new Chart(canvas, config);
        this.charts.set(canvasId, chart);
        return chart;
    }
    
    /**
     * Update chart data
     */
    updateChart(chartId, newData) {
        const chart = this.charts.get(chartId);
        if (!chart) {
            console.error(`Chart not found: ${chartId}`);
            return;
        }
        
        chart.data = newData;
        chart.update();
    }
    
    /**
     * Destroy chart
     */
    destroyChart(chartId) {
        const chart = this.charts.get(chartId);
        if (chart) {
            chart.destroy();
            this.charts.delete(chartId);
        }
    }
    
    /**
     * Resize all charts
     */
    resizeAllCharts() {
        this.charts.forEach(chart => {
            chart.resize();
        });
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Create global dashboard instance
    window.dashboard = new NetworkSecurityDashboard();
    window.networkMonitor = new NetworkMonitor();
    window.chartManager = new ChartManager();
    
    // Start network monitoring
    window.networkMonitor.startMonitoring();
    
    // Global refresh function for backwards compatibility
    window.refreshData = () => {
        window.dashboard.refreshData();
    };
    
    console.log('Network Security Dashboard loaded successfully');
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Page is hidden, reduce update frequency
        if (window.dashboard) {
            window.dashboard.updateInterval = 30000; // 30 seconds
        }
    } else {
        // Page is visible, restore normal update frequency
        if (window.dashboard) {
            window.dashboard.updateInterval = 5000; // 5 seconds
        }
    }
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        NetworkSecurityDashboard,
        NetworkMonitor,
        ChartManager
    };
}
