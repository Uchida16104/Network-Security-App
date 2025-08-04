/**
 * Network Security Monitor
 * Real-time network monitoring and device detection
 * 
 * @author Hirotoshi Uchida
 * @version 1.0.0
 * @project Network Security App
 */

/**
 * Network monitoring and security analysis
 */
class NetworkSecurityMonitor {
    constructor() {
        this.isMonitoring = false;
        this.monitoringInterval = null;
        this.websocketReconnectTimer = null;
        this.networkStatus = {
            isOnline: navigator.onLine,
            latency: 0,
            lastCheck: null,
            consecutiveFailures: 0
        };
        this.deviceCache = new Map();
        this.alertThresholds = {
            highTraffic: 100 * 1024 * 1024, // 100 MB/s
            suspiciousConnections: 10,
            portScanThreshold: 5,
            responseTimeThreshold: 1000 // ms
        };
        this.eventHandlers = new Map();
        this.monitoringConfig = {
            interval: 5000, // 5 seconds
            timeoutDuration: 10000, // 10 seconds
            maxRetries: 3,
            backoffMultiplier: 2
        };
        
        this.init();
    }

    /**
     * Initialize the network monitor
     */
    init() {
        this.setupEventListeners();
        this.loadConfiguration();
        console.log('Network Security Monitor initialized');
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Network connectivity events
        window.addEventListener('online', () => this.handleNetworkOnline());
        window.addEventListener('offline', () => this.handleNetworkOffline());
        
        // Page visibility changes
        document.addEventListener('visibilitychange', () => this.handleVisibilityChange());
        
        // Before unload cleanup
        window.addEventListener('beforeunload', () => this.cleanup());
        
        // Performance observer for network performance
        if ('PerformanceObserver' in window) {
            try {
                const observer = new PerformanceObserver((list) => {
                    this.analyzeNetworkPerformance(list.getEntries());
                });
                observer.observe({ entryTypes: ['navigation', 'resource'] });
            } catch (error) {
                console.warn('Performance observer not supported:', error);
            }
        }
    }

    /**
     * Load monitoring configuration
     */
    loadConfiguration() {
        try {
            const config = localStorage.getItem('networkMonitorConfig');
            if (config) {
                const parsedConfig = JSON.parse(config);
                this.monitoringConfig = { ...this.monitoringConfig, ...parsedConfig };
            }
        } catch (error) {
            console.warn('Failed to load configuration:', error);
        }
    }

    /**
     * Save monitoring configuration
     */
    saveConfiguration() {
        try {
            localStorage.setItem('networkMonitorConfig', JSON.stringify(this.monitoringConfig));
        } catch (error) {
            console.warn('Failed to save configuration:', error);
        }
    }

    /**
     * Start network monitoring
     */
    startMonitoring() {
        if (this.isMonitoring) {
            console.log('Network monitoring already active');
            return;
        }

        this.isMonitoring = true;
        console.log('Starting network monitoring...');

        // Initial network check
        this.performNetworkCheck();

        // Start periodic monitoring
        this.monitoringInterval = setInterval(() => {
            this.performNetworkCheck();
            this.monitorDevices();
            this.analyzeTraffic();
            this.detectAnomalies();
        }, this.monitoringConfig.interval);

        // Update UI
        this.updateMonitoringStatus(true);
        this.emit('monitoring-started');
    }

    /**
     * Stop network monitoring
     */
    stopMonitoring() {
        if (!this.isMonitoring) {
            console.log('Network monitoring not active');
            return;
        }

        this.isMonitoring = false;
        console.log('Stopping network monitoring...');

        // Clear intervals
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
        }

        if (this.websocketReconnectTimer) {
            clearTimeout(this.websocketReconnectTimer);
            this.websocketReconnectTimer = null;
        }

        // Update UI
        this.updateMonitoringStatus(false);
        this.emit('monitoring-stopped');
    }

    /**
     * Perform comprehensive network check
     */
    async performNetworkCheck() {
        try {
            const startTime = performance.now();
            
            // Check API connectivity
            const response = await this.fetchWithTimeout('/api/health-check', {
                method: 'HEAD',
                cache: 'no-cache'
            }, this.monitoringConfig.timeoutDuration);

            const endTime = performance.now();
            const latency = endTime - startTime;

            // Update network status
            this.networkStatus = {
                isOnline: response.ok,
                latency: Math.round(latency),
                lastCheck: new Date(),
                consecutiveFailures: response.ok ? 0 : this.networkStatus.consecutiveFailures + 1
            };

            // Check for performance issues
            if (latency > this.alertThresholds.responseTimeThreshold) {
                this.emit('performance-warning', {
                    message: `High response time detected: ${latency.toFixed(0)}ms`,
                    latency: latency,
                    threshold: this.alertThresholds.responseTimeThreshold
                });
            }

            // Update network status indicators
            this.updateNetworkStatusUI();

            // If connection restored after failures
            if (response.ok && this.networkStatus.consecutiveFailures > 0) {
                this.emit('connection-restored', {
                    message: 'Network connection restored',
                    previousFailures: this.networkStatus.consecutiveFailures
                });
            }

        } catch (error) {
            console.warn('Network check failed:', error);
            
            this.networkStatus.consecutiveFailures++;
            this.networkStatus.isOnline = false;
            this.networkStatus.lastCheck = new Date();

            // Emit connection issues after multiple failures
            if (this.networkStatus.consecutiveFailures >= 3) {
                this.emit('connection-issues', {
                    message: 'Multiple network check failures detected',
                    failures: this.networkStatus.consecutiveFailures,
                    error: error.message
                });
            }

            this.updateNetworkStatusUI();
        }
    }

    /**
     * Monitor network devices
     */
    async monitorDevices() {
        try {
            const response = await this.fetchWithTimeout('/api/network-scan', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.processDeviceData(data.devices || []);
            }

        } catch (error) {
            console.warn('Device monitoring failed:', error);
        }
    }

    /**
     * Process device data and detect changes
     */
    processDeviceData(devices) {
        const currentDevices = new Map();
        const newDevices = [];
        const offlineDevices = [];

        // Process current devices
        devices.forEach(device => {
            const deviceId = device.ip || device.mac;
            if (!deviceId) return;

            currentDevices.set(deviceId, device);

            // Check if this is a new device
            if (!this.deviceCache.has(deviceId)) {
                newDevices.push(device);
                this.emit('new-device-detected', {
                    device: device,
                    timestamp: new Date()
                });
            } else {
                // Check for status changes
                const cachedDevice = this.deviceCache.get(deviceId);
                if (cachedDevice.status !== device.status) {
                    this.emit('device-status-changed', {
                        device: device,
                        previousStatus: cachedDevice.status,
                        newStatus: device.status,
                        timestamp: new Date()
                    });
                }
            }
        });

        // Find devices that went offline
        this.deviceCache.forEach((cachedDevice, deviceId) => {
            if (!currentDevices.has(deviceId)) {
                offlineDevices.push(cachedDevice);
                this.emit('device-offline', {
                    device: cachedDevice,
                    timestamp: new Date()
                });
            }
        });

        // Update device cache
        this.deviceCache.clear();
        currentDevices.forEach((device, deviceId) => {
            this.deviceCache.set(deviceId, device);
        });

        // Emit summary events
        if (newDevices.length > 0) {
            this.emit('devices-updated', {
                newDevices: newDevices,
                offlineDevices: offlineDevices,
                totalDevices: currentDevices.size
            });
        }
    }

    /**
     * Analyze network traffic patterns
     */
    async analyzeTraffic() {
        try {
            const response = await this.fetchWithTimeout('/api/traffic-analysis', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const trafficData = await response.json();
                this.processTrafficData(trafficData);
            }

        } catch (error) {
            console.warn('Traffic analysis failed:', error);
        }
    }

    /**
     * Process traffic data and detect anomalies
     */
    processTrafficData(trafficData) {
        if (!trafficData) return;

        const totalTraffic = (trafficData.rx_bytes || 0) + (trafficData.tx_bytes || 0);

        // Check for high traffic volume
        if (totalTraffic > this.alertThresholds.highTraffic) {
            this.emit('high-traffic-detected', {
                message: 'High network traffic detected',
                totalTraffic: totalTraffic,
                threshold: this.alertThresholds.highTraffic,
                timestamp: new Date()
            });
        }

        // Analyze protocol distribution
        if (trafficData.protocols) {
            this.analyzeProtocolDistribution(trafficData.protocols);
        }

        // Check for suspicious patterns
        this.detectSuspiciousTraffic(trafficData);
    }

    /**
     * Analyze protocol distribution for anomalies
     */
    analyzeProtocolDistribution(protocols) {
        const totalPackets = Object.values(protocols).reduce((sum, count) => sum + count, 0);
        
        // Check for unusual protocol usage
        Object.entries(protocols).forEach(([protocol, count]) => {
            const percentage = (count / totalPackets) * 100;
            
            // Alert on unusual protocol distributions
            if (protocol === 'SSH' && percentage > 30) {
                this.emit('suspicious-protocol-usage', {
                    protocol: protocol,
                    percentage: percentage,
                    message: 'Unusually high SSH traffic detected'
                });
            } else if (protocol === 'FTP' && percentage > 20) {
                this.emit('suspicious-protocol-usage', {
                    protocol: protocol,
                    percentage: percentage,
                    message: 'Unusually high FTP traffic detected'
                });
            }
        });
    }

    /**
     * Detect suspicious traffic patterns
     */
    detectSuspiciousTraffic(trafficData) {
        // Check for potential DDoS patterns
        if (trafficData.connection_count > this.alertThresholds.suspiciousConnections) {
            this.emit('potential-ddos', {
                message: 'Potential DDoS attack detected',
                connectionCount: trafficData.connection_count,
                threshold: this.alertThresholds.suspiciousConnections,
                timestamp: new Date()
            });
        }

        // Check for port scan attempts
        if (trafficData.unique_ports && trafficData.unique_ports > this.alertThresholds.portScanThreshold) {
            this.emit('port-scan-detected', {
                message: 'Potential port scan detected',
                uniquePorts: trafficData.unique_ports,
                threshold: this.alertThresholds.portScanThreshold,
                timestamp: new Date()
            });
        }
    }

    /**
     * Detect network anomalies
     */
    detectAnomalies() {
        // Check for connection quality issues
        if (this.networkStatus.consecutiveFailures > 2) {
            this.emit('connection-instability', {
                message: 'Network connection instability detected',
                failures: this.networkStatus.consecutiveFailures,
                timestamp: new Date()
            });
        }

        // Check for performance degradation
        if (this.networkStatus.latency > this.alertThresholds.responseTimeThreshold * 2) {
            this.emit('performance-degradation', {
                message: 'Severe network performance degradation',
                latency: this.networkStatus.latency,
                threshold: this.alertThresholds.responseTimeThreshold,
                timestamp: new Date()
            });
        }
    }

    /**
     * Handle network online event
     */
    handleNetworkOnline() {
        console.log('Network connection restored');
        this.networkStatus.isOnline = true;
        this.networkStatus.consecutiveFailures = 0;
        
        this.updateNetworkStatusUI();
        this.emit('network-online');

        // Restart monitoring if it was stopped due to offline status
        if (!this.isMonitoring) {
            this.startMonitoring();
        }
    }

    /**
     * Handle network offline event
     */
    handleNetworkOffline() {
        console.log('Network connection lost');
        this.networkStatus.isOnline = false;
        
        this.updateNetworkStatusUI();
        this.emit('network-offline');
    }

    /**
     * Handle page visibility changes
     */
    handleVisibilityChange() {
        if (document.hidden) {
            // Reduce monitoring frequency when page is hidden
            if (this.isMonitoring) {
                clearInterval(this.monitoringInterval);
                this.monitoringInterval = setInterval(() => {
                    this.performNetworkCheck();
                }, this.monitoringConfig.interval * 3); // 3x slower
            }
        } else {
            // Restore normal monitoring frequency
            if (this.isMonitoring) {
                clearInterval(this.monitoringInterval);
                this.monitoringInterval = setInterval(() => {
                    this.performNetworkCheck();
                    this.monitorDevices();
                    this.analyzeTraffic();
                    this.detectAnomalies();
                }, this.monitoringConfig.interval);
            }
        }
    }

    /**
     * Analyze network performance from Performance API
     */
    analyzeNetworkPerformance(entries) {
        entries.forEach(entry => {
            if (entry.entryType === 'navigation') {
                // Analyze page load performance
                const loadTime = entry.loadEventEnd - entry.loadEventStart;
                if (loadTime > 3000) { // 3 seconds threshold
                    this.emit('slow-page-load', {
                        message: 'Slow page load detected',
                        loadTime: loadTime,
                        entry: entry
                    });
                }
            } else if (entry.entryType === 'resource') {
                // Analyze resource load performance
                const duration = entry.responseEnd - entry.requestStart;
                if (duration > 2000 && entry.name.includes('/api/')) { // 2 seconds for API calls
                    this.emit('slow-api-response', {
                        message: 'Slow API response detected',
                        duration: duration,
                        url: entry.name,
                        entry: entry
                    });
                }
            }
        });
    }

    /**
     * Update network status UI indicators
     */
    updateNetworkStatusUI() {
        const indicators = document.querySelectorAll('.realtime-indicator, .network-status-indicator');
        const statusElements = document.querySelectorAll('.network-status');
        
        indicators.forEach(indicator => {
            indicator.classList.remove('online', 'offline', 'warning');
            
            if (this.networkStatus.isOnline) {
                if (this.networkStatus.latency > this.alertThresholds.responseTimeThreshold) {
                    indicator.classList.add('warning');
                } else {
                    indicator.classList.add('online');
                }
            } else {
                indicator.classList.add('offline');
            }
        });

        // Update status text elements
        statusElements.forEach(element => {
            if (this.networkStatus.isOnline) {
                element.textContent = `Online (${this.networkStatus.latency}ms)`;
                element.className = 'network-status status-online';
            } else {
                element.textContent = 'Offline';
                element.className = 'network-status status-offline';
            }
        });

        // Update last check time
        const lastCheckElements = document.querySelectorAll('.last-network-check');
        lastCheckElements.forEach(element => {
            if (this.networkStatus.lastCheck) {
                element.textContent = `Last check: ${this.networkStatus.lastCheck.toLocaleTimeString()}`;
            }
        });
    }

    /**
     * Update monitoring status UI
     */
    updateMonitoringStatus(isActive) {
        const statusElements = document.querySelectorAll('.monitoring-status');
        const controlButtons = document.querySelectorAll('.monitoring-control-btn');

        statusElements.forEach(element => {
            element.textContent = isActive ? 'Active' : 'Inactive';
            element.className = isActive ? 'monitoring-status status-active' : 'monitoring-status status-inactive';
        });

        controlButtons.forEach(button => {
            button.textContent = isActive ? 'Stop Monitoring' : 'Start Monitoring';
            button.className = isActive ? 'btn btn-danger monitoring-control-btn' : 'btn btn-success monitoring-control-btn';
        });
    }

    /**
     * Get current network statistics
     */
    getNetworkStats() {
        return {
            status: this.networkStatus,
            deviceCount: this.deviceCache.size,
            isMonitoring: this.isMonitoring,
            configuration: this.monitoringConfig,
            uptime: this.isMonitoring ? Date.now() - this.monitoringStartTime : 0
        };
    }

    /**
     * Get device list
     */
    getDevices() {
        return Array.from(this.deviceCache.values());
    }

    /**
     * Get device by identifier
     */
    getDevice(identifier) {
        return this.deviceCache.get(identifier);
    }

    /**
     * Manually trigger device scan
     */
    async triggerDeviceScan() {
        this.emit('scan-started');
        
        try {
            await this.monitorDevices();
            this.emit('scan-completed', {
                deviceCount: this.deviceCache.size,
                timestamp: new Date()
            });
        } catch (error) {
            this.emit('scan-failed', {
                error: error.message,
                timestamp: new Date()
            });
        }
    }

    /**
     * Update monitoring configuration
     */
    updateConfiguration(config) {
        this.monitoringConfig = { ...this.monitoringConfig, ...config };
        this.saveConfiguration();
        
        // Restart monitoring with new configuration
        if (this.isMonitoring) {
            this.stopMonitoring();
            setTimeout(() => this.startMonitoring(), 1000);
        }
        
        this.emit('configuration-updated', this.monitoringConfig);
    }

    /**
     * Set alert thresholds
     */
    setAlertThresholds(thresholds) {
        this.alertThresholds = { ...this.alertThresholds, ...thresholds };
        this.emit('thresholds-updated', this.alertThresholds);
    }

    /**
     * Fetch with timeout
     */
    async fetchWithTimeout(url, options = {}, timeout = 10000) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    /**
     * Event emitter functionality
     */
    on(event, handler) {
        if (!this.eventHandlers.has(event)) {
            this.eventHandlers.set(event, []);
        }
        this.eventHandlers.get(event).push(handler);
    }

    off(event, handler) {
        if (this.eventHandlers.has(event)) {
            const handlers = this.eventHandlers.get(event);
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        }
    }

    emit(event, data = null) {
        if (this.eventHandlers.has(event)) {
            this.eventHandlers.get(event).forEach(handler => {
                try {
                    handler(data);
                } catch (error) {
                    console.error(`Error in event handler for ${event}:`, error);
                }
            });
        }
        
        // Also emit to window for global listeners
        window.dispatchEvent(new CustomEvent(`network-monitor-${event}`, {
            detail: data
        }));
    }

    /**
     * Cleanup resources
     */
    cleanup() {
        this.stopMonitoring();
        this.eventHandlers.clear();
        this.deviceCache.clear();
        console.log('Network monitor cleanup completed');
    }

    /**
     * Export monitoring data
     */
    exportData() {
        return {
            timestamp: new Date().toISOString(),
            networkStatus: this.networkStatus,
            devices: Array.from(this.deviceCache.values()),
            configuration: this.monitoringConfig,
            alertThresholds: this.alertThresholds
        };
    }

    /**
     * Import monitoring data
     */
    importData(data) {
        try {
            if (data.devices) {
                this.deviceCache.clear();
                data.devices.forEach(device => {
                    const deviceId = device.ip || device.mac;
                    if (deviceId) {
                        this.deviceCache.set(deviceId, device);
                    }
                });
            }

            if (data.configuration) {
                this.monitoringConfig = { ...this.monitoringConfig, ...data.configuration };
            }

            if (data.alertThresholds) {
                this.alertThresholds = { ...this.alertThresholds, ...data.alertThresholds };
            }

            this.emit('data-imported', {
                deviceCount: this.deviceCache.size,
                timestamp: new Date()
            });

        } catch (error) {
            console.error('Failed to import data:', error);
            this.emit('import-failed', { error: error.message });
        }
    }
}

/**
 * Network Security Alert Manager
 */
class SecurityAlertManager {
    constructor() {
        this.alerts = [];
        this.maxAlerts = 100;
        this.alertCooldowns = new Map();
        this.alertRules = new Map();
        
        this.setupDefaultRules();
    }

    /**
     * Setup default alert rules
     */
    setupDefaultRules() {
        this.addRule('high-traffic', {
            cooldown: 300000, // 5 minutes
            severity: 'medium',
            category: 'performance'
        });

        this.addRule('new-device-detected', {
            cooldown: 60000, // 1 minute
            severity: 'low',
            category: 'security'
        });

        this.addRule('port-scan-detected', {
            cooldown: 600000, // 10 minutes
            severity: 'high',
            category: 'security'
        });

        this.addRule('potential-ddos', {
            cooldown: 300000, // 5 minutes
            severity: 'critical',
            category: 'security'
        });
    }

    /**
     * Add alert rule
     */
    addRule(alertType, rule) {
        this.alertRules.set(alertType, rule);
    }

    /**
     * Process alert
     */
    processAlert(type, data) {
        const rule = this.alertRules.get(type);
        if (!rule) return;

        // Check cooldown
        const lastAlert = this.alertCooldowns.get(type);
        if (lastAlert && (Date.now() - lastAlert) < rule.cooldown) {
            return; // Still in cooldown period
        }

        // Create alert
        const alert = {
            id: this.generateAlertId(),
            type: type,
            severity: rule.severity,
            category: rule.category,
            message: data.message || `${type} alert`,
            timestamp: new Date(),
            data: data,
            acknowledged: false
        };

        this.addAlert(alert);
        this.alertCooldowns.set(type, Date.now());
    }

    /**
     * Add alert to list
     */
    addAlert(alert) {
        this.alerts.unshift(alert);
        
        // Maintain max alert limit
        if (this.alerts.length > this.maxAlerts) {
            this.alerts = this.alerts.slice(0, this.maxAlerts);
        }

        // Emit alert event
        window.dispatchEvent(new CustomEvent('security-alert', {
            detail: alert
        }));
    }

    /**
     * Get alerts
     */
    getAlerts(filter = {}) {
        let filteredAlerts = this.alerts;

        if (filter.severity) {
            filteredAlerts = filteredAlerts.filter(alert => alert.severity === filter.severity);
        }

        if (filter.category) {
            filteredAlerts = filteredAlerts.filter(alert => alert.category === filter.category);
        }

        if (filter.unacknowledged) {
            filteredAlerts = filteredAlerts.filter(alert => !alert.acknowledged);
        }

        return filteredAlerts;
    }

    /**
     * Acknowledge alert
     */
    acknowledgeAlert(alertId) {
        const alert = this.alerts.find(a => a.id === alertId);
        if (alert) {
            alert.acknowledged = true;
            alert.acknowledgedAt = new Date();
        }
    }

    /**
     * Clear alerts
     */
    clearAlerts(filter = {}) {
        if (Object.keys(filter).length === 0) {
            this.alerts = [];
        } else {
            this.alerts = this.alerts.filter(alert => {
                if (filter.severity && alert.severity !== filter.severity) return true;
                if (filter.category && alert.category !== filter.category) return true;
                if (filter.acknowledged !== undefined && alert.acknowledged !== filter.acknowledged) return true;
                return false;
            });
        }
    }

    /**
     * Generate alert ID
     */
    generateAlertId() {
        return 'alert_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
}

// Global instances
let networkMonitor = null;
let alertManager = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    networkMonitor = new NetworkSecurityMonitor();
    alertManager = new SecurityAlertManager();

    // Make globally available
    window.networkMonitor = networkMonitor;
    window.alertManager = alertManager;

    // Setup alert processing
    networkMonitor.on('high-traffic-detected', (data) => alertManager.processAlert('high-traffic', data));
    networkMonitor.on('new-device-detected', (data) => alertManager.processAlert('new-device-detected', data));
    networkMonitor.on('port-scan-detected', (data) => alertManager.processAlert('port-scan-detected', data));
    networkMonitor.on('potential-ddos', (data) => alertManager.processAlert('potential-ddos', data));
    networkMonitor.on('suspicious-protocol-usage', (data) => alertManager.processAlert('suspicious-protocol-usage', data));

    // Auto-start monitoring
    if (networkMonitor.networkStatus.isOnline) {
        networkMonitor.startMonitoring();
    }

    console.log('Network monitoring system initialized');
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        NetworkSecurityMonitor,
        SecurityAlertManager
    };
}
