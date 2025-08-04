# Network Security App Dockerfile
# Multi-stage build for optimized production deployment
# Author: Hirotoshi Uchida
# Project: Network Security App
# Homepage: https://hirotoshiuchida.onrender.com

# Build Stage
FROM ubuntu:22.04 AS builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV PHP_VERSION=8.1
ENV NODE_VERSION=24

# Set working directory
WORKDIR /app
       
# Install system dependencies and network tools
RUN apt-get update && apt-get install -y \
    # Basic system tools
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg2 \
    curl \
    wget \
    unzip \
    git \
    supervisor \
    cron \
    logrotate \
    # Network monitoring tools
    nmap \
    tcpdump \
    tshark \
    wireshark \
    net-tools \
    iproute2 \
    arp-scan \
    traceroute \
    dnsutils \
    iputils-ping \
    netcat \
    iftop \
    iotop \
    htop \
    lsof \
    strace \
    procps \
    psmisc \
    # Web server and PHP
    nginx \
    php${PHP_VERSION}-fpm \
    php${PHP_VERSION}-cli \
    php${PHP_VERSION}-common \
    php${PHP_VERSION}-mysql \
    php${PHP_VERSION}-sqlite3 \
    php${PHP_VERSION}-redis \
    php${PHP_VERSION}-xml \
    php${PHP_VERSION}-mbstring \
    php${PHP_VERSION}-curl \
    php${PHP_VERSION}-zip \
    php${PHP_VERSION}-gd \
    php${PHP_VERSION}-bcmath \
    php${PHP_VERSION}-intl \
    php${PHP_VERSION}-soap \
    php${PHP_VERSION}-xsl \
    php${PHP_VERSION}-opcache \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js and npm
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g npm@latest

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && chmod +x /usr/local/bin/composer

# Configure network tools permissions for non-root execution
RUN chmod u+s /usr/bin/nmap \
    && chmod u+s /usr/bin/tcpdump \
    && chmod u+s /usr/sbin/arp-scan \
    && chmod u+s /bin/ping \
    && chmod u+s /usr/bin/traceroute \
    && chmod u+s /usr/bin/tshark

# Create application user and directories
RUN useradd -m -s /bin/bash -u 1001 appuser \
    && mkdir -p /app/storage/logs \
    && mkdir -p /app/storage/app/public \
    && mkdir -p /app/storage/framework/cache \
    && mkdir -p /app/storage/framework/sessions \
    && mkdir -p /app/storage/framework/views \
    && mkdir -p /app/bootstrap/cache \
    && mkdir -p /app/public/assets \
    && mkdir -p /var/log/supervisor

# Copy application files
COPY --chown=appuser:appuser . /app/

# Create minimal Laravel artisan file if it doesn't exist
RUN if [ ! -f /app/artisan ]; then \
    echo '#!/usr/bin/env php' > /app/artisan && \
    echo '<?php' >> /app/artisan && \
    echo 'echo "Minimal artisan stub - migrations not needed for this app\n";' >> /app/artisan && \
    echo 'exit(0);' >> /app/artisan && \
    chmod +x /app/artisan; \
    fi

# Install PHP dependencies
RUN cd /app && composer install --no-plugins --no-scripts

# Run composer scripts manually to handle missing artisan gracefully
RUN cd /app && \
    (composer run-script post-install-cmd || echo "Post-install scripts completed with warnings") && \
    (composer run-script post-update-cmd || echo "Post-update scripts completed with warnings")

# Create minimal package.json and install Node.js dependencies if needed
RUN cd /app && \
    if [ ! -f package.json ]; then \
        echo '{"name": "network-security-app", "version": "1.0.0", "scripts": {"production": "echo Production build completed"}}' > package.json; \
    fi && \
    if [ ! -f package-lock.json ]; then \
        npm install --package-lock-only; \
    fi && \
    (npm ci --omit=dev || npm install --production) && \
    (npm run production || echo "Production build skipped - no build script found") && \
    rm -rf node_modules

# Production Stage
FROM ubuntu:22.04 AS production

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV PHP_VERSION=8.1
ENV APP_ENV=production
ENV APP_DEBUG=false

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    # Network monitoring tools
    nmap \
    tcpdump \
    tshark \
    net-tools \
    iproute2 \
    arp-scan \
    traceroute \
    dnsutils \
    iputils-ping \
    netcat \
    # Web server and PHP runtime
    nginx \
    php${PHP_VERSION}-fpm \
    php${PHP_VERSION}-cli \
    php${PHP_VERSION}-common \
    php${PHP_VERSION}-mysql \
    php${PHP_VERSION}-sqlite3 \
    php${PHP_VERSION}-redis \
    php${PHP_VERSION}-xml \
    php${PHP_VERSION}-mbstring \
    php${PHP_VERSION}-curl \
    php${PHP_VERSION}-zip \
    php${PHP_VERSION}-gd \
    php${PHP_VERSION}-bcmath \
    php${PHP_VERSION}-intl \
    php${PHP_VERSION}-opcache \
    # System utilities
    supervisor \
    cron \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN useradd -m -s /bin/bash -u 1001 appuser

# Set working directory
WORKDIR /app

# Copy application from builder stage
COPY --from=builder --chown=appuser:appuser /app /app

# Copy configuration files
COPY --chown=root:root config/nginx.conf /etc/nginx/sites-available/default
COPY --chown=root:root config/php-fpm.conf /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
COPY --chown=root:root config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Configure network tools permissions
RUN chmod u+s /usr/bin/nmap \
    && chmod u+s /usr/bin/tcpdump \
    && chmod u+s /usr/sbin/arp-scan \
    && chmod u+s /bin/ping \
    && chmod u+s /usr/bin/traceroute \
    && chmod u+s /usr/bin/tshark

# Set directory permissions including supervisor logs
RUN chown -R appuser:appuser /app/storage \
    && chown -R appuser:appuser /app/bootstrap/cache \
    && chown -R appuser:appuser /var/log/supervisor \
    && chmod -R 755 /app/storage \
    && chmod -R 755 /app/bootstrap/cache \
    && chmod -R 755 /app/public \
    && chmod -R 755 /var/log/supervisor

# Create comprehensive public/index.php with embedded NetworkController and NetworkMonitor
RUN mkdir -p /app/public && cat > /app/public/index.php << 'EOF'
<?php
// Network Security App - Integrated Implementation
// Author: Hirotoshi Uchida
// Homepage: https://hirotoshiuchida.onrender.com

error_reporting(E_ALL);
ini_set('display_errors', 1);
set_time_limit(300);

// Simple autoloader for classes
spl_autoload_register(function ($class) {
    // No need to load external classes - everything is embedded
});

// NetworkController class embedded
class NetworkController {
    private $networkInterface;
    private $scanResults;
    
    public function __construct() {
        $this->networkInterface = $this->detectNetworkInterface();
        $this->scanResults = [];
    }
    
    public function dashboard() {
        try {
            $data = [
                'devices' => $this->getActiveDevices(),
                'traffic' => $this->getNetworkTraffic(),
                'security_events' => $this->getSecurityEvents(),
                'system_status' => $this->getSystemStatus(),
                'topology' => $this->getNetworkTopology(),
                'alerts' => $this->getSecurityAlerts()
            ];
            
            return [
                'success' => true,
                'data' => $data,
                'timestamp' => date('c')
            ];
            
        } catch (Exception $e) {
            error_log('Dashboard error: ' . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to load dashboard data'
            ];
        }
    }
    
    public function networkScan($networkRange = null, $scanType = 'quick') {
        try {
            $networkRange = $networkRange ?: $this->getNetworkRange();
            $scanResults = $this->performNetworkScan($networkRange, $scanType);
            
            return [
                'success' => true,
                'data' => $scanResults,
                'scan_type' => $scanType,
                'network_range' => $networkRange,
                'timestamp' => date('c')
            ];
            
        } catch (Exception $e) {
            error_log('Network scan error: ' . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Network scan failed'
            ];
        }
    }
    
    private function performNetworkScan($networkRange, $scanType) {
        $results = [
            'devices' => [],
            'ports' => [],
            'services' => [],
            'vulnerabilities' => []
        ];
        
        // Nmap host discovery
        $nmapCommand = "nmap -sn {$networkRange} 2>/dev/null";
        $nmapOutput = shell_exec($nmapCommand);
        
        if ($nmapOutput) {
            $hosts = $this->parseNmapHostDiscovery($nmapOutput);
            
            foreach ($hosts as $host) {
                $deviceInfo = $this->scanDevice($host, $scanType);
                $results['devices'][] = $deviceInfo;
            }
        }
        
        // ARP scan for local network
        $arpCommand = "arp-scan -l 2>/dev/null || arp -a 2>/dev/null";
        $arpOutput = shell_exec($arpCommand);
        
        if ($arpOutput) {
            $arpDevices = $this->parseArpScan($arpOutput);
            $results['devices'] = array_merge($results['devices'], $arpDevices);
        }
        
        // Remove duplicates and sort
        $uniqueDevices = [];
        $seenIps = [];
        foreach ($results['devices'] as $device) {
            if (!in_array($device['ip'], $seenIps)) {
                $uniqueDevices[] = $device;
                $seenIps[] = $device['ip'];
            }
        }
        
        usort($uniqueDevices, function($a, $b) {
            return strcmp($a['ip'], $b['ip']);
        });
        
        $results['devices'] = $uniqueDevices;
        
        return $results;
    }
    
    private function scanDevice($ip, $scanType) {
        $device = [
            'ip' => $ip,
            'mac' => '',
            'hostname' => '',
            'os' => '',
            'ports' => [],
            'services' => [],
            'last_seen' => date('c'),
            'status' => 'unknown'
        ];
        
        // Get MAC address from ARP table
        $arpCommand = "arp -n {$ip} 2>/dev/null";
        $arpOutput = shell_exec($arpCommand);
        if ($arpOutput && preg_match('/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i', $arpOutput, $matches)) {
            $device['mac'] = $matches[1];
        }
        
        // Get hostname
        $hostCommand = "nslookup {$ip} 2>/dev/null | grep 'name =' | head -1";
        $hostOutput = shell_exec($hostCommand);
        if ($hostOutput && preg_match('/name = (.+)\./', $hostOutput, $matches)) {
            $device['hostname'] = trim($matches[1]);
        }
        
        // Ping test
        $pingCommand = "ping -c 1 -W 1 {$ip} 2>/dev/null";
        $pingOutput = shell_exec($pingCommand);
        $device['status'] = $pingOutput && strpos($pingOutput, '1 received') !== false ? 'online' : 'offline';
        
        if ($scanType === 'detailed' && $device['status'] === 'online') {
            // Port scan
            $portCommand = "nmap -F {$ip} 2>/dev/null";
            $portOutput = shell_exec($portCommand);
            if ($portOutput) {
                $device['ports'] = $this->parseNmapPorts($portOutput);
            }
            
            // OS detection
            $osCommand = "nmap -O {$ip} 2>/dev/null";
            $osOutput = shell_exec($osCommand);
            if ($osOutput && preg_match('/Running: (.+)/i', $osOutput, $matches)) {
                $device['os'] = trim($matches[1]);
            }
        }
        
        return $device;
    }
    
    private function getActiveDevices() {
        $devices = [];
        
        // Get devices from ARP table
        $arpCommand = "arp -a 2>/dev/null";
        $arpOutput = shell_exec($arpCommand);
        
        if ($arpOutput) {
            $devices = array_merge($devices, $this->parseArpTable($arpOutput));
        }
        
        // Get devices from network scan
        $networkRange = $this->getNetworkRange();
        $nmapCommand = "nmap -sn {$networkRange} 2>/dev/null";
        $nmapOutput = shell_exec($nmapCommand);
        
        if ($nmapOutput) {
            $nmapDevices = $this->parseNmapHostDiscovery($nmapOutput);
            foreach ($nmapDevices as $ip) {
                $found = false;
                foreach ($devices as $device) {
                    if ($device['ip'] === $ip) {
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    $devices[] = ['ip' => $ip, 'mac' => '', 'hostname' => '', 'status' => 'online'];
                }
            }
        }
        
        return $devices;
    }
    
    private function getNetworkTraffic() {
        $interface = $this->networkInterface;
        $rxBytes = 0;
        $txBytes = 0;
        
        $statsCommand = "cat /proc/net/dev 2>/dev/null | grep {$interface}";
        $statsOutput = shell_exec($statsCommand);
        
        if ($statsOutput) {
            $stats = preg_split('/\s+/', trim($statsOutput));
            if (count($stats) >= 10) {
                $rxBytes = intval($stats[1]);
                $txBytes = intval($stats[9]);
            }
        }
        
        return [
            'rx_bytes' => $rxBytes,
            'tx_bytes' => $txBytes,
            'total_bytes' => $rxBytes + $txBytes,
            'interface' => $interface
        ];
    }
    
    private function getSecurityEvents() {
        $alerts = $this->monitorSecurity();
        return count($alerts);
    }
    
    private function getSystemStatus() {
        $uptime = shell_exec('uptime 2>/dev/null');
        $loadAvg = shell_exec('cat /proc/loadavg 2>/dev/null');
        $memInfo = shell_exec('cat /proc/meminfo 2>/dev/null');
        
        return [
            'status' => 'online',
            'uptime' => trim($uptime ?: 'Unknown'),
            'load_average' => trim($loadAvg ?: '0.00 0.00 0.00'),
            'memory_info' => $this->parseMemInfo($memInfo ?: '')
        ];
    }
    
    private function getNetworkTopology() {
        $devices = $this->getActiveDevices();
        $gateway = $this->getGateway();
        
        $topology = [
            'nodes' => [],
            'links' => []
        ];
        
        // Add gateway as central node
        $topology['nodes'][] = [
            'id' => $gateway,
            'label' => 'Gateway',
            'type' => 'gateway',
            'ip' => $gateway
        ];
        
        // Add devices as nodes
        foreach ($devices as $device) {
            if ($device['ip'] !== $gateway) {
                $topology['nodes'][] = [
                    'id' => $device['ip'],
                    'label' => $device['hostname'] ?: $device['ip'],
                    'type' => 'device',
                    'ip' => $device['ip'],
                    'mac' => $device['mac'] ?? ''
                ];
                
                // Add link to gateway
                $topology['links'][] = [
                    'source' => $gateway,
                    'target' => $device['ip']
                ];
            }
        }
        
        return $topology;
    }
    
    private function getSecurityAlerts() {
        return $this->monitorSecurity();
    }
    
    private function monitorSecurity() {
        $alerts = [];
        
        // Check for suspicious network activity
        $suspiciousIps = $this->detectSuspiciousActivity();
        foreach ($suspiciousIps as $ip => $activity) {
            $alerts[] = [
                'type' => 'suspicious_activity',
                'severity' => 'medium',
                'ip' => $ip,
                'description' => "Suspicious network activity detected from {$ip}",
                'details' => $activity,
                'timestamp' => date('c')
            ];
        }
        
        return $alerts;
    }
    
    private function detectSuspiciousActivity() {
        $suspicious = [];
        
        // Monitor for unusual traffic patterns
        $netstatCommand = "netstat -tn 2>/dev/null | grep ESTABLISHED";
        $netstatOutput = shell_exec($netstatCommand);
        
        if ($netstatOutput) {
            $connections = $this->parseConnections($netstatOutput);
            $ipCounts = [];
            
            foreach ($connections as $conn) {
                $ip = $conn['remote_ip'];
                if (!isset($ipCounts[$ip])) {
                    $ipCounts[$ip] = 0;
                }
                $ipCounts[$ip]++;
            }
            
            foreach ($ipCounts as $ip => $count) {
                if ($count > 10) { // Threshold for suspicious activity
                    $suspicious[$ip] = [
                        'connection_count' => $count,
                        'type' => 'high_connection_count'
                    ];
                }
            }
        }
        
        return $suspicious;
    }
    
    // Parser methods
    private function parseNmapHostDiscovery($output) {
        $hosts = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/Nmap scan report for (.+)/', $line, $matches)) {
                $host = trim($matches[1]);
                if (filter_var($host, FILTER_VALIDATE_IP)) {
                    $hosts[] = $host;
                } elseif (preg_match('/\(([0-9.]+)\)/', $host, $ipMatches)) {
                    $hosts[] = $ipMatches[1];
                }
            }
        }
        
        return array_unique($hosts);
    }
    
    private function parseArpScan($output) {
        $devices = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/([0-9.]+)\s+([0-9a-f:]+)/i', $line, $matches)) {
                $devices[] = [
                    'ip' => $matches[1],
                    'mac' => strtolower($matches[2]),
                    'hostname' => '',
                    'status' => 'online',
                    'last_seen' => date('c')
                ];
            }
        }
        
        return $devices;
    }
    
    private function parseArpTable($output) {
        $devices = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/\(([0-9.]+)\) at ([0-9a-f:]+)/i', $line, $matches)) {
                $devices[] = [
                    'ip' => $matches[1],
                    'mac' => strtolower($matches[2]),
                    'hostname' => '',
                    'status' => 'online',
                    'last_seen' => date('c')
                ];
            }
        }
        
        return $devices;
    }
    
    private function parseNmapPorts($output) {
        $ports = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/(\d+)\/tcp\s+(\w+)\s+(.+)/', $line, $matches)) {
                $ports[] = [
                    'port' => intval($matches[1]),
                    'protocol' => 'tcp',
                    'state' => $matches[2],
                    'service' => trim($matches[3])
                ];
            }
        }
        
        return $ports;
    }
    
    private function parseConnections($output) {
        $connections = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/tcp\s+\d+\s+\d+\s+([0-9.]+):(\d+)\s+([0-9.]+):(\d+)\s+(\w+)/', $line, $matches)) {
                $connections[] = [
                    'local_ip' => $matches[1],
                    'local_port' => intval($matches[2]),
                    'remote_ip' => $matches[3],
                    'remote_port' => intval($matches[4]),
                    'state' => $matches[5]
                ];
            }
        }
        
        return $connections;
    }
    
    private function parseMemInfo($output) {
        $memInfo = ['total' => 0, 'free' => 0, 'available' => 0];
        
        if (empty($output)) {
            return $memInfo;
        }
        
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/MemTotal:\s+(\d+)\s+kB/', $line, $matches)) {
                $memInfo['total'] = intval($matches[1]);
            } elseif (preg_match('/MemFree:\s+(\d+)\s+kB/', $line, $matches)) {
                $memInfo['free'] = intval($matches[1]);
            } elseif (preg_match('/MemAvailable:\s+(\d+)\s+kB/', $line, $matches)) {
                $memInfo['available'] = intval($matches[1]);
            }
        }
        
        return $memInfo;
    }
    
    private function detectNetworkInterface() {
        $routeCommand = "ip route | grep default 2>/dev/null";
        $routeOutput = shell_exec($routeCommand);
        
        if ($routeOutput && preg_match('/dev\s+(\w+)/', $routeOutput, $matches)) {
            return $matches[1];
        }
        
        // Fallback methods
        $interfaces = ['eth0', 'wlan0', 'enp0s3', 'ens33'];
        foreach ($interfaces as $interface) {
            $testCommand = "ip link show {$interface} 2>/dev/null";
            if (shell_exec($testCommand)) {
                return $interface;
            }
        }
        
        return 'eth0'; // Default fallback
    }
    
    private function getNetworkRange() {
        $routeCommand = "ip route | grep {$this->networkInterface} | grep -v default 2>/dev/null | head -1";
        $routeOutput = shell_exec($routeCommand);
        
        if ($routeOutput && preg_match('/([0-9.]+\/\d+)/', $routeOutput, $matches)) {
            return $matches[1];
        }
        
        // Fallback to common private network ranges
        $privateRanges = ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24'];
        foreach ($privateRanges as $range) {
            $testCommand = "nmap -sn {$range} 2>/dev/null | grep 'Nmap scan report'";
            if (shell_exec($testCommand)) {
                return $range;
            }
        }
        
        return '192.168.1.0/24'; // Default fallback
    }
    
    private function getGateway() {
        $routeCommand = "ip route | grep default 2>/dev/null";
        $routeOutput = shell_exec($routeCommand);
        
        if ($routeOutput && preg_match('/default via ([0-9.]+)/', $routeOutput, $matches)) {
            return $matches[1];
        }
        
        return '192.168.1.1'; // Default fallback
    }
}

// NetworkMonitor class embedded (simplified version without HHVM dependencies)
class NetworkMonitor {
    private $networkInterface;
    private $deviceCache;
    private $securityEvents;
    private $lastScanTime;

    public function __construct() {
        $this->networkInterface = $this->detectPrimaryInterface();
        $this->deviceCache = [];
        $this->securityEvents = [];
        $this->lastScanTime = 0.0;
    }

    public function performNetworkAnalysis() {
        $startTime = microtime(true);

        $nmapResults = $this->executeNmapScan();
        $arpResults = $this->executeArpScan();
        $netstatResults = $this->executeNetstatAnalysis();

        $analysisResults = [
            'nmap' => $nmapResults,
            'arp' => $arpResults,
            'netstat' => $netstatResults,
            'execution_time' => microtime(true) - $startTime,
            'timestamp' => date('c')
        ];

        return $analysisResults;
    }

    private function executeNmapScan() {
        $range = $this->getNetworkRange();
        $out = shell_exec("nmap -sn {$range} 2>/dev/null");
        $hosts = $out ? $this->parseNmapHostDiscovery($out) : [];

        return [
            'hosts' => $hosts,
            'services' => [],
            'os_detection' => []
        ];
    }

    private function executeArpScan() {
        $out1 = shell_exec('arp-scan -l 2>/dev/null || arp -a 2>/dev/null');
        return $out1 ? $this->parseArpOutput($out1) : [];
    }

    private function executeNetstatAnalysis() {
        $conn = shell_exec('netstat -tn 2>/dev/null');
        $lstn = shell_exec('netstat -ln 2>/dev/null');

        return [
            'connections' => $conn ? $this->parseNetstatConnections($conn) : [],
            'listening_ports' => $lstn ? $this->parseNetstatListening($lstn) : [],
            'interface_stats' => [],
            'routing_table' => []
        ];
    }

    private function parseNmapHostDiscovery($output) {
        $hosts = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/Nmap scan report for (.+)/', $line, $matches)) {
                $host = trim($matches[1]);
                if (filter_var($host, FILTER_VALIDATE_IP)) {
                    $hosts[] = $host;
                } elseif (preg_match('/\(([0-9.]+)\)/', $host, $ipMatches)) {
                    $hosts[] = $ipMatches[1];
                }
            }
        }
        
        return array_unique($hosts);
    }

    private function parseArpOutput($output) {
        $devices = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/([0-9.]+)\s+([0-9a-f:]+)/i', $line, $matches)) {
                $devices[] = [
                    'ip' => $matches[1],
                    'mac' => strtolower($matches[2])
                ];
            }
        }
        
        return $devices;
    }

    private function parseNetstatConnections($output) {
        $connections = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/tcp\s+\d+\s+\d+\s+([0-9.]+):(\d+)\s+([0-9.]+):(\d+)\s+(\w+)/', $line, $matches)) {
                $connections[] = [
                    'local_ip' => $matches[1],
                    'local_port' => intval($matches[2]),
                    'remote_ip' => $matches[3],
                    'remote_port' => intval($matches[4]),
                    'state' => $matches[5]
                ];
            }
        }
        
        return $connections;
    }

    private function parseNetstatListening($output) {
        $listening = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/tcp\s+\d+\s+\d+\s+([0-9.*]+):(\d+)\s+[0-9.*:]+\s+LISTEN/', $line, $matches)) {
                $listening[] = [
                    'ip' => $matches[1],
                    'port' => intval($matches[2]),
                    'protocol' => 'tcp'
                ];
            }
        }
        
        return $listening;
    }

    private function detectPrimaryInterface() {
        $out = shell_exec('ip route | grep default');
        if ($out && preg_match('/dev\s+(\w+)/', $out, $m)) {
            return $m[1];
        }
        return 'eth0';
    }

    private function getNetworkRange() {
        $out = shell_exec("ip route | grep {$this->networkInterface} | grep -v default | head -1");
        if ($out && preg_match('/([0-9\.]+\/\d+)/', $out, $m)) {
            return $m[1];
        }
        return '192.168.1.0/24';
    }
}

// Main application routing and handling
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$pathInfo = parse_url($requestUri, PHP_URL_PATH);

// Initialize controllers
$networkController = new NetworkController();
$networkMonitor = new NetworkMonitor();

// API routing
if (str_starts_with($pathInfo, '/api/')) {
    header('Content-Type: application/json');
    
    switch ($pathInfo) {
        case '/api/dashboard':
            echo json_encode($networkController->dashboard());
            break;
            
        case '/api/network-scan':
            $range = $_GET['range'] ?? null;
            $type = $_GET['type'] ?? 'quick';
            echo json_encode($networkController->networkScan($range, $type));
            break;
            
        case '/api/analysis':
            echo json_encode($networkMonitor->performNetworkAnalysis());
            break;
            
        case '/api/health-check':
            echo json_encode([
                'success' => true,
                'status' => 'healthy',
                'timestamp' => date('c')
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'API endpoint not found']);
    }
    exit;
}

// Handle AJAX requests
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['action']) {
        case 'dashboard':
            echo json_encode($networkController->dashboard());
            break;
            
        case 'scan':
            $range = $_GET['range'] ?? null;
            $type = $_GET['type'] ?? 'quick';
            echo json_encode($networkController->networkScan($range, $type));
            break;
            
        case 'analysis':
            echo json_encode($networkMonitor->performNetworkAnalysis());
            break;
            
        default:
            echo json_encode(['error' => 'Unknown action']);
    }
    exit;
}

// HTML Interface
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security App - Hirotoshi Uchida</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            color: white;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .card:hover {
            transform: translateY(-2px);
        }
        
        .card h3 {
            color: #5a67d8;
            margin-bottom: 15px;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-online {
            background-color: #48bb78;
        }
        
        .status-offline {
            background-color: #f56565;
        }
        
        .device-list {
            max-height: 200px;
            overflow-y: auto;
        }
        
        .device-item {
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .device-item:last-child {
            border-bottom: none;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: opacity 0.2s;
        }
        
        .btn:hover {
            opacity: 0.9;
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        .loading {
            text-align: center;
            color: #666;
            font-style: italic;
        }
        
        .error {
            color: #e53e3e;
            background: #fed7d7;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        
        .success {
            color: #38a169;
            background: #c6f6d5;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: white;
            opacity: 0.8;
        }
        
        .footer a {
            color: white;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Network Security Monitor</h1>
            <p>Real-time network monitoring and security analysis</p>
            <p>by <strong>Hirotoshi Uchida</strong></p>
        </div>
        
        <div class="dashboard">
            <div class="card">
                <h3>🖥️ System Status</h3>
                <div id="system-status">
                    <div class="loading pulse">Loading system status...</div>
                </div>
            </div>
            
            <div class="card">
                <h3>🌐 Network Devices</h3>
                <div id="network-devices">
                    <div class="loading pulse">Discovering devices...</div>
                </div>
                <button class="btn" onclick="scanNetwork()" id="scan-btn">🔍 Scan Network</button>
            </div>
            
            <div class="card">
                <h3>📊 Network Traffic</h3>
                <div id="network-traffic">
                    <div class="loading pulse">Analyzing traffic...</div>
                </div>
            </div>
            
            <div class="card">
                <h3>🚨 Security Alerts</h3>
                <div id="security-alerts">
                    <div class="loading pulse">Monitoring security events...</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>🔬 Network Analysis</h3>
            <div id="network-analysis">
                <div class="loading pulse">Performing network analysis...</div>
            </div>
            <button class="btn" onclick="runAnalysis()" id="analysis-btn">🔄 Run Analysis</button>
        </div>
        
        <div class="footer">
            <p>&copy; 2024 Hirotoshi Uchida - Network Security App</p>
            <p>Visit: <a href="https://hirotoshiuchida.onrender.com" target="_blank">https://hirotoshiuchida.onrender.com</a></p>
        </div>
    </div>

    <script>
        // Auto-refresh dashboard data
        let refreshInterval;
        
        function loadDashboard() {
            fetch('/?action=dashboard')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateSystemStatus(data.data.system_status);
                        updateNetworkDevices(data.data.devices);
                        updateNetworkTraffic(data.data.traffic);
                        updateSecurityAlerts(data.data.alerts);
                    } else {
                        showError('Failed to load dashboard data');
                    }
                })
                .catch(error => {
                    console.error('Dashboard error:', error);
                    showError('Dashboard connection failed');
                });
        }
        
        function updateSystemStatus(status) {
            const container = document.getElementById('system-status');
            container.innerHTML = `
                <div class="device-item">
                    <span>Status</span>
                    <span><span class="status-indicator status-online"></span>Online</span>
                </div>
                <div class="device-item">
                    <span>Uptime</span>
                    <span>${status.uptime || 'Unknown'}</span>
                </div>
                <div class="device-item">
                    <span>Load Average</span>
                    <span>${status.load_average || '0.00'}</span>
                </div>
            `;
        }
        
        function updateNetworkDevices(devices) {
            const container = document.getElementById('network-devices');
            if (!devices || devices.length === 0) {
                container.innerHTML = '<p>No devices detected</p>';
                return;
            }
            
            let html = '<div class="device-list">';
            devices.forEach(device => {
                const statusClass = device.status === 'online' ? 'status-online' : 'status-offline';
                html += `
                    <div class="device-item">
                        <span>
                            <span class="status-indicator ${statusClass}"></span>
                            ${device.ip}
                        </span>
                        <span>${device.hostname || device.mac || 'Unknown'}</span>
                    </div>
                `;
            });
            html += '</div>';
            container.innerHTML = html;
        }
        
        function updateNetworkTraffic(traffic) {
            const container = document.getElementById('network-traffic');
            container.innerHTML = `
                <div class="device-item">
                    <span>Interface</span>
                    <span>${traffic.interface || 'Unknown'}</span>
                </div>
                <div class="device-item">
                    <span>RX Bytes</span>
                    <span>${formatBytes(traffic.rx_bytes || 0)}</span>
                </div>
                <div class="device-item">
                    <span>TX Bytes</span>
                    <span>${formatBytes(traffic.tx_bytes || 0)}</span>
                </div>
                <div class="device-item">
                    <span>Total</span>
                    <span>${formatBytes(traffic.total_bytes || 0)}</span>
                </div>
            `;
        }
        
        function updateSecurityAlerts(alerts) {
            const container = document.getElementById('security-alerts');
            if (!alerts || alerts.length === 0) {
                container.innerHTML = '<p style="color: #38a169;">✅ No security alerts</p>';
                return;
            }
            
            let html = '<div class="device-list">';
            alerts.forEach(alert => {
                const severityColor = alert.severity === 'high' ? '#e53e3e' : '#ed8936';
                html += `
                    <div class="device-item" style="color: ${severityColor};">
                        <span>${alert.type}</span>
                        <span>${alert.severity}</span>
                    </div>
                `;
            });
            html += '</div>';
            container.innerHTML = html;
        }
        
        function scanNetwork() {
            const btn = document.getElementById('scan-btn');
            btn.disabled = true;
            btn.textContent = '🔍 Scanning...';
            
            fetch('/?action=scan')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateNetworkDevices(data.data.devices);
                        showSuccess('Network scan completed successfully');
                    } else {
                        showError('Network scan failed');
                    }
                })
                .catch(error => {
                    console.error('Scan error:', error);
                    showError('Network scan connection failed');
                })
                .finally(() => {
                    btn.disabled = false;
                    btn.textContent = '🔍 Scan Network';
                });
        }
        
        function runAnalysis() {
            const btn = document.getElementById('analysis-btn');
            const container = document.getElementById('network-analysis');
            
            btn.disabled = true;
            btn.textContent = '🔄 Analyzing...';
            container.innerHTML = '<div class="loading pulse">Running comprehensive analysis...</div>';
            
            fetch('/?action=analysis')
                .then(response => response.json())
                .then(data => {
                    let html = '<div class="device-list">';
                    
                    // NMAP Results
                    if (data.nmap && data.nmap.hosts) {
                        html += `<div class="device-item"><strong>Discovered Hosts: ${data.nmap.hosts.length}</strong></div>`;
                        data.nmap.hosts.forEach(host => {
                            html += `<div class="device-item"><span>📍 ${host}</span></div>`;
                        });
                    }
                    
                    // ARP Results
                    if (data.arp && data.arp.length > 0) {
                        html += `<div class="device-item"><strong>ARP Entries: ${data.arp.length}</strong></div>`;
                    }
                    
                    // Netstat Results
                    if (data.netstat && data.netstat.connections) {
                        html += `<div class="device-item"><strong>Active Connections: ${data.netstat.connections.length}</strong></div>`;
                    }
                    
                    html += `<div class="device-item"><span>Execution Time</span><span>${(data.execution_time || 0).toFixed(2)}s</span></div>`;
                    html += '</div>';
                    
                    container.innerHTML = html;
                    showSuccess('Network analysis completed');
                })
                .catch(error => {
                    console.error('Analysis error:', error);
                    container.innerHTML = '<p class="error">Analysis failed</p>';
                    showError('Network analysis failed');
                })
                .finally(() => {
                    btn.disabled = false;
                    btn.textContent = '🔄 Run Analysis';
                });
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function showError(message) {
            const notification = document.createElement('div');
            notification.className = 'error';
            notification.textContent = message;
            document.body.insertBefore(notification, document.body.firstChild);
            setTimeout(() => notification.remove(), 5000);
        }
        
        function showSuccess(message) {
            const notification = document.createElement('div');
            notification.className = 'success';
            notification.textContent = message;
            document.body.insertBefore(notification, document.body.firstChild);
            setTimeout(() => notification.remove(), 3000);
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboard();
            refreshInterval = setInterval(loadDashboard, 30000); // Refresh every 30 seconds
        });
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', function() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        });
    </script>
</body>
</html>
EOF

COPY NetworkController.php /app/app/Http/Controllers/NetworkController.php

COPY NetworkMonitor.php /app/app/Services/NetworkMonitor.php

COPY index.html /app/public/index.html

RUN mkdir -p /app/public/assets

COPY assets/ /app/public/assets/

# Create SQLite database
RUN touch /app/storage/database.sqlite \
    && chown appuser:appuser /app/storage/database.sqlite \
    && chmod 664 /app/storage/database.sqlite

# Configure PHP-FPM
RUN sed -i 's/listen = \/run\/php\/php8.1-fpm.sock/listen = 127.0.0.1:9000/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf \
    && sed -i 's/;listen.mode = 0660/listen.mode = 0660/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf

# Configure Nginx
RUN rm -f /etc/nginx/sites-enabled/default \
    && ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

COPY start.sh /app/start.sh

COPY network-monitor.sh /app/network-monitor.sh

COPY health-check.sh /app/health-check.sh

RUN chmod +x /app/start.sh

RUN chmod +x /app/health-check.sh

RUN chmod +x /app/network-monitor.sh

# Create log directory and set permissions
RUN mkdir -p /var/log/network-security \
    && chown -R appuser:appuser /var/log/network-security \
    && chmod -R 755 /var/log/network-security

# Set up log rotation
COPY logrotate.d/network-security /etc/logrotate.d/network-security

# Expose ports
EXPOSE 8080 9000

# Set up volume for persistent data
VOLUME ["/app/storage"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# DO NOT switch to appuser - supervisor needs root privileges to manage services
# USER appuser

# Set environment variables for the application
ENV PATH="/app:${PATH}"
ENV APP_KEY=""
ENV APP_URL="http://localhost:8080"
ENV LOG_CHANNEL=stderr
ENV LOG_LEVEL=info
ENV DB_CONNECTION=sqlite
ENV DB_DATABASE=/app/storage/database.sqlite
ENV CACHE_DRIVER=file
ENV SESSION_DRIVER=file
ENV QUEUE_CONNECTION=sync
ENV NETWORK_INTERFACE=eth0
ENV SCAN_TIMEOUT=30
ENV MONITOR_INTERVAL=5
ENV MAX_SCAN_RANGE=254
ENV ENABLE_REAL_TIME=true
ENV SECURITY_ALERTS=true

# Default command
CMD ["/app/start.sh"]

# Build information
LABEL maintainer="Hirotoshi Uchida <contact.hirotoshiuchida@gmail.com>"
LABEL description="Network Security Monitoring Application"
LABEL version="1.0.0"
LABEL homepage="https://hirotoshiuchida.onrender.com"
LABEL repository="https://github.com/Uchida16104/Network-Security-App"
LABEL documentation="https://github.com/Uchida16104/Network-Security-App/README.md"
LABEL license="MIT"

# Additional build arguments for customization
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Network Security App" \
      org.label-schema.description="Real-time network security monitoring and analysis" \
      org.label-schema.url="https://hirotoshiuchida.onrender.com" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/Uchida16104/Network-Security-App" \
      org.label-schema.vendor="Hirotoshi Uchida" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"
