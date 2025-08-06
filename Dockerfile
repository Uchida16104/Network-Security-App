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

# Create minimal composer.json if it doesn't exist
RUN if [ ! -f /app/composer.json ]; then \
        echo '{' > /app/composer.json && \
        echo '  "name": "uchida16104/network-security-app",' >> /app/composer.json && \
        echo '  "description": "Network Security Monitoring Application",' >> /app/composer.json && \
        echo '  "type": "project",' >> /app/composer.json && \
        echo '  "require": {' >> /app/composer.json && \
        echo '    "php": "^8.1"' >> /app/composer.json && \
        echo '  },' >> /app/composer.json && \
        echo '  "autoload": {' >> /app/composer.json && \
        echo '    "psr-4": {' >> /app/composer.json && \
        echo '      "App\\\\": "app/"' >> /app/composer.json && \
        echo '    }' >> /app/composer.json && \
        echo '  },' >> /app/composer.json && \
        echo '  "minimum-stability": "stable"' >> /app/composer.json && \
        echo '}' >> /app/composer.json; \
    fi && \
    composer install --no-dev --optimize-autoloader --no-scripts || echo "Composer install completed with warnings"

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
RUN mkdir -p /app/public && \
    echo '<?php' > /app/public/index.php && \
    echo '// Network Security App - Integrated Implementation' >> /app/public/index.php && \
    echo '// Author: Hirotoshi Uchida' >> /app/public/index.php && \
    echo '// Homepage: https://hirotoshiuchida.onrender.com' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo 'error_reporting(E_ALL);' >> /app/public/index.php && \
    echo 'ini_set("display_errors", 1);' >> /app/public/index.php && \
    echo 'set_time_limit(300);' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '// Simple autoloader for classes' >> /app/public/index.php && \
    echo 'spl_autoload_register(function ($class) {' >> /app/public/index.php && \
    echo '    // No need to load external classes - everything is embedded' >> /app/public/index.php && \
    echo '});' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '// NetworkController class embedded' >> /app/public/index.php && \
    echo 'class NetworkController {' >> /app/public/index.php && \
    echo '    private $networkInterface;' >> /app/public/index.php && \
    echo '    private $scanResults;' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    public function __construct() {' >> /app/public/index.php && \
    echo '        $this->networkInterface = $this->detectNetworkInterface();' >> /app/public/index.php && \
    echo '        $this->scanResults = [];' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    public function dashboard() {' >> /app/public/index.php && \
    echo '        try {' >> /app/public/index.php && \
    echo '            $data = [' >> /app/public/index.php && \
    echo '                "devices" => $this->getActiveDevices(),' >> /app/public/index.php && \
    echo '                "traffic" => $this->getNetworkTraffic(),' >> /app/public/index.php && \
    echo '                "security_events" => $this->getSecurityEvents(),' >> /app/public/index.php && \
    echo '                "system_status" => $this->getSystemStatus(),' >> /app/public/index.php && \
    echo '                "topology" => $this->getNetworkTopology(),' >> /app/public/index.php && \
    echo '                "alerts" => $this->getSecurityAlerts()' >> /app/public/index.php && \
    echo '            ];' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            return [' >> /app/public/index.php && \
    echo '                "success" => true,' >> /app/public/index.php && \
    echo '                "data" => $data,' >> /app/public/index.php && \
    echo '                "timestamp" => date("c")' >> /app/public/index.php && \
    echo '            ];' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        } catch (Exception $e) {' >> /app/public/index.php && \
    echo '            error_log("Dashboard error: " . $e->getMessage());' >> /app/public/index.php && \
    echo '            return [' >> /app/public/index.php && \
    echo '                "success" => false,' >> /app/public/index.php && \
    echo '                "error" => "Failed to load dashboard data"' >> /app/public/index.php && \
    echo '            ];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    public function networkScan($networkRange = null, $scanType = "quick") {' >> /app/public/index.php && \
    echo '        try {' >> /app/public/index.php && \
    echo '            $networkRange = $networkRange ?: $this->getNetworkRange();' >> /app/public/index.php && \
    echo '            $scanResults = $this->performNetworkScan($networkRange, $scanType);' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            return [' >> /app/public/index.php && \
    echo '                "success" => true,' >> /app/public/index.php && \
    echo '                "data" => $scanResults,' >> /app/public/index.php && \
    echo '                "scan_type" => $scanType,' >> /app/public/index.php && \
    echo '                "network_range" => $networkRange,' >> /app/public/index.php && \
    echo '                "timestamp" => date("c")' >> /app/public/index.php && \
    echo '            ];' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        } catch (Exception $e) {' >> /app/public/index.php && \
    echo '            error_log("Network scan error: " . $e->getMessage());' >> /app/public/index.php && \
    echo '            return [' >> /app/public/index.php && \
    echo '                "success" => false,' >> /app/public/index.php && \
    echo '                "error" => "Network scan failed"' >> /app/public/index.php && \
    echo '            ];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function performNetworkScan($networkRange, $scanType) {' >> /app/public/index.php && \
    echo '        $results = [' >> /app/public/index.php && \
    echo '            "devices" => [],' >> /app/public/index.php && \
    echo '            "ports" => [],' >> /app/public/index.php && \
    echo '            "services" => [],' >> /app/public/index.php && \
    echo '            "vulnerabilities" => []' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Nmap host discovery' >> /app/public/index.php && \
    echo '        $nmapCommand = "nmap -sn {$networkRange} 2>/dev/null";' >> /app/public/index.php && \
    echo '        $nmapOutput = shell_exec($nmapCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($nmapOutput) {' >> /app/public/index.php && \
    echo '            $hosts = $this->parseNmapHostDiscovery($nmapOutput);' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            foreach ($hosts as $host) {' >> /app/public/index.php && \
    echo '                $deviceInfo = $this->scanDevice($host, $scanType);' >> /app/public/index.php && \
    echo '                $results["devices"][] = $deviceInfo;' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // ARP scan for local network' >> /app/public/index.php && \
    echo '        $arpCommand = "arp-scan -l 2>/dev/null || arp -a 2>/dev/null";' >> /app/public/index.php && \
    echo '        $arpOutput = shell_exec($arpCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($arpOutput) {' >> /app/public/index.php && \
    echo '            $arpDevices = $this->parseArpScan($arpOutput);' >> /app/public/index.php && \
    echo '            $results["devices"] = array_merge($results["devices"], $arpDevices);' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Remove duplicates and sort' >> /app/public/index.php && \
    echo '        $uniqueDevices = [];' >> /app/public/index.php && \
    echo '        $seenIps = [];' >> /app/public/index.php && \
    echo '        foreach ($results["devices"] as $device) {' >> /app/public/index.php && \
    echo '            if (!in_array($device["ip"], $seenIps)) {' >> /app/public/index.php && \
    echo '                $uniqueDevices[] = $device;' >> /app/public/index.php && \
    echo '                $seenIps[] = $device["ip"];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        usort($uniqueDevices, function($a, $b) {' >> /app/public/index.php && \
    echo '            return strcmp($a["ip"], $b["ip"]);' >> /app/public/index.php && \
    echo '        });' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        $results["devices"] = $uniqueDevices;' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $results;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function scanDevice($ip, $scanType) {' >> /app/public/index.php && \
    echo '        $device = [' >> /app/public/index.php && \
    echo '            "ip" => $ip,' >> /app/public/index.php && \
    echo '            "mac" => "",' >> /app/public/index.php && \
    echo '            "hostname" => "",' >> /app/public/index.php && \
    echo '            "os" => "",' >> /app/public/index.php && \
    echo '            "ports" => [],' >> /app/public/index.php && \
    echo '            "services" => [],' >> /app/public/index.php && \
    echo '            "last_seen" => date("c"),' >> /app/public/index.php && \
    echo '            "status" => "unknown"' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Get MAC address from ARP table' >> /app/public/index.php && \
    echo '        $arpCommand = "arp -n {$ip} 2>/dev/null";' >> /app/public/index.php && \
    echo '        $arpOutput = shell_exec($arpCommand);' >> /app/public/index.php && \
    echo '        if ($arpOutput && preg_match("/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i", $arpOutput, $matches)) {' >> /app/public/index.php && \
    echo '            $device["mac"] = $matches[1];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Get hostname' >> /app/public/index.php && \
    echo '        $hostCommand = "nslookup {$ip} 2>/dev/null | grep \"name =\" | head -1";' >> /app/public/index.php && \
    echo '        $hostOutput = shell_exec($hostCommand);' >> /app/public/index.php && \
    echo '        if ($hostOutput && preg_match("/name = (.+)\./", $hostOutput, $matches)) {' >> /app/public/index.php && \
    echo '            $device["hostname"] = trim($matches[1]);' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Ping test' >> /app/public/index.php && \
    echo '        $pingCommand = "ping -c 1 -W 1 {$ip} 2>/dev/null";' >> /app/public/index.php && \
    echo '        $pingOutput = shell_exec($pingCommand);' >> /app/public/index.php && \
    echo '        $device["status"] = $pingOutput && strpos($pingOutput, "1 received") !== false ? "online" : "offline";' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($scanType === "detailed" && $device["status"] === "online") {' >> /app/public/index.php && \
    echo '            // Port scan' >> /app/public/index.php && \
    echo '            $portCommand = "nmap -F {$ip} 2>/dev/null";' >> /app/public/index.php && \
    echo '            $portOutput = shell_exec($portCommand);' >> /app/public/index.php && \
    echo '            if ($portOutput) {' >> /app/public/index.php && \
    echo '                $device["ports"] = $this->parseNmapPorts($portOutput);' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            // OS detection' >> /app/public/index.php && \
    echo '            $osCommand = "nmap -O {$ip} 2>/dev/null";' >> /app/public/index.php && \
    echo '            $osOutput = shell_exec($osCommand);' >> /app/public/index.php && \
    echo '            if ($osOutput && preg_match("/Running: (.+)/i", $osOutput, $matches)) {' >> /app/public/index.php && \
    echo '                $device["os"] = trim($matches[1]);' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $device;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function getActiveDevices() {' >> /app/public/index.php && \
    echo '        $devices = [];' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Get devices from ARP table' >> /app/public/index.php && \
    echo '        $arpCommand = "arp -a 2>/dev/null";' >> /app/public/index.php && \
    echo '        $arpOutput = shell_exec($arpCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($arpOutput) {' >> /app/public/index.php && \
    echo '            $devices = array_merge($devices, $this->parseArpTable($arpOutput));' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Get devices from network scan' >> /app/public/index.php && \
    echo '        $networkRange = $this->getNetworkRange();' >> /app/public/index.php && \
    echo '        $nmapCommand = "nmap -sn {$networkRange} 2>/dev/null";' >> /app/public/index.php && \
    echo '        $nmapOutput = shell_exec($nmapCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($nmapOutput) {' >> /app/public/index.php && \
    echo '            $nmapDevices = $this->parseNmapHostDiscovery($nmapOutput);' >> /app/public/index.php && \
    echo '            foreach ($nmapDevices as $ip) {' >> /app/public/index.php && \
    echo '                $found = false;' >> /app/public/index.php && \
    echo '                foreach ($devices as $device) {' >> /app/public/index.php && \
    echo '                    if ($device["ip"] === $ip) {' >> /app/public/index.php && \
    echo '                        $found = true;' >> /app/public/index.php && \
    echo '                        break;' >> /app/public/index.php && \
    echo '                    }' >> /app/public/index.php && \
    echo '                }' >> /app/public/index.php && \
    echo '                if (!$found) {' >> /app/public/index.php && \
    echo '                    $devices[] = ["ip" => $ip, "mac" => "", "hostname" => "", "status" => "online"];' >> /app/public/index.php && \
    echo '                }' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $devices;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function getNetworkTraffic() {' >> /app/public/index.php && \
    echo '        $interface = $this->networkInterface;' >> /app/public/index.php && \
    echo '        $rxBytes = 0;' >> /app/public/index.php && \
    echo '        $txBytes = 0;' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        $statsCommand = "cat /proc/net/dev 2>/dev/null | grep {$interface}";' >> /app/public/index.php && \
    echo '        $statsOutput = shell_exec($statsCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($statsOutput) {' >> /app/public/index.php && \
    echo '            $stats = preg_split("/\s+/", trim($statsOutput));' >> /app/public/index.php && \
    echo '            if (count($stats) >= 10) {' >> /app/public/index.php && \
    echo '                $rxBytes = intval($stats[1]);' >> /app/public/index.php && \
    echo '                $txBytes = intval($stats[9]);' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return [' >> /app/public/index.php && \
    echo '            "rx_bytes" => $rxBytes,' >> /app/public/index.php && \
    echo '            "tx_bytes" => $txBytes,' >> /app/public/index.php && \
    echo '            "total_bytes" => $rxBytes + $txBytes,' >> /app/public/index.php && \
    echo '            "interface" => $interface' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function getSecurityEvents() {' >> /app/public/index.php && \
    echo '        $alerts = $this->monitorSecurity();' >> /app/public/index.php && \
    echo '        return count($alerts);' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function getSystemStatus() {' >> /app/public/index.php && \
    echo '        $uptime = shell_exec("uptime 2>/dev/null");' >> /app/public/index.php && \
    echo '        $loadAvg = shell_exec("cat /proc/loadavg 2>/dev/null");' >> /app/public/index.php && \
    echo '        $memInfo = shell_exec("cat /proc/meminfo 2>/dev/null");' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return [' >> /app/public/index.php && \
    echo '            "status" => "online",' >> /app/public/index.php && \
    echo '            "uptime" => trim($uptime ?: "Unknown"),' >> /app/public/index.php && \
    echo '            "load_average" => trim($loadAvg ?: "0.00 0.00 0.00"),' >> /app/public/index.php && \
    echo '            "memory_info" => $this->parseMemInfo($memInfo ?: "")' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function getNetworkTopology() {' >> /app/public/index.php && \
    echo '        $devices = $this->getActiveDevices();' >> /app/public/index.php && \
    echo '        $gateway = $this->getGateway();' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        $topology = [' >> /app/public/index.php && \
    echo '            "nodes" => [],' >> /app/public/index.php && \
    echo '            "links" => []' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Add gateway as central node' >> /app/public/index.php && \
    echo '        $topology["nodes"][] = [' >> /app/public/index.php && \
    echo '            "id" => $gateway,' >> /app/public/index.php && \
    echo '            "label" => "Gateway",' >> /app/public/index.php && \
    echo '            "type" => "gateway",' >> /app/public/index.php && \
    echo '            "ip" => $gateway' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Add devices as nodes' >> /app/public/index.php && \
    echo '        foreach ($devices as $device) {' >> /app/public/index.php && \
    echo '            if ($device["ip"] !== $gateway) {' >> /app/public/index.php && \
    echo '                $topology["nodes"][] = [' >> /app/public/index.php && \
    echo '                    "id" => $device["ip"],' >> /app/public/index.php && \
    echo '                    "label" => $device["hostname"] ?: $device["ip"],' >> /app/public/index.php && \
    echo '                    "type" => "device",' >> /app/public/index.php && \
    echo '                    "ip" => $device["ip"],' >> /app/public/index.php && \
    echo '                    "mac" => $device["mac"] ?? ""' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '                ' >> /app/public/index.php && \
    echo '                // Add link to gateway' >> /app/public/index.php && \
    echo '                $topology["links"][] = [' >> /app/public/index.php && \
    echo '                    "source" => $gateway,' >> /app/public/index.php && \
    echo '                    "target" => $device["ip"]' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $topology;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function getSecurityAlerts() {' >> /app/public/index.php && \
    echo '        return $this->monitorSecurity();' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function monitorSecurity() {' >> /app/public/index.php && \
    echo '        $alerts = [];' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Check for suspicious network activity' >> /app/public/index.php && \
    echo '        $suspiciousIps = $this->detectSuspiciousActivity();' >> /app/public/index.php && \
    echo '        foreach ($suspiciousIps as $ip => $activity) {' >> /app/public/index.php && \
    echo '            $alerts[] = [' >> /app/public/index.php && \
    echo '                "type" => "suspicious_activity",' >> /app/public/index.php && \
    echo '                "severity" => "medium",' >> /app/public/index.php && \
    echo '                "ip" => $ip,' >> /app/public/index.php && \
    echo '                "description" => "Suspicious network activity detected from {$ip}",' >> /app/public/index.php && \
    echo '                "details" => $activity,' >> /app/public/index.php && \
    echo '                "timestamp" => date("c")' >> /app/public/index.php && \
    echo '            ];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $alerts;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function detectSuspiciousActivity() {' >> /app/public/index.php && \
    echo '        $suspicious = [];' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Monitor for unusual traffic patterns' >> /app/public/index.php && \
    echo '        $netstatCommand = "netstat -tn 2>/dev/null | grep ESTABLISHED";' >> /app/public/index.php && \
    echo '        $netstatOutput = shell_exec($netstatCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($netstatOutput) {' >> /app/public/index.php && \
    echo '            $connections = $this->parseConnections($netstatOutput);' >> /app/public/index.php && \
    echo '            $ipCounts = [];' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            foreach ($connections as $conn) {' >> /app/public/index.php && \
    echo '                $ip = $conn["remote_ip"];' >> /app/public/index.php && \
    echo '                if (!isset($ipCounts[$ip])) {' >> /app/public/index.php && \
    echo '                    $ipCounts[$ip] = 0;' >> /app/public/index.php && \
    echo '                }' >> /app/public/index.php && \
    echo '                $ipCounts[$ip]++;' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            foreach ($ipCounts as $ip => $count) {' >> /app/public/index.php && \
    echo '                if ($count > 10) { // Threshold for suspicious activity' >> /app/public/index.php && \
    echo '                    $suspicious[$ip] = [' >> /app/public/index.php && \
    echo '                        "connection_count" => $count,' >> /app/public/index.php && \
    echo '                        "type" => "high_connection_count"' >> /app/public/index.php && \
    echo '                    ];' >> /app/public/index.php && \
    echo '                }' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $suspicious;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    // Parser methods' >> /app/public/index.php && \
    echo '    private function parseNmapHostDiscovery($output) {' >> /app/public/index.php && \
    echo '        $hosts = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/Nmap scan report for (.+)/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $host = trim($matches[1]);' >> /app/public/index.php && \
    echo '                if (filter_var($host, FILTER_VALIDATE_IP)) {' >> /app/public/index.php && \
    echo '                    $hosts[] = $host;' >> /app/public/index.php && \
    echo '                } elseif (preg_match("/\(([0-9.]+)\)/", $host, $ipMatches)) {' >> /app/public/index.php && \
    echo '                    $hosts[] = $ipMatches[1];' >> /app/public/index.php && \
    echo '                }' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return array_unique($hosts);' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function parseArpScan($output) {' >> /app/public/index.php && \
    echo '        $devices = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/([0-9.]+)\s+([0-9a-f:]+)/i", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $devices[] = [' >> /app/public/index.php && \
    echo '                    "ip" => $matches[1],' >> /app/public/index.php && \
    echo '                    "mac" => strtolower($matches[2]),' >> /app/public/index.php && \
    echo '                    "hostname" => "",' >> /app/public/index.php && \
    echo '                    "status" => "online",' >> /app/public/index.php && \
    echo '                    "last_seen" => date("c")' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $devices;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function parseArpTable($output) {' >> /app/public/index.php && \
    echo '        $devices = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/\(([0-9.]+)\) at ([0-9a-f:]+)/i", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $devices[] = [' >> /app/public/index.php && \
    echo '                    "ip" => $matches[1],' >> /app/public/index.php && \
    echo '                    "mac" => strtolower($matches[2]),' >> /app/public/index.php && \
    echo '                    "hostname" => "",' >> /app/public/index.php && \
    echo '                    "status" => "online",' >> /app/public/index.php && \
    echo '                    "last_seen" => date("c")' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $devices;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function parseNmapPorts($output) {' >> /app/public/index.php && \
    echo '        $ports = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/(\d+)\/tcp\s+(\w+)\s+(.+)/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $ports[] = [' >> /app/public/index.php && \
    echo '                    "port" => intval($matches[1]),' >> /app/public/index.php && \
    echo '                    "protocol" => "tcp",' >> /app/public/index.php && \
    echo '                    "state" => $matches[2],' >> /app/public/index.php && \
    echo '                    "service" => trim($matches[3])' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $ports;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function parseConnections($output) {' >> /app/public/index.php && \
    echo '        $connections = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/tcp\s+\d+\s+\d+\s+([0-9.]+):(\d+)\s+([0-9.]+):(\d+)\s+(\w+)/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $connections[] = [' >> /app/public/index.php && \
    echo '                    "local_ip" => $matches[1],' >> /app/public/index.php && \
    echo '                    "local_port" => intval($matches[2]),' >> /app/public/index.php && \
    echo '                    "remote_ip" => $matches[3],' >> /app/public/index.php && \
    echo '                    "remote_port" => intval($matches[4]),' >> /app/public/index.php && \
    echo '                    "state" => $matches[5]' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $connections;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function parseMemInfo($output) {' >> /app/public/index.php && \
    echo '        $memInfo = ["total" => 0, "free" => 0, "available" => 0];' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if (empty($output)) {' >> /app/public/index.php && \
    echo '            return $memInfo;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/MemTotal:\s+(\d+)\s+kB/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $memInfo["total"] = intval($matches[1]);' >> /app/public/index.php && \
    echo '            } elseif (preg_match("/MemFree:\s+(\d+)\s+kB/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $memInfo["free"] = intval($matches[1]);' >> /app/public/index.php && \
    echo '            } elseif (preg_match("/MemAvailable:\s+(\d+)\s+kB/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $memInfo["available"] = intval($matches[1]);' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $memInfo;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function detectNetworkInterface() {' >> /app/public/index.php && \
    echo '        $routeCommand = "ip route | grep default 2>/dev/null";' >> /app/public/index.php && \
    echo '        $routeOutput = shell_exec($routeCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($routeOutput && preg_match("/dev\s+(\w+)/", $routeOutput, $matches)) {' >> /app/public/index.php && \
    echo '            return $matches[1];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Fallback methods' >> /app/public/index.php && \
    echo '        $interfaces = ["eth0", "wlan0", "enp0s3", "ens33"];' >> /app/public/index.php && \
    echo '        foreach ($interfaces as $interface) {' >> /app/public/index.php && \
    echo '            $testCommand = "ip link show {$interface} 2>/dev/null";' >> /app/public/index.php && \
    echo '            if (shell_exec($testCommand)) {' >> /app/public/index.php && \
    echo '                return $interface;' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return "eth0"; // Default fallback' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function getNetworkRange() {' >> /app/public/index.php && \
    echo '        $routeCommand = "ip route | grep {$this->networkInterface} | grep -v default 2>/dev/null | head -1";' >> /app/public/index.php && \
    echo '        $routeOutput = shell_exec($routeCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($routeOutput && preg_match("/([0-9.]+\/\d+)/", $routeOutput, $matches)) {' >> /app/public/index.php && \
    echo '            return $matches[1];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Fallback to common private network ranges' >> /app/public/index.php && \
    echo '        $privateRanges = ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"];' >> /app/public/index.php && \
    echo '        foreach ($privateRanges as $range) {' >> /app/public/index.php && \
    echo '            $testCommand = "nmap -sn {$range} 2>/dev/null | grep \"Nmap scan report\"";' >> /app/public/index.php && \
    echo '            if (shell_exec($testCommand)) {' >> /app/public/index.php && \
    echo '                return $range;' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return "192.168.1.0/24"; // Default fallback' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    private function getGateway() {' >> /app/public/index.php && \
    echo '        $routeCommand = "ip route | grep default 2>/dev/null";' >> /app/public/index.php && \
    echo '        $routeOutput = shell_exec($routeCommand);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        if ($routeOutput && preg_match("/default via ([0-9.]+)/", $routeOutput, $matches)) {' >> /app/public/index.php && \
    echo '            return $matches[1];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return "192.168.1.1"; // Default fallback' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '}' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '// NetworkMonitor class embedded (simplified version without HHVM dependencies)' >> /app/public/index.php && \
    echo 'class NetworkMonitor {' >> /app/public/index.php && \
    echo '    private $networkInterface;' >> /app/public/index.php && \
    echo '    private $deviceCache;' >> /app/public/index.php && \
    echo '    private $securityEvents;' >> /app/public/index.php && \
    echo '    private $lastScanTime;' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    public function __construct() {' >> /app/public/index.php && \
    echo '        $this->networkInterface = $this->detectPrimaryInterface();' >> /app/public/index.php && \
    echo '        $this->deviceCache = [];' >> /app/public/index.php && \
    echo '        $this->securityEvents = [];' >> /app/public/index.php && \
    echo '        $this->lastScanTime = 0.0;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    public function performNetworkAnalysis() {' >> /app/public/index.php && \
    echo '        $startTime = microtime(true);' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '        $nmapResults = $this->executeNmapScan();' >> /app/public/index.php && \
    echo '        $arpResults = $this->executeArpScan();' >> /app/public/index.php && \
    echo '        $netstatResults = $this->executeNetstatAnalysis();' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '        $analysisResults = [' >> /app/public/index.php && \
    echo '            "nmap" => $nmapResults,' >> /app/public/index.php && \
    echo '            "arp" => $arpResults,' >> /app/public/index.php && \
    echo '            "netstat" => $netstatResults,' >> /app/public/index.php && \
    echo '            "execution_time" => microtime(true) - $startTime,' >> /app/public/index.php && \
    echo '            "timestamp" => date("c")' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '        return $analysisResults;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function executeNmapScan() {' >> /app/public/index.php && \
    echo '        $range = $this->getNetworkRange();' >> /app/public/index.php && \
    echo '        $out = shell_exec("nmap -sn {$range} 2>/dev/null");' >> /app/public/index.php && \
    echo '        $hosts = $out ? $this->parseNmapHostDiscovery($out) : [];' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '        return [' >> /app/public/index.php && \
    echo '            "hosts" => $hosts,' >> /app/public/index.php && \
    echo '            "services" => [],' >> /app/public/index.php && \
    echo '            "os_detection" => []' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function executeArpScan() {' >> /app/public/index.php && \
    echo '        $out1 = shell_exec("arp-scan -l 2>/dev/null || arp -a 2>/dev/null");' >> /app/public/index.php && \
    echo '        return $out1 ? $this->parseArpOutput($out1) : [];' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function executeNetstatAnalysis() {' >> /app/public/index.php && \
    echo '        $conn = shell_exec("netstat -tn 2>/dev/null");' >> /app/public/index.php && \
    echo '        $lstn = shell_exec("netstat -ln 2>/dev/null");' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '        return [' >> /app/public/index.php && \
    echo '            "connections" => $conn ? $this->parseNetstatConnections($conn) : [],' >> /app/public/index.php && \
    echo '            "listening_ports" => $lstn ? $this->parseNetstatListening($lstn) : [],' >> /app/public/index.php && \
    echo '            "interface_stats" => [],' >> /app/public/index.php && \
    echo '            "routing_table" => []' >> /app/public/index.php && \
    echo '        ];' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function parseNmapHostDiscovery($output) {' >> /app/public/index.php && \
    echo '        $hosts = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/Nmap scan report for (.+)/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $host = trim($matches[1]);' >> /app/public/index.php && \
    echo '                if (filter_var($host, FILTER_VALIDATE_IP)) {' >> /app/public/index.php && \
    echo '                    $hosts[] = $host;' >> /app/public/index.php && \
    echo '                } elseif (preg_match("/\(([0-9.]+)\)/", $host, $ipMatches)) {' >> /app/public/index.php && \
    echo '                    $hosts[] = $ipMatches[1];' >> /app/public/index.php && \
    echo '                }' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return array_unique($hosts);' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function parseArpOutput($output) {' >> /app/public/index.php && \
    echo '        $devices = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/([0-9.]+)\s+([0-9a-f:]+)/i", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $devices[] = [' >> /app/public/index.php && \
    echo '                    "ip" => $matches[1],' >> /app/public/index.php && \
    echo '                    "mac" => strtolower($matches[2])' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $devices;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function parseNetstatConnections($output) {' >> /app/public/index.php && \
    echo '        $connections = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/tcp\s+\d+\s+\d+\s+([0-9.]+):(\d+)\s+([0-9.]+):(\d+)\s+(\w+)/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $connections[] = [' >> /app/public/index.php && \
    echo '                    "local_ip" => $matches[1],' >> /app/public/index.php && \
    echo '                    "local_port" => intval($matches[2]),' >> /app/public/index.php && \
    echo '                    "remote_ip" => $matches[3],' >> /app/public/index.php && \
    echo '                    "remote_port" => intval($matches[4]),' >> /app/public/index.php && \
    echo '                    "state" => $matches[5]' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $connections;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function parseNetstatListening($output) {' >> /app/public/index.php && \
    echo '        $listening = [];' >> /app/public/index.php && \
    echo '        $lines = explode("\n", $output);' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        foreach ($lines as $line) {' >> /app/public/index.php && \
    echo '            if (preg_match("/tcp\s+\d+\s+\d+\s+([0-9.*]+):(\d+)\s+[0-9.*:]+\s+LISTEN/", $line, $matches)) {' >> /app/public/index.php && \
    echo '                $listening[] = [' >> /app/public/index.php && \
    echo '                    "ip" => $matches[1],' >> /app/public/index.php && \
    echo '                    "port" => intval($matches[2]),' >> /app/public/index.php && \
    echo '                    "protocol" => "tcp"' >> /app/public/index.php && \
    echo '                ];' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        return $listening;' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function detectPrimaryInterface() {' >> /app/public/index.php && \
    echo '        $out = shell_exec("ip route | grep default");' >> /app/public/index.php && \
    echo '        if ($out && preg_match("/dev\s+(\w+)/", $out, $m)) {' >> /app/public/index.php && \
    echo '            return $m[1];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        return "eth0";' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    private function getNetworkRange() {' >> /app/public/index.php && \
    echo '        $out = shell_exec("ip route | grep {$this->networkInterface} | grep -v default | head -1");' >> /app/public/index.php && \
    echo '        if ($out && preg_match("/([0-9\.]+\/\d+)/", $out, $m)) {' >> /app/public/index.php && \
    echo '            return $m[1];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        return "192.168.1.0/24";' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '}' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '// Main application routing and handling' >> /app/public/index.php && \
    echo '$requestMethod = $_SERVER["REQUEST_METHOD"] ?? "GET";' >> /app/public/index.php && \
    echo '$requestUri = $_SERVER["REQUEST_URI"] ?? "/";' >> /app/public/index.php && \
    echo '$pathInfo = parse_url($requestUri, PHP_URL_PATH);' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '// Initialize controllers' >> /app/public/index.php && \
    echo '$networkController = new NetworkController();' >> /app/public/index.php && \
    echo '$networkMonitor = new NetworkMonitor();' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '// API routing' >> /app/public/index.php && \
    echo 'if (str_starts_with($pathInfo, "/api/")) {' >> /app/public/index.php && \
    echo '    header("Content-Type: application/json");' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    switch ($pathInfo) {' >> /app/public/index.php && \
    echo '        case "/api/dashboard":' >> /app/public/index.php && \
    echo '            echo json_encode($networkController->dashboard());' >> /app/public/index.php && \
    echo '            break;' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        case "/api/network-scan":' >> /app/public/index.php && \
    echo '            $range = $_GET["range"] ?? null;' >> /app/public/index.php && \
    echo '            $type = $_GET["type"] ?? "quick";' >> /app/public/index.php && \
    echo '            echo json_encode($networkController->networkScan($range, $type));' >> /app/public/index.php && \
    echo '            break;' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        case "/api/analysis":' >> /app/public/index.php && \
    echo '            echo json_encode($networkMonitor->performNetworkAnalysis());' >> /app/public/index.php && \
    echo '            break;' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        case "/api/health-check":' >> /app/public/index.php && \
    echo '            echo json_encode([' >> /app/public/index.php && \
    echo '                "success" => true,' >> /app/public/index.php && \
    echo '                "status" => "healthy",' >> /app/public/index.php && \
    echo '                "timestamp" => date("c")' >> /app/public/index.php && \
    echo '            ]);' >> /app/public/index.php && \
    echo '            break;' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        default:' >> /app/public/index.php && \
    echo '            http_response_code(404);' >> /app/public/index.php && \
    echo '            echo json_encode(["error" => "API endpoint not found"]);' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    exit;' >> /app/public/index.php && \
    echo '}' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '// Handle AJAX requests' >> /app/public/index.php && \
    echo 'if (isset($_GET["action"])) {' >> /app/public/index.php && \
    echo '    header("Content-Type: application/json");' >> /app/public/index.php && \
    echo '    ' >> /app/public/index.php && \
    echo '    switch ($_GET["action"]) {' >> /app/public/index.php && \
    echo '        case "dashboard":' >> /app/public/index.php && \
    echo '            echo json_encode($networkController->dashboard());' >> /app/public/index.php && \
    echo '            break;' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        case "scan":' >> /app/public/index.php && \
    echo '            $range = $_GET["range"] ?? null;' >> /app/public/index.php && \
    echo '            $type = $_GET["type"] ?? "quick";' >> /app/public/index.php && \
    echo '            echo json_encode($networkController->networkScan($range, $type));' >> /app/public/index.php && \
    echo '            break;' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        case "analysis":' >> /app/public/index.php && \
    echo '            echo json_encode($networkMonitor->performNetworkAnalysis());' >> /app/public/index.php && \
    echo '            break;' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '        default:' >> /app/public/index.php && \
    echo '            echo json_encode(["error" => "Unknown action"]);' >> /app/public/index.php && \
    echo '    }' >> /app/public/index.php && \
    echo '    exit;' >> /app/public/index.php && \
    echo '}' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '// HTML Interface' >> /app/public/index.php && \
    echo '?>' >> /app/public/index.php && \
    echo '<!DOCTYPE html>' >> /app/public/index.php && \
    echo '<html lang="en">' >> /app/public/index.php && \
    echo '<head>' >> /app/public/index.php && \
    echo '    <meta charset="UTF-8">' >> /app/public/index.php && \
    echo '    <meta name="viewport" content="width=device-width, initial-scale=1.0">' >> /app/public/index.php && \
    echo '    <title>Network Security App - Hirotoshi Uchida</title>' >> /app/public/index.php && \
    echo '    <style>' >> /app/public/index.php && \
    echo '        * {' >> /app/public/index.php && \
    echo '            margin: 0;' >> /app/public/index.php && \
    echo '            padding: 0;' >> /app/public/index.php && \
    echo '            box-sizing: border-box;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        body {' >> /app/public/index.php && \
    echo '            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;' >> /app/public/index.php && \
    echo '            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);' >> /app/public/index.php && \
    echo '            min-height: 100vh;' >> /app/public/index.php && \
    echo '            color: #333;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .container {' >> /app/public/index.php && \
    echo '            max-width: 1200px;' >> /app/public/index.php && \
    echo '            margin: 0 auto;' >> /app/public/index.php && \
    echo '            padding: 20px;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .header {' >> /app/public/index.php && \
    echo '            text-align: center;' >> /app/public/index.php && \
    echo '            margin-bottom: 30px;' >> /app/public/index.php && \
    echo '            color: white;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .header h1 {' >> /app/public/index.php && \
    echo '            font-size: 2.5rem;' >> /app/public/index.php && \
    echo '            margin-bottom: 10px;' >> /app/public/index.php && \
    echo '            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .header p {' >> /app/public/index.php && \
    echo '            font-size: 1.1rem;' >> /app/public/index.php && \
    echo '            opacity: 0.9;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .dashboard {' >> /app/public/index.php && \
    echo '            display: grid;' >> /app/public/index.php && \
    echo '            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));' >> /app/public/index.php && \
    echo '            gap: 20px;' >> /app/public/index.php && \
    echo '            margin-bottom: 30px;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .card {' >> /app/public/index.php && \
    echo '            background: white;' >> /app/public/index.php && \
    echo '            border-radius: 10px;' >> /app/public/index.php && \
    echo '            padding: 20px;' >> /app/public/index.php && \
    echo '            box-shadow: 0 4px 6px rgba(0,0,0,0.1);' >> /app/public/index.php && \
    echo '            transition: transform 0.2s;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .card:hover {' >> /app/public/index.php && \
    echo '            transform: translateY(-2px);' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .card h3 {' >> /app/public/index.php && \
    echo '            color: #5a67d8;' >> /app/public/index.php && \
    echo '            margin-bottom: 15px;' >> /app/public/index.php && \
    echo '            border-bottom: 2px solid #e2e8f0;' >> /app/public/index.php && \
    echo '            padding-bottom: 10px;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .status-indicator {' >> /app/public/index.php && \
    echo '            display: inline-block;' >> /app/public/index.php && \
    echo '            width: 12px;' >> /app/public/index.php && \
    echo '            height: 12px;' >> /app/public/index.php && \
    echo '            border-radius: 50%;' >> /app/public/index.php && \
    echo '            margin-right: 8px;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .status-online {' >> /app/public/index.php && \
    echo '            background-color: #48bb78;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .status-offline {' >> /app/public/index.php && \
    echo '            background-color: #f56565;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .device-list {' >> /app/public/index.php && \
    echo '            max-height: 200px;' >> /app/public/index.php && \
    echo '            overflow-y: auto;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .device-item {' >> /app/public/index.php && \
    echo '            padding: 8px 0;' >> /app/public/index.php && \
    echo '            border-bottom: 1px solid #e2e8f0;' >> /app/public/index.php && \
    echo '            display: flex;' >> /app/public/index.php && \
    echo '            justify-content: space-between;' >> /app/public/index.php && \
    echo '            align-items: center;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .device-item:last-child {' >> /app/public/index.php && \
    echo '            border-bottom: none;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .btn {' >> /app/public/index.php && \
    echo '            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);' >> /app/public/index.php && \
    echo '            color: white;' >> /app/public/index.php && \
    echo '            border: none;' >> /app/public/index.php && \
    echo '            padding: 10px 20px;' >> /app/public/index.php && \
    echo '            border-radius: 5px;' >> /app/public/index.php && \
    echo '            cursor: pointer;' >> /app/public/index.php && \
    echo '            font-size: 14px;' >> /app/public/index.php && \
    echo '            transition: opacity 0.2s;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .btn:hover {' >> /app/public/index.php && \
    echo '            opacity: 0.9;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .btn:disabled {' >> /app/public/index.php && \
    echo '            opacity: 0.6;' >> /app/public/index.php && \
    echo '            cursor: not-allowed;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .loading {' >> /app/public/index.php && \
    echo '            text-align: center;' >> /app/public/index.php && \
    echo '            color: #666;' >> /app/public/index.php && \
    echo '            font-style: italic;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .error {' >> /app/public/index.php && \
    echo '            color: #e53e3e;' >> /app/public/index.php && \
    echo '            background: #fed7d7;' >> /app/public/index.php && \
    echo '            padding: 10px;' >> /app/public/index.php && \
    echo '            border-radius: 5px;' >> /app/public/index.php && \
    echo '            margin: 10px 0;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .success {' >> /app/public/index.php && \
    echo '            color: #38a169;' >> /app/public/index.php && \
    echo '            background: #c6f6d5;' >> /app/public/index.php && \
    echo '            padding: 10px;' >> /app/public/index.php && \
    echo '            border-radius: 5px;' >> /app/public/index.php && \
    echo '            margin: 10px 0;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .footer {' >> /app/public/index.php && \
    echo '            text-align: center;' >> /app/public/index.php && \
    echo '            margin-top: 40px;' >> /app/public/index.php && \
    echo '            padding: 20px;' >> /app/public/index.php && \
    echo '            color: white;' >> /app/public/index.php && \
    echo '            opacity: 0.8;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .footer a {' >> /app/public/index.php && \
    echo '            color: white;' >> /app/public/index.php && \
    echo '            text-decoration: none;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .footer a:hover {' >> /app/public/index.php && \
    echo '            text-decoration: underline;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        @keyframes pulse {' >> /app/public/index.php && \
    echo '            0% { opacity: 1; }' >> /app/public/index.php && \
    echo '            50% { opacity: 0.5; }' >> /app/public/index.php && \
    echo '            100% { opacity: 1; }' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        .pulse {' >> /app/public/index.php && \
    echo '            animation: pulse 2s infinite;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '    </style>' >> /app/public/index.php && \
    echo '</head>' >> /app/public/index.php && \
    echo '<body>' >> /app/public/index.php && \
    echo '    <div class="container">' >> /app/public/index.php && \
    echo '        <div class="header">' >> /app/public/index.php && \
    echo '            <h1>🛡️ Network Security Monitor</h1>' >> /app/public/index.php && \
    echo '            <p>Real-time network monitoring and security analysis</p>' >> /app/public/index.php && \
    echo '            <p>by <strong>Hirotoshi Uchida</strong></p>' >> /app/public/index.php && \
    echo '        </div>' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        <div class="dashboard">' >> /app/public/index.php && \
    echo '            <div class="card">' >> /app/public/index.php && \
    echo '                <h3>🖥️ System Status</h3>' >> /app/public/index.php && \
    echo '                <div id="system-status">' >> /app/public/index.php && \
    echo '                    <div class="loading pulse">Loading system status...</div>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '            </div>' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            <div class="card">' >> /app/public/index.php && \
    echo '                <h3>🌐 Network Devices</h3>' >> /app/public/index.php && \
    echo '                <div id="network-devices">' >> /app/public/index.php && \
    echo '                    <div class="loading pulse">Discovering devices...</div>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '                <button class="btn" onclick="scanNetwork()" id="scan-btn">🔍 Scan Network</button>' >> /app/public/index.php && \
    echo '            </div>' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            <div class="card">' >> /app/public/index.php && \
    echo '                <h3>📊 Network Traffic</h3>' >> /app/public/index.php && \
    echo '                <div id="network-traffic">' >> /app/public/index.php && \
    echo '                    <div class="loading pulse">Analyzing traffic...</div>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '            </div>' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            <div class="card">' >> /app/public/index.php && \
    echo '                <h3>🚨 Security Alerts</h3>' >> /app/public/index.php && \
    echo '                <div id="security-alerts">' >> /app/public/index.php && \
    echo '                    <div class="loading pulse">Monitoring security events...</div>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '            </div>' >> /app/public/index.php && \
    echo '        </div>' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        <div class="card">' >> /app/public/index.php && \
    echo '            <h3>🔬 Network Analysis</h3>' >> /app/public/index.php && \
    echo '            <div id="network-analysis">' >> /app/public/index.php && \
    echo '                <div class="loading pulse">Performing network analysis...</div>' >> /app/public/index.php && \
    echo '            </div>' >> /app/public/index.php && \
    echo '            <button class="btn" onclick="runAnalysis()" id="analysis-btn">🔄 Run Analysis</button>' >> /app/public/index.php && \
    echo '        </div>' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        <div class="footer">' >> /app/public/index.php && \
    echo '            <p>&copy; 2024 Hirotoshi Uchida - Network Security App</p>' >> /app/public/index.php && \
    echo '            <p>Visit: <a href="https://hirotoshiuchida.onrender.com" target="_blank">https://hirotoshiuchida.onrender.com</a></p>' >> /app/public/index.php && \
    echo '        </div>' >> /app/public/index.php && \
    echo '    </div>' >> /app/public/index.php && \
    echo '' >> /app/public/index.php && \
    echo '    <script>' >> /app/public/index.php && \
    echo '        // Auto-refresh dashboard data' >> /app/public/index.php && \
    echo '        let refreshInterval;' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function loadDashboard() {' >> /app/public/index.php && \
    echo '            fetch("/?action=dashboard")' >> /app/public/index.php && \
    echo '                .then(response => response.json())' >> /app/public/index.php && \
    echo '                .then(data => {' >> /app/public/index.php && \
    echo '                    if (data.success) {' >> /app/public/index.php && \
    echo '                        updateSystemStatus(data.data.system_status);' >> /app/public/index.php && \
    echo '                        updateNetworkDevices(data.data.devices);' >> /app/public/index.php && \
    echo '                        updateNetworkTraffic(data.data.traffic);' >> /app/public/index.php && \
    echo '                        updateSecurityAlerts(data.data.alerts);' >> /app/public/index.php && \
    echo '                    } else {' >> /app/public/index.php && \
    echo '                        showError("Failed to load dashboard data");' >> /app/public/index.php && \
    echo '                    }' >> /app/public/index.php && \
    echo '                })' >> /app/public/index.php && \
    echo '                .catch(error => {' >> /app/public/index.php && \
    echo '                    console.error("Dashboard error:", error);' >> /app/public/index.php && \
    echo '                    showError("Dashboard connection failed");' >> /app/public/index.php && \
    echo '                });' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function updateSystemStatus(status) {' >> /app/public/index.php && \
    echo '            const container = document.getElementById("system-status");' >> /app/public/index.php && \
    echo '            container.innerHTML = `' >> /app/public/index.php && \
    echo '                <div class="device-item">' >> /app/public/index.php && \
    echo '                    <span>Status</span>' >> /app/public/index.php && \
    echo '                    <span><span class="status-indicator status-online"></span>Online</span>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '                <div class="device-item">' >> /app/public/index.php && \
    echo '                    <span>Uptime</span>' >> /app/public/index.php && \
    echo '                    <span>${status.uptime || "Unknown"}</span>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '                <div class="device-item">' >> /app/public/index.php && \
    echo '                    <span>Load Average</span>' >> /app/public/index.php && \
    echo '                    <span>${status.load_average || "0.00"}</span>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '            `;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function updateNetworkDevices(devices) {' >> /app/public/index.php && \
    echo '            const container = document.getElementById("network-devices");' >> /app/public/index.php && \
    echo '            if (!devices || devices.length === 0) {' >> /app/public/index.php && \
    echo '                container.innerHTML = "<p>No devices detected</p>";' >> /app/public/index.php && \
    echo '                return;' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            let html = "<div class=\"device-list\">";' >> /app/public/index.php && \
    echo '            devices.forEach(device => {' >> /app/public/index.php && \
    echo '                const statusClass = device.status === "online" ? "status-online" : "status-offline";' >> /app/public/index.php && \
    echo '                html += `' >> /app/public/index.php && \
    echo '                    <div class="device-item">' >> /app/public/index.php && \
    echo '                        <span>' >> /app/public/index.php && \
    echo '                            <span class="status-indicator ${statusClass}"></span>' >> /app/public/index.php && \
    echo '                            ${device.ip}' >> /app/public/index.php && \
    echo '                        </span>' >> /app/public/index.php && \
    echo '                        <span>${device.hostname || device.mac || "Unknown"}</span>' >> /app/public/index.php && \
    echo '                    </div>' >> /app/public/index.php && \
    echo '                `;' >> /app/public/index.php && \
    echo '            });' >> /app/public/index.php && \
    echo '            html += "</div>";' >> /app/public/index.php && \
    echo '            container.innerHTML = html;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function updateNetworkTraffic(traffic) {' >> /app/public/index.php && \
    echo '            const container = document.getElementById("network-traffic");' >> /app/public/index.php && \
    echo '            container.innerHTML = `' >> /app/public/index.php && \
    echo '                <div class="device-item">' >> /app/public/index.php && \
    echo '                    <span>Interface</span>' >> /app/public/index.php && \
    echo '                    <span>${traffic.interface || "Unknown"}</span>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '                <div class="device-item">' >> /app/public/index.php && \
    echo '                    <span>RX Bytes</span>' >> /app/public/index.php && \
    echo '                    <span>${formatBytes(traffic.rx_bytes || 0)}</span>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '                <div class="device-item">' >> /app/public/index.php && \
    echo '                    <span>TX Bytes</span>' >> /app/public/index.php && \
    echo '                    <span>${formatBytes(traffic.tx_bytes || 0)}</span>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '                <div class="device-item">' >> /app/public/index.php && \
    echo '                    <span>Total</span>' >> /app/public/index.php && \
    echo '                    <span>${formatBytes(traffic.total_bytes || 0)}</span>' >> /app/public/index.php && \
    echo '                </div>' >> /app/public/index.php && \
    echo '            `;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function updateSecurityAlerts(alerts) {' >> /app/public/index.php && \
    echo '            const container = document.getElementById("security-alerts");' >> /app/public/index.php && \
    echo '            if (!alerts || alerts.length === 0) {' >> /app/public/index.php && \
    echo '                container.innerHTML = "<p style=\"color: #38a169;\">✅ No security alerts</p>";' >> /app/public/index.php && \
    echo '                return;' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            let html = "<div class=\"device-list\">";' >> /app/public/index.php && \
    echo '            alerts.forEach(alert => {' >> /app/public/index.php && \
    echo '                const severityColor = alert.severity === "high" ? "#e53e3e" : "#ed8936";' >> /app/public/index.php && \
    echo '                html += `' >> /app/public/index.php && \
    echo '                    <div class="device-item" style="color: ${severityColor};">' >> /app/public/index.php && \
    echo '                        <span>${alert.type}</span>' >> /app/public/index.php && \
    echo '                        <span>${alert.severity}</span>' >> /app/public/index.php && \
    echo '                    </div>' >> /app/public/index.php && \
    echo '                `;' >> /app/public/index.php && \
    echo '            });' >> /app/public/index.php && \
    echo '            html += "</div>";' >> /app/public/index.php && \
    echo '            container.innerHTML = html;' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function scanNetwork() {' >> /app/public/index.php && \
    echo '            const btn = document.getElementById("scan-btn");' >> /app/public/index.php && \
    echo '            btn.disabled = true;' >> /app/public/index.php && \
    echo '            btn.textContent = "🔍 Scanning...";' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            fetch("/?action=scan")' >> /app/public/index.php && \
    echo '                .then(response => response.json())' >> /app/public/index.php && \
    echo '                .then(data => {' >> /app/public/index.php && \
    echo '                    if (data.success) {' >> /app/public/index.php && \
    echo '                        updateNetworkDevices(data.data.devices);' >> /app/public/index.php && \
    echo '                        showSuccess("Network scan completed successfully");' >> /app/public/index.php && \
    echo '                    } else {' >> /app/public/index.php && \
    echo '                        showError("Network scan failed");' >> /app/public/index.php && \
    echo '                    }' >> /app/public/index.php && \
    echo '                })' >> /app/public/index.php && \
    echo '                .catch(error => {' >> /app/public/index.php && \
    echo '                    console.error("Scan error:", error);' >> /app/public/index.php && \
    echo '                    showError("Network scan connection failed");' >> /app/public/index.php && \
    echo '                })' >> /app/public/index.php && \
    echo '                .finally(() => {' >> /app/public/index.php && \
    echo '                    btn.disabled = false;' >> /app/public/index.php && \
    echo '                    btn.textContent = "🔍 Scan Network";' >> /app/public/index.php && \
    echo '                });' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function runAnalysis() {' >> /app/public/index.php && \
    echo '            const btn = document.getElementById("analysis-btn");' >> /app/public/index.php && \
    echo '            const container = document.getElementById("network-analysis");' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            btn.disabled = true;' >> /app/public/index.php && \
    echo '            btn.textContent = "🔄 Analyzing...";' >> /app/public/index.php && \
    echo '            container.innerHTML = "<div class=\"loading pulse\">Running comprehensive analysis...</div>";' >> /app/public/index.php && \
    echo '            ' >> /app/public/index.php && \
    echo '            fetch("/?action=analysis")' >> /app/public/index.php && \
    echo '                .then(response => response.json())' >> /app/public/index.php && \
    echo '                .then(data => {' >> /app/public/index.php && \
    echo '                    let html = "<div class=\"device-list\">";' >> /app/public/index.php && \
    echo '                    ' >> /app/public/index.php && \
    echo '                    // NMAP Results' >> /app/public/index.php && \
    echo '                    if (data.nmap && data.nmap.hosts) {' >> /app/public/index.php && \
    echo '                        html += `<div class="device-item"><strong>Discovered Hosts: ${data.nmap.hosts.length}</strong></div>`;' >> /app/public/index.php && \
    echo '                        data.nmap.hosts.forEach(host => {' >> /app/public/index.php && \
    echo '                            html += `<div class="device-item"><span>📍 ${host}</span></div>`;' >> /app/public/index.php && \
    echo '                        });' >> /app/public/index.php && \
    echo '                    }' >> /app/public/index.php && \
    echo '                    ' >> /app/public/index.php && \
    echo '                    // ARP Results' >> /app/public/index.php && \
    echo '                    if (data.arp && data.arp.length > 0) {' >> /app/public/index.php && \
    echo '                        html += `<div class="device-item"><strong>ARP Entries: ${data.arp.length}</strong></div>`;' >> /app/public/index.php && \
    echo '                    }' >> /app/public/index.php && \
    echo '                    ' >> /app/public/index.php && \
    echo '                    // Netstat Results' >> /app/public/index.php && \
    echo '                    if (data.netstat && data.netstat.connections) {' >> /app/public/index.php && \
    echo '                        html += `<div class="device-item"><strong>Active Connections: ${data.netstat.connections.length}</strong></div>`;' >> /app/public/index.php && \
    echo '                    }' >> /app/public/index.php && \
    echo '                    ' >> /app/public/index.php && \
    echo '                    html += `<div class="device-item"><span>Execution Time</span><span>${(data.execution_time || 0).toFixed(2)}s</span></div>`;' >> /app/public/index.php && \
    echo '                    html += "</div>";' >> /app/public/index.php && \
    echo '                    ' >> /app/public/index.php && \
    echo '                    container.innerHTML = html;' >> /app/public/index.php && \
    echo '                    showSuccess("Network analysis completed");' >> /app/public/index.php && \
    echo '                })' >> /app/public/index.php && \
    echo '                .catch(error => {' >> /app/public/index.php && \
    echo '                    console.error("Analysis error:", error);' >> /app/public/index.php && \
    echo '                    container.innerHTML = "<p class=\"error\">Analysis failed</p>";' >> /app/public/index.php && \
    echo '                    showError("Network analysis failed");' >> /app/public/index.php && \
    echo '                })' >> /app/public/index.php && \
    echo '                .finally(() => {' >> /app/public/index.php && \
    echo '                    btn.disabled = false;' >> /app/public/index.php && \
    echo '                    btn.textContent = "🔄 Run Analysis";' >> /app/public/index.php && \
    echo '                });' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function formatBytes(bytes) {' >> /app/public/index.php && \
    echo '            if (bytes === 0) return "0 B";' >> /app/public/index.php && \
    echo '            const k = 1024;' >> /app/public/index.php && \
    echo '            const sizes = ["B", "KB", "MB", "GB", "TB"];' >> /app/public/index.php && \
    echo '            const i = Math.floor(Math.log(bytes) / Math.log(k));' >> /app/public/index.php && \
    echo '            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function showError(message) {' >> /app/public/index.php && \
    echo '            const notification = document.createElement("div");' >> /app/public/index.php && \
    echo '            notification.className = "error";' >> /app/public/index.php && \
    echo '            notification.textContent = message;' >> /app/public/index.php && \
    echo '            document.body.insertBefore(notification, document.body.firstChild);' >> /app/public/index.php && \
    echo '            setTimeout(() => notification.remove(), 5000);' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        function showSuccess(message) {' >> /app/public/index.php && \
    echo '            const notification = document.createElement("div");' >> /app/public/index.php && \
    echo '            notification.className = "success";' >> /app/public/index.php && \
    echo '            notification.textContent = message;' >> /app/public/index.php && \
    echo '            document.body.insertBefore(notification, document.body.firstChild);' >> /app/public/index.php && \
    echo '            setTimeout(() => notification.remove(), 3000);' >> /app/public/index.php && \
    echo '        }' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Initialize' >> /app/public/index.php && \
    echo '        document.addEventListener("DOMContentLoaded", function() {' >> /app/public/index.php && \
    echo '            loadDashboard();' >> /app/public/index.php && \
    echo '            refreshInterval = setInterval(loadDashboard, 30000); // Refresh every 30 seconds' >> /app/public/index.php && \
    echo '        });' >> /app/public/index.php && \
    echo '        ' >> /app/public/index.php && \
    echo '        // Cleanup on page unload' >> /app/public/index.php && \
    echo '        window.addEventListener("beforeunload", function() {' >> /app/public/index.php && \
    echo '            if (refreshInterval) {' >> /app/public/index.php && \
    echo '                clearInterval(refreshInterval);' >> /app/public/index.php && \
    echo '            }' >> /app/public/index.php && \
    echo '        });' >> /app/public/index.php && \
    echo '    </script>' >> /app/public/index.php && \
    echo '</body>' >> /app/public/index.php && \
    echo '</html>' >> /app/public/index.php && \
    chown appuser:appuser /app/public/index.php

# Create nginx configuration
RUN echo 'server {' > /etc/nginx/sites-available/default && \
    echo '    listen       8080;' >> /etc/nginx/sites-available/default && \
    echo '    server_name  _;' >> /etc/nginx/sites-available/default && \
    echo '    root         /app/public;' >> /etc/nginx/sites-available/default && \
    echo '    index        index.php;' >> /etc/nginx/sites-available/default && \
    echo '' >> /etc/nginx/sites-available/default && \
    echo '    location / {' >> /etc/nginx/sites-available/default && \
    echo '        try_files $uri $uri/ /index.php?$query_string;' >> /etc/nginx/sites-available/default && \
    echo '    }' >> /etc/nginx/sites-available/default && \
    echo '' >> /etc/nginx/sites-available/default && \
    echo '    location ~ \.php$ {' >> /etc/nginx/sites-available/default && \
    echo '        fastcgi_pass   127.0.0.1:9000;' >> /etc/nginx/sites-available/default && \
    echo '        fastcgi_index  index.php;' >> /etc/nginx/sites-available/default && \
    echo '        include        fastcgi_params;' >> /etc/nginx/sites-available/default && \
    echo '        fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;' >> /etc/nginx/sites-available/default && \
    echo '    }' >> /etc/nginx/sites-available/default && \
    echo '}' >> /etc/nginx/sites-available/default

# Create PHP-FPM configuration
RUN echo '[www]' > /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'user = appuser' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'group = appuser' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'listen = 127.0.0.1:9000' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm = dynamic' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm.max_children = 10' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm.start_servers = 2' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm.min_spare_servers = 1' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf && \
    echo 'pm.max_spare_servers = 3' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf

# Create supervisor configuration
RUN echo '[supervisord]' > /etc/supervisor/conf.d/supervisord.conf && \
    echo 'nodaemon = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'logfile = /var/log/supervisor/supervisord.log' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'pidfile = /var/run/supervisord.pid' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'user = root' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo '' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo '[program:nginx]' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'command = /usr/sbin/nginx -g "daemon off;"' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'autostart = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'autorestart = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'stdout_logfile = /var/log/supervisor/nginx.log' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'stderr_logfile = /var/log/supervisor/nginx_error.log' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo '' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo '[program:php-fpm]' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'command = /usr/sbin/php-fpm8.1 -F' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'autostart = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'autorestart = true' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'stdout_logfile = /var/log/supervisor/php-fpm.log' >> /etc/supervisor/conf.d/supervisord.conf && \
    echo 'stderr_logfile = /var/log/supervisor/php-fpm_error.log' >> /etc/supervisor/conf.d/supervisord.conf

# Create start script
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo 'set -e' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo 'echo "=== Network Security App Starting ==="' >> /app/start.sh && \
    echo 'echo "Author: Hirotoshi Uchida"' >> /app/start.sh && \
    echo 'echo "Homepage: https://hirotoshiuchida.onrender.com"' >> /app/start.sh && \
    echo 'echo "======================================"' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Wait for network interface to be ready' >> /app/start.sh && \
    echo 'sleep 2' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Detect network interface' >> /app/start.sh && \
    echo 'INTERFACE=$(ip route | grep default | awk "{print \$5}" | head -1 || echo "eth0")' >> /app/start.sh && \
    echo 'echo "Detected network interface: $INTERFACE"' >> /app/start.sh && \
    echo 'export NETWORK_INTERFACE=$INTERFACE' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Ensure directories exist and have correct permissions' >> /app/start.sh && \
    echo 'mkdir -p /app/storage/logs /app/storage/framework/cache /app/storage/framework/sessions /app/storage/framework/views /app/bootstrap/cache' >> /app/start.sh && \
    echo 'chown -R appuser:appuser /app/storage /app/bootstrap/cache 2>/dev/null || true' >> /app/start.sh && \
    echo 'chmod -R 755 /app/storage /app/bootstrap/cache 2>/dev/null || true' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Start services with supervisor' >> /app/start.sh && \
    echo 'echo "Starting services..."' >> /app/start.sh && \
    echo 'exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf' >> /app/start.sh && \
    chmod +x /app/start.sh

# Create health check script
RUN echo '#!/bin/bash' > /app/health-check.sh && \
    echo '' >> /app/health-check.sh && \
    echo '# Check if services are running' >> /app/health-check.sh && \
    echo 'if ! pgrep -f "php-fpm" > /dev/null; then' >> /app/health-check.sh && \
    echo '    echo "PHP-FPM is not running"' >> /app/health-check.sh && \
    echo '    exit 1' >> /app/health-check.sh && \
    echo 'fi' >> /app/health-check.sh && \
    echo '' >> /app/health-check.sh && \
    echo 'if ! pgrep -f "nginx" > /dev/null; then' >> /app/health-check.sh && \
    echo '    echo "Nginx is not running"' >> /app/health-check.sh && \
    echo '    exit 1' >> /app/health-check.sh && \
    echo 'fi' >> /app/health-check.sh && \
    echo '' >> /app/health-check.sh && \
    echo '# Check API endpoint' >> /app/health-check.sh && \
    echo 'if ! curl -f -s http://127.0.0.1:8080/api/health-check > /dev/null; then' >> /app/health-check.sh && \
    echo '    echo "API health check failed"' >> /app/health-check.sh && \
    echo '    exit 1' >> /app/health-check.sh && \
    echo 'fi' >> /app/health-check.sh && \
    echo '' >> /app/health-check.sh && \
    echo 'echo "All services are healthy"' >> /app/health-check.sh && \
    echo 'exit 0' >> /app/health-check.sh && \
    chmod +x /app/health-check.sh

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

# Create log directory and set permissions
RUN mkdir -p /var/log/network-security \
    && chown -R appuser:appuser /var/log/network-security \
    && chmod -R 755 /var/log/network-security

# Expose ports
EXPOSE 8080 9000

# Set up volume for persistent data
VOLUME ["/app/storage"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

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
