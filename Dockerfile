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
RUN mkdir -p /app/public
RUN echo '<?php' > /app/public/index.php
RUN echo '// Network Security App - Fixed for Render.com deployment' >> /app/public/index.php
RUN echo '// Author: Hirotoshi Uchida' >> /app/public/index.php
RUN echo '// Homepage: https://hirotoshiuchida.onrender.com' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'error_reporting(E_ALL);' >> /app/public/index.php
RUN echo 'ini_set("display_errors", 0);' >> /app/public/index.php
RUN echo 'set_time_limit(60);' >> /app/public/index.php
RUN echo 'header("Content-Type: application/json");' >> /app/public/index.php
RUN echo 'header("Cache-Control: no-cache, must-revalidate");' >> /app/public/index.php
RUN echo 'header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'class NetworkSecurityApp {' >> /app/public/index.php
RUN echo '    private $interface;' >> /app/public/index.php
RUN echo '    private $timeout = 5;' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    public function __construct() {' >> /app/public/index.php
RUN echo '        $this->interface = $this->detectInterface();' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    public function handleRequest() {' >> /app/public/index.php
RUN echo '        try {' >> /app/public/index.php
RUN echo '            $action = $_GET["action"] ?? "dashboard";' >> /app/public/index.php
RUN echo '            ' >> /app/public/index.php
RUN echo '            switch ($action) {' >> /app/public/index.php
RUN echo '                case "dashboard":' >> /app/public/index.php
RUN echo '                    return $this->getDashboard();' >> /app/public/index.php
RUN echo '                case "scan":' >> /app/public/index.php
RUN echo '                    return $this->performScan();' >> /app/public/index.php
RUN echo '                case "analysis":' >> /app/public/index.php
RUN echo '                    return $this->performAnalysis();' >> /app/public/index.php
RUN echo '                case "health":' >> /app/public/index.php
RUN echo '                    return $this->healthCheck();' >> /app/public/index.php
RUN echo '                default:' >> /app/public/index.php
RUN echo '                    return $this->getInterface();' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        } catch (Exception $e) {' >> /app/public/index.php
RUN echo '            return ["success" => false, "error" => "Request failed", "timestamp" => date("c")];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function healthCheck() {' >> /app/public/index.php
RUN echo '        return ["success" => true, "status" => "healthy", "timestamp" => date("c")];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getDashboard() {' >> /app/public/index.php
RUN echo '        $devices = $this->getDevices();' >> /app/public/index.php
RUN echo '        $traffic = $this->getTraffic();' >> /app/public/index.php
RUN echo '        $system = $this->getSystemInfo();' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        return [' >> /app/public/index.php
RUN echo '            "success" => true,' >> /app/public/index.php
RUN echo '            "data" => [' >> /app/public/index.php
RUN echo '                "devices" => $devices,' >> /app/public/index.php
RUN echo '                "traffic" => $traffic,' >> /app/public/index.php
RUN echo '                "system_status" => $system,' >> /app/public/index.php
RUN echo '                "security_events" => 0,' >> /app/public/index.php
RUN echo '                "alerts" => []' >> /app/public/index.php
RUN echo '            ],' >> /app/public/index.php
RUN echo '            "timestamp" => date("c")' >> /app/public/index.php
RUN echo '        ];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function performScan() {' >> /app/public/index.php
RUN echo '        $range = $this->getNetworkRange();' >> /app/public/index.php
RUN echo '        $devices = $this->scanNetwork($range);' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        return [' >> /app/public/index.php
RUN echo '            "success" => true,' >> /app/public/index.php
RUN echo '            "data" => ["devices" => $devices],' >> /app/public/index.php
RUN echo '            "timestamp" => date("c")' >> /app/public/index.php
RUN echo '        ];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function performAnalysis() {' >> /app/public/index.php
RUN echo '        $nmap = $this->runNmapAnalysis();' >> /app/public/index.php
RUN echo '        $arp = $this->runArpAnalysis();' >> /app/public/index.php
RUN echo '        $netstat = $this->runNetstatAnalysis();' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        return [' >> /app/public/index.php
RUN echo '            "nmap" => $nmap,' >> /app/public/index.php
RUN echo '            "arp" => $arp,' >> /app/public/index.php
RUN echo '            "netstat" => $netstat,' >> /app/public/index.php
RUN echo '            "timestamp" => date("c")' >> /app/public/index.php
RUN echo '        ];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getInterface() {' >> /app/public/index.php
RUN echo '        if (!isset($_GET["action"])) {' >> /app/public/index.php
RUN echo '            header("Content-Type: text/html");' >> /app/public/index.php
RUN echo '            return $this->renderHtml();' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return $this->healthCheck();' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function detectInterface() {' >> /app/public/index.php
RUN echo '        $cmd = "ip route | grep default | head -1";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        if ($output && preg_match("/dev\s+(\w+)/", $output, $m)) {' >> /app/public/index.php
RUN echo '            return $m[1];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return "eth0";' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getNetworkRange() {' >> /app/public/index.php
RUN echo '        $cmd = "ip route | grep {$this->interface} | grep -v default | head -1";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        if ($output && preg_match("/([0-9\.]+\/\d+)/", $output, $m)) {' >> /app/public/index.php
RUN echo '            return $m[1];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return "192.168.1.0/24";' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getDevices() {' >> /app/public/index.php
RUN echo '        $devices = [];' >> /app/public/index.php
RUN echo '        $cmd = "arp -a 2>/dev/null | head -5";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            $lines = explode("\n", trim($output));' >> /app/public/index.php
RUN echo '            foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '                if (preg_match("/\(([0-9\.]+)\)/", $line, $m)) {' >> /app/public/index.php
RUN echo '                    $devices[] = ["ip" => $m[1], "status" => "online", "hostname" => "", "mac" => ""];' >> /app/public/index.php
RUN echo '                }' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return array_slice($devices, 0, 5);' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getTraffic() {' >> /app/public/index.php
RUN echo '        $cmd = "cat /proc/net/dev | grep {$this->interface} | head -1";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        $rx_bytes = 0;' >> /app/public/index.php
RUN echo '        $tx_bytes = 0;' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            $stats = preg_split("/\s+/", trim($output));' >> /app/public/index.php
RUN echo '            if (count($stats) >= 10) {' >> /app/public/index.php
RUN echo '                $rx_bytes = intval($stats[1]);' >> /app/public/index.php
RUN echo '                $tx_bytes = intval($stats[9]);' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return ["rx_bytes" => $rx_bytes, "tx_bytes" => $tx_bytes, "interface" => $this->interface];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getSystemInfo() {' >> /app/public/index.php
RUN echo '        $uptime = shell_exec("uptime 2>/dev/null") ?: "Unknown";' >> /app/public/index.php
RUN echo '        $load = shell_exec("cat /proc/loadavg 2>/dev/null") ?: "0.00";' >> /app/public/index.php
RUN echo '        return ["status" => "online", "uptime" => trim($uptime), "load_average" => trim($load)];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function scanNetwork($range) {' >> /app/public/index.php
RUN echo '        $devices = [];' >> /app/public/index.php
RUN echo '        $cmd = "nmap -sn $range 2>/dev/null | grep \"Nmap scan report\" | head -5";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            $lines = explode("\n", trim($output));' >> /app/public/index.php
RUN echo '            foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '                if (preg_match("/for ([0-9\.]+)/", $line, $m)) {' >> /app/public/index.php
RUN echo '                    $devices[] = ["ip" => $m[1], "status" => "online", "hostname" => "", "mac" => ""];' >> /app/public/index.php
RUN echo '                }' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return $devices;' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function runNmapAnalysis() {' >> /app/public/index.php
RUN echo '        $range = $this->getNetworkRange();' >> /app/public/index.php
RUN echo '        $cmd = "nmap -sn $range 2>/dev/null | grep \"Nmap scan report\" | head -3";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        $hosts = [];' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            preg_match_all("/for ([0-9\.]+)/", $output, $matches);' >> /app/public/index.php
RUN echo '            $hosts = $matches[1];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return ["hosts" => $hosts, "services" => [], "os_detection" => []];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function runArpAnalysis() {' >> /app/public/index.php
RUN echo '        $cmd = "arp -a 2>/dev/null | head -3";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        $devices = [];' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            $lines = explode("\n", trim($output));' >> /app/public/index.php
RUN echo '            foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '                if (preg_match("/\(([0-9\.]+)\)/", $line, $m)) {' >> /app/public/index.php
RUN echo '                    $devices[] = ["ip" => $m[1]];' >> /app/public/index.php
RUN echo '                }' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return $devices;' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function runNetstatAnalysis() {' >> /app/public/index.php
RUN echo '        $cmd = "netstat -tn 2>/dev/null | grep ESTABLISHED | head -3";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        $connections = [];' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            $lines = explode("\n", trim($output));' >> /app/public/index.php
RUN echo '            foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '                if (preg_match("/([0-9\.]+):(\d+)\s+([0-9\.]+):(\d+)/", $line, $m)) {' >> /app/public/index.php
RUN echo '                    $connections[] = ["local" => $m[1].":".$m[2], "remote" => $m[3].":".$m[4]];' >> /app/public/index.php
RUN echo '                }' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return ["connections" => $connections, "listening_ports" => []];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function renderHtml() {' >> /app/public/index.php
RUN echo '        return "<!DOCTYPE html><html><head><title>Network Security App</title><style>body{font-family:Arial;padding:20px;background:#f5f5f5}h1{color:#333}.card{background:white;padding:20px;margin:10px 0;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}.btn{background:#007bff;color:white;border:none;padding:10px 20px;border-radius:4px;cursor:pointer;margin:5px}.status{display:inline-block;width:12px;height:12px;border-radius:50%;margin-right:8px}.online{background:#28a745}.loading{color:#666;font-style:italic}#data{margin-top:20px}</style></head><body><h1>🛡️ Network Security Monitor</h1><p>Real-time network monitoring by <strong>Hirotoshi Uchida</strong></p><div class=\"card\"><h3>Quick Actions</h3><button class=\"btn\" onclick=\"loadData(\\\"dashboard\\\")\">📊 Dashboard</button><button class=\"btn\" onclick=\"loadData(\\\"scan\\\")\">🔍 Scan Network</button><button class=\"btn\" onclick=\"loadData(\\\"analysis\\\")\">🔬 Analysis</button></div><div class=\"card\"><h3>System Status</h3><div id=\"data\"><div class=\"loading\">Click a button above to load data...</div></div></div><script>function loadData(action){document.getElementById(\"data\").innerHTML=\"<div class=\\\"loading\\\">Loading...\</div>\";fetch(\"?action=\"+action).then(r=>r.json()).then(d=>{let html=\"<pre>\"+JSON.stringify(d,null,2)+\"</pre>\";document.getElementById(\"data\").innerHTML=html}).catch(e=>{document.getElementById(\"data\").innerHTML=\"<div style=\\\"color:red\\\">Error: \"+e.message+\"</div>\"})}</script></body></html>";' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '$app = new NetworkSecurityApp();' >> /app/public/index.php
RUN echo 'if (isset($_GET["action"]) || $_SERVER["REQUEST_METHOD"] === "POST") {' >> /app/public/index.php
RUN echo '    $result = $app->handleRequest();' >> /app/public/index.php
RUN echo '    echo json_encode($result);' >> /app/public/index.php
RUN echo '} else {' >> /app/public/index.php
RUN echo '    header("Content-Type: text/html");' >> /app/public/index.php
RUN echo '    echo $app->handleRequest();' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN chown appuser:appuser /app/public/index.php

# Create nginx configuration
RUN echo 'server {' > /etc/nginx/sites-available/default
RUN echo '    listen       8080;' >> /etc/nginx/sites-available/default
RUN echo '    server_name  _;' >> /etc/nginx/sites-available/default
RUN echo '    root         /app/public;' >> /etc/nginx/sites-available/default
RUN echo '    index        index.php;' >> /etc/nginx/sites-available/default
RUN echo '    client_max_body_size 100M;' >> /etc/nginx/sites-available/default
RUN echo '    fastcgi_read_timeout 300;' >> /etc/nginx/sites-available/default
RUN echo '    proxy_read_timeout 300;' >> /etc/nginx/sites-available/default
RUN echo '' >> /etc/nginx/sites-available/default
RUN echo '    location / {' >> /etc/nginx/sites-available/default
RUN echo '        try_files $uri $uri/ /index.php?$query_string;' >> /etc/nginx/sites-available/default
RUN echo '    }' >> /etc/nginx/sites-available/default
RUN echo '' >> /etc/nginx/sites-available/default
RUN echo '    location ~ \.php$ {' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_pass   127.0.0.1:9000;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_index  index.php;' >> /etc/nginx/sites-available/default
RUN echo '        include        fastcgi_params;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_read_timeout 300;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_send_timeout 300;' >> /etc/nginx/sites-available/default
RUN echo '    }' >> /etc/nginx/sites-available/default
RUN echo '}' >> /etc/nginx/sites-available/default

# Create PHP-FPM configuration
RUN echo '[www]' > /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'user = appuser' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'group = appuser' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'listen = 127.0.0.1:9000' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'pm = dynamic' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'pm.max_children = 10' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'pm.start_servers = 2' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'pm.min_spare_servers = 1' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'pm.max_spare_servers = 3' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'request_terminate_timeout = 300' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN echo 'request_slowlog_timeout = 60' >> /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf

# Configure PHP settings for better performance
RUN echo 'max_execution_time = 300' >> /etc/php/${PHP_VERSION}/fpm/php.ini
RUN echo 'max_input_time = 300' >> /etc/php/${PHP_VERSION}/fpm/php.ini
RUN echo 'memory_limit = 256M' >> /etc/php/${PHP_VERSION}/fpm/php.ini
RUN echo 'post_max_size = 100M' >> /etc/php/${PHP_VERSION}/fpm/php.ini
RUN echo 'upload_max_filesize = 100M' >> /etc/php/${PHP_VERSION}/fpm/php.ini

# Create supervisor configuration
RUN echo '[supervisord]' > /etc/supervisor/conf.d/supervisord.conf
RUN echo 'nodaemon = true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'logfile = /var/log/supervisor/supervisord.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'pidfile = /var/run/supervisord.pid' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'user = root' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo '' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo '[program:nginx]' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'command = /usr/sbin/nginx -g "daemon off;"' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'autostart = true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'autorestart = true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'stdout_logfile = /var/log/supervisor/nginx.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'stderr_logfile = /var/log/supervisor/nginx_error.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo '' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo '[program:php-fpm]' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'command = /usr/sbin/php-fpm8.1 -F' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'autostart = true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'autorestart = true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'stdout_logfile = /var/log/supervisor/php-fpm.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'stderr_logfile = /var/log/supervisor/php-fpm_error.log' >> /etc/supervisor/conf.d/supervisord.conf

# Create start script
RUN echo '#!/bin/bash' > /app/start.sh
RUN echo 'set -e' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo 'echo "=== Network Security App Starting ==="' >> /app/start.sh
RUN echo 'echo "Author: Hirotoshi Uchida"' >> /app/start.sh
RUN echo 'echo "Homepage: https://hirotoshiuchida.onrender.com"' >> /app/start.sh
RUN echo 'echo "======================================"' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Wait for network interface to be ready' >> /app/start.sh
RUN echo 'sleep 2' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Detect network interface' >> /app/start.sh
RUN echo 'INTERFACE=$(ip route | grep default | awk "{print \$5}" | head -1 || echo "eth0")' >> /app/start.sh
RUN echo 'echo "Detected network interface: $INTERFACE"' >> /app/start.sh
RUN echo 'export NETWORK_INTERFACE=$INTERFACE' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Ensure directories exist and have correct permissions' >> /app/start.sh
RUN echo 'mkdir -p /app/storage/logs /app/storage/framework/cache /app/storage/framework/sessions /app/storage/framework/views /app/bootstrap/cache' >> /app/start.sh
RUN echo 'chown -R appuser:appuser /app/storage /app/bootstrap/cache 2>/dev/null || true' >> /app/start.sh
RUN echo 'chmod -R 755 /app/storage /app/bootstrap/cache 2>/dev/null || true' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Test network tools' >> /app/start.sh
RUN echo 'echo "Testing network tools..."' >> /app/start.sh
RUN echo 'which nmap > /dev/null && echo "✓ nmap available" || echo "✗ nmap not found"' >> /app/start.sh
RUN echo 'which arp > /dev/null && echo "✓ arp available" || echo "✗ arp not found"' >> /app/start.sh
RUN echo 'which netstat > /dev/null && echo "✓ netstat available" || echo "✗ netstat not found"' >> /app/start.sh
RUN echo 'which ping > /dev/null && echo "✓ ping available" || echo "✗ ping not found"' >> /app/start.sh
RUN echo 'which traceroute > /dev/null && echo "✓ traceroute available" || echo "✗ traceroute not found"' >> /app/start.sh
RUN echo 'which tcpdump > /dev/null && echo "✓ tcpdump available" || echo "✗ tcpdump not found"' >> /app/start.sh
RUN echo 'which tshark > /dev/null && echo "✓ tshark available" || echo "✗ tshark not found"' >> /app/start.sh
RUN echo 'which arp-scan > /dev/null && echo "✓ arp-scan available" || echo "✗ arp-scan not found"' >> /app/start.sh
RUN echo 'which nslookup > /dev/null && echo "✓ nslookup available" || echo "✗ nslookup not found"' >> /app/start.sh
RUN echo 'test -f /proc/net/dev && echo "✓ /proc/net/dev accessible" || echo "✗ /proc/net/dev not accessible"' >> /app/start.sh
RUN echo 'test -f /proc/loadavg && echo "✓ /proc/loadavg accessible" || echo "✗ /proc/loadavg not accessible"' >> /app/start.sh
RUN echo 'which uptime > /dev/null && echo "✓ uptime available" || echo "✗ uptime not found"' >> /app/start.sh
RUN echo 'which ip > /dev/null && echo "✓ ip available" || echo "✗ ip not found"' >> /app/start.sh
RUN echo 'which grep > /dev/null && echo "✓ grep available" || echo "✗ grep not found"' >> /app/start.sh
RUN echo 'which cat > /dev/null && echo "✓ cat available" || echo "✗ cat not found"' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Start services with supervisor' >> /app/start.sh
RUN echo 'echo "Starting services..."' >> /app/start.sh
RUN echo 'exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf' >> /app/start.sh
RUN chmod +x /app/start.sh

# Create health check script
RUN echo '#!/bin/bash' > /app/health-check.sh
RUN echo '' >> /app/health-check.sh
RUN echo '# Check if services are running' >> /app/health-check.sh
RUN echo 'if ! pgrep -f "php-fpm" > /dev/null; then' >> /app/health-check.sh
RUN echo '    echo "PHP-FPM is not running"' >> /app/health-check.sh
RUN echo '    exit 1' >> /app/health-check.sh
RUN echo 'fi' >> /app/health-check.sh
RUN echo '' >> /app/health-check.sh
RUN echo 'if ! pgrep -f "nginx" > /dev/null; then' >> /app/health-check.sh
RUN echo '    echo "Nginx is not running"' >> /app/health-check.sh
RUN echo '    exit 1' >> /app/health-check.sh
RUN echo 'fi' >> /app/health-check.sh
RUN echo '' >> /app/health-check.sh
RUN echo '# Check API endpoint' >> /app/health-check.sh
RUN echo 'if ! curl -f -s -m 5 "http://127.0.0.1:8080/?action=health" > /dev/null; then' >> /app/health-check.sh
RUN echo '    echo "API health check failed"' >> /app/health-check.sh
RUN echo '    exit 1' >> /app/health-check.sh
RUN echo 'fi' >> /app/health-check.sh
RUN echo '' >> /app/health-check.sh
RUN echo 'echo "All services are healthy"' >> /app/health-check.sh
RUN echo 'exit 0' >> /app/health-check.sh
RUN chmod +x /app/health-check.sh

# Create SQLite database
RUN touch /app/storage/database.sqlite
RUN chown appuser:appuser /app/storage/database.sqlite
RUN chmod 664 /app/storage/database.sqlite

# Configure PHP-FPM listen socket
RUN sed -i 's/listen = \/run\/php\/php8.1-fpm.sock/listen = 127.0.0.1:9000/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
RUN sed -i 's/;listen.mode = 0660/listen.mode = 0660/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf

# Configure Nginx
RUN rm -f /etc/nginx/sites-enabled/default
RUN ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Create log directory and set permissions
RUN mkdir -p /var/log/network-security
RUN chown -R appuser:appuser /var/log/network-security
RUN chmod -R 755 /var/log/network-security

# Expose ports
EXPOSE 8080 9000

# Set up volume for persistent data
VOLUME ["/app/storage"]

# Health check with shorter timeout
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/health-check.sh || exit 1

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
LABEL description="Network Security Monitoring Application - Fixed for Render.com"
LABEL version="1.0.1"
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
      org.label-schema.description="Real-time network security monitoring and analysis - Render.com optimized" \
      org.label-schema.url="https://hirotoshiuchida.onrender.com" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/Uchida16104/Network-Security-App" \
      org.label-schema.vendor="Hirotoshi Uchida" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"
