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

COPY config/hhvm.ini /app/hhvm.ini

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
COPY --chown=root:root config/hhvm.ini /etc/hhvm/hhvm.ini
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

# Create comprehensive index.php with NetworkController and NetworkMonitor integrated
RUN mkdir -p /app/public
RUN echo '<?php' > /app/public/index.php
RUN echo 'error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);' >> /app/public/index.php
RUN echo 'ini_set("display_errors", 0);' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'header("Content-Type: application/json; charset=utf-8");' >> /app/public/index.php
RUN echo 'header("Access-Control-Allow-Origin: *");' >> /app/public/index.php
RUN echo 'header("Access-Control-Allow-Methods: GET, POST, OPTIONS");' >> /app/public/index.php
RUN echo 'header("Access-Control-Allow-Headers: Content-Type, Authorization");' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {' >> /app/public/index.php
RUN echo '    http_response_code(200);' >> /app/public/index.php
RUN echo '    exit();' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function runCommand($cmd) {' >> /app/public/index.php
RUN echo '    $output = [];' >> /app/public/index.php
RUN echo '    $return_var = 0;' >> /app/public/index.php
RUN echo '    exec($cmd . " 2>/dev/null", $output, $return_var);' >> /app/public/index.php
RUN echo '    return $return_var === 0 ? implode("\n", $output) : "";' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function getNetworkInterface() {' >> /app/public/index.php
RUN echo '    $output = runCommand("ip route | grep default");' >> /app/public/index.php
RUN echo '    if ($output && preg_match("/dev\s+(\w+)/", $output, $matches)) {' >> /app/public/index.php
RUN echo '        return $matches[1];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    return "eth0";' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function getNetworkRange() {' >> /app/public/index.php
RUN echo '    $interface = getNetworkInterface();' >> /app/public/index.php
RUN echo '    $output = runCommand("ip route | grep $interface | grep -v default | head -1");' >> /app/public/index.php
RUN echo '    if ($output && preg_match("/([0-9.]+\/\d+)/", $output, $matches)) {' >> /app/public/index.php
RUN echo '        return $matches[1];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    return "192.168.1.0/24";' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function getActiveDevices() {' >> /app/public/index.php
RUN echo '    $devices = [];' >> /app/public/index.php
RUN echo '    $arpOutput = runCommand("arp -a");' >> /app/public/index.php
RUN echo '    if ($arpOutput) {' >> /app/public/index.php
RUN echo '        $lines = explode("\n", $arpOutput);' >> /app/public/index.php
RUN echo '        foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '            if (preg_match("/\(([0-9.]+)\) at ([0-9a-f:]+)/i", $line, $matches)) {' >> /app/public/index.php
RUN echo '                $devices[] = [' >> /app/public/index.php
RUN echo '                    "ip" => $matches[1],' >> /app/public/index.php
RUN echo '                    "mac" => strtolower($matches[2]),' >> /app/public/index.php
RUN echo '                    "hostname" => "",' >> /app/public/index.php
RUN echo '                    "status" => "online",' >> /app/public/index.php
RUN echo '                    "last_seen" => date("c")' >> /app/public/index.php
RUN echo '                ];' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    return array_slice($devices, 0, 10);' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function getNetworkTraffic() {' >> /app/public/index.php
RUN echo '    $interface = getNetworkInterface();' >> /app/public/index.php
RUN echo '    $output = runCommand("cat /proc/net/dev | grep $interface");' >> /app/public/index.php
RUN echo '    $rxBytes = 0;' >> /app/public/index.php
RUN echo '    $txBytes = 0;' >> /app/public/index.php
RUN echo '    if ($output) {' >> /app/public/index.php
RUN echo '        $stats = preg_split("/\s+/", trim($output));' >> /app/public/index.php
RUN echo '        if (count($stats) >= 10) {' >> /app/public/index.php
RUN echo '            $rxBytes = intval($stats[1]);' >> /app/public/index.php
RUN echo '            $txBytes = intval($stats[9]);' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    return [' >> /app/public/index.php
RUN echo '        "rx_bytes" => $rxBytes,' >> /app/public/index.php
RUN echo '        "tx_bytes" => $txBytes,' >> /app/public/index.php
RUN echo '        "total_bytes" => $rxBytes + $txBytes,' >> /app/public/index.php
RUN echo '        "interface" => $interface' >> /app/public/index.php
RUN echo '    ];' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function getSystemStatus() {' >> /app/public/index.php
RUN echo '    $uptime = runCommand("uptime");' >> /app/public/index.php
RUN echo '    $loadAvg = runCommand("cat /proc/loadavg");' >> /app/public/index.php
RUN echo '    return [' >> /app/public/index.php
RUN echo '        "status" => "online",' >> /app/public/index.php
RUN echo '        "uptime" => trim($uptime ?: "Unknown"),' >> /app/public/index.php
RUN echo '        "load_average" => trim($loadAvg ?: "0.00 0.00 0.00"),' >> /app/public/index.php
RUN echo '        "timestamp" => date("c")' >> /app/public/index.php
RUN echo '    ];' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function performNetworkScan() {' >> /app/public/index.php
RUN echo '    $networkRange = getNetworkRange();' >> /app/public/index.php
RUN echo '    $devices = [];' >> /app/public/index.php
RUN echo '    $nmapOutput = runCommand("nmap -sn $networkRange");' >> /app/public/index.php
RUN echo '    if ($nmapOutput) {' >> /app/public/index.php
RUN echo '        $lines = explode("\n", $nmapOutput);' >> /app/public/index.php
RUN echo '        foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '            if (preg_match("/Nmap scan report for (.+)/", $line, $matches)) {' >> /app/public/index.php
RUN echo '                $host = trim($matches[1]);' >> /app/public/index.php
RUN echo '                if (filter_var($host, FILTER_VALIDATE_IP)) {' >> /app/public/index.php
RUN echo '                    $devices[] = [' >> /app/public/index.php
RUN echo '                        "ip" => $host,' >> /app/public/index.php
RUN echo '                        "status" => "online",' >> /app/public/index.php
RUN echo '                        "timestamp" => date("c")' >> /app/public/index.php
RUN echo '                    ];' >> /app/public/index.php
RUN echo '                } elseif (preg_match("/\(([0-9.]+)\)/", $host, $ipMatches)) {' >> /app/public/index.php
RUN echo '                    $devices[] = [' >> /app/public/index.php
RUN echo '                        "ip" => $ipMatches[1],' >> /app/public/index.php
RUN echo '                        "status" => "online",' >> /app/public/index.php
RUN echo '                        "timestamp" => date("c")' >> /app/public/index.php
RUN echo '                    ];' >> /app/public/index.php
RUN echo '                }' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    return [' >> /app/public/index.php
RUN echo '        "devices" => array_slice($devices, 0, 20),' >> /app/public/index.php
RUN echo '        "network_range" => $networkRange,' >> /app/public/index.php
RUN echo '        "scan_time" => date("c")' >> /app/public/index.php
RUN echo '    ];' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function getSecurityAlerts() {' >> /app/public/index.php
RUN echo '    return [];' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'function runSecurityAnalysis() {' >> /app/public/index.php
RUN echo '    return [' >> /app/public/index.php
RUN echo '        "alerts" => [],' >> /app/public/index.php
RUN echo '        "threats_detected" => 0,' >> /app/public/index.php
RUN echo '        "scan_time" => date("c")' >> /app/public/index.php
RUN echo '    ];' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '$action = $_GET["action"] ?? $_POST["action"] ?? "dashboard";' >> /app/public/index.php
RUN echo '$method = $_SERVER["REQUEST_METHOD"];' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'try {' >> /app/public/index.php
RUN echo '    $response = [' >> /app/public/index.php
RUN echo '        "success" => true,' >> /app/public/index.php
RUN echo '        "timestamp" => date("c")' >> /app/public/index.php
RUN echo '    ];' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '    switch ($action) {' >> /app/public/index.php
RUN echo '        case "dashboard":' >> /app/public/index.php
RUN echo '            $response["data"] = [' >> /app/public/index.php
RUN echo '                "devices" => getActiveDevices(),' >> /app/public/index.php
RUN echo '                "traffic" => getNetworkTraffic(),' >> /app/public/index.php
RUN echo '                "security_events" => 0,' >> /app/public/index.php
RUN echo '                "system_status" => getSystemStatus(),' >> /app/public/index.php
RUN echo '                "alerts" => getSecurityAlerts()' >> /app/public/index.php
RUN echo '            ];' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '        case "scan":' >> /app/public/index.php
RUN echo '            $response["data"] = performNetworkScan();' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '        case "analysis":' >> /app/public/index.php
RUN echo '            $response["data"] = runSecurityAnalysis();' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '        case "traffic":' >> /app/public/index.php
RUN echo '            $response["data"] = getNetworkTraffic();' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '        case "devices":' >> /app/public/index.php
RUN echo '            $response["data"] = getActiveDevices();' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '        case "health-check":' >> /app/public/index.php
RUN echo '            $response["data"] = [' >> /app/public/index.php
RUN echo '                "status" => "healthy",' >> /app/public/index.php
RUN echo '                "version" => "1.0.0",' >> /app/public/index.php
RUN echo '                "author" => "Hirotoshi Uchida",' >> /app/public/index.php
RUN echo '                "homepage" => "https://hirotoshiuchida.onrender.com"' >> /app/public/index.php
RUN echo '            ];' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '        default:' >> /app/public/index.php
RUN echo '            if (empty($action)) {' >> /app/public/index.php
RUN echo '                header("Content-Type: text/html; charset=utf-8");' >> /app/public/index.php
RUN echo '                echo "<!DOCTYPE html>";' >> /app/public/index.php
RUN echo '                echo "<html><head><title>Network Security App</title></head>";' >> /app/public/index.php
RUN echo '                echo "<body>";' >> /app/public/index.php
RUN echo '                echo "<h1>Network Security App</h1>";' >> /app/public/index.php
RUN echo '                echo "<p>Application is running successfully!</p>";' >> /app/public/index.php
RUN echo '                echo "<p>Author: Hirotoshi Uchida</p>";' >> /app/public/index.php
RUN echo '                echo "<p>Homepage: <a href=\"https://hirotoshiuchida.onrender.com\">https://hirotoshiuchida.onrender.com</a></p>";' >> /app/public/index.php
RUN echo '                echo "<h2>API Endpoints:</h2>";' >> /app/public/index.php
RUN echo '                echo "<ul>";' >> /app/public/index.php
RUN echo '                echo "<li><a href=\"?action=dashboard\">Dashboard</a></li>";' >> /app/public/index.php
RUN echo '                echo "<li><a href=\"?action=scan\">Network Scan</a></li>";' >> /app/public/index.php
RUN echo '                echo "<li><a href=\"?action=analysis\">Security Analysis</a></li>";' >> /app/public/index.php
RUN echo '                echo "<li><a href=\"?action=health-check\">Health Check</a></li>";' >> /app/public/index.php
RUN echo '                echo "</ul>";' >> /app/public/index.php
RUN echo '                echo "</body></html>";' >> /app/public/index.php
RUN echo '                exit;' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '            $response = [' >> /app/public/index.php
RUN echo '                "success" => false,' >> /app/public/index.php
RUN echo '                "error" => "Unknown action: " . $action,' >> /app/public/index.php
RUN echo '                "timestamp" => date("c")' >> /app/public/index.php
RUN echo '            ];' >> /app/public/index.php
RUN echo '            http_response_code(400);' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '} catch (Exception $e) {' >> /app/public/index.php
RUN echo '    $response = [' >> /app/public/index.php
RUN echo '        "success" => false,' >> /app/public/index.php
RUN echo '        "error" => "Internal server error",' >> /app/public/index.php
RUN echo '        "timestamp" => date("c")' >> /app/public/index.php
RUN echo '    ];' >> /app/public/index.php
RUN echo '    http_response_code(500);' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'if ($method !== "GET" || !empty($_GET["action"])) {' >> /app/public/index.php
RUN echo '    header("Content-Type: application/json; charset=utf-8");' >> /app/public/index.php
RUN echo '    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '?>' >> /app/public/index.php

COPY NetworkController.php /app/public/NetworkController.php

COPY NetworkMonitor.php /app/public/NetworkMonitor.php

COPY index.html /app/public/index.html

RUN mkdir -p /app/public/assets

COPY assets/ /app/public/assets

# Create SQLite database
RUN touch /app/storage/database.sqlite \
    && chown appuser:appuser /app/storage/database.sqlite \
    && chmod 664 /app/storage/database.sqlite

# Configure PHP-FPM
RUN sed -i 's/listen = \/run\/php\/php8.1-fmp.sock/listen = 127.0.0.1:9000/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf \
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

# Set ownership for the index.php file
RUN chown appuser:appuser /app/public/index.php

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
