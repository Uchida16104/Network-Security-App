# Network Security App Dockerfile - Fixed Version
# Author: Hirotoshi Uchida
# Project: Network Security App
# Homepage: https://hirotoshiuchida.onrender.com

FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV PHP_VERSION=8.1
ENV APP_ENV=production
ENV PORT=8080

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

# Configure network tools permissions
RUN chmod u+s /usr/bin/nmap \
    && chmod u+s /usr/bin/tcpdump \
    && chmod u+s /usr/sbin/arp-scan \
    && chmod u+s /bin/ping \
    && chmod u+s /usr/bin/traceroute \
    && chmod u+s /usr/bin/tshark

# Create application user and directories
RUN useradd -m -s /bin/bash -u 1001 appuser \
    && mkdir -p /app/public \
    && mkdir -p /var/log/supervisor \
    && chown -R appuser:appuser /app

# Create comprehensive public/index.php with all network monitoring functionality
RUN echo '<?php' > /app/public/index.php
RUN echo '// Network Security App - Complete Implementation' >> /app/public/index.php
RUN echo '// Author: Hirotoshi Uchida' >> /app/public/index.php
RUN echo '// Homepage: https://hirotoshiuchida.onrender.com' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'error_reporting(E_ALL);' >> /app/public/index.php
RUN echo 'ini_set("display_errors", 0);' >> /app/public/index.php
RUN echo 'set_time_limit(60);' >> /app/public/index.php
RUN echo 'header("X-Content-Type-Options: nosniff");' >> /app/public/index.php
RUN echo 'header("X-Frame-Options: DENY");' >> /app/public/index.php
RUN echo 'header("X-XSS-Protection: 1; mode=block");' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'class NetworkController {' >> /app/public/index.php
RUN echo '    private $networkInterface;' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    public function __construct() {' >> /app/public/index.php
RUN echo '        $this->networkInterface = $this->detectNetworkInterface();' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    public function dashboard() {' >> /app/public/index.php
RUN echo '        try {' >> /app/public/index.php
RUN echo '            $data = [' >> /app/public/index.php
RUN echo '                "devices" => $this->getActiveDevices(),' >> /app/public/index.php
RUN echo '                "traffic" => $this->getNetworkTraffic(),' >> /app/public/index.php
RUN echo '                "system_status" => $this->getSystemStatus(),' >> /app/public/index.php
RUN echo '                "alerts" => $this->getSecurityAlerts()' >> /app/public/index.php
RUN echo '            ];' >> /app/public/index.php
RUN echo '            return ["success" => true, "data" => $data, "timestamp" => date("c")];' >> /app/public/index.php
RUN echo '        } catch (Exception $e) {' >> /app/public/index.php
RUN echo '            error_log("Dashboard error: " . $e->getMessage());' >> /app/public/index.php
RUN echo '            return ["success" => false, "error" => "Dashboard unavailable", "timestamp" => date("c")];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    public function networkScan($range = null, $type = "quick") {' >> /app/public/index.php
RUN echo '        try {' >> /app/public/index.php
RUN echo '            $range = $range ?: $this->getNetworkRange();' >> /app/public/index.php
RUN echo '            $devices = $this->performNetworkScan($range, $type);' >> /app/public/index.php
RUN echo '            return ["success" => true, "data" => ["devices" => $devices], "range" => $range, "timestamp" => date("c")];' >> /app/public/index.php
RUN echo '        } catch (Exception $e) {' >> /app/public/index.php
RUN echo '            error_log("Scan error: " . $e->getMessage());' >> /app/public/index.php
RUN echo '            return ["success" => false, "error" => "Scan failed", "timestamp" => date("c")];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    public function networkAnalysis() {' >> /app/public/index.php
RUN echo '        try {' >> /app/public/index.php
RUN echo '            $startTime = microtime(true);' >> /app/public/index.php
RUN echo '            $analysis = [' >> /app/public/index.php
RUN echo '                "nmap" => $this->executeNmapAnalysis(),' >> /app/public/index.php
RUN echo '                "arp" => $this->executeArpAnalysis(),' >> /app/public/index.php
RUN echo '                "netstat" => $this->executeNetstatAnalysis(),' >> /app/public/index.php
RUN echo '                "traceroute" => $this->executeTracerouteAnalysis(),' >> /app/public/index.php
RUN echo '                "execution_time" => microtime(true) - $startTime' >> /app/public/index.php
RUN echo '            ];' >> /app/public/index.php
RUN echo '            return ["success" => true, "data" => $analysis, "timestamp" => date("c")];' >> /app/public/index.php
RUN echo '        } catch (Exception $e) {' >> /app/public/index.php
RUN echo '            error_log("Analysis error: " . $e->getMessage());' >> /app/public/index.php
RUN echo '            return ["success" => false, "error" => "Analysis failed", "timestamp" => date("c")];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function performNetworkScan($range, $type) {' >> /app/public/index.php
RUN echo '        $devices = [];' >> /app/public/index.php
RUN echo '        $nmapCmd = "timeout 30 nmap -sn " . escapeshellarg($range) . " 2>/dev/null";' >> /app/public/index.php
RUN echo '        $nmapOutput = shell_exec($nmapCmd);' >> /app/public/index.php
RUN echo '        if ($nmapOutput) {' >> /app/public/index.php
RUN echo '            $hosts = $this->parseNmapHosts($nmapOutput);' >> /app/public/index.php
RUN echo '            foreach ($hosts as $host) {' >> /app/public/index.php
RUN echo '                $devices[] = $this->getDeviceInfo($host);' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        $arpCmd = "arp -a 2>/dev/null";' >> /app/public/index.php
RUN echo '        $arpOutput = shell_exec($arpCmd);' >> /app/public/index.php
RUN echo '        if ($arpOutput) {' >> /app/public/index.php
RUN echo '            $arpDevices = $this->parseArpOutput($arpOutput);' >> /app/public/index.php
RUN echo '            $devices = array_merge($devices, $arpDevices);' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return array_unique($devices, SORT_REGULAR);' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function executeNmapAnalysis() {' >> /app/public/index.php
RUN echo '        $range = $this->getNetworkRange();' >> /app/public/index.php
RUN echo '        $cmd = "timeout 20 nmap -sn " . escapeshellarg($range) . " 2>/dev/null";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        return ["hosts" => $this->parseNmapHosts($output ?: ""), "range" => $range];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function executeArpAnalysis() {' >> /app/public/index.php
RUN echo '        $cmd = "arp -a 2>/dev/null";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        return $this->parseArpOutput($output ?: "");' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function executeNetstatAnalysis() {' >> /app/public/index.php
RUN echo '        $connCmd = "netstat -tn 2>/dev/null | grep ESTABLISHED";' >> /app/public/index.php
RUN echo '        $listenCmd = "netstat -ln 2>/dev/null | grep LISTEN";' >> /app/public/index.php
RUN echo '        $connOutput = shell_exec($connCmd);' >> /app/public/index.php
RUN echo '        $listenOutput = shell_exec($listenCmd);' >> /app/public/index.php
RUN echo '        return [' >> /app/public/index.php
RUN echo '            "connections" => $this->parseNetstatConnections($connOutput ?: ""),' >> /app/public/index.php
RUN echo '            "listening" => $this->parseNetstatListening($listenOutput ?: "")' >> /app/public/index.php
RUN echo '        ];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function executeTracerouteAnalysis() {' >> /app/public/index.php
RUN echo '        $gateway = $this->getGateway();' >> /app/public/index.php
RUN echo '        $cmd = "timeout 10 traceroute -m 5 " . escapeshellarg($gateway) . " 2>/dev/null";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        return ["gateway" => $gateway, "hops" => $this->parseTraceroute($output ?: "")];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getActiveDevices() {' >> /app/public/index.php
RUN echo '        $devices = [];' >> /app/public/index.php
RUN echo '        $arpCmd = "arp -a 2>/dev/null";' >> /app/public/index.php
RUN echo '        $output = shell_exec($arpCmd);' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            $devices = $this->parseArpOutput($output);' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return array_slice($devices, 0, 20);' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getNetworkTraffic() {' >> /app/public/index.php
RUN echo '        $interface = $this->networkInterface;' >> /app/public/index.php
RUN echo '        $cmd = "cat /proc/net/dev 2>/dev/null | grep " . escapeshellarg($interface);' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        $rxBytes = 0; $txBytes = 0;' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            $stats = preg_split("/\s+/", trim($output));' >> /app/public/index.php
RUN echo '            if (count($stats) >= 10) {' >> /app/public/index.php
RUN echo '                $rxBytes = intval($stats[1]);' >> /app/public/index.php
RUN echo '                $txBytes = intval($stats[9]);' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return ["interface" => $interface, "rx_bytes" => $rxBytes, "tx_bytes" => $txBytes, "total_bytes" => $rxBytes + $txBytes];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getSystemStatus() {' >> /app/public/index.php
RUN echo '        $uptime = trim(shell_exec("uptime 2>/dev/null") ?: "Unknown");' >> /app/public/index.php
RUN echo '        $loadavg = trim(shell_exec("cat /proc/loadavg 2>/dev/null") ?: "0.00 0.00 0.00");' >> /app/public/index.php
RUN echo '        return ["status" => "online", "uptime" => $uptime, "load_average" => $loadavg];' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getSecurityAlerts() {' >> /app/public/index.php
RUN echo '        $alerts = [];' >> /app/public/index.php
RUN echo '        $netstatCmd = "netstat -tn 2>/dev/null | grep ESTABLISHED";' >> /app/public/index.php
RUN echo '        $output = shell_exec($netstatCmd);' >> /app/public/index.php
RUN echo '        if ($output) {' >> /app/public/index.php
RUN echo '            $connections = $this->parseNetstatConnections($output);' >> /app/public/index.php
RUN echo '            $ipCounts = [];' >> /app/public/index.php
RUN echo '            foreach ($connections as $conn) {' >> /app/public/index.php
RUN echo '                $ip = $conn["remote_ip"] ?? "";' >> /app/public/index.php
RUN echo '                $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '            foreach ($ipCounts as $ip => $count) {' >> /app/public/index.php
RUN echo '                if ($count > 10 && !empty($ip)) {' >> /app/public/index.php
RUN echo '                    $alerts[] = ["type" => "high_connections", "ip" => $ip, "count" => $count, "severity" => "medium"];' >> /app/public/index.php
RUN echo '                }' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return $alerts;' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function parseNmapHosts($output) {' >> /app/public/index.php
RUN echo '        $hosts = [];' >> /app/public/index.php
RUN echo '        $lines = explode("\n", $output);' >> /app/public/index.php
RUN echo '        foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '            if (preg_match("/Nmap scan report for (.+)/", $line, $matches)) {' >> /app/public/index.php
RUN echo '                $host = trim($matches[1]);' >> /app/public/index.php
RUN echo '                if (filter_var($host, FILTER_VALIDATE_IP)) {' >> /app/public/index.php
RUN echo '                    $hosts[] = $host;' >> /app/public/index.php
RUN echo '                } elseif (preg_match("/\(([0-9.]+)\)/", $host, $ipMatches)) {' >> /app/public/index.php
RUN echo '                    $hosts[] = $ipMatches[1];' >> /app/public/index.php
RUN echo '                }' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return array_unique($hosts);' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function parseArpOutput($output) {' >> /app/public/index.php
RUN echo '        $devices = [];' >> /app/public/index.php
RUN echo '        $lines = explode("\n", $output);' >> /app/public/index.php
RUN echo '        foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '            if (preg_match("/\(([0-9.]+)\) at ([0-9a-f:]+)/i", $line, $matches)) {' >> /app/public/index.php
RUN echo '                $devices[] = ["ip" => $matches[1], "mac" => strtolower($matches[2]), "status" => "online"];' >> /app/public/index.php
RUN echo '            } elseif (preg_match("/([0-9.]+)\s+([0-9a-f:]+)/i", $line, $matches)) {' >> /app/public/index.php
RUN echo '                $devices[] = ["ip" => $matches[1], "mac" => strtolower($matches[2]), "status" => "online"];' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return $devices;' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function parseNetstatConnections($output) {' >> /app/public/index.php
RUN echo '        $connections = [];' >> /app/public/index.php
RUN echo '        $lines = explode("\n", $output);' >> /app/public/index.php
RUN echo '        foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '            if (preg_match("/tcp\s+\d+\s+\d+\s+([0-9.]+):(\d+)\s+([0-9.]+):(\d+)\s+(\w+)/", $line, $matches)) {' >> /app/public/index.php
RUN echo '                $connections[] = ["local_ip" => $matches[1], "local_port" => intval($matches[2]), "remote_ip" => $matches[3], "remote_port" => intval($matches[4]), "state" => $matches[5]];' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return $connections;' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function parseNetstatListening($output) {' >> /app/public/index.php
RUN echo '        $listening = [];' >> /app/public/index.php
RUN echo '        $lines = explode("\n", $output);' >> /app/public/index.php
RUN echo '        foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '            if (preg_match("/tcp\s+\d+\s+\d+\s+([0-9.*:]+):(\d+)\s+.+LISTEN/", $line, $matches)) {' >> /app/public/index.php
RUN echo '                $listening[] = ["ip" => $matches[1], "port" => intval($matches[2]), "protocol" => "tcp"];' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return $listening;' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function parseTraceroute($output) {' >> /app/public/index.php
RUN echo '        $hops = [];' >> /app/public/index.php
RUN echo '        $lines = explode("\n", $output);' >> /app/public/index.php
RUN echo '        foreach ($lines as $line) {' >> /app/public/index.php
RUN echo '            if (preg_match("/^\s*(\d+)\s+([0-9.]+)\s+(.+)/", $line, $matches)) {' >> /app/public/index.php
RUN echo '                $hops[] = ["hop" => intval($matches[1]), "ip" => $matches[2], "time" => trim($matches[3])];' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return $hops;' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getDeviceInfo($ip) {' >> /app/public/index.php
RUN echo '        $device = ["ip" => $ip, "mac" => "", "hostname" => "", "status" => "unknown"];' >> /app/public/index.php
RUN echo '        $arpCmd = "arp -n " . escapeshellarg($ip) . " 2>/dev/null";' >> /app/public/index.php
RUN echo '        $arpOutput = shell_exec($arpCmd);' >> /app/public/index.php
RUN echo '        if ($arpOutput && preg_match("/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i", $arpOutput, $matches)) {' >> /app/public/index.php
RUN echo '            $device["mac"] = $matches[1];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        $hostCmd = "nslookup " . escapeshellarg($ip) . " 2>/dev/null | grep \"name =\" | head -1";' >> /app/public/index.php
RUN echo '        $hostOutput = shell_exec($hostCmd);' >> /app/public/index.php
RUN echo '        if ($hostOutput && preg_match("/name = (.+)\./", $hostOutput, $matches)) {' >> /app/public/index.php
RUN echo '            $device["hostname"] = trim($matches[1]);' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        $pingCmd = "ping -c 1 -W 1 " . escapeshellarg($ip) . " 2>/dev/null";' >> /app/public/index.php
RUN echo '        $pingOutput = shell_exec($pingCmd);' >> /app/public/index.php
RUN echo '        $device["status"] = ($pingOutput && strpos($pingOutput, "1 received") !== false) ? "online" : "offline";' >> /app/public/index.php
RUN echo '        return $device;' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function detectNetworkInterface() {' >> /app/public/index.php
RUN echo '        $cmd = "ip route | grep default 2>/dev/null | head -1";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        if ($output && preg_match("/dev\s+(\w+)/", $output, $matches)) {' >> /app/public/index.php
RUN echo '            return $matches[1];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return "eth0";' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getNetworkRange() {' >> /app/public/index.php
RUN echo '        $cmd = "ip route | grep " . escapeshellarg($this->networkInterface) . " | grep -v default 2>/dev/null | head -1";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        if ($output && preg_match("/([0-9.]+\/\d+)/", $output, $matches)) {' >> /app/public/index.php
RUN echo '            return $matches[1];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return "192.168.1.0/24";' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    private function getGateway() {' >> /app/public/index.php
RUN echo '        $cmd = "ip route | grep default 2>/dev/null | head -1";' >> /app/public/index.php
RUN echo '        $output = shell_exec($cmd);' >> /app/public/index.php
RUN echo '        if ($output && preg_match("/default via ([0-9.]+)/", $output, $matches)) {' >> /app/public/index.php
RUN echo '            return $matches[1];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        return "8.8.8.8";' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '$requestMethod = $_SERVER["REQUEST_METHOD"] ?? "GET";' >> /app/public/index.php
RUN echo '$requestUri = $_SERVER["REQUEST_URI"] ?? "/";' >> /app/public/index.php
RUN echo '$pathInfo = parse_url($requestUri, PHP_URL_PATH);' >> /app/public/index.php
RUN echo '$controller = new NetworkController();' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo 'if (str_starts_with($pathInfo, "/api/") || isset($_GET["action"])) {' >> /app/public/index.php
RUN echo '    header("Content-Type: application/json; charset=utf-8");' >> /app/public/index.php
RUN echo '    header("Cache-Control: no-cache, no-store, must-revalidate");' >> /app/public/index.php
RUN echo '    header("Pragma: no-cache");' >> /app/public/index.php
RUN echo '    header("Expires: 0");' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    $action = $_GET["action"] ?? basename($pathInfo);' >> /app/public/index.php
RUN echo '    ' >> /app/public/index.php
RUN echo '    switch ($action) {' >> /app/public/index.php
RUN echo '        case "dashboard":' >> /app/public/index.php
RUN echo '            echo json_encode($controller->dashboard(), JSON_UNESCAPED_SLASHES);' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '        case "scan":' >> /app/public/index.php
RUN echo '            $range = $_GET["range"] ?? null;' >> /app/public/index.php
RUN echo '            $type = $_GET["type"] ?? "quick";' >> /app/public/index.php
RUN echo '            echo json_encode($controller->networkScan($range, $type), JSON_UNESCAPED_SLASHES);' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '        case "analysis":' >> /app/public/index.php
RUN echo '            echo json_encode($controller->networkAnalysis(), JSON_UNESCAPED_SLASHES);' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '        case "health":' >> /app/public/index.php
RUN echo '        case "health-check":' >> /app/public/index.php
RUN echo '            echo json_encode(["success" => true, "status" => "healthy", "timestamp" => date("c")], JSON_UNESCAPED_SLASHES);' >> /app/public/index.php
RUN echo '            break;' >> /app/public/index.php
RUN echo '        default:' >> /app/public/index.php
RUN echo '            http_response_code(404);' >> /app/public/index.php
RUN echo '            echo json_encode(["success" => false, "error" => "Endpoint not found"], JSON_UNESCAPED_SLASHES);' >> /app/public/index.php
RUN echo '    }' >> /app/public/index.php
RUN echo '    exit;' >> /app/public/index.php
RUN echo '}' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '?>' >> /app/public/index.php
RUN echo '<!DOCTYPE html>' >> /app/public/index.php
RUN echo '<html lang="en">' >> /app/public/index.php
RUN echo '<head>' >> /app/public/index.php
RUN echo '    <meta charset="UTF-8">' >> /app/public/index.php
RUN echo '    <meta name="viewport" content="width=device-width, initial-scale=1.0">' >> /app/public/index.php
RUN echo '    <title>Network Security Monitor - Hirotoshi Uchida</title>' >> /app/public/index.php
RUN echo '    <style>' >> /app/public/index.php
RUN echo '        * { margin: 0; padding: 0; box-sizing: border-box; }' >> /app/public/index.php
RUN echo '        body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; color: #333; }' >> /app/public/index.php
RUN echo '        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }' >> /app/public/index.php
RUN echo '        .header { text-align: center; margin-bottom: 30px; color: white; }' >> /app/public/index.php
RUN echo '        .header h1 { font-size: 2.5rem; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }' >> /app/public/index.php
RUN echo '        .header p { font-size: 1.1rem; opacity: 0.9; }' >> /app/public/index.php
RUN echo '        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }' >> /app/public/index.php
RUN echo '        .card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: transform 0.2s; }' >> /app/public/index.php
RUN echo '        .card:hover { transform: translateY(-2px); }' >> /app/public/index.php
RUN echo '        .card h3 { color: #5a67d8; margin-bottom: 15px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }' >> /app/public/index.php
RUN echo '        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }' >> /app/public/index.php
RUN echo '        .status-online { background-color: #48bb78; }' >> /app/public/index.php
RUN echo '        .status-offline { background-color: #f56565; }' >> /app/public/index.php
RUN echo '        .device-list { max-height: 200px; overflow-y: auto; }' >> /app/public/index.php
RUN echo '        .device-item { padding: 8px 0; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; }' >> /app/public/index.php
RUN echo '        .device-item:last-child { border-bottom: none; }' >> /app/public/index.php
RUN echo '        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; transition: opacity 0.2s; margin: 5px; }' >> /app/public/index.php
RUN echo '        .btn:hover { opacity: 0.9; }' >> /app/public/index.php
RUN echo '        .btn:disabled { opacity: 0.6; cursor: not-allowed; }' >> /app/public/index.php
RUN echo '        .loading { text-align: center; color: #666; font-style: italic; animation: pulse 2s infinite; }' >> /app/public/index.php
RUN echo '        .error { color: #e53e3e; background: #fed7d7; padding: 10px; border-radius: 5px; margin: 10px 0; }' >> /app/public/index.php
RUN echo '        .success { color: #38a169; background: #c6f6d5; padding: 10px; border-radius: 5px; margin: 10px 0; }' >> /app/public/index.php
RUN echo '        .chart-container { height: 200px; margin: 15px 0; background: #f7fafc; border-radius: 5px; padding: 10px; display: flex; align-items: center; justify-content: center; }' >> /app/public/index.php
RUN echo '        .metric { text-align: center; padding: 10px; }' >> /app/public/index.php
RUN echo '        .metric-value { font-size: 1.8rem; font-weight: bold; color: #5a67d8; }' >> /app/public/index.php
RUN echo '        .metric-label { font-size: 0.9rem; color: #666; }' >> /app/public/index.php
RUN echo '        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }' >> /app/public/index.php
RUN echo '        .footer { text-align: center; margin-top: 40px; padding: 20px; color: white; opacity: 0.8; }' >> /app/public/index.php
RUN echo '        .footer a { color: white; text-decoration: none; }' >> /app/public/index.php
RUN echo '        .footer a:hover { text-decoration: underline; }' >> /app/public/index.php
RUN echo '    </style>' >> /app/public/index.php
RUN echo '</head>' >> /app/public/index.php
RUN echo '<body>' >> /app/public/index.php
RUN echo '    <div class="container">' >> /app/public/index.php
RUN echo '        <div class="header">' >> /app/public/index.php
RUN echo '            <h1>🛡️ Network Security Monitor</h1>' >> /app/public/index.php
RUN echo '            <p>Real-time network monitoring and security analysis</p>' >> /app/public/index.php
RUN echo '            <p>by <strong>Hirotoshi Uchida</strong></p>' >> /app/public/index.php
RUN echo '        </div>' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        <div class="dashboard">' >> /app/public/index.php
RUN echo '            <div class="card">' >> /app/public/index.php
RUN echo '                <h3>🖥️ System Status</h3>' >> /app/public/index.php
RUN echo '                <div id="system-status">' >> /app/public/index.php
RUN echo '                    <div class="loading">Loading system status...</div>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '            </div>' >> /app/public/index.php
RUN echo '            ' >> /app/public/index.php
RUN echo '            <div class="card">' >> /app/public/index.php
RUN echo '                <h3>🌐 Network Devices</h3>' >> /app/public/index.php
RUN echo '                <div id="network-devices">' >> /app/public/index.php
RUN echo '                    <div class="loading">Discovering devices...</div>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '                <button class="btn" onclick="scanNetwork()" id="scan-btn">🔍 Scan Network</button>' >> /app/public/index.php
RUN echo '            </div>' >> /app/public/index.php
RUN echo '            ' >> /app/public/index.php
RUN echo '            <div class="card">' >> /app/public/index.php
RUN echo '                <h3>📊 Network Traffic</h3>' >> /app/public/index.php
RUN echo '                <div id="network-traffic">' >> /app/public/index.php
RUN echo '                    <div class="loading">Analyzing traffic...</div>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '                <div class="chart-container" id="traffic-chart">' >> /app/public/index.php
RUN echo '                    <div class="metric">' >> /app/public/index.php
RUN echo '                        <div class="metric-value" id="rx-value">0</div>' >> /app/public/index.php
RUN echo '                        <div class="metric-label">RX Bytes</div>' >> /app/public/index.php
RUN echo '                    </div>' >> /app/public/index.php
RUN echo '                    <div class="metric">' >> /app/public/index.php
RUN echo '                        <div class="metric-value" id="tx-value">0</div>' >> /app/public/index.php
RUN echo '                        <div class="metric-label">TX Bytes</div>' >> /app/public/index.php
RUN echo '                    </div>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '            </div>' >> /app/public/index.php
RUN echo '            ' >> /app/public/index.php
RUN echo '            <div class="card">' >> /app/public/index.php
RUN echo '                <h3>🚨 Security Alerts</h3>' >> /app/public/index.php
RUN echo '                <div id="security-alerts">' >> /app/public/index.php
RUN echo '                    <div class="loading">Monitoring security events...</div>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '            </div>' >> /app/public/index.php
RUN echo '        </div>' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        <div class="card">' >> /app/public/index.php
RUN echo '            <h3>🔬 Network Analysis</h3>' >> /app/public/index.php
RUN echo '            <div id="network-analysis">' >> /app/public/index.php
RUN echo '                <div class="loading">Ready for analysis...</div>' >> /app/public/index.php
RUN echo '            </div>' >> /app/public/index.php
RUN echo '            <button class="btn" onclick="runAnalysis()" id="analysis-btn">🔄 Run Analysis</button>' >> /app/public/index.php
RUN echo '        </div>' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        <div class="footer">' >> /app/public/index.php
RUN echo '            <p>&copy; 2024 Hirotoshi Uchida - Network Security App</p>' >> /app/public/index.php
RUN echo '            <p>Visit: <a href="https://hirotoshiuchida.onrender.com" target="_blank">https://hirotoshiuchida.onrender.com</a></p>' >> /app/public/index.php
RUN echo '        </div>' >> /app/public/index.php
RUN echo '    </div>' >> /app/public/index.php
RUN echo '' >> /app/public/index.php
RUN echo '    <script>' >> /app/public/index.php
RUN echo '        let refreshInterval;' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function loadDashboard() {' >> /app/public/index.php
RUN echo '            fetch("/?action=dashboard", { method: "GET", headers: { "Accept": "application/json" } })' >> /app/public/index.php
RUN echo '                .then(response => {' >> /app/public/index.php
RUN echo '                    if (!response.ok) throw new Error(`HTTP ${response.status}`);' >> /app/public/index.php
RUN echo '                    return response.json();' >> /app/public/index.php
RUN echo '                })' >> /app/public/index.php
RUN echo '                .then(data => {' >> /app/public/index.php
RUN echo '                    if (data.success) {' >> /app/public/index.php
RUN echo '                        updateSystemStatus(data.data.system_status);' >> /app/public/index.php
RUN echo '                        updateNetworkDevices(data.data.devices);' >> /app/public/index.php
RUN echo '                        updateNetworkTraffic(data.data.traffic);' >> /app/public/index.php
RUN echo '                        updateSecurityAlerts(data.data.alerts);' >> /app/public/index.php
RUN echo '                    } else {' >> /app/public/index.php
RUN echo '                        showError("Failed to load dashboard: " + (data.error || "Unknown error"));' >> /app/public/index.php
RUN echo '                    }' >> /app/public/index.php
RUN echo '                })' >> /app/public/index.php
RUN echo '                .catch(error => {' >> /app/public/index.php
RUN echo '                    console.error("Dashboard error:", error);' >> /app/public/index.php
RUN echo '                    showError("Connection failed: " + error.message);' >> /app/public/index.php
RUN echo '                });' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function updateSystemStatus(status) {' >> /app/public/index.php
RUN echo '            const container = document.getElementById("system-status");' >> /app/public/index.php
RUN echo '            container.innerHTML = `' >> /app/public/index.php
RUN echo '                <div class="device-item">' >> /app/public/index.php
RUN echo '                    <span>Status</span>' >> /app/public/index.php
RUN echo '                    <span><span class="status-indicator status-online"></span>Online</span>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '                <div class="device-item">' >> /app/public/index.php
RUN echo '                    <span>Uptime</span>' >> /app/public/index.php
RUN echo '                    <span>${status.uptime || "Unknown"}</span>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '                <div class="device-item">' >> /app/public/index.php
RUN echo '                    <span>Load Average</span>' >> /app/public/index.php
RUN echo '                    <span>${status.load_average || "0.00"}</span>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '            `;' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function updateNetworkDevices(devices) {' >> /app/public/index.php
RUN echo '            const container = document.getElementById("network-devices");' >> /app/public/index.php
RUN echo '            if (!devices || devices.length === 0) {' >> /app/public/index.php
RUN echo '                container.innerHTML = "<p>No devices detected</p>";' >> /app/public/index.php
RUN echo '                return;' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '            let html = "<div class=\"device-list\">";' >> /app/public/index.php
RUN echo '            devices.forEach(device => {' >> /app/public/index.php
RUN echo '                const statusClass = device.status === "online" ? "status-online" : "status-offline";' >> /app/public/index.php
RUN echo '                html += `' >> /app/public/index.php
RUN echo '                    <div class="device-item">' >> /app/public/index.php
RUN echo '                        <span>' >> /app/public/index.php
RUN echo '                            <span class="status-indicator ${statusClass}"></span>' >> /app/public/index.php
RUN echo '                            ${device.ip || "Unknown"}' >> /app/public/index.php
RUN echo '                        </span>' >> /app/public/index.php
RUN echo '                        <span>${device.hostname || device.mac || "N/A"}</span>' >> /app/public/index.php
RUN echo '                    </div>' >> /app/public/index.php
RUN echo '                `;' >> /app/public/index.php
RUN echo '            });' >> /app/public/index.php
RUN echo '            html += "</div>";' >> /app/public/index.php
RUN echo '            container.innerHTML = html;' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function updateNetworkTraffic(traffic) {' >> /app/public/index.php
RUN echo '            const container = document.getElementById("network-traffic");' >> /app/public/index.php
RUN echo '            container.innerHTML = `' >> /app/public/index.php
RUN echo '                <div class="device-item">' >> /app/public/index.php
RUN echo '                    <span>Interface</span>' >> /app/public/index.php
RUN echo '                    <span>${traffic.interface || "Unknown"}</span>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '                <div class="device-item">' >> /app/public/index.php
RUN echo '                    <span>Total Traffic</span>' >> /app/public/index.php
RUN echo '                    <span>${formatBytes(traffic.total_bytes || 0)}</span>' >> /app/public/index.php
RUN echo '                </div>' >> /app/public/index.php
RUN echo '            `;' >> /app/public/index.php
RUN echo '            document.getElementById("rx-value").textContent = formatBytes(traffic.rx_bytes || 0);' >> /app/public/index.php
RUN echo '            document.getElementById("tx-value").textContent = formatBytes(traffic.tx_bytes || 0);' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function updateSecurityAlerts(alerts) {' >> /app/public/index.php
RUN echo '            const container = document.getElementById("security-alerts");' >> /app/public/index.php
RUN echo '            if (!alerts || alerts.length === 0) {' >> /app/public/index.php
RUN echo '                container.innerHTML = "<p style=\"color: #38a169;\">✅ No security alerts</p>";' >> /app/public/index.php
RUN echo '                return;' >> /app/public/index.php
RUN echo '            }' >> /app/public/index.php
RUN echo '            let html = "<div class=\"device-list\">";' >> /app/public/index.php
RUN echo '            alerts.forEach(alert => {' >> /app/public/index.php
RUN echo '                const severityColor = alert.severity === "high" ? "#e53e3e" : "#ed8936";' >> /app/public/index.php
RUN echo '                html += `' >> /app/public/index.php
RUN echo '                    <div class="device-item" style="color: ${severityColor};">' >> /app/public/index.php
RUN echo '                        <span>${alert.type}: ${alert.ip}</span>' >> /app/public/index.php
RUN echo '                        <span>Count: ${alert.count}</span>' >> /app/public/index.php
RUN echo '                    </div>' >> /app/public/index.php
RUN echo '                `;' >> /app/public/index.php
RUN echo '            });' >> /app/public/index.php
RUN echo '            html += "</div>";' >> /app/public/index.php
RUN echo '            container.innerHTML = html;' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function scanNetwork() {' >> /app/public/index.php
RUN echo '            const btn = document.getElementById("scan-btn");' >> /app/public/index.php
RUN echo '            btn.disabled = true;' >> /app/public/index.php
RUN echo '            btn.textContent = "🔍 Scanning...";' >> /app/public/index.php
RUN echo '            ' >> /app/public/index.php
RUN echo '            fetch("/?action=scan", { method: "GET", headers: { "Accept": "application/json" } })' >> /app/public/index.php
RUN echo '                .then(response => {' >> /app/public/index.php
RUN echo '                    if (!response.ok) throw new Error(`HTTP ${response.status}`);' >> /app/public/index.php
RUN echo '                    return response.json();' >> /app/public/index.php
RUN echo '                })' >> /app/public/index.php
RUN echo '                .then(data => {' >> /app/public/index.php
RUN echo '                    if (data.success) {' >> /app/public/index.php
RUN echo '                        updateNetworkDevices(data.data.devices);' >> /app/public/index.php
RUN echo '                        showSuccess("Network scan completed");' >> /app/public/index.php
RUN echo '                    } else {' >> /app/public/index.php
RUN echo '                        showError("Scan failed: " + (data.error || "Unknown error"));' >> /app/public/index.php
RUN echo '                    }' >> /app/public/index.php
RUN echo '                })' >> /app/public/index.php
RUN echo '                .catch(error => {' >> /app/public/index.php
RUN echo '                    console.error("Scan error:", error);' >> /app/public/index.php
RUN echo '                    showError("Scan failed: " + error.message);' >> /app/public/index.php
RUN echo '                })' >> /app/public/index.php
RUN echo '                .finally(() => {' >> /app/public/index.php
RUN echo '                    btn.disabled = false;' >> /app/public/index.php
RUN echo '                    btn.textContent = "🔍 Scan Network";' >> /app/public/index.php
RUN echo '                });' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function runAnalysis() {' >> /app/public/index.php
RUN echo '            const btn = document.getElementById("analysis-btn");' >> /app/public/index.php
RUN echo '            const container = document.getElementById("network-analysis");' >> /app/public/index.php
RUN echo '            ' >> /app/public/index.php
RUN echo '            btn.disabled = true;' >> /app/public/index.php
RUN echo '            btn.textContent = "🔄 Analyzing...";' >> /app/public/index.php
RUN echo '            container.innerHTML = "<div class=\"loading\">Running comprehensive analysis...</div>";' >> /app/public/index.php
RUN echo '            ' >> /app/public/index.php
RUN echo '            fetch("/?action=analysis", { method: "GET", headers: { "Accept": "application/json" } })' >> /app/public/index.php
RUN echo '                .then(response => {' >> /app/public/index.php
RUN echo '                    if (!response.ok) throw new Error(`HTTP ${response.status}`);' >> /app/public/index.php
RUN echo '                    return response.json();' >> /app/public/index.php
RUN echo '                })' >> /app/public/index.php
RUN echo '                .then(data => {' >> /app/public/index.php
RUN echo '                    if (data.success) {' >> /app/public/index.php
RUN echo '                        let html = "<div class=\"device-list\">";' >> /app/public/index.php
RUN echo '                        ' >> /app/public/index.php
RUN echo '                        if (data.data.nmap && data.data.nmap.hosts) {' >> /app/public/index.php
RUN echo '                            html += `<div class="device-item"><strong>NMAP: ${data.data.nmap.hosts.length} hosts discovered</strong></div>`;' >> /app/public/index.php
RUN echo '                            data.data.nmap.hosts.slice(0, 5).forEach(host => {' >> /app/public/index.php
RUN echo '                                html += `<div class="device-item"><span>📍 ${host}</span></div>`;' >> /app/public/index.php
RUN echo '                            });' >> /app/public/index.php
RUN echo '                        }' >> /app/public/index.php
RUN echo '                        ' >> /app/public/index.php
RUN echo '                        if (data.data.arp && data.data.arp.length > 0) {' >> /app/public/index.php
RUN echo '                            html += `<div class="device-item"><strong>ARP: ${data.data.arp.length} entries</strong></div>`;' >> /app/public/index.php
RUN echo '                        }' >> /app/public/index.php
RUN echo '                        ' >> /app/public/index.php
RUN echo '                        if (data.data.netstat) {' >> /app/public/index.php
RUN echo '                            html += `<div class="device-item"><strong>NETSTAT: ${(data.data.netstat.connections || []).length} connections</strong></div>`;' >> /app/public/index.php
RUN echo '                            html += `<div class="device-item"><strong>LISTENING: ${(data.data.netstat.listening || []).length} ports</strong></div>`;' >> /app/public/index.php
RUN echo '                        }' >> /app/public/index.php
RUN echo '                        ' >> /app/public/index.php
RUN echo '                        if (data.data.traceroute) {' >> /app/public/index.php
RUN echo '                            html += `<div class="device-item"><strong>TRACEROUTE: ${(data.data.traceroute.hops || []).length} hops to ${data.data.traceroute.gateway}</strong></div>`;' >> /app/public/index.php
RUN echo '                        }' >> /app/public/index.php
RUN echo '                        ' >> /app/public/index.php
RUN echo '                        html += `<div class="device-item"><span>Execution Time</span><span>${(data.data.execution_time || 0).toFixed(2)}s</span></div>`;' >> /app/public/index.php
RUN echo '                        html += "</div>";' >> /app/public/index.php
RUN echo '                        ' >> /app/public/index.php
RUN echo '                        container.innerHTML = html;' >> /app/public/index.php
RUN echo '                        showSuccess("Analysis completed successfully");' >> /app/public/index.php
RUN echo '                    } else {' >> /app/public/index.php
RUN echo '                        container.innerHTML = "<p class=\"error\">Analysis failed: " + (data.error || "Unknown error") + "</p>";' >> /app/public/index.php
RUN echo '                        showError("Analysis failed: " + (data.error || "Unknown error"));' >> /app/public/index.php
RUN echo '                    }' >> /app/public/index.php
RUN echo '                })' >> /app/public/index.php
RUN echo '                .catch(error => {' >> /app/public/index.php
RUN echo '                    console.error("Analysis error:", error);' >> /app/public/index.php
RUN echo '                    container.innerHTML = "<p class=\"error\">Analysis failed: " + error.message + "</p>";' >> /app/public/index.php
RUN echo '                    showError("Analysis failed: " + error.message);' >> /app/public/index.php
RUN echo '                })' >> /app/public/index.php
RUN echo '                .finally(() => {' >> /app/public/index.php
RUN echo '                    btn.disabled = false;' >> /app/public/index.php
RUN echo '                    btn.textContent = "🔄 Run Analysis";' >> /app/public/index.php
RUN echo '                });' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function formatBytes(bytes) {' >> /app/public/index.php
RUN echo '            if (bytes === 0) return "0 B";' >> /app/public/index.php
RUN echo '            const k = 1024;' >> /app/public/index.php
RUN echo '            const sizes = ["B", "KB", "MB", "GB", "TB"];' >> /app/public/index.php
RUN echo '            const i = Math.floor(Math.log(bytes) / Math.log(k));' >> /app/public/index.php
RUN echo '            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function showError(message) {' >> /app/public/index.php
RUN echo '            const notification = document.createElement("div");' >> /app/public/index.php
RUN echo '            notification.className = "error";' >> /app/public/index.php
RUN echo '            notification.textContent = message;' >> /app/public/index.php
RUN echo '            document.body.insertBefore(notification, document.body.firstChild);' >> /app/public/index.php
RUN echo '            setTimeout(() => notification.remove(), 5000);' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        function showSuccess(message) {' >> /app/public/index.php
RUN echo '            const notification = document.createElement("div");' >> /app/public/index.php
RUN echo '            notification.className = "success";' >> /app/public/index.php
RUN echo '            notification.textContent = message;' >> /app/public/index.php
RUN echo '            document.body.insertBefore(notification, document.body.firstChild);' >> /app/public/index.php
RUN echo '            setTimeout(() => notification.remove(), 3000);' >> /app/public/index.php
RUN echo '        }' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        document.addEventListener("DOMContentLoaded", function() {' >> /app/public/index.php
RUN echo '            loadDashboard();' >> /app/public/index.php
RUN echo '            refreshInterval = setInterval(loadDashboard, 30000);' >> /app/public/index.php
RUN echo '        });' >> /app/public/index.php
RUN echo '        ' >> /app/public/index.php
RUN echo '        window.addEventListener("beforeunload", function() {' >> /app/public/index.php
RUN echo '            if (refreshInterval) clearInterval(refreshInterval);' >> /app/public/index.php
RUN echo '        });' >> /app/public/index.php
RUN echo '    </script>' >> /app/public/index.php
RUN echo '</body>' >> /app/public/index.php
RUN echo '</html>' >> /app/public/index.php

# Set ownership of the index.php file
RUN chown appuser:appuser /app/public/index.php

# Create nginx configuration
RUN echo 'server {' > /etc/nginx/sites-available/default
RUN echo '    listen 8080 default_server;' >> /etc/nginx/sites-available/default
RUN echo '    server_name _;' >> /etc/nginx/sites-available/default
RUN echo '    root /app/public;' >> /etc/nginx/sites-available/default
RUN echo '    index index.php;' >> /etc/nginx/sites-available/default
RUN echo '    client_max_body_size 50M;' >> /etc/nginx/sites-available/default
RUN echo '    ' >> /etc/nginx/sites-available/default
RUN echo '    location / {' >> /etc/nginx/sites-available/default
RUN echo '        try_files $uri $uri/ /index.php$is_args$args;' >> /etc/nginx/sites-available/default
RUN echo '    }' >> /etc/nginx/sites-available/default
RUN echo '    ' >> /etc/nginx/sites-available/default
RUN echo '    location ~ \.php$ {' >> /etc/nginx/sites-available/default
RUN echo '        include fastcgi_params;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_pass 127.0.0.1:9000;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_index index.php;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_read_timeout 300;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_send_timeout 300;' >> /etc/nginx/sites-available/default
RUN echo '        fastcgi_connect_timeout 300;' >> /etc/nginx/sites-available/default
RUN echo '    }' >> /etc/nginx/sites-available/default
RUN echo '    ' >> /etc/nginx/sites-available/default
RUN echo '    location ~ /\.ht {' >> /etc/nginx/sites-available/default
RUN echo '        deny all;' >> /etc/nginx/sites-available/default
RUN echo '    }' >> /etc/nginx/sites-available/default
RUN echo '}' >> /etc/nginx/sites-available/default

# Create PHP-FPM pool configuration
RUN echo '[www]' > /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'user = appuser' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'group = appuser' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'listen = 127.0.0.1:9000' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'listen.owner = appuser' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'listen.group = appuser' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'pm = dynamic' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'pm.max_children = 20' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'pm.start_servers = 3' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'pm.min_spare_servers = 2' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'pm.max_spare_servers = 6' >> /etc/php/8.1/fpm/pool.d/www.conf
RUN echo 'request_terminate_timeout = 300' >> /etc/php/8.1/fpm/pool.d/www.conf

# Configure PHP settings for better performance and timeout handling
RUN echo 'max_execution_time = 300' >> /etc/php/8.1/fpm/php.ini
RUN echo 'memory_limit = 256M' >> /etc/php/8.1/fpm/php.ini
RUN echo 'post_max_size = 50M' >> /etc/php/8.1/fpm/php.ini
RUN echo 'upload_max_filesize = 50M' >> /etc/php/8.1/fpm/php.ini
RUN echo 'max_input_time = 300' >> /etc/php/8.1/fpm/php.ini

# Create supervisor configuration
RUN echo '[supervisord]' > /etc/supervisor/conf.d/supervisord.conf
RUN echo 'nodaemon=true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'logfile=/var/log/supervisor/supervisord.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'pidfile=/var/run/supervisord.pid' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'user=root' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo '' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo '[program:nginx]' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'command=/usr/sbin/nginx -g "daemon off;"' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'autostart=true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'autorestart=true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'stdout_logfile=/var/log/supervisor/nginx.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'stderr_logfile=/var/log/supervisor/nginx_error.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'priority=10' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo '' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo '[program:php-fpm]' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'command=/usr/sbin/php-fpm8.1 -F' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'autostart=true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'autorestart=true' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'stdout_logfile=/var/log/supervisor/php-fpm.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'stderr_logfile=/var/log/supervisor/php-fpm_error.log' >> /etc/supervisor/conf.d/supervisord.conf
RUN echo 'priority=20' >> /etc/supervisor/conf.d/supervisord.conf

# Create startup script
RUN echo '#!/bin/bash' > /app/start.sh
RUN echo 'set -e' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo 'echo "===== Network Security App Starting ====="' >> /app/start.sh
RUN echo 'echo "Author: Hirotoshi Uchida"' >> /app/start.sh
RUN echo 'echo "Homepage: https://hirotoshiuchida.onrender.com"' >> /app/start.sh
RUN echo 'echo "========================================"' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Wait for system initialization' >> /app/start.sh
RUN echo 'sleep 3' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Create necessary directories' >> /app/start.sh
RUN echo 'mkdir -p /var/log/supervisor' >> /app/start.sh
RUN echo 'mkdir -p /var/run' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Set proper permissions' >> /app/start.sh
RUN echo 'chown -R appuser:appuser /app/public' >> /app/start.sh
RUN echo 'chmod -R 755 /app/public' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Test PHP-FPM configuration' >> /app/start.sh
RUN echo 'php-fpm8.1 -t' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Test nginx configuration' >> /app/start.sh
RUN echo 'nginx -t' >> /app/start.sh
RUN echo '' >> /app/start.sh
RUN echo '# Start supervisor with all services' >> /app/start.sh
RUN echo 'echo "Starting services..."' >> /app/start.sh
RUN echo 'exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf' >> /app/start.sh

# Make startup script executable
RUN chmod +x /app/start.sh

# Create health check script
RUN echo '#!/bin/bash' > /app/health-check.sh
RUN echo 'if ! pgrep -f "php-fpm" > /dev/null; then echo "PHP-FPM not running"; exit 1; fi' >> /app/health-check.sh
RUN echo 'if ! pgrep -f "nginx" > /dev/null; then echo "Nginx not running"; exit 1; fi' >> /app/health-check.sh
RUN echo 'if ! curl -f -s http://127.0.0.1:8080/?action=health > /dev/null; then echo "Health check failed"; exit 1; fi' >> /app/health-check.sh
RUN echo 'echo "Services healthy"; exit 0' >> /app/health-check.sh
RUN chmod +x /app/health-check.sh

# Set proper permissions and ownership
RUN chown -R appuser:appuser /app \
    && chown -R appuser:appuser /var/log/supervisor \
    && chmod -R 755 /app \
    && chmod -R 755 /var/log/supervisor

# Remove default nginx site and enable our configuration
RUN rm -f /etc/nginx/sites-enabled/default
RUN ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /app/health-check.sh

# Set environment variables
ENV PATH="/app:${PATH}"
ENV NGINX_PORT=8080
ENV PHP_FPM_PORT=9000

# Default command
CMD ["/app/start.sh"]

# Labels
LABEL maintainer="Hirotoshi Uchida <contact.hirotoshiuchida@gmail.com>"
LABEL description="Network Security Monitoring Application"
LABEL version="1.0.0"
LABEL homepage="https://hirotoshiuchida.onrender.com"
