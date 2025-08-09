<?php
// Network Security App - Optimized for Render.com
// Author: Hirotoshi Uchida
// Homepage: https://hirotoshiuchida.onrender.com

error_reporting(E_ERROR | E_WARNING);
ini_set('display_errors', 0);
set_time_limit(60);
ini_set('memory_limit', '512M');

// Enhanced NetworkController class
class NetworkController {
    private $networkInterface;
    private $scanResults;
    private $cacheTimeout = 10; // Cache results for 10 seconds
    private $lastScan = 0;
    
    public function __construct() {
        $this->networkInterface = $this->detectNetworkInterface();
        $this->scanResults = [];
    }
    
    public function dashboard() {
        try {
            $currentTime = time();
            
            // Use cached results if recent scan exists
            if (($currentTime - $this->lastScan) < $this->cacheTimeout && !empty($this->scanResults)) {
                return [
                    "success" => true,
                    "data" => $this->scanResults,
                    "timestamp" => date("c"),
                    "cached" => true
                ];
            }
            
            $data = [
                "devices" => $this->getActiveDevicesQuick(),
                "traffic" => $this->getNetworkTraffic(),
                "security_events" => 0,
                "system_status" => $this->getSystemStatus(),
                "topology" => $this->getNetworkTopology(),
                "alerts" => []
            ];
            
            $this->scanResults = $data;
            $this->lastScan = $currentTime;
            
            return [
                "success" => true,
                "data" => $data,
                "timestamp" => date("c"),
                "cached" => false
            ];
            
        } catch (Exception $e) {
            error_log("Dashboard error: " . $e->getMessage());
            return [
                "success" => false,
                "error" => "Dashboard temporarily unavailable",
                "timestamp" => date("c")
            ];
        }
    }
    
    public function networkScan($networkRange = null, $scanType = "quick") {
        try {
            $networkRange = $networkRange ?: $this->getNetworkRange();
            $scanResults = $this->performNetworkScanOptimized($networkRange, $scanType);
            
            return [
                "success" => true,
                "data" => $scanResults,
                "scan_type" => $scanType,
                "network_range" => $networkRange,
                "timestamp" => date("c")
            ];
            
        } catch (Exception $e) {
            error_log("Network scan error: " . $e->getMessage());
            return [
                "success" => false,
                "error" => "Network scan failed",
                "timestamp" => date("c")
            ];
        }
    }
    
    private function performNetworkScanOptimized($networkRange, $scanType) {
        $results = [
            "devices" => [],
            "ports" => [],
            "services" => [],
            "vulnerabilities" => []
        ];
        
        // Quick ARP scan only for better performance
        $arpCommand = "timeout 30 arp-scan -l 2>/dev/null | head -20";
        $arpOutput = shell_exec($arpCommand);
        
        if ($arpOutput) {
            $arpDevices = $this->parseArpScan($arpOutput);
            $results["devices"] = array_merge($results["devices"], $arpDevices);
        }
        
        // Fallback ARP table check
        $arpTableCommand = "timeout 10 arp -a 2>/dev/null | head -10";
        $arpTableOutput = shell_exec($arpTableCommand);
        
        if ($arpTableOutput) {
            $tableDevices = $this->parseArpTable($arpTableOutput);
            foreach ($tableDevices as $device) {
                $found = false;
                foreach ($results["devices"] as $existing) {
                    if ($existing["ip"] === $device["ip"]) {
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    $results["devices"][] = $device;
                }
            }
        }
        
        // Sort and limit results
        usort($results["devices"], function($a, $b) {
            return ip2long($a["ip"]) - ip2long($b["ip"]);
        });
        
        $results["devices"] = array_slice($results["devices"], 0, 20);
        
        return $results;
    }
    
    private function getActiveDevicesQuick() {
        $devices = [];
        
        // Quick ARP table check
        $arpCommand = "timeout 5 arp -a 2>/dev/null | head -5";
        $arpOutput = shell_exec($arpCommand);
        
        if ($arpOutput) {
            $devices = $this->parseArpTable($arpOutput);
        }
        
        // Add gateway as a device
        $gateway = $this->getGateway();
        if ($gateway && !empty($devices)) {
            $gatewayExists = false;
            foreach ($devices as $device) {
                if ($device["ip"] === $gateway) {
                    $gatewayExists = true;
                    break;
                }
            }
            if (!$gatewayExists) {
                array_unshift($devices, [
                    "ip" => $gateway,
                    "mac" => "",
                    "hostname" => "Gateway",
                    "status" => "online",
                    "last_seen" => date("c")
                ]);
            }
        }
        
        return array_slice($devices, 0, 10);
    }
    
    private function getNetworkTraffic() {
        $interface = $this->networkInterface;
        $rxBytes = 0;
        $txBytes = 0;
        
        $statsCommand = "timeout 2 cat /proc/net/dev 2>/dev/null | grep {$interface}";
        $statsOutput = shell_exec($statsCommand);
        
        if ($statsOutput) {
            $stats = preg_split("/\s+/", trim($statsOutput));
            if (count($stats) >= 10) {
                $rxBytes = intval($stats[1]);
                $txBytes = intval($stats[9]);
            }
        }
        
        return [
            "rx_bytes" => $rxBytes,
            "tx_bytes" => $txBytes,
            "total_bytes" => $rxBytes + $txBytes,
            "interface" => $interface
        ];
    }
    
    private function getSystemStatus() {
        $uptime = shell_exec("timeout 2 uptime 2>/dev/null");
        $loadAvg = shell_exec("timeout 2 cat /proc/loadavg 2>/dev/null");
        
        return [
            "status" => "online",
            "uptime" => trim($uptime ?: "Unknown"),
            "load_average" => trim($loadAvg ?: "0.00 0.00 0.00"),
            "memory_info" => ["total" => 0, "free" => 0, "available" => 0]
        ];
    }
    
    private function getNetworkTopology() {
        $devices = $this->getActiveDevicesQuick();
        $gateway = $this->getGateway();
        
        $topology = [
            "nodes" => [],
            "links" => []
        ];
        
        // Add gateway as central node
        $topology["nodes"][] = [
            "id" => $gateway,
            "label" => "Gateway",
            "type" => "gateway",
            "ip" => $gateway
        ];
        
        // Add devices as nodes (limit to 5 for performance)
        $deviceCount = 0;
        foreach ($devices as $device) {
            if ($device["ip"] !== $gateway && $deviceCount < 5) {
                $topology["nodes"][] = [
                    "id" => $device["ip"],
                    "label" => $device["hostname"] ?: $device["ip"],
                    "type" => "device",
                    "ip" => $device["ip"],
                    "mac" => $device["mac"] ?? ""
                ];
                
                $topology["links"][] = [
                    "source" => $gateway,
                    "target" => $device["ip"]
                ];
                
                $deviceCount++;
            }
        }
        
        return $topology;
    }
    
    // Parser methods
    private function parseArpScan($output) {
        $devices = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match("/([0-9.]+)\s+([0-9a-f:]+)/i", $line, $matches)) {
                $devices[] = [
                    "ip" => $matches[1],
                    "mac" => strtolower($matches[2]),
                    "hostname" => "",
                    "status" => "online",
                    "last_seen" => date("c")
                ];
            }
        }
        
        return $devices;
    }
    
    private function parseArpTable($output) {
        $devices = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match("/\(([0-9.]+)\) at ([0-9a-f:]+)/i", $line, $matches)) {
                $devices[] = [
                    "ip" => $matches[1],
                    "mac" => strtolower($matches[2]),
                    "hostname" => "",
                    "status" => "online",
                    "last_seen" => date("c")
                ];
            }
        }
        
        return $devices;
    }
    
    private function detectNetworkInterface() {
        $routeCommand = "timeout 2 ip route | grep default 2>/dev/null";
        $routeOutput = shell_exec($routeCommand);
        
        if ($routeOutput && preg_match("/dev\s+(\w+)/", $routeOutput, $matches)) {
            return $matches[1];
        }
        
        return "eth0"; // Default fallback
    }
    
    private function getNetworkRange() {
        $routeCommand = "timeout 2 ip route | grep {$this->networkInterface} | grep -v default 2>/dev/null | head -1";
        $routeOutput = shell_exec($routeCommand);
        
        if ($routeOutput && preg_match("/([0-9.]+\/\d+)/", $routeOutput, $matches)) {
            return $matches[1];
        }
        
        return "192.168.1.0/24"; // Default fallback
    }
    
    private function getGateway() {
        $routeCommand = "timeout 2 ip route | grep default 2>/dev/null";
        $routeOutput = shell_exec($routeCommand);
        
        if ($routeOutput && preg_match("/default via ([0-9.]+)/", $routeOutput, $matches)) {
            return $matches[1];
        }
        
        return "192.168.1.1"; // Default fallback
    }
}

// NetworkMonitor class for detailed analysis
class NetworkMonitor {
    private $networkInterface;
    
    public function __construct() {
        $this->networkInterface = $this->detectPrimaryInterface();
    }
    
    public function performNetworkAnalysis() {
        $startTime = microtime(true);
        
        try {
            $nmapResults = $this->executeNmapScanQuick();
            $arpResults = $this->executeArpScanQuick();
            $netstatResults = $this->executeNetstatAnalysisQuick();
            
            return [
                "nmap" => $nmapResults,
                "arp" => $arpResults,
                "netstat" => $netstatResults,
                "execution_time" => microtime(true) - $startTime,
                "timestamp" => date("c"),
                "success" => true
            ];
            
        } catch (Exception $e) {
            error_log("Analysis error: " . $e->getMessage());
            return [
                "error" => "Analysis failed",
                "execution_time" => microtime(true) - $startTime,
                "timestamp" => date("c"),
                "success" => false
            ];
        }
    }
    
    private function executeNmapScanQuick() {
        $range = $this->getNetworkRange();
        $out = shell_exec("timeout 15 nmap -sn {$range} 2>/dev/null | head -10");
        $hosts = $out ? $this->parseNmapHostDiscovery($out) : [];
        
        return [
            "hosts" => array_slice($hosts, 0, 5),
            "services" => [],
            "os_detection" => []
        ];
    }
    
    private function executeArpScanQuick() {
        $out1 = shell_exec("timeout 5 arp -a 2>/dev/null | head -5");
        return $out1 ? array_slice($this->parseArpOutput($out1), 0, 5) : [];
    }
    
    private function executeNetstatAnalysisQuick() {
        $conn = shell_exec("timeout 3 netstat -tn 2>/dev/null | head -10");
        $lstn = shell_exec("timeout 3 netstat -ln 2>/dev/null | head -5");
        
        return [
            "connections" => $conn ? array_slice($this->parseNetstatConnections($conn), 0, 5) : [],
            "listening_ports" => $lstn ? array_slice($this->parseNetstatListening($lstn), 0, 3) : [],
            "interface_stats" => [],
            "routing_table" => []
        ];
    }
    
    private function parseNmapHostDiscovery($output) {
        $hosts = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match("/Nmap scan report for (.+)/", $line, $matches)) {
                $host = trim($matches[1]);
                if (filter_var($host, FILTER_VALIDATE_IP)) {
                    $hosts[] = $host;
                } elseif (preg_match("/\(([0-9.]+)\)/", $host, $ipMatches)) {
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
            if (preg_match("/\(([0-9.]+)\) at ([0-9a-f:]+)/i", $line, $matches)) {
                $devices[] = [
                    "ip" => $matches[1],
                    "mac" => strtolower($matches[2])
                ];
            }
        }
        
        return $devices;
    }
    
    private function parseNetstatConnections($output) {
        $connections = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match("/tcp\s+\d+\s+\d+\s+([0-9.]+):(\d+)\s+([0-9.]+):(\d+)\s+(\w+)/", $line, $matches)) {
                $connections[] = [
                    "local_ip" => $matches[1],
                    "local_port" => intval($matches[2]),
                    "remote_ip" => $matches[3],
                    "remote_port" => intval($matches[4]),
                    "state" => $matches[5]
                ];
            }
        }
        
        return $connections;
    }
    
    private function parseNetstatListening($output) {
        $listening = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match("/tcp\s+\d+\s+\d+\s+([0-9.*]+):(\d+)\s+[0-9.*:]+\s+LISTEN/", $line, $matches)) {
                $listening[] = [
                    "ip" => $matches[1],
                    "port" => intval($matches[2]),
                    "protocol" => "tcp"
                ];
            }
        }
        
        return $listening;
    }
    
    private function detectPrimaryInterface() {
        $out = shell_exec("timeout 2 ip route | grep default");
        if ($out && preg_match("/dev\s+(\w+)/", $out, $m)) {
            return $m[1];
        }
        return "eth0";
    }
    
    private function getNetworkRange() {
        $out = shell_exec("timeout 2 ip route | grep {$this->networkInterface} | grep -v default | head -1");
        if ($out && preg_match("/([0-9\.]+\/\d+)/", $out, $m)) {
            return $m[1];
        }
        return "192.168.1.0/24";
    }
}

// Main application routing and handling
$requestMethod = $_SERVER["REQUEST_METHOD"] ?? "GET";
$requestUri = $_SERVER["REQUEST_URI"] ?? "/";
$pathInfo = parse_url($requestUri, PHP_URL_PATH);

// Initialize controllers
$networkController = new NetworkController();
$networkMonitor = new NetworkMonitor();

// Set proper headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

// API routing with timeout protection
if (str_starts_with($pathInfo, "/api/")) {
    header("Content-Type: application/json");
    
    switch ($pathInfo) {
        case "/api/dashboard":
            echo json_encode($networkController->dashboard());
            break;
            
        case "/api/network-scan":
            $range = $_GET["range"] ?? null;
            $type = $_GET["type"] ?? "quick";
            echo json_encode($networkController->networkScan($range, $type));
            break;
            
        case "/api/analysis":
            echo json_encode($networkMonitor->performNetworkAnalysis());
            break;
            
        case "/api/health-check":
            echo json_encode([
                "success" => true,
                "status" => "healthy",
                "timestamp" => date("c"),
                "version" => "1.0.0"
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(["error" => "API endpoint not found"]);
    }
    exit;
}

// Handle AJAX requests with timeout protection
if (isset($_GET["action"])) {
    header("Content-Type: application/json");
    
    switch ($_GET["action"]) {
        case "dashboard":
            echo json_encode($networkController->dashboard());
            break;
            
        case "scan":
            $range = $_GET["range"] ?? null;
            $type = $_GET["type"] ?? "quick";
            echo json_encode($networkController->networkScan($range, $type));
            break;
            
        case "analysis":
            echo json_encode($networkMonitor->performNetworkAnalysis());
            break;
            
        default:
            echo json_encode(["error" => "Unknown action"]);
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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
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
            margin: 10px 5px 0 0;
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
        
        .chart-container {
            position: relative;
            height: 200px;
            margin-top: 15px;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .metric {
            text-align: center;
            padding: 10px;
            background: #f7fafc;
            border-radius: 5px;
        }
        
        .metric-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: #5a67d8;
        }
        
        .metric-label {
            font-size: 0.8rem;
            color: #718096;
            margin-top: 5px;
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
                <div class="chart-container">
                    <canvas id="trafficChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h3>🚨 Security Status</h3>
                <div id="security-alerts">
                    <div class="loading pulse">Monitoring security events...</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>🔬 Network Analysis</h3>
            <div id="network-analysis">
                <div class="loading pulse">Ready for analysis...</div>
            </div>
            <button class="btn" onclick="runAnalysis()" id="analysis-btn">🔄 Run Analysis</button>
            
            <div class="metrics" id="analysis-metrics" style="display: none;">
                <div class="metric">
                    <div class="metric-value" id="hosts-count">0</div>
                    <div class="metric-label">Hosts Found</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="connections-count">0</div>
                    <div class="metric-label">Connections</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="ports-count">0</div>
                    <div class="metric-label">Open Ports</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="execution-time">0</div>
                    <div class="metric-label">Exec Time (s)</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>&copy; 2024 Hirotoshi Uchida - Network Security App</p>
            <p>Visit: <a href="https://hirotoshiuchida.onrender.com" target="_blank">https://hirotoshiuchida.onrender.com</a></p>
        </div>
    </div>

    <script>
        let refreshInterval;
        let trafficChart;
        let previousTraffic = null;
        let trafficData = {
            labels: [],
            datasets: [{
                label: 'RX Bytes',
                data: [],
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.1)',
                tension: 0.1
            }, {
                label: 'TX Bytes',
                data: [],
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                tension: 0.1
            }]
        };
        
        function initTrafficChart() {
            const ctx = document.getElementById('trafficChart').getContext('2d');
            trafficChart = new Chart(ctx, {
                type: 'line',
                data: trafficData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                callback: function(value) {
                                    return formatBytes(value);
                                }
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top'
                        }
                    }
                }
            });
        }

        function updateTrafficChart(traffic) {
            const now = new Date().toLocaleTimeString();
            let deltaRx = 0;
            let deltaTx = 0;
            if (previousTraffic !== null) {
                deltaRx = Math.max(0, (traffic.rx_bytes || 0) - (previousTraffic.rx_bytes || 0));
                deltaTx = Math.max(0, (traffic.tx_bytes || 0) - (previousTraffic.tx_bytes || 0));
            }
            previousTraffic = {
                rx_bytes: traffic.rx_bytes || 0,
                tx_bytes: traffic.tx_bytes || 0
            };
            if (previousTraffic.rx_bytes > 0 || previousTraffic.tx_bytes > 0) {
                trafficData.labels.push(now);
                trafficData.datasets[0].data.push(deltaRx);
                trafficData.datasets[1].data.push(deltaTx);
                if (trafficData.labels.length > 10) {
                    trafficData.labels.shift();
                    trafficData.datasets[0].data.shift();
                    trafficData.datasets[1].data.shift();
                }
                trafficChart.update('none');
            }
        }
        
        // Load dashboard with error handling and timeout
        function loadDashboard() {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
            
            fetch("/?action=dashboard", { 
                signal: controller.signal,
                headers: {
                    'Cache-Control': 'no-cache'
                }
            })
                .then(response => {
                    clearTimeout(timeoutId);
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        updateSystemStatus(data.data.system_status);
                        updateNetworkDevices(data.data.devices);
                        updateNetworkTraffic(data.data.traffic);
                        updateSecurityAlerts(data.data.alerts);
                        updateTrafficChart(data.data.traffic);
                    } else {
                        showError("Dashboard data unavailable");
                    }
                })
                .catch(error => {
                    clearTimeout(timeoutId);
                    console.error("Dashboard error:", error.name === 'AbortError' ? 'Request timeout' : error.message);
                    showError("Dashboard connection timeout");
                });
        }
        
        function updateSystemStatus(status) {
            const container = document.getElementById("system-status");
            container.innerHTML = `
                <div class="device-item">
                    <span>Status</span>
                    <span><span class="status-indicator status-online"></span>Online</span>
                </div>
                <div class="device-item">
                    <span>Uptime</span>
                    <span>${(status.uptime || "Unknown").substring(0, 50)}</span>
                </div>
                <div class="device-item">
                    <span>Load Average</span>
                    <span>${(status.load_average || "0.00").split(' ')[0]}</span>
                </div>
            `;
        }
        
        function updateNetworkDevices(devices) {
            const container = document.getElementById("network-devices");
            if (!devices || devices.length === 0) {
                container.innerHTML = "<p>No devices detected</p>";
                return;
            }
            let html = "<div class=\"device-list\">";
            devices.forEach(device => {
                const statusClass = device.status === "online" ? "status-online" : "status-offline";
                const displayName = device.hostname || device.mac || "Unknown";
                html += `
                    <div class="device-item">
                        <span>
                            <span class="status-indicator ${statusClass}"></span>
                            ${device.ip}
                        </span>
                        <span>${displayName.substring(0, 20)}</span>
                    </div>
                `;
            });
            html += "</div>";
            container.innerHTML = html;
        }
        
        // Global variables for traffic display delta calculation
        let previousDisplayTraffic = null;
        function updateNetworkTraffic(traffic) {
            const container = document.getElementById("network-traffic");
            // Calculate delta for display
            let deltaRxDisplay = traffic.rx_bytes || 0;
            let deltaTxDisplay = traffic.tx_bytes || 0;
            if (previousDisplayTraffic !== null) {
                deltaRxDisplay = Math.max(0, (traffic.rx_bytes || 0) - (previousDisplayTraffic.rx_bytes || 0));
                deltaTxDisplay = Math.max(0, (traffic.tx_bytes || 0) - (previousDisplayTraffic.tx_bytes || 0));
            }
            // Update previous values
            previousDisplayTraffic = {
                rx_bytes: traffic.rx_bytes || 0,
                tx_bytes: traffic.tx_bytes || 0
    
            };
            container.innerHTML = `
                <div class="device-item">
                    <span>Interface</span>
                    <span>${traffic.interface || "Unknown"}</span>
                </div>
                <div class="device-item">
                    <span>RX Bytes</span>
                    <span>${formatBytes(deltaRxDisplay)}</span>
                </div>
                <div class="device-item">
                    <span>TX Bytes</span>
                    <span>${formatBytes(deltaTxDisplay)}</span>
                </div>
            `;
        }
        
        function updateSecurityAlerts(alerts) {
            const container = document.getElementById("security-alerts");
            if (!alerts || alerts.length === 0) {
                container.innerHTML = "<p style=\"color: #38a169;\">✅ No security alerts</p>";
                return;
            }
            
            let html = "<div class=\"device-list\">";
            alerts.slice(0, 5).forEach(alert => {
                const severityColor = alert.severity === "high" ? "#e53e3e" : "#ed8936";
                html += `
                    <div class="device-item" style="color: ${severityColor};">
                        <span>${alert.type}</span>
                        <span>${alert.severity}</span>
                    </div>
                `;
            });
            html += "</div>";
            container.innerHTML = html;
        }
        
        function scanNetwork() {
            const btn = document.getElementById("scan-btn");
            btn.disabled = true;
            btn.textContent = "🔍 Scanning...";
            
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout
            
            fetch("/?action=scan", { 
                signal: controller.signal,
                headers: {
                    'Cache-Control': 'no-cache'
                }
            })
                .then(response => {
                    clearTimeout(timeoutId);
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        updateNetworkDevices(data.data.devices);
                        showSuccess("Network scan completed");
                    } else {
                        showError("Network scan failed");
                    }
                })
                .catch(error => {
                    clearTimeout(timeoutId);
                    console.error("Scan error:", error.name === 'AbortError' ? 'Request timeout' : error.message);
                    showError("Network scan timeout");
                })
                .finally(() => {
                    btn.disabled = false;
                    btn.textContent = "🔍 Scan Network";
                });
        }
        
        function runAnalysis() {
            const btn = document.getElementById("analysis-btn");
            const container = document.getElementById("network-analysis");
            const metrics = document.getElementById("analysis-metrics");
            
            btn.disabled = true;
            btn.textContent = "🔄 Analyzing...";
            container.innerHTML = "<div class=\"loading pulse\">Running analysis...</div>";
            metrics.style.display = "none";
            
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 20000); // 20 second timeout
            
            fetch("/?action=analysis", { 
                signal: controller.signal,
                headers: {
                    'Cache-Control': 'no-cache'
                }
            })
                .then(response => {
                    clearTimeout(timeoutId);
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success !== false) {
                        let html = "<div class=\"device-list\">";
                        
                        // NMAP Results
                        const hostCount = (data.nmap && data.nmap.hosts) ? data.nmap.hosts.length : 0;
                        if (hostCount > 0) {
                            html += `<div class="device-item"><strong>Discovered Hosts: ${hostCount}</strong></div>`;
                            data.nmap.hosts.forEach(host => {
                                html += `<div class="device-item"><span>📍 ${host}</span></div>`;
                            });
                        }
                        
                        // ARP Results
                        const arpCount = data.arp ? data.arp.length : 0;
                        if (arpCount > 0) {
                            html += `<div class="device-item"><strong>ARP Entries: ${arpCount}</strong></div>`;
                        }
                        
                        // Netstat Results
                        const connCount = (data.netstat && data.netstat.connections) ? data.netstat.connections.length : 0;
                        const portCount = (data.netstat && data.netstat.listening_ports) ? data.netstat.listening_ports.length : 0;
                        if (connCount > 0) {
                            html += `<div class="device-item"><strong>Active Connections: ${connCount}</strong></div>`;
                        }
                        
                        html += `<div class="device-item"><span>Execution Time</span><span>${(data.execution_time || 0).toFixed(2)}s</span></div>`;
                        html += "</div>";
                        
                        container.innerHTML = html;
                        
                        // Update metrics
                        document.getElementById("hosts-count").textContent = hostCount;
                        document.getElementById("connections-count").textContent = connCount;
                        document.getElementById("ports-count").textContent = portCount;
                        document.getElementById("execution-time").textContent = (data.execution_time || 0).toFixed(2);
                        metrics.style.display = "grid";
                        
                        showSuccess("Network analysis completed");
                    } else {
                        throw new Error("Analysis failed");
                    }
                })
                .catch(error => {
                    clearTimeout(timeoutId);
                    console.error("Analysis error:", error.name === 'AbortError' ? 'Request timeout' : error.message);
                    container.innerHTML = "<p class=\"error\">Analysis timeout or failed</p>";
                    showError("Network analysis timeout");
                })
                .finally(() => {
                    btn.disabled = false;
                    btn.textContent = "🔄 Run Analysis";
                });
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return "0 B";
            const k = 1024;
            const sizes = ["B", "KB", "MB", "GB", "TB"];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
        }
        
        function showError(message) {
            const notification = document.createElement("div");
            notification.className = "error";
            notification.textContent = message;
            document.body.insertBefore(notification, document.body.firstChild);
            setTimeout(() => notification.remove(), 5000);
        }
        
        function showSuccess(message) {
            const notification = document.createElement("div");
            notification.className = "success";
            notification.textContent = message;
            document.body.insertBefore(notification, document.body.firstChild);
            setTimeout(() => notification.remove(), 3000);
        }
        
        // Initialize
        document.addEventListener("DOMContentLoaded", function() {
            initTrafficChart();
            loadDashboard();
            // Reduced refresh interval to prevent timeouts
            refreshInterval = setInterval(loadDashboard, 60000); // Refresh every 60 seconds
        });
        
        // Cleanup on page unload
        window.addEventListener("beforeunload", function() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        });
    </script>
</body>
</html>
