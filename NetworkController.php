<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Collection;

class NetworkController extends Controller
{
    private $networkInterface;
    private $scanResults;
    
    public function __construct()
    {
        $this->networkInterface = $this->detectNetworkInterface();
        $this->scanResults = collect();
    }
    
    /**
     * Main dashboard endpoint
     */
    public function dashboard(Request $request): JsonResponse
    {
        try {
            $data = [
                'devices' => $this->getActiveDevices(),
                'traffic' => $this->getNetworkTraffic(),
                'security_events' => $this->getSecurityEvents(),
                'system_status' => $this->getSystemStatus(),
                'topology' => $this->getNetworkTopology(),
                'alerts' => $this->getSecurityAlerts()
            ];
            
            return response()->json([
                'success' => true,
                'data' => $data,
                'timestamp' => now()->toISOString()
            ]);
            
        } catch (\Exception $e) {
            Log::error('Dashboard error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'error' => 'Failed to load dashboard data'
            ], 500);
        }
    }
    
    /**
     * Network scan endpoint
     */
    public function networkScan(Request $request): JsonResponse
    {
        try {
            $networkRange = $request->input('range', $this->getNetworkRange());
            $scanType = $request->input('type', 'quick');
            
            $scanResults = $this->performNetworkScan($networkRange, $scanType);
            
            Cache::put('network_scan_' . md5($networkRange), $scanResults, 300);
            
            return response()->json([
                'success' => true,
                'data' => $scanResults,
                'scan_type' => $scanType,
                'network_range' => $networkRange,
                'timestamp' => now()->toISOString()
            ]);
            
        } catch (\Exception $e) {
            Log::error('Network scan error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'error' => 'Network scan failed'
            ], 500);
        }
    }
    
    /**
     * Real-time traffic monitoring
     */
    public function trafficMonitor(Request $request): JsonResponse
    {
        try {
            $interface = $request->input('interface', $this->networkInterface);
            $duration = $request->input('duration', 60);
            
            $trafficData = $this->monitorTraffic($interface, $duration);
            
            return response()->json([
                'success' => true,
                'data' => $trafficData,
                'interface' => $interface,
                'duration' => $duration,
                'timestamp' => now()->toISOString()
            ]);
            
        } catch (\Exception $e) {
            Log::error('Traffic monitor error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'error' => 'Traffic monitoring failed'
            ], 500);
        }
    }
    
    /**
     * Device details endpoint
     */
    public function deviceDetails(Request $request, $ip): JsonResponse
    {
        try {
            $deviceInfo = $this->getDeviceDetails($ip);
            
            return response()->json([
                'success' => true,
                'data' => $deviceInfo,
                'ip' => $ip,
                'timestamp' => now()->toISOString()
            ]);
            
        } catch (\Exception $e) {
            Log::error('Device details error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'error' => 'Failed to get device details'
            ], 500);
        }
    }
    
    /**
     * Security monitoring endpoint
     */
    public function securityMonitor(Request $request): JsonResponse
    {
        try {
            $alerts = $this->monitorSecurity();
            
            return response()->json([
                'success' => true,
                'data' => $alerts,
                'timestamp' => now()->toISOString()
            ]);
            
        } catch (\Exception $e) {
            Log::error('Security monitor error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'error' => 'Security monitoring failed'
            ], 500);
        }
    }
    
    /**
     * Perform comprehensive network scan using multiple tools
     */
    private function performNetworkScan($networkRange, $scanType): array
    {
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
        $results['devices'] = collect($results['devices'])
            ->unique('ip')
            ->sortBy('ip')
            ->values()
            ->toArray();
        
        return $results;
    }
    
    /**
     * Scan individual device for detailed information
     */
    private function scanDevice($ip, $scanType): array
    {
        $device = [
            'ip' => $ip,
            'mac' => '',
            'hostname' => '',
            'os' => '',
            'ports' => [],
            'services' => [],
            'last_seen' => now()->toISOString(),
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
    
    /**
     * Monitor network traffic using tcpdump and netstat
     */
    private function monitorTraffic($interface, $duration): array
    {
        $trafficData = [
            'interface' => $interface,
            'packets' => [],
            'connections' => [],
            'bandwidth' => 0,
            'protocols' => []
        ];
        
        // Capture packets with tcpdump
        $tcpdumpCommand = "timeout {$duration} tcpdump -i {$interface} -c 100 -n 2>/dev/null";
        $tcpdumpOutput = shell_exec($tcpdumpCommand);
        
        if ($tcpdumpOutput) {
            $trafficData['packets'] = $this->parseTcpdump($tcpdumpOutput);
        }
        
        // Get network statistics
        $netstatCommand = "netstat -i 2>/dev/null";
        $netstatOutput = shell_exec($netstatCommand);
        
        if ($netstatOutput) {
            $trafficData['bandwidth'] = $this->parseNetstat($netstatOutput, $interface);
        }
        
        // Get active connections
        $connectionsCommand = "netstat -tn 2>/dev/null";
        $connectionsOutput = shell_exec($connectionsCommand);
        
        if ($connectionsOutput) {
            $trafficData['connections'] = $this->parseConnections($connectionsOutput);
        }
        
        return $trafficData;
    }
    
    /**
     * Monitor security events and threats
     */
    private function monitorSecurity(): array
    {
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
                'timestamp' => now()->toISOString()
            ];
        }
        
        // Check for port scans
        $portScans = $this->detectPortScans();
        foreach ($portScans as $scan) {
            $alerts[] = [
                'type' => 'port_scan',
                'severity' => 'high',
                'ip' => $scan['source'],
                'description' => "Port scan detected from {$scan['source']}",
                'details' => $scan,
                'timestamp' => now()->toISOString()
            ];
        }
        
        // Check for unauthorized devices
        $unauthorizedDevices = $this->detectUnauthorizedDevices();
        foreach ($unauthorizedDevices as $device) {
            $alerts[] = [
                'type' => 'unauthorized_device',
                'severity' => 'medium',
                'ip' => $device['ip'],
                'mac' => $device['mac'],
                'description' => "Unauthorized device detected: {$device['ip']}",
                'details' => $device,
                'timestamp' => now()->toISOString()
            ];
        }
        
        return $alerts;
    }
    
    /**
     * Get active network devices
     */
    private function getActiveDevices(): array
    {
        $cacheKey = 'active_devices';
        
        return Cache::remember($cacheKey, 60, function () {
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
                    if (!collect($devices)->contains('ip', $ip)) {
                        $devices[] = ['ip' => $ip, 'mac' => '', 'hostname' => '', 'status' => 'online'];
                    }
                }
            }
            
            return $devices;
        });
    }
    
    /**
     * Get network traffic statistics
     */
    private function getNetworkTraffic(): array
    {
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
    
    /**
     * Get security events count
     */
    private function getSecurityEvents(): int
    {
        $alerts = $this->monitorSecurity();
        return count($alerts);
    }
    
    /**
     * Get system status
     */
    private function getSystemStatus(): array
    {
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
    
    /**
     * Get network topology
     */
    private function getNetworkTopology(): array
    {
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
    
    /**
     * Get security alerts
     */
    private function getSecurityAlerts(): array
    {
        return Cache::remember('security_alerts', 30, function () {
            return $this->monitorSecurity();
        });
    }
    
    /**
     * Helper methods for parsing command outputs
     */
    private function parseNmapHostDiscovery($output): array
    {
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
    
    private function parseArpScan($output): array
    {
        $devices = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/([0-9.]+)\s+([0-9a-f:]+)/i', $line, $matches)) {
                $devices[] = [
                    'ip' => $matches[1],
                    'mac' => strtolower($matches[2]),
                    'hostname' => '',
                    'status' => 'online',
                    'last_seen' => now()->toISOString()
                ];
            }
        }
        
        return $devices;
    }
    
    private function parseArpTable($output): array
    {
        $devices = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/\(([0-9.]+)\) at ([0-9a-f:]+)/i', $line, $matches)) {
                $devices[] = [
                    'ip' => $matches[1],
                    'mac' => strtolower($matches[2]),
                    'hostname' => '',
                    'status' => 'online',
                    'last_seen' => now()->toISOString()
                ];
            }
        }
        
        return $devices;
    }
    
    private function parseNmapPorts($output): array
    {
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
    
    private function parseTcpdump($output): array
    {
        $packets = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/(\d+:\d+:\d+\.\d+)\s+IP\s+([0-9.]+)\.(\d+)\s+>\s+([0-9.]+)\.(\d+):\s+(.+)/', $line, $matches)) {
                $packets[] = [
                    'timestamp' => $matches[1],
                    'source_ip' => $matches[2],
                    'source_port' => intval($matches[3]),
                    'dest_ip' => $matches[4],
                    'dest_port' => intval($matches[5]),
                    'protocol' => $this->extractProtocol($matches[6]),
                    'data' => trim($matches[6])
                ];
            }
        }
        
        return $packets;
    }
    
    private function parseNetstat($output, $interface): float
    {
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (strpos($line, $interface) !== false) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 3) {
                    return floatval($parts[2]) / 1024 / 1024; // Convert to MB
                }
            }
        }
        
        return 0.0;
    }
    
    private function parseConnections($output): array
    {
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
    
    private function parseMemInfo($output): array
    {
        $memInfo = ['total' => 0, 'free' => 0, 'available' => 0];
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
    
    private function extractProtocol($data): string
    {
        if (stripos($data, 'HTTP') !== false) return 'HTTP';
        if (stripos($data, 'HTTPS') !== false) return 'HTTPS';
        if (stripos($data, 'FTP') !== false) return 'FTP';
        if (stripos($data, 'SSH') !== false) return 'SSH';
        if (stripos($data, 'DNS') !== false) return 'DNS';
        if (stripos($data, 'SMTP') !== false) return 'SMTP';
        if (stripos($data, 'POP3') !== false) return 'POP3';
        if (stripos($data, 'IMAP') !== false) return 'IMAP';
        return 'TCP';
    }
    
    private function detectSuspiciousActivity(): array
    {
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
    
    private function detectPortScans(): array
    {
        $portScans = [];
        
        // Use netstat to detect multiple connection attempts
        $netstatCommand = "netstat -tn 2>/dev/null";
        $netstatOutput = shell_exec($netstatCommand);
        
        if ($netstatOutput) {
            $connections = $this->parseConnections($netstatOutput);
            $scanAttempts = [];
            
            foreach ($connections as $conn) {
                $key = $conn['remote_ip'];
                if (!isset($scanAttempts[$key])) {
                    $scanAttempts[$key] = [];
                }
                $scanAttempts[$key][] = $conn['local_port'];
            }
            
            foreach ($scanAttempts as $ip => $ports) {
                if (count(array_unique($ports)) > 5) { // Multiple different ports
                    $portScans[] = [
                        'source' => $ip,
                        'ports_scanned' => array_unique($ports),
                        'scan_count' => count($ports)
                    ];
                }
            }
        }
        
        return $portScans;
    }
    
    private function detectUnauthorizedDevices(): array
    {
        $unauthorized = [];
        $knownDevices = Cache::get('known_devices', []);
        $currentDevices = $this->getActiveDevices();
        
        foreach ($currentDevices as $device) {
            $isKnown = false;
            foreach ($knownDevices as $known) {
                if ($known['ip'] === $device['ip'] || $known['mac'] === $device['mac']) {
                    $isKnown = true;
                    break;
                }
            }
            
            if (!$isKnown && !empty($device['mac'])) {
                $unauthorized[] = $device;
            }
        }
        
        return $unauthorized;
    }
    
    private function getDeviceDetails($ip): array
    {
        $device = [
            'ip' => $ip,
            'mac' => '',
            'hostname' => '',
            'os' => '',
            'ports' => [],
            'services' => [],
            'ping_response' => false,
            'traceroute' => [],
            'arp_info' => []
        ];
        
        // Ping test
        $pingCommand = "ping -c 4 -W 1 {$ip} 2>/dev/null";
        $pingOutput = shell_exec($pingCommand);
        $device['ping_response'] = $pingOutput && strpos($pingOutput, '4 received') !== false;
        
        // Traceroute
        $tracerouteCommand = "traceroute -m 10 {$ip} 2>/dev/null";
        $tracerouteOutput = shell_exec($tracerouteCommand);
        if ($tracerouteOutput) {
            $device['traceroute'] = $this->parseTraceroute($tracerouteOutput);
        }
        
        // ARP information
        $arpCommand = "arp -n {$ip} 2>/dev/null";
        $arpOutput = shell_exec($arpCommand);
        if ($arpOutput) {
            $device['arp_info'] = $this->parseArpInfo($arpOutput);
            if (preg_match('/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i', $arpOutput, $matches)) {
                $device['mac'] = $matches[1];
            }
        }
        
        // Detailed port scan
        $nmapCommand = "nmap -sS -O -sV {$ip} 2>/dev/null";
        $nmapOutput = shell_exec($nmapCommand);
        if ($nmapOutput) {
            $device['ports'] = $this->parseNmapPorts($nmapOutput);
            $device['services'] = $this->parseNmapServices($nmapOutput);
            if (preg_match('/Running: (.+)/i', $nmapOutput, $matches)) {
                $device['os'] = trim($matches[1]);
            }
        }
        
        // Hostname resolution
        $hostCommand = "nslookup {$ip} 2>/dev/null";
        $hostOutput = shell_exec($hostCommand);
        if ($hostOutput && preg_match('/name = (.+)\./', $hostOutput, $matches)) {
            $device['hostname'] = trim($matches[1]);
        }
        
        return $device;
    }
    
    private function parseTraceroute($output): array
    {
        $hops = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/^\s*(\d+)\s+([^\s]+)\s+\(([0-9.]+)\)\s+([0-9.]+)\s*ms/', $line, $matches)) {
                $hops[] = [
                    'hop' => intval($matches[1]),
                    'hostname' => $matches[2],
                    'ip' => $matches[3],
                    'rtt' => floatval($matches[4])
                ];
            }
        }
        
        return $hops;
    }
    
    private function parseArpInfo($output): array
    {
        $info = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/([0-9.]+)\s+ether\s+([0-9a-f:]+)\s+(\w+)\s+(.+)/', $line, $matches)) {
                $info = [
                    'ip' => $matches[1],
                    'mac' => $matches[2],
                    'flags' => $matches[3],
                    'interface' => trim($matches[4])
                ];
            }
        }
        
        return $info;
    }
    
    private function parseNmapServices($output): array
    {
        $services = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            if (preg_match('/(\d+)\/tcp\s+open\s+(\w+)\s+(.+)/', $line, $matches)) {
                $services[] = [
                    'port' => intval($matches[1]),
                    'service' => $matches[2],
                    'version' => trim($matches[3])
                ];
            }
        }
        
        return $services;
    }
    
    private function detectNetworkInterface(): string
    {
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
    
    private function getNetworkRange(): string
    {
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
    
    private function getGateway(): string
    {
        $routeCommand = "ip route | grep default 2>/dev/null";
        $routeOutput = shell_exec($routeCommand);
        
        if ($routeOutput && preg_match('/default via ([0-9.]+)/', $routeOutput, $matches)) {
            return $matches[1];
        }
        
        return '192.168.1.1'; // Default fallback
    }
    
    /**
     * WebSocket endpoint for real-time updates
     */
    public function websocketData(Request $request): JsonResponse
    {
        try {
            $type = $request->input('type', 'dashboard');
            $data = [];
            
            switch ($type) {
                case 'traffic':
                    $data = $this->getNetworkTraffic();
                    break;
                case 'devices':
                    $data = $this->getActiveDevices();
                    break;
                case 'alerts':
                    $data = $this->getSecurityAlerts();
                    break;
                default:
                    $data = [
                        'devices' => $this->getActiveDevices(),
                        'traffic' => $this->getNetworkTraffic(),
                        'alerts' => $this->getSecurityAlerts()
                    ];
            }
            
            return response()->json([
                'success' => true,
                'type' => $type,
                'data' => $data,
                'timestamp' => now()->toISOString()
            ]);
            
        } catch (\Exception $e) {
            Log::error('WebSocket data error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'error' => 'Failed to get real-time data'
            ], 500);
        }
    }
}
