<?hh // strict

/**
 * Network Security Monitor for HHVM
 * Real-time network monitoring and security analysis
 * 
 * @author Hirotoshi Uchida
 * @version 1.0.0
 */

namespace NetworkSecurity;

use HH\Lib\{C, Dict, Keyset, Math, Regex, Str, Vec};

class NetworkMonitor {
    
    private string $networkInterface;
    private dict<string, mixed> $deviceCache;
    private vec<dict<string, mixed>> $securityEvents;
    private float $lastScanTime;
    
    public function __construct(): void {
        $this->networkInterface = $this->detectPrimaryInterface();
        $this->deviceCache = dict[];
        $this->securityEvents = vec[];
        $this->lastScanTime = 0.0;
    }
    
    /**
     * Perform comprehensive network discovery and analysis
     */
    public async function performNetworkAnalysis(): Awaitable<dict<string, mixed>> {
        $startTime = \microtime(true);
        
        // Parallel execution of network discovery tools
        $nmapTask = $this->executeNmapScan();
        $arpTask = $this->executeArpScan();
        $netstatTask = $this->executeNetstatAnalysis();
        $tcpdumpTask = $this->executeTcpdumpCapture();
        
        // Wait for all tasks to complete
        concurrent {
            $nmapResults = await $nmapTask;
            $arpResults = await $arpTask;
            $netstatResults = await $netstatTask;
            $tcpdumpResults = await $tcpdumpTask;
        }
        
        // Merge and analyze results
        $analysisResults = $this->mergeNetworkData(
            $nmapResults,
            $arpResults,
            $netstatResults,
            $tcpdumpResults
        );
        
        $analysisResults['execution_time'] = \microtime(true) - $startTime;
        $analysisResults['timestamp'] = \date('c');
        
        return $analysisResults;
    }
    
    /**
     * Execute Nmap network scan with multiple techniques
     */
    private async function executeNmapScan(): Awaitable<dict<string, mixed>> {
        $networkRange = await $this->getNetworkRange();
        $results = dict['hosts' => vec[], 'services' => dict[], 'os_detection' => dict[]];
        
        // Host discovery scan
        $hostDiscoveryCmd = \sprintf('nmap -sn %s 2>/dev/null', \escapeshellarg($networkRange));
        $hostDiscoveryOutput = await $this->executeShellCommand($hostDiscoveryCmd);
        
        if ($hostDiscoveryOutput !== null) {
            $discoveredHosts = $this->parseNmapHostDiscovery($hostDiscoveryOutput);
            $results['hosts'] = $discoveredHosts;
            
            // Detailed scan for each discovered host
            foreach ($discoveredHosts as $host) {
                $hostDetails = await $this->performDetailedHostScan($host);
                $results['services'][$host] = $hostDetails['services'];
                $results['os_detection'][$host] = $hostDetails['os_info'];
            }
        }
        
        return $results;
    }
    
    /**
     * Execute ARP scan for local network discovery
     */
    private async function executeArpScan(): Awaitable<vec<dict<string, string>>> {
        $devices = vec[];
        
        // Try arp-scan first, fallback to arp -a
        $arpScanCmd = 'arp-scan -l 2>/dev/null || arp -a 2>/dev/null';
        $arpOutput = await $this->executeShellCommand($arpScanCmd);
        
        if ($arpOutput !== null) {
            $devices = $this->parseArpOutput($arpOutput);
        }
        
        // Additional ARP table analysis
        $arpTableCmd = 'cat /proc/net/arp 2>/dev/null';
        $arpTableOutput = await $this->executeShellCommand($arpTableCmd);
        
        if ($arpTableOutput !== null) {
            $arpTableDevices = $this->parseArpTable($arpTableOutput);
            $devices = Vec\concat($devices, $arpTableDevices);
        }
        
        return Vec\unique_by($devices, $device ==> $device['ip']);
    }
    
    /**
     * Execute comprehensive network statistics analysis
     */
    private async function executeNetstatAnalysis(): Awaitable<dict<string, mixed>> {
        $results = dict[
            'connections' => vec[],
            'listening_ports' => vec[],
            'interface_stats' => dict[],
            'routing_table' => vec[]
        ];
        
        // Active connections
        $connectionsCmd = 'netstat -tn 2>/dev/null';
        $connectionsOutput = await $this->executeShellCommand($connectionsCmd);
        if ($connectionsOutput !== null) {
            $results['connections'] = $this->parseNetstatConnections($connectionsOutput);
        }
        
        // Listening ports
        $listeningCmd = 'netstat -ln 2>/dev/null';
        $listeningOutput = await $this->executeShellCommand($listeningCmd);
        if ($listeningOutput !== null) {
            $results['listening_ports'] = $this->parseNetstatListening($listeningOutput);
        }
        
        // Interface statistics
        $interfaceCmd = 'netstat -i 2>/dev/null';
        $interfaceOutput = await $this->executeShellCommand($interfaceCmd);
        if ($interfaceOutput !== null) {
            $results['interface_stats'] = $this->parseNetstatInterface($interfaceOutput);
        }
        
        // Routing table
        $routeCmd = 'netstat -rn 2>/dev/null';
        $routeOutput = await $this->executeShellCommand($routeCmd);
        if ($routeOutput !== null) {
            $results['routing_table'] = $this->parseNetstatRoute($routeOutput);
        }
        
        return $results;
    }
    
    /**
     * Execute tcpdump packet capture and analysis
     */
    private async function executeTcpdumpCapture(): Awaitable<dict<string, mixed>> {
        $results = dict[
            'packets' => vec[],
            'protocols' => dict[],
            'traffic_patterns' => dict[]
        ];
        
        $interface = $this->networkInterface;
        $captureCmd = \sprintf(
            'timeout 30 tcpdump -i %s -c 200 -n -q 2>/dev/null',
            \escapeshellarg($interface)
        );
        
        $captureOutput = await $this->executeShellCommand($captureCmd);
        
        if ($captureOutput !== null) {
            $packets = $this->parseTcpdumpOutput($captureOutput);
            $results['packets'] = $packets;
            $results['protocols'] = $this->analyzeProtocolDistribution($packets);
            $results['traffic_patterns'] = $this->analyzeTrafficPatterns($packets);
        }
        
        return $results;
    }
    
    /**
     * Execute tshark for detailed packet analysis
     */
    private async function executeTsharkAnalysis(): Awaitable<vec<dict<string, mixed>>> {
        $packets = vec[];
        $interface = $this->networkInterface;
        
        $tsharkCmd = \sprintf(
            'timeout 30 tshark -i %s -c 100 -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.protocols 2>/dev/null',
            \escapeshellarg($interface)
        );
        
        $tsharkOutput = await $this->executeShellCommand($tsharkCmd);
        
        if ($tsharkOutput !== null) {
            $packets = $this->parseTsharkOutput($tsharkOutput);
        }
        
        return $packets;
    }
    
    /**
     * Perform detailed host scanning with multiple tools
     */
    private async function performDetailedHostScan(string $host): Awaitable<dict<string, mixed>> {
        $results = dict['services' => vec[], 'os_info' => dict[], 'vulnerabilities' => vec[]];
        
        // Service detection
        $serviceCmd = \sprintf('nmap -sV -F %s 2>/dev/null', \escapeshellarg($host));
        $serviceOutput = await $this->executeShellCommand($serviceCmd);
        if ($serviceOutput !== null) {
            $results['services'] = $this->parseNmapServices($serviceOutput);
        }
        
        // OS detection
        $osCmd = \sprintf('nmap -O %s 2>/dev/null', \escapeshellarg($host));
        $osOutput = await $this->executeShellCommand($osCmd);
        if ($osOutput !== null) {
            $results['os_info'] = $this->parseNmapOSDetection($osOutput);
        }
        
        // Traceroute analysis
        $traceCmd = \sprintf('traceroute -m 15 %s 2>/dev/null', \escapeshellarg($host));
        $traceOutput = await $this->executeShellCommand($traceCmd);
        if ($traceOutput !== null) {
            $results['route_info'] = $this->parseTraceroute($traceOutput);
        }
        
        return $results;
    }
    
    /**
     * Monitor security events and detect threats
     */
    public async function monitorSecurityEvents(): Awaitable<vec<dict<string, mixed>>> {
        $events = vec[];
        
        // Monitor for port scans
        $portScanEvents = await $this->detectPortScans();
        $events = Vec\concat($events, $portScanEvents);
        
        // Monitor for suspicious network activity
        $suspiciousActivity = await $this->detectSuspiciousActivity();
        $events = Vec\concat($events, $suspiciousActivity);
        
        // Monitor for unauthorized devices
        $unauthorizedDevices = await $this->detectUnauthorizedDevices();
        $events = Vec\concat($events, $unauthorizedDevices);
        
        // Monitor for DDoS patterns
        $ddosPatterns = await $this->detectDDoSPatterns();
        $events = Vec\concat($events, $ddosPatterns);
        
        $this->securityEvents = Vec\concat($this->securityEvents, $events);
        
        return $events;
    }
    
    /**
     * Detect potential port scanning activities
     */
    private async function detectPortScans(): Awaitable<vec<dict<string, mixed>>> {
        $portScans = vec[];
        
        $netstatCmd = 'netstat -tn 2>/dev/null | grep SYN_RECV';
        $netstatOutput = await $this->executeShellCommand($netstatCmd);
        
        if ($netstatOutput !== null) {
            $connections = $this->parseNetstatConnections($netstatOutput);
            $ipConnections = Dict\group_by($connections, $conn ==> $conn['remote_ip']);
            
            foreach ($ipConnections as $ip => $conns) {
                if (C\count($conns) > 10) {
                    $portScans[] = dict[
                        'type' => 'port_scan',
                        'severity' => 'high',
                        'source_ip' => $ip,
                        'target_ports' => Vec\map($conns, $conn ==> $conn['local_port']),
                        'timestamp' => \date('c'),
                        'description' => \sprintf('Port scan detected from %s', $ip)
                    ];
                }
            }
        }
        
        return $portScans;
    }
    
    /**
     * Detect suspicious network activity patterns
     */
    private async function detectSuspiciousActivity(): Awaitable<vec<dict<string, mixed>>> {
        $suspicious = vec[];
        
        // Analyze traffic patterns using tcpdump
        $tcpdumpCmd = \sprintf(
            'timeout 10 tcpdump -i %s -c 50 -n 2>/dev/null',
            \escapeshellarg($this->networkInterface)
        );
        
        $tcpdumpOutput = await $this->executeShellCommand($tcpdumpCmd);
        
        if ($tcpdumpOutput !== null) {
            $packets = $this->parseTcpdumpOutput($tcpdumpOutput);
            $trafficAnalysis = $this->analyzeTrafficPatterns($packets);
            
            // Detect unusual traffic volumes
            if (C\count($packets) > 0) {
                $ipTraffic = Dict\group_by($packets, $packet ==> $packet['source_ip']);
                
                foreach ($ipTraffic as $ip => $traffic) {
                    if (C\count($traffic) > 20) { // Threshold for suspicious activity
                        $suspicious[] = dict[
                            'type' => 'high_traffic_volume',
                            'severity' => 'medium',
                            'source_ip' => $ip,
                            'packet_count' => C\count($traffic),
                            'timestamp' => \date('c'),
                            'description' => \sprintf('High traffic volume from %s', $ip)
                        ];
                    }
                }
            }
        }
        
        return $suspicious;
    }
    
    /**
     * Detect unauthorized devices on the network
     */
    private async function detectUnauthorizedDevices(): Awaitable<vec<dict<string, mixed>>> {
        $unauthorized = vec[];
        $currentDevices = await $this->executeArpScan();
        $knownDevices = $this->getKnownDevices();
        
        foreach ($currentDevices as $device) {
            $isKnown = false;
            foreach ($knownDevices as $known) {
                if ($known['ip'] === $device['ip'] || $known['mac'] === $device['mac']) {
                    $isKnown = true;
                    break;
                }
            }
            
            if (!$isKnown && $device['mac'] !== '') {
                $unauthorized[] = dict[
                    'type' => 'unauthorized_device',
                    'severity' => 'medium',
                    'device_ip' => $device['ip'],
                    'device_mac' => $device['mac'],
                    'timestamp' => \date('c'),
                    'description' => \sprintf('Unauthorized device detected: %s (%s)', $device['ip'], $device['mac'])
                ];
            }
        }
        
        return $unauthorized;
    }
    
    /**
     * Detect potential DDoS attack patterns
     */
    private async function detectDDoSPatterns(): Awaitable<vec<dict<string, mixed>>> {
        $ddosEvents = vec[];
        
        $netstatCmd = 'netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l';
        $connectionCount = await $this->executeShellCommand($netstatCmd);
        
        if ($connectionCount !== null && (int)$connectionCount > 1000) {
            $ddosEvents[] = dict[
                'type' => 'potential_ddos',
                'severity' => 'critical',
                'connection_count' => (int)$connectionCount,
                'timestamp' => \date('c'),
                'description' => 'Potential DDoS attack detected - high connection count'
            ];
        }
        
        return $ddosEvents;
    }
    
    /**
     * Real-time network monitoring with continuous updates
     */
    public async function startRealTimeMonitoring(): Awaitable<void> {
        while (true) {
            try {
                $currentTime = \microtime(true);
                
                // Perform network analysis every 30 seconds
                if ($currentTime - $this->lastScanTime > 30.0) {
                    $analysisResults = await $this->performNetworkAnalysis();
                    $this->updateDeviceCache($analysisResults);
                    $this->lastScanTime = $currentTime;
                }
                
                // Monitor security events every 10 seconds
                $securityEvents = await $this->monitorSecurityEvents();
                if (C\count($securityEvents) > 0) {
                    $this->handleSecurityEvents($securityEvents);
                }
                
                // Sleep for 5 seconds before next iteration
                await \HH\Asio\usleep(5000000);
                
            } catch (\Exception $e) {
                \error_log('Real-time monitoring error: ' . $e->getMessage());
                await \HH\Asio\usleep(10000000); // Wait 10 seconds on error
            }
        }
    }
    
    /**
     * Update device cache with latest scan results
     */
    private function updateDeviceCache(dict<string, mixed> $analysisResults): void {
        $devices = $analysisResults['devices'] ?? vec[];
        
        foreach ($devices as $device) {
            $deviceKey = $device['ip'] ?? '';
            if ($deviceKey !== '') {
                $this->deviceCache[$deviceKey] = dict[
                    'ip' => $device['ip'],
                    'mac' => $device['mac'] ?? '',
                    'hostname' => $device['hostname'] ?? '',
                    'last_seen' => \date('c'),
                    'services' => $device['services'] ?? vec[],
                    'os_info' => $device['os_info'] ?? dict[]
                ];
            }
        }
    }
    
    /**
     * Handle security events by logging and alerting
     */
    private function handleSecurityEvents(vec<dict<string, mixed>> $events): void {
        foreach ($events as $event) {
            // Log security event
            $logMessage = \sprintf(
                '[%s] %s: %s',
                $event['severity'] ?? 'unknown',
                $event['type'] ?? 'unknown',
                $event['description'] ?? 'No description'
            );
            \error_log($logMessage);
            
            // Send alerts for high severity events
            if (($event['severity'] ?? '') === 'high' || ($event['severity'] ?? '') === 'critical') {
                $this->sendSecurityAlert($event);
            }
        }
    }
    
    /**
     * Send security alert notification
     */
    private function sendSecurityAlert(dict<string, mixed> $event): void {
        // Implementation for sending alerts (email, webhook, etc.)
        $alertData = \json_encode($event, \JSON_PRETTY_PRINT);
        \error_log('SECURITY ALERT: ' . $alertData);
    }
    
    /**
     * Execute shell command asynchronously
     */
    private async function executeShellCommand(string $command): Awaitable<?string> {
        try {
            $process = \proc_open(
                $command,
                dict[
                    0 => dict['pipe', 'r'],
                    1 => dict['pipe', 'w'],
                    2 => dict['pipe', 'w']
                ],
                inout $pipes
            );
            
            if (!\is_resource($process)) {
                return null;
            }
            
            \fclose($pipes[0]);
            $output = \stream_get_contents($pipes[1]);
            $error = \stream_get_contents($pipes[2]);
            \fclose($pipes[1]);
            \fclose($pipes[2]);
            
            $returnCode = \proc_close($process);
            
            return $returnCode === 0 ? $output : null;
            
        } catch (\Exception $e) {
            \error_log('Command execution error: ' . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Parse Nmap host discovery output
     */
    private function parseNmapHostDiscovery(string $output): vec<string> {
        $hosts = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $matches = Regex\first_match($line, re"/Nmap scan report for (.+)/");
            if ($matches !== null) {
                $hostInfo = $matches[1];
                $ipMatch = Regex\first_match($hostInfo, re"/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/");
                if ($ipMatch !== null) {
                    $hosts[] = $ipMatch[1];
                } else if (\filter_var($hostInfo, \FILTER_VALIDATE_IP)) {
                    $hosts[] = $hostInfo;
                }
            }
        }
        
        return Vec\unique($hosts);
    }
    
    /**
     * Parse ARP scan output
     */
    private function parseArpOutput(string $output): vec<dict<string, string>> {
        $devices = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            // Parse arp-scan format
            $arpScanMatch = Regex\first_match($line, re"/([0-9.]+)\s+([0-9a-f:]{17})/i");
            if ($arpScanMatch !== null) {
                $devices[] = dict[
                    'ip' => $arpScanMatch[1],
                    'mac' => Str\lowercase($arpScanMatch[2]),
                    'hostname' => '',
                    'status' => 'online'
                ];
                continue;
            }
            
            // Parse arp -a format
            $arpTableMatch = Regex\first_match($line, re"/\(([0-9.]+)\) at ([0-9a-f:]{17})/i");
            if ($arpTableMatch !== null) {
                $devices[] = dict[
                    'ip' => $arpTableMatch[1],
                    'mac' => Str\lowercase($arpTableMatch[2]),
                    'hostname' => '',
                    'status' => 'online'
                ];
            }
        }
        
        return $devices;
    }
    
    /**
     * Parse ARP table from /proc/net/arp
     */
    private function parseArpTable(string $output): vec<dict<string, string>> {
        $devices = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $parts = Regex\split($line, re"/\s+/");
            if (C\count($parts) >= 4) {
                $ip = $parts[0];
                $mac = $parts[3];
                
                if (\filter_var($ip, \FILTER_VALIDATE_IP) && $mac !== '00:00:00:00:00:00') {
                    $devices[] = dict[
                        'ip' => $ip,
                        'mac' => Str\lowercase($mac),
                        'hostname' => '',
                        'status' => 'online'
                    ];
                }
            }
        }
        
        return $devices;
    }
    
    /**
     * Parse Nmap service detection output
     */
    private function parseNmapServices(string $output): vec<dict<string, mixed>> {
        $services = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $serviceMatch = Regex\first_match($line, re"/(\d+)\/(tcp|udp)\s+open\s+(\w+)\s*(.*)$/");
            if ($serviceMatch !== null) {
                $services[] = dict[
                    'port' => (int)$serviceMatch[1],
                    'protocol' => $serviceMatch[2],
                    'service' => $serviceMatch[3],
                    'version' => Str\trim($serviceMatch[4])
                ];
            }
        }
        
        return $services;
    }
    
    /**
     * Parse Nmap OS detection output
     */
    private function parseNmapOSDetection(string $output): dict<string, string> {
        $osInfo = dict[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $runningMatch = Regex\first_match($line, re"/Running: (.+)$/i");
            if ($runningMatch !== null) {
                $osInfo['running'] = Str\trim($runningMatch[1]);
            }
            
            $osMatch = Regex\first_match($line, re"/OS details: (.+)$/i");
            if ($osMatch !== null) {
                $osInfo['details'] = Str\trim($osMatch[1]);
            }
        }
        
        return $osInfo;
    }
    
    /**
     * Parse netstat connections output
     */
    private function parseNetstatConnections(string $output): vec<dict<string, mixed>> {
        $connections = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $connMatch = Regex\first_match(
                $line,
                re"/(tcp|udp)\s+\d+\s+\d+\s+([0-9.]+):(\d+)\s+([0-9.]+):(\d+)\s+(\w+)/"
            );
            
            if ($connMatch !== null) {
                $connections[] = dict[
                    'protocol' => $connMatch[1],
                    'local_ip' => $connMatch[2],
                    'local_port' => (int)$connMatch[3],
                    'remote_ip' => $connMatch[4],
                    'remote_port' => (int)$connMatch[5],
                    'state' => $connMatch[6]
                ];
            }
        }
        
        return $connections;
    }
    
    /**
     * Parse netstat listening ports output
     */
    private function parseNetstatListening(string $output): vec<dict<string, mixed>> {
        $listening = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $listenMatch = Regex\first_match(
                $line,
                re"/(tcp|udp)\s+\d+\s+\d+\s+([0-9.*]+):(\d+)\s+[0-9.*:]+\s+LISTEN/"
            );
            
            if ($listenMatch !== null) {
                $listening[] = dict[
                    'protocol' => $listenMatch[1],
                    'address' => $listenMatch[2],
                    'port' => (int)$listenMatch[3]
                ];
            }
        }
        
        return $listening;
    }
    
    /**
     * Parse netstat interface statistics
     */
    private function parseNetstatInterface(string $output): dict<string, dict<string, int>> {
        $interfaces = dict[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $parts = Regex\split($line, re"/\s+/");
            if (C\count($parts) >= 8) {
                $interface = $parts[0];
                if ($interface !== 'Iface' && $interface !== 'Kernel') {
                    $interfaces[$interface] = dict[
                        'rx_packets' => (int)($parts[2] ?? 0),
                        'rx_errors' => (int)($parts[3] ?? 0),
                        'tx_packets' => (int)($parts[6] ?? 0),
                        'tx_errors' => (int)($parts[7] ?? 0)
                    ];
                }
            }
        }
        
        return $interfaces;
    }
    
    /**
     * Parse netstat routing table
     */
    private function parseNetstatRoute(string $output): vec<dict<string, string>> {
        $routes = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $parts = Regex\split($line, re"/\s+/");
            if (C\count($parts) >= 8) {
                $destination = $parts[0];
                if ($destination !== 'Destination' && $destination !== 'Kernel') {
                    $routes[] = dict[
                        'destination' => $destination,
                        'gateway' => $parts[1],
                        'netmask' => $parts[2],
                        'interface' => $parts[7]
                    ];
                }
            }
        }
        
        return $routes;
    }
    
    /**
     * Parse tcpdump packet capture output
     */
    private function parseTcpdumpOutput(string $output): vec<dict<string, mixed>> {
        $packets = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $packetMatch = Regex\first_match(
                $line,
                re"/(\d+:\d+:\d+\.\d+)\s+IP\s+([0-9.]+)\.(\d+)\s+>\s+([0-9.]+)\.(\d+)/"
            );
            
            if ($packetMatch !== null) {
                $packets[] = dict[
                    'timestamp' => $packetMatch[1],
                    'source_ip' => $packetMatch[2],
                    'source_port' => (int)$packetMatch[3],
                    'dest_ip' => $packetMatch[4],
                    'dest_port' => (int)$packetMatch[5],
                    'protocol' => $this->extractProtocolFromPacket($line)
                ];
            }
        }
        
        return $packets;
    }
    
    /**
     * Parse tshark output
     */
    private function parseTsharkOutput(string $output): vec<dict<string, mixed>> {
        $packets = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $fields = Str\split($line, "\t");
            if (C\count($fields) >= 6) {
                $packets[] = dict[
                    'timestamp' => $fields[0],
                    'source_ip' => $fields[1],
                    'dest_ip' => $fields[2],
                    'source_port' => $fields[3] !== '' ? (int)$fields[3] : 0,
                    'dest_port' => $fields[4] !== '' ? (int)$fields[4] : 0,
                    'protocols' => $fields[5]
                ];
            }
        }
        
        return $packets;
    }
    
    /**
     * Parse traceroute output
     */
    private function parseTraceroute(string $output): vec<dict<string, mixed>> {
        $hops = vec[];
        $lines = Str\split($output, "\n");
        
        foreach ($lines as $line) {
            $hopMatch = Regex\first_match(
                $line,
                re"/^\s*(\d+)\s+([^\s]+)\s+\(([0-9.]+)\)\s+([0-9.]+)\s*ms/"
            );
            
            if ($hopMatch !== null) {
                $hops[] = dict[
                    'hop' => (int)$hopMatch[1],
                    'hostname' => $hopMatch[2],
                    'ip' => $hopMatch[3],
                    'rtt' => (float)$hopMatch[4]
                ];
            }
        }
        
        return $hops;
    }
    
    /**
     * Analyze protocol distribution from packets
     */
    private function analyzeProtocolDistribution(vec<dict<string, mixed>> $packets): dict<string, int> {
        $protocols = dict[];
        
        foreach ($packets as $packet) {
            $protocol = $packet['protocol'] ?? 'unknown';
            $protocols[$protocol] = ($protocols[$protocol] ?? 0) + 1;
        }
        
        return $protocols;
    }
    
    /**
     * Analyze traffic patterns from packets
     */
    private function analyzeTrafficPatterns(vec<dict<string, mixed>> $packets): dict<string, mixed> {
        $patterns = dict[
            'top_sources' => dict[],
            'top_destinations' => dict[],
            'port_usage' => dict[],
            'time_distribution' => dict[]
        ];
        
        foreach ($packets as $packet) {
            $sourceIp = $packet['source_ip'] ?? '';
            $destIp = $packet['dest_ip'] ?? '';
            $destPort = $packet['dest_port'] ?? 0;
            
            if ($sourceIp !== '') {
                $patterns['top_sources'][$sourceIp] = ($patterns['top_sources'][$sourceIp] ?? 0) + 1;
            }
            
            if ($destIp !== '') {
                $patterns['top_destinations'][$destIp] = ($patterns['top_destinations'][$destIp] ?? 0) + 1;
            }
            
            if ($destPort > 0) {
                $patterns['port_usage'][(string)$destPort] = ($patterns['port_usage'][(string)$destPort] ?? 0) + 1;
            }
        }
        
        return $patterns;
    }
    
    /**
     * Merge network data from multiple sources
     */
    private function mergeNetworkData(
        dict<string, mixed> $nmapResults,
        vec<dict<string, string>> $arpResults,
        dict<string, mixed> $netstatResults,
        dict<string, mixed> $tcpdumpResults
    ): dict<string, mixed> {
        
        $mergedDevices = vec[];
        $deviceMap = dict[];
        
        // Process Nmap results
        foreach ($nmapResults['hosts'] as $host) {
            $deviceMap[$host] = dict[
                'ip' => $host,
                'mac' => '',
                'hostname' => '',
                'services' => $nmapResults['services'][$host] ?? vec[],
                'os_info' => $nmapResults['os_detection'][$host] ?? dict[],
                'status' => 'online'
            ];
        }
        
        // Merge ARP results
        foreach ($arpResults as $arpDevice) {
            $ip = $arpDevice['ip'];
            if (C\contains_key($deviceMap, $ip)) {
                $deviceMap[$ip]['mac'] = $arpDevice['mac'];
            } else {
                $deviceMap[$ip] = $arpDevice;
            }
        }
        
        $mergedDevices = Vec\values($deviceMap);
        
        return dict[
            'devices' => $mergedDevices,
            'network_stats' => $netstatResults,
            'traffic_analysis' => $tcpdumpResults,
            'total_devices' => C\count($mergedDevices),
            'active_connections' => C\count($netstatResults['connections'] ?? vec[])
        ];
    }
    
    /**
     * Detect primary network interface
     */
    private function detectPrimaryInterface(): string {
        $routeCmd = 'ip route | grep default';
        $routeOutput = \shell_exec($routeCmd);
        
        if ($routeOutput !== null) {
            $match = Regex\first_match($routeOutput, re"/dev\s+(\w+)/");
            if ($match !== null) {
                return $match[1];
            }
        }
        
        return 'eth0'; // Fallback
    }
    
    /**
     * Get network range for scanning
     */
    private async function getNetworkRange(): Awaitable<string> {
        $interface = $this->networkInterface;
        $routeCmd = \sprintf('ip route | grep %s | grep -v default | head -1', \escapeshellarg($interface));
        $routeOutput = await $this->executeShellCommand($routeCmd);
        
        if ($routeOutput !== null) {
            $match = Regex\first_match($routeOutput, re"/([0-9.]+\/\d+)/");
            if ($match !== null) {
                return $match[1];
            }
        }
        
        return '192.168.1.0/24'; // Fallback
    }
    
    /**
     * Extract protocol from packet data
     */
    private function extractProtocolFromPacket(string $packetData): string {
        if (Str\contains($packetData, 'HTTP')) return 'HTTP';
        if (Str\contains($packetData, 'HTTPS')) return 'HTTPS';
        if (Str\contains($packetData, 'SSH')) return 'SSH';
        if (Str\contains($packetData, 'FTP')) return 'FTP';
        if (Str\contains($packetData, 'DNS')) return 'DNS';
        if (Str\contains($packetData, 'SMTP')) return 'SMTP';
        if (Str\contains($packetData, 'TCP')) return 'TCP';
        if (Str\contains($packetData, 'UDP')) return 'UDP';
        return 'OTHER';
    }
    
    /**
     * Get known devices list (would be stored in database in production)
     */
    private function getKnownDevices(): vec<dict<string, string>> {
        // In production, this would read from a database
        return vec[
            dict['ip' => '192.168.1.1', 'mac' => '00:11:22:33:44:55', 'name' => 'Gateway'],
            dict['ip' => '192.168.1.2', 'mac' => '00:11:22:33:44:56', 'name' => 'Server']
        ];
    }
    
    /**
     * Get current device cache
     */
    public function getDeviceCache(): dict<string, mixed> {
        return $this->deviceCache;
    }
    
    /**
     * Get security events history
     */
    public function getSecurityEvents(): vec<dict<string, mixed>> {
        return $this->securityEvents;
    }
    
    /**
     * Get network interface statistics
     */
    public async function getInterfaceStats(): Awaitable<dict<string, mixed>> {
        $interface = $this->networkInterface;
        $statsCmd = \sprintf('cat /proc/net/dev | grep %s', \escapeshellarg($interface));
        $output = await $this->executeShellCommand($statsCmd);
        
        if ($output !== null) {
            $parts = Regex\split(Str\trim($output), re"/\s+/");
            if (C\count($parts) >= 10) {
                return dict[
                    'interface' => $interface,
                    'rx_bytes' => (int)$parts[1],
                    'rx_packets' => (int)$parts[2],
                    'rx_errors' => (int)$parts[3],
                    'tx_bytes' => (int)$parts[9],
                    'tx_packets' => (int)$parts[10],
                    'tx_errors' => (int)$parts[11]
                ];
            }
        }
        
        return dict['interface' => $interface, 'error' => 'Unable to read stats'];
    }
}
