# 🛡️ Network Security App

[![GHCR](https://img.shields.io/badge/NetworkSecurityApp-red?logo=docker)](https://hub.docker.com/r/hirotoshiuchida/network-security-app)

Real-time network monitoring and security analysis application built with PHP and modern web technologies.

**Author:** Hirotoshi Uchida  
**Homepage:** https://hirotoshiuchida.onrender.com  
**Live Demo:** https://network-security-app.onrender.com

## ✨ Features

### 🖥️ System Monitoring
- **Real-time System Status**: Monitor system uptime, load average, and overall health
- **Resource Usage Tracking**: Track system resources and performance metrics
- **Automated Health Checks**: Built-in health monitoring with timeout protection

### 🌐 Network Discovery
- **Device Discovery**: Automatically discover active devices on the network
- **ARP Table Analysis**: Parse and display ARP table entries for device identification
- **IP Range Scanning**: Support for custom network range scanning
- **MAC Address Resolution**: Display device MAC addresses and hostnames

### 📊 Traffic Analysis
- **Real-time Traffic Monitoring**: Monitor RX/TX bytes with live charts
- **Network Interface Detection**: Automatic detection of primary network interfaces
- **Visual Traffic Charts**: Interactive charts using Chart.js for data visualization
- **Historical Data Tracking**: Track network traffic over time

### 🔬 Network Analysis Tools
- **Nmap Integration**: Host discovery using nmap scanning
- **Netstat Analysis**: Active connections and listening ports analysis
- **Port Scanning**: Detect open ports and running services
- **Network Topology Mapping**: Visual representation of network structure

### 🚨 Security Monitoring
- **Security Event Monitoring**: Real-time security alerts and notifications
- **Connection Analysis**: Monitor active network connections
- **Vulnerability Assessment**: Basic security vulnerability detection
- **Alert Management**: Categorized security alerts with severity levels

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Network access for scanning capabilities
- Minimum 512MB RAM recommended

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/Uchida16104/Network-Security-App.git
cd Network-Security-App
```

2. **Build and run with Docker:**
```bash
docker build -t network-security-app .
docker run -p 8080:8080 --privileged network-security-app
```

3. **Access the application:**
Open your browser and navigate to `http://localhost:8080`

### Docker Compose (Alternative)
```yaml
version: '3.8'
services:
  network-security-app:
    build: .
    ports:
      - "8080:8080"
    privileged: true
    volumes:
      - ./storage:/app/storage
    environment:
      - APP_ENV=production
      - APP_DEBUG=false
```

## 🏗️ Architecture

### Backend Components
- **PHP 8.1**: Core application logic and API endpoints
- **NetworkController**: Handles dashboard data and network scanning
- **NetworkMonitor**: Advanced network analysis and monitoring
- **Nginx**: Web server for serving the application
- **PHP-FPM**: FastCGI Process Manager for PHP execution

### Frontend Technologies
- **HTML5**: Modern semantic markup
- **CSS3**: Responsive design with gradients and animations
- **Vanilla JavaScript**: Client-side interactivity and API communication
- **Chart.js**: Interactive data visualization

### Network Tools Integration
- **nmap**: Network discovery and port scanning
- **arp-scan**: ARP table scanning for device detection
- **netstat**: Network connection analysis
- **tcpdump/tshark**: Packet capture capabilities (when available)
- **traceroute**: Network path tracing
- **ping**: Network connectivity testing

## 📡 API Endpoints

### Dashboard API
```http
GET /api/dashboard
```
Returns comprehensive dashboard data including system status, network devices, traffic information, and security alerts.

### Network Scanning
```http
GET /api/network-scan?range=192.168.1.0/24&type=quick
```
Parameters:
- `range` (optional): Network range to scan
- `type` (optional): Scan type (`quick` or `detailed`)

### Network Analysis
```http
GET /api/analysis
```
Performs comprehensive network analysis including nmap scans, ARP table parsing, and connection analysis.

### Health Check
```http
GET /api/health-check
```
Returns application health status and version information.

## ⚙️ Configuration

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `production` | Application environment |
| `APP_DEBUG` | `false` | Enable debug mode |
| `NETWORK_INTERFACE` | `eth0` | Primary network interface |
| `SCAN_TIMEOUT` | `30` | Scan timeout in seconds |
| `MONITOR_INTERVAL` | `5` | Monitoring interval in seconds |
| `MAX_SCAN_RANGE` | `254` | Maximum IP range for scanning |
| `ENABLE_REAL_TIME` | `true` | Enable real-time monitoring |
| `SECURITY_ALERTS` | `true` | Enable security alerting |

### Network Interface Detection
The application automatically detects the primary network interface using:
```bash
ip route | grep default
```

### Timeout Protection
All network operations include timeout protection:
- Dashboard requests: 10 seconds
- Network scans: 15 seconds  
- Analysis operations: 20 seconds

## 🔧 Development

### Local Development Setup
1. Install PHP 8.1+ with required extensions
2. Install required system tools (nmap, arp-scan, netstat)
3. Configure web server (Nginx recommended)
4. Set appropriate file permissions

### Required PHP Extensions
- `php-fpm`
- `php-cli`
- `php-sqlite3`
- `php-curl`
- `php-mbstring`
- `php-xml`

### System Dependencies
```bash
# Ubuntu/Debian
apt-get install nmap arp-scan net-tools iproute2 traceroute dnsutils
```

## 🐳 Docker Details

### Multi-stage Build
The Dockerfile uses a multi-stage build process:
1. **Builder Stage**: Installs all dependencies and builds the application
2. **Production Stage**: Creates optimized runtime image with only necessary components

### Security Features
- Non-root user execution (`appuser:1001`)
- Minimal attack surface with optimized image
- Network tools with appropriate permissions
- Health check monitoring

### Volume Mounts
- `/app/storage`: Persistent data storage for logs and database
- Automatic directory creation with correct permissions

## 📊 Performance

### Optimization Features
- **Caching**: Results cached for 10 seconds to reduce system load
- **Timeout Protection**: All operations have configurable timeouts
- **Resource Limits**: Memory limit set to 512MB
- **Connection Pooling**: Efficient handling of multiple requests
- **Minimal Scanning**: Quick scans limited to essential information

### Performance Metrics
- Dashboard load time: < 2 seconds
- Network scan time: < 30 seconds  
- Memory usage: < 256MB typical
- CPU usage: < 5% idle, < 50% during scans

## 🔒 Security Considerations

### Network Privileges
The application requires privileged access for network scanning:
```bash
docker run --privileged network-security-app
```

### Security Headers
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`  
- `X-XSS-Protection: 1; mode=block`

### Data Privacy
- No sensitive data stored permanently
- In-memory caching with automatic expiration
- SQLite database for temporary session data only

## 🚨 Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Fix permissions for network tools
chmod u+s /usr/bin/nmap
chmod u+s /usr/sbin/arp-scan
```

#### Network Interface Detection
```bash
# Check available interfaces
ip link show
# Manually set interface
export NETWORK_INTERFACE=eth0
```

#### Timeout Issues
- Increase timeout values in environment variables
- Check network connectivity
- Verify system resources

### Debugging
Enable debug mode:
```bash
docker run -e APP_DEBUG=true -e LOG_LEVEL=debug network-security-app
```

## ❗️Caution
Please note that we cannot accept any responsibility for accidents occurring during use.

## 📄 License

MIT License - See LICENSE file for details.

## 👨‍💻 Author

**Hirotoshi Uchida**
- Homepage: https://hirotoshiuchida.onrender.com
- Contact: https://hirotoshiuchida.onrender.com/#contact

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📈 Roadmap

- Enhanced vulnerability scanning
- Network topology visualization
- Advanced alerting system
- API authentication
- Multi-language support
- Mobile responsiveness improvements

---

*Built with ❤️ for network security professionals and enthusiasts.*

*by Hirotoshi Uchida*
