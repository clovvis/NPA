# NPA - Network Packet Analyzer & ARP Interceptor

![Version](https://img.shields.io/badge/version-0.20.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-Educational-orange.svg)

A powerful network traffic analysis tool with ARP spoofing capabilities, offline PCAP analysis, and comprehensive network scanning features.

## Legal Notice

**IMPORTANT**: This tool is intended for **authorized security testing and educational purposes only**.

- Use only on networks where you have **explicit permission**
- Unauthorized use is **ILLEGAL** and may result in criminal penalties
- Designed for penetration testing, network diagnostics, and educational research
- Users are responsible for ensuring compliance with local laws and regulations

## Features

### Core Capabilities

- **ARP Spoofing**: Man-in-the-middle attack capabilities for traffic interception
- **Live Traffic Capture**: Real-time network packet capture and analysis
- **Offline Analysis**: Process existing PCAP files without live capture
- **Network Scanning**: Discover active hosts and their MAC addresses
- **Port Scanning**: Detect open ports on discovered hosts (SYN scan)

### Protocol Support

- **HTTP**: Extract and save files from HTTP traffic
- **HTTPS/TLS**: Extract SNI (Server Name Indication) and certificates
- **DNS**: Log DNS queries and responses
- **ICMP**: Track ping requests and responses
- **TCP/UDP**: Comprehensive packet analysis

### Additional Features

- PCAP file generation (Wireshark compatible)
- Automatic log cleanup
- Tcpdump integration for detailed analysis
- Multi-threaded port scanning for speed
- Colorful ASCII art banners using `toilet`

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu, Debian, Arch, Fedora, etc.)
- **Python**: 3.7 or higher
- **Privileges**: Root access required for live capture and network scanning

### Required Dependencies

```bash
# Install Python dependencies
pip3 install scapy netifaces

# Install system tools
sudo apt-get install tcpdump openssl toilet  # Debian/Ubuntu
sudo dnf install tcpdump openssl toilet      # Fedora/RHEL
sudo pacman -S tcpdump openssl toilet        # Arch Linux
brew install tcpdump openssl toilet          # macOS
```

## Installation

1. **Clone or download the repository**:

   ```bash
   wget https://example.com/npa.py
   # or
   git clone https://example.com/npa.git
   cd npa
   ```

2. **Install dependencies**:

   ```bash
   pip3 install -r requirements.txt
   # or manually:
   pip3 install scapy netifaces
   ```

3. **Make executable** (optional):
   ```bash
   chmod +x npa.py
   ```

## Usage

### Basic Syntax

```bash
sudo python3 npa.py [OPTIONS]
```

### Common Use Cases

#### 1. Live Traffic Capture (ARP Spoofing)

Intercept traffic between a target device and the gateway:

```bash
sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i eth0
```

**Parameters**:

- `-v, --victim`: Target IP address
- `-g, --gateway`: Gateway/router IP address
- `-i, --interface`: Network interface to use

#### 2. Network Scanning

Discover all active devices on the local network:

```bash
# Basic scan (IP + MAC)
sudo python3 npa.py -i eth0 --scan-network

# Scan with port detection
sudo python3 npa.py -i eth0 --scan-network --port-scan
```

**Features**:

- Discovers active hosts using ARP
- Lists IP addresses and MAC addresses
- Optional port scanning for common services
- Saves results to timestamped log files

#### 3. Offline PCAP Analysis

Analyze existing capture files without live interception:

```bash
python3 npa.py --pcap-input capture.pcap -o results
```

**Note**: No root privileges required for offline analysis.

#### 4. Advanced Usage

**Custom output directory**:

```bash
sudo python3 npa.py -v 192.168.1.50 -g 192.168.1.1 -i eth0 -o /tmp/captures
```

**With tcpdump analysis**:

```bash
sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i wlan0 --tcpdump
```

**Custom tcpdump filter**:

```bash
sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i eth0 \
    --tcpdump --tcpdump-filter 'tcp port 80 or tcp port 443'
```

### List Available Interfaces

```bash
python3 npa.py --list-interfaces
```

## Command-Line Options

| Option               | Description                                             |
| -------------------- | ------------------------------------------------------- |
| `-v, --victim`       | Target IP address                                       |
| `-g, --gateway`      | Gateway IP address                                      |
| `-i, --interface`    | Network interface (eth0, wlan0, etc.)                   |
| `-o, --output`       | Output directory (default: `captures`)                  |
| `-s, --scan-network` | Scan local network for active hosts                     |
| `-p, --port-scan`    | Enable port scanning during network scan                |
| `--pcap-input`       | PCAP file for offline analysis                          |
| `--tcpdump`          | Enable tcpdump analysis after capture                   |
| `--tcpdump-filter`   | Custom filter for tcpdump                               |
| `--cleanup-age`      | Log file age for automatic cleanup (hours, default: 24) |
| `--list-interfaces`  | List available network interfaces                       |
| `-V, --version`      | Show version information                                |
| `-h, --help`         | Display help message                                    |

## Output Files

The tool generates several types of output files in the specified directory (default: `captures/`):

### Live Capture

- `capture_YYYYMMDD_HHMMSS.pcap` - Complete packet capture (Wireshark compatible)
- `http_YYYYMMDD_HHMMSS_<mime>.ext` - Extracted HTTP files
- `https_YYYYMMDD_HHMMSS_<sni>.bin` - Encrypted HTTPS payloads
- `tls_cert_YYYYMMDD_HHMMSS_<sni>.pem` - TLS certificates
- `dns_queries_YYYYMMDD.log` - DNS query logs
- `dns_responses_YYYYMMDD.log` - DNS response logs
- `icmp_requests_YYYYMMDD.log` - ICMP echo request logs
- `icmp_replies_YYYYMMDD.log` - ICMP echo reply logs

### Network Scan

- `network_scan_YYYYMMDD_HHMMSS.log` - Network scan results with IPs, MACs, and ports

## How It Works

### ARP Spoofing Process

1. **Discovery**: Obtains MAC addresses of target and gateway
2. **Poisoning**: Sends forged ARP packets to both target and gateway
3. **Interception**: Routes traffic through attacker's machine
4. **Capture**: Sniffs and analyzes intercepted packets
5. **Restoration**: Restores original ARP tables on exit

### Network Scanning

1. **ARP Ping**: Sends ARP requests to all IPs in the subnet
2. **Host Discovery**: Collects responses with IP and MAC addresses
3. **Port Scanning**: Optional SYN scan on common ports (multi-threaded)
4. **Reporting**: Generates formatted output and log files

### Port Scanning

Uses SYN scanning technique (stealth scan):

- Sends SYN packet to target port
- Detects SYN-ACK response (port open)
- Sends RST to close connection gracefully
- Multi-threaded for improved performance

**Common ports scanned**: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 3306 (MySQL), 3389 (RDP), 5900 (VNC), 8080 (HTTP-Alt)

## Troubleshooting

### Common Issues

**"This program requires root privileges"**

- Solution: Run with `sudo` for live capture and scanning
- Offline analysis (`--pcap-input`) does not require root

**"Could not get MAC addresses"**

- Verify target and gateway IPs are correct and reachable
- Check network connectivity: `ping <target_ip>`
- Ensure you're on the same subnet

**"Interface not found"**

- List interfaces: `python3 npa.py --list-interfaces`
- Check interface status: `ip link show`

**"tcpdump not found"**

- Install: `sudo apt-get install tcpdump`

**"toilet not installed"**

- The tool works without it (uses fallback banners)
- Install for better visuals: `sudo apt-get install toilet`

## Security Considerations

### Best Practices

- Always obtain written authorization before testing
- Use only in isolated lab environments or authorized networks
- Be aware of legal implications in your jurisdiction
- Monitor and log all testing activities
- Restore network state after testing

### Ethical Guidelines

- Never use on public networks without permission
- Respect privacy and data protection laws
- Use for improving security, not compromising it
- Follow responsible disclosure practices
- Consider the impact on network availability

## Technical Details

### Supported File Types (HTTP Extraction)

- **Images**: JPEG, PNG, BMP, WebP
- **Videos**: MP4, AVI
- **Documents**: TXT, PDF, DOC, DOCX, JSON

### Protocol Details

- **ARP**: Address Resolution Protocol spoofing
- **DNS**: Query/response logging (UDP/TCP port 53)
- **HTTP**: Clear-text traffic analysis (port 80)
- **HTTPS**: SNI extraction, certificate capture (port 443)
- **ICMP**: Echo request/reply tracking
- **TLS**: ClientHello SNI, Server Certificate extraction

## Contributing

Contributions are welcome! Please ensure:

- Code follows existing style conventions
- All features are documented
- Legal warnings are preserved
- Ethical use is emphasized

## License

This tool is provided for **educational and authorized testing purposes only**. Users assume all responsibility for legal compliance.

## Author

Network Packet Analyzer (NPA) - Version 0.20.0

## Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Wireshark](https://www.wireshark.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
