```
┌──────────────────────────────────────────────────┐
│                                                  │
│                                                  │
│                                                  │
│ ███   ██            ██████▒               ▒██▒   │
│ ███   ██            ███████▒              ▓██▓   │
│ ███▒  ██            ██   ▒██              ████   │
│ ████  ██            ██    ██              ████   │
│ ██▒█▒ ██            ██   ▒██             ▒█▓▓█▒  │
│ ██ ██ ██            ███████▒             ▓█▒▒█▓  │
│ ██ ██ ██            ██████▒              ██  ██  │
│ ██ ▒█▒██            ██                   ██████  │
│ ██  ████            ██                  ░██████░ │
│ ██  ▒███     ██     ██           ██     ▒██  ██▒ │
│ ██   ███     ██     ██           ██     ███  ███ │
│ ██   ███     ██     ██           ██     ██▒  ▒██ │
│                                                  │
│                                                  │
│                                                  │
│                                                  │
└──────────────────────────────────────────────────┘

────────────────────────────────────────────────────────────────────────────────
    NPA-Network Packet Analyzer & ARP Interceptor
    Version 1.17.0 - Network Traffic Analysis

NPA
Overview
NPA is an advanced Python-based network traffic analysis tool designed for authorized security testing and penetration testing. It supports live packet capture with ARP spoofing (poisoning) to intercept traffic, 
offline PCAP analysis, DNS/ICMP processing, HTTP content extraction, TLS SNI/certificate handling, and network scanning for IPs and MAC addresses.

Version: 1.16.0
Author: Built with Scapy and enhanced for ethical hacking workflows.
License: MIT (with strong emphasis on legal use only – see Legal Notice below).
NPA uses Scapy for packet manipulation and provides beautiful ASCII banners via toilet (optional, with fallback).

Features
ARP Poisoning: Redirect traffic from a victim to your machine via the gateway.
Packet Sniffing: Capture HTTP/HTTPS (with SNI and cert extraction), DNS queries/responses, and ICMP.
File Extraction: Save HTTP bodies (images, PDFs, etc.) and TLS certificates.
Offline Analysis: Process existing PCAP files without root privileges.
Tcpdump Integration: Optional post-capture analysis with custom filters.
Network Scanning: Discover active IPs and MACs on the local network.
Logging & Cleanup: Automatic log rotation and cleanup of old files.
Wireshark-Compatible: Exports to PCAP for further analysis.
Cross-Platform: Tested on Linux (Ubuntu/Fedora/Arch); macOS with adjustments.
Installation
Prerequisites
Python 3.8+
Root privileges for live capture/poisoning/scanning (use sudo).
Network interface with IPv4 (e.g., eth0, wlan0).
Dependencies
Install via pip:

pip3 install scapy netifaces
-----------------------------

Optional (for enhanced features):

* toilet (ASCII banners):
    * Ubuntu/Debian: sudo apt install toilet
    * Fedora/RHEL: sudo dnf install toilet
    * Arch: sudo pacman -S toilet
    * macOS: brew install toilet
* tcpdump (analysis): sudo apt install tcpdump (or equivalent).
* openssl (cert analysis): sudo apt install openssl (or equivalent).

Setup:
1. Clone or download npa.py.
2. Make executable: chmod +x npa.py.
3 Run: sudo python3 npa.py --help.

Usage:

Basic Commands
Live Capture (ARP Poisoning + Sniffing)
Intercept traffic from a victim through the gateway:

sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i eth0
-----------------------------------------------------------

* Captures for 5s delay before starting, then runs until Ctrl+C.
* Saves PCAP, logs, and extracted files to ./captures/.

With Tcpdump Analysis

sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i eth0 --tcpdump
---------------------------------------------------------------------
Custom Tcpdump Filter

sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i eth0 --tcpdump --tcpdump-filter 'tcp port 80 or tcp port 443'
--------------------------------------------------------------------------------------------------------------------

Offline PCAP Analysis
No root needed:

python3 npa.py --pcap-input capture.pcap -o results
----------------------------------------------------

Network Scan
Discover devices on the local network:

sudo python3 npa.py -i eth0 --scan-network
------------------------------------------

* Outputs IPs, MACs, and saves to log.
List Interfaces

python3 npa.py --list-interfaces
---------------------------------

Custom Output & Cleanup

sudo python3 npa.py -v 192.168.1.100 -g 192.168.1.1 -i eth0 -o /tmp/my_captures --cleanup-age 12
-------------------------------------------------------------------------------------------------

Exemplos de Configuração (Configuration Examples)
Aqui estão exemplos práticos de configurações para cenários comuns. Esses comandos podem ser salvos em scripts shell (ex.: run_npa.sh) para automação. Sempre use com permissão explícita na rede.

1. Escaneamento de Rede em Wi-Fi (Wireless Setup)
Para uma rede Wi-Fi doméstica ou corporativa, escaneie dispositivos ativos:

#!/bin/bash
# run_wifi_scan.sh
sudo python3 npa.py -i wlan0 --scan-network -o ~/network_scans --cleanup-age 48
--------------------------------------------------------------------------------

* Uso: ./run_wifi_scan.sh
* Saída: Lista de IPs/MACs no terminal e log em ~/network_scans/.
2. Captura em Rede Corporativa com Filtro Personalizado (Corporate Network Capture)
Intercepte tráfego HTTP/HTTPS de um colega de trabalho (com autorização) e analise com tcpdump focado em portas web:

#!/bin/bash
# run_corporate_capture.sh
sudo python3 npa.py \
    -v 192.168.10.50 \
    -g 192.168.10.1 \
    -i enp0s3 \
    -o /var/log/npa_corporate \
    --tcpdump \
    --tcpdump-filter 'tcp port 80 or tcp port 443 or udp port 53' \
    --cleanup-age 24
-----------------------------------------------------------------------

* Uso: ./run_corporate_capture.sh
* Dica: Ajuste IPs para sua sub-rede (ex.: use ip route para gateway).
3. Análise Offline de PCAP de Ferramenta Externa (Offline from Wireshark)
Processe um arquivo PCAP capturado por Wireshark, extraindo apenas certificados TLS:

#!/bin/bash
# run_offline_analysis.sh
python3 npa.py \
    --pcap-input ~/Downloads/suspicious_traffic.pcap \
    -o ~/analysis_results \
    --tcpdump \
    --tcpdump-filter 'tcp port 443'
----------------------------------------------------------

* Uso: ./run_offline_analysis.sh
* Benefício: Não requer root; ideal para análise forense.
4. Configuração Avançada com Limpeza Automática (Automated Cleanup Setup)
Para testes longos, configure limpeza mais frequente e saída em diretório temporário:

#!/bin/bash
# run_long_test.sh
OUTPUT_DIR=$(mktemp -d /tmp/npa_test_XXXXXX)
sudo python3 npa.py \
    -v 10.0.0.100 \
    -g 10.0.0.1 \
    -i eth1 \
    -o "$OUTPUT_DIR" \
    --cleanup-age 6 \
    --tcpdump
echo "Results in: $OUTPUT_DIR"
-------------------------------------------

* Uso: ./run_long_test.sh
* Dica: O mktemp cria um diretório temporário seguro.
5. Integração com Script de Automação (Automation Integration)
Combine escaneamento + captura em um fluxo:

#!/bin/bash
# full_audit.sh
INTERFACE="eth0"
GATEWAY=$(ip route | grep default | awk '{print $3}')
VICTIM="192.168.1.150"  # Ajuste conforme necessário

echo "Step 1: Scanning network..."
sudo python3 npa.py -i $INTERFACE --scan-network -o audit_results

echo "Step 2: Starting capture on $VICTIM..."
sudo python3 npa.py -v $VICTIM -g $GATEWAY -i $INTERFACE -o audit_results --tcpdump

echo "Audit complete!"
--------------------------------------------------------------------------------------------

* Uso: ./full_audit.sh
* Dica: Detecta gateway automaticamente via ip route.
Esses exemplos assumem uma rede IPv4 padrão. Para IPv6 ou configurações avançadas, modifique os filtros BPF no código fonte.


----------------------Full Options-------------------------------

Run python3 npa.py -h for details:

-v, --victim: Target IP.
-g, --gateway: Gateway IP.
-i, --interface: Network interface.
-o, --output: Output dir (default: captures).
--cleanup-age: Hours before log cleanup (default: 24).
--tcpdump: Enable tcpdump analysis.
--tcpdump-filter: Custom tcpdump filter.
--pcap-input: Input PCAP file.
--scan-network: Scan local network.
-V, --version: Show version.
--list-interfaces: List interfaces.
------------------------------------------------------------------

---------------------Output Files-------------------------

*   PCAP: capture_YYYYMMDD_HHMMSS.pcap (Wireshark-readable).
*   HTTP Extracts: http_YYYYMMDD_HHMMSS_mime.ext (e.g., images, PDFs).
*   HTTPS Payloads: https_YYYYMMDD_HHMMSS_sni.bin.
*   TLS Certs: tls_cert_YYYYMMDD_HHMMSS_sni.pem (with OpenSSL analysis).
*   Logs: DNS/ICMP scans, network scans (e.g., network_scan_YYYYMMDD_HHMMSS.log).

------------------------------------------------------------------------------------

---------------------------------Troubleshooting----------------------

*   Permission Denied: Run with sudo for live modes.
*   Interface Not Found: Use --list-interfaces.
*   No MAC Resolved: Check network connectivity; increase ARP timeout.
*   Dependencies Missing: See Installation.
*   Toilet Not Found: Falls back to simple borders; install for fancy banners.
--------------------------------------------------------------------------------

-------------------------------Legal Notice ⚠️---------------------------

This tool is for EDUCATIONAL and AUTHORIZED USE ONLY.

*   ARP poisoning and packet interception may violate laws (e.g., Wiretap Act, CFAA) if used without explicit permission.
*   Obtain written consent from network owners before use.
*   xAI and contributors are not liable for misuse.

For ethical guidelines, refer to OWASP Testing Guide or CREST standards.
---------------------------------------------------------------------------

-------------------------------Contributing-----------------------------

*   Fork the repo.
*   Submit PRs for features/bug fixes.
*   Report issues with repro steps.
----------------------------------------

```
