# Nmap-mini

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.7+-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Platform-Windows/Linux/Mac-orange?style=for-the-badge">
</p>

<p align="center">
  <b>A lightweight, colorful network scanner inspired by Nmap</b>
  <br>
  <i>Created by Rikixz</i>
</p>

---

## 📋 Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Scan Types](#scan-types)
- [Command Options](#command-options)
- [Usage Examples](#usage-examples)
- [OS Detection](#os-detection)
- [Service Detection](#service-detection)
- [Advanced Usage](#advanced-usage)
- [Output Examples](#output-examples)
- [Port Reference](#port-reference)
- [Disclaimer](#disclaimer)

---

## 📖 About

**Nmap-mini** is a lightweight, Python-based network scanner that provides a colorful, user-friendly interface for network reconnaissance. Inspired by the legendary Nmap tool, it offers essential scanning capabilities with beautiful terminal output.

### Key Features
- 🔍 **Multiple Scan Types** - SYN, TCP Connect, UDP, ACK, FIN, Xmas, Null scans
- 🖥️ **OS Detection** - Identify remote operating systems
- 📡 **Service Detection** - Detect running services and versions
- 🎨 **Colorful Output** - Beautiful terminal UI with color-coded results
- ⚡ **Fast Scanning** - Multi-threaded concurrent port scanning
- 📝 **Export Results** - Save scan results to files
- 🌐 **Full Port Scan** - Scan all 65,535 ports
- 📊 **Top Ports** - Quick scan with top 100 most common ports
- 🔢 **500+ Services** - Extensive service/port database

---

## 🚀 Installation

### Prerequisites
```bash
Python 3.7 or higher
```

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/blaxkmiradev/nmap-mini.git
cd nmap-mini

# Install required package
pip install colorama
```

### For Linux/Mac (Optional - Root Required for SYN Scans)
```bash
sudo pip install colorama
sudo chmod +x nmap-mini.py
```

---

## ⚡ Quick Start

### Basic Scan
```bash
# Scan a single target with default settings
python nmap-mini.py 192.168.1.1
```

### Scan Specific Ports
```bash
# Scan common web ports
python nmap-mini.py -p 80,443,8080 target.com

# Scan port range
python nmap-mini.py -p 1-1000 192.168.1.1

# Fast scan (top 100 ports)
python nmap-mini.py -F target.com

# Full scan (all 65535 ports)
python nmap-mini.py -p- target.com
```

### Service and Version Detection
```bash
# Enable service version detection
python nmap-mini.py -sV target.com
```

### OS Detection
```bash
# Detect operating system
python nmap-mini.py -O target.com
```

### Full Scan
```bash
# Comprehensive scan with all features
python nmap-mini.py -sV -O -T4 -p- target.com
```

---

## 🔍 Scan Types

| Flag | Scan Type | Description | Requires Root |
|------|-----------|-------------|---------------|
| `-sS` | TCP SYN Scan | Stealth scan, sends SYN packets | ✅ Yes |
| `-sT` | TCP Connect | Full TCP connection scan | ❌ No |
| `-sU` | UDP Scan | Scans UDP ports | ❌ No |
| `-sA` | ACK Scan | Firewall detection | ❌ No |
| `-sF` | FIN Scan | Stealth scan, no response expected | ❌ No |
| `-sN` | Null Scan | Stealth scan with no flags | ❌ No |
| `-sX` | Xmas Scan | Stealth scan with all flags | ❌ No |

### Scan Type Details

#### 🔹 TCP SYN Scan (`-sS`)
- **Best for:** Stealth scanning, fast reconnaissance
- **Behavior:** Sends SYN packet, analyzes response
- **Advantages:** Less likely to be logged, faster
- **Note:** Requires administrator/root privileges

#### 🔹 TCP Connect Scan (`-sT`)
- **Best for:** When you don't have root access
- **Behavior:** Completes full TCP 3-way handshake
- **Advantages:** Works without special privileges, reliable
- **Note:** More likely to be logged by firewalls

#### 🔹 UDP Scan (`-sU`)
- **Best for:** Finding DNS, DHCP, SNMP services
- **Behavior:** Sends UDP packets, analyzes ICMP responses
- **Advantages:** Discovers UDP-based services
- **Note:** Slower than TCP scans

#### 🔹 Stealth Scans (`-sF`, `-sN`, `-sX`)
- **Best for:** Bypassing basic firewall rules
- **Behavior:** Send malformed packets
- **Advantages:** Can evade simple firewall detection
- **Note:** May not work against all systems

---

## 📋 Command Options

### Target Specification

| Option | Description | Example |
|--------|-------------|---------|
| `<target>` | Target IP or hostname | `192.168.1.1` |
| `-iL <file>` | Scan from host list file | `-iL hosts.txt` |

### Port Specification

| Option | Description | Example |
|--------|-------------|---------|
| `-p <ports>` | Scan specific ports | `-p 80,443,8080` |
| `-p <range>` | Scan port range | `-p 1-1000` |
| `-p-` | Scan ALL 65,535 ports | `-p-` |
| `-F` | Fast scan (top 100 ports) | `-F` |
| `-r` | Scan ports sequentially | `-r` |

### Detection Options

| Option | Description |
|--------|-------------|
| `-sV` | Enable service/version detection |
| `-O` | Enable OS detection |
| `-sC` | Run default scripts |

### Timing Options

| Option | Timing | Description | Delay |
|--------|--------|-------------|-------|
| `-T0` | Paranoid | IDS evasion | 5 sec |
| `-T1` | Sneaky | IDS evasion | 1 sec |
| `-T2` | Polite | Slow scan | 0.5 sec |
| `-T3` | Normal | Default speed | Dynamic |
| `-T4` | Aggressive | Fast scan | 0.25 sec |
| `-T5` | Insane | Fastest scan | 0 sec |

### Output Options

| Option | Description |
|--------|-------------|
| `-o <file>` | Save output to file |
| `-v` | Verbose mode |
| `-vv` | Very verbose mode |

### Other Options

| Option | Description |
|--------|-------------|
| `-h` | Show help message |
| `--help` | Show full help |

---

## 💡 Usage Examples

### 🔸 Basic Examples

```bash
# Scan localhost
python nmap-mini.py 127.0.0.1

# Scan a website
python nmap-mini.py example.com

# Scan with verbose output
python nmap-mini.py -v 192.168.1.1

# Save results to file
python nmap-mini.py -o scan.txt 192.168.1.1
```

### 🔸 Port Selection Examples

```bash
# Scan specific ports
python nmap-mini.py -p 22,80,443 target.com

# Scan port range
python nmap-mini.py -p 1-100 target.com

# Scan common ports only
python nmap-mini.py -F target.com

# Scan all ports (slow)
python nmap-mini.py -p- target.com

# Multiple ranges
python nmap-mini.py -p 22,80-100,443,8080 target.com
```

### 🔸 Scan Type Examples

```bash
# TCP SYN scan (requires root)
sudo python nmap-mini.py -sS target.com

# TCP Connect scan
python nmap-mini.py -sT target.com

# UDP scan
python nmap-mini.py -sU target.com

# ACK scan (firewall detection)
python nmap-mini.py -sA target.com

# FIN scan
python nmap-mini.py -sF target.com

# Xmas scan
python nmap-mini.py -sX target.com

# Null scan
python nmap-mini.py -sN target.com
```

### 🔸 Service & OS Detection Examples

```bash
# Service version detection
python nmap-mini.py -sV target.com

# OS detection
python nmap-mini.py -O target.com

# Both service and OS detection
python nmap-mini.py -sV -O target.com

# Aggressive timing with all detections
python nmap-mini.py -sV -O -T4 target.com
```

### 🔸 Advanced Examples

```bash
# Full comprehensive scan
python nmap-mini.py -sV -O -T4 -p- -v target.com

# Fast comprehensive scan
python nmap-mini.py -F -sV -T5 target.com

# Stealth scan with service detection
sudo python nmap-mini.py -sS -sV -T2 target.com

# Script scan
python nmap-mini.py -sC target.com

# UDP scan with timing
python nmap-mini.py -sU -T4 target.com
```

### 🔸 Real-World Scenarios

```bash
# Web server assessment
python nmap-mini.py -sV -p 80,443,8080,8443 target.com

# Full web application assessment
python nmap-mini.py -sV -sC -p 80,443,8080,8443,3000,5000 target.com

# Database server discovery
python nmap-mini.py -sV -p 1433,1521,3306,5432,6379,27017 target.com

# Network infrastructure scan
python nmap-mini.py -sT -p 22,23,161,162,389,636 target.com

# Windows environment scan
python nmap-mini.py -sV -p 135,139,445,3389,8080 target.com
```

---

## 🖥️ OS Detection

### How OS Detection Works

The `-O` flag enables OS detection, which analyzes various network characteristics to identify the remote operating system:

1. **TTL Analysis** - Measures time-to-live values
2. **Window Size** - Analyzes TCP window sizes
3. **Response Timing** - Measures response latencies
4. **TCP Flags** - Examines packet flag behaviors

### Example Output

```
══════════════════════════════════════════════════════════════════════
OS Detection:
  OS Guess:     Linux/FreeBSD (Fast response)
  TTL:          64
  Window Size:  65535
  MTU:          1500
══════════════════════════════════════════════════════════════════════
```

### OS Detection Flags

| Flag | Description |
|------|-------------|
| `-O` | Enable OS detection |
| `--osscan-guess` | Aggressive OS guessing |

### OS Detection Interpretation

| OS Type | TTL | Response Speed |
|---------|-----|----------------|
| Linux/FreeBSD | 64 | Fast (< 0.1s) |
| Windows | 128 | Moderate (0.1-0.3s) |
| Network Device | 255 | Slow (> 0.3s) |

---

## 📡 Service Detection

### How Service Detection Works

The `-sV` flag enables service and version detection:

1. **Port Detection** - Identifies open ports
2. **Service Identification** - Matches known services to ports
3. **Version Detection** - Probes services for version information
4. **Banner Grabbing** - Extracts service banners

### Detected Services

Nmap-mini recognizes 90+ common services including:

| Port | Service | Description |
|------|---------|-------------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell |
| 23 | Telnet | Unencrypted text communications |
| 25 | SMTP | Mail sending |
| 53 | DNS | Domain Name System |
| 80 | HTTP | Web server |
| 110 | POP3 | Mail retrieval |
| 143 | IMAP | Mail access |
| 443 | HTTPS | Secure web |
| 445 | SMB | Windows file sharing |
| 3306 | MySQL | Database |
| 3389 | RDP | Remote Desktop |
| 5432 | PostgreSQL | Database |
| 5900 | VNC | Remote desktop |

### Example Output

```
PORT       STATE      SERVICE           VERSION INFO
──────────────────────────────────────────────────────────────────────
22         open       ssh               OpenSSH 8.2p1 Ubuntu
80         open       http              Apache httpd 2.4.41
443        open       https             nginx/1.18.0
3306       open       mysql             MySQL 8.0.23
3389       open       ms-wbt-server     Microsoft Terminal Service
```

### Service Detection Flags

| Flag | Description |
|------|-------------|
| `-sV` | Probe open ports for version |
| `--version-intensity <0-9>` | Set probe intensity |

---

## 🎯 Advanced Usage

### Timing Templates

Control scan speed with timing options:

```bash
# IDS evasion (slowest)
python nmap-mini.py -T0 -p- target.com

# Stealth scan
python nmap-mini.py -T1 -p- target.com

# Polite (slower but polite)
python nmap-mini.py -T2 -p- target.com

# Normal (default)
python nmap-mini.py -T3 -p- target.com

# Aggressive (faster)
python nmap-mini.py -T4 -p- target.com

# Insane (fastest, may miss things)
python nmap-mini.py -T5 -p- target.com
```

### Verbose Output

```bash
# Basic verbose
python nmap-mini.py -v target.com

# Very verbose (shows every port)
python nmap-mini.py -vv target.com
```

### Combining Options

```bash
# Comprehensive scan
python nmap-mini.py -sV -O -T4 -p- -v target.com

# Quick assessment
python nmap-mini.py -F -sV -T4 target.com

# Stealth assessment
python nmap-mini.py -sS -T2 -p 1-1000 target.com
```

---

## 📊 Output Examples

### Standard Scan Output

```
══════════════════════════════════════════════════════════════════════
SCAN RESULTS FOR 192.168.1.1 (192.168.1.1)
══════════════════════════════════════════════════════════════════════

PORT       STATE      SERVICE           VERSION INFO
──────────────────────────────────────────────────────────────────────
22         open       ssh               OpenSSH 8.2p1 Ubuntu
80         open       http              Apache httpd 2.4.41
443        open       https             nginx/1.18.0
3306       open       mysql             MySQL 8.0.23

──────────────────────────────────────────────────────────────────────
Port Statistics:
  Open:       4
  Closed:     17
  Filtered:   0

Scan completed in 2.45 seconds
══════════════════════════════════════════════════════════════════════
```

### Verbose Output

```
[+] Port 22/ssh is open | OpenSSH 8.2p1 Ubuntu
[+] Port 80/http is open | Apache httpd 2.4.41
[+] Port 443/https is open | nginx/1.18.0
[+] Port 3306/mysql is open | MySQL 8.0.23
```

---

## 📖 Port Reference

### Scan Modes

| Mode | Ports | Command |
|------|-------|---------|
| Default | 21 common ports | (no flag) |
| Fast (-F) | Top 100 ports | `-F` |
| Custom | User specified | `-p 80,443` |
| Range | User specified | `-p 1-1000` |
| Full (-p-) | All 65535 ports | `-p-` |

### Common Port Ranges

| Range | Purpose | Examples |
|-------|---------|----------|
| 0-1023 | Well-known ports | 22, 80, 443 |
| 1024-49151 | Registered ports | 1433, 3306 |
| 49152-65535 | Dynamic ports | Random assignments |

### Top 100 Ports (Fast Scan)

The fast scan mode (-F) checks these most commonly used ports:
```
7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026,
1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
5357, 5432, 5631, 5632, 5666, 5800, 5900, 5901, 6000, 6001, 6646, 7070, 8000,
8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153,
49154, 49155, 49156, 49157, 50000, 51413
```

### Quick Reference

| Service | Port | Protocol |
|---------|------|----------|
| SSH | 22 | TCP |
| HTTP | 80 | TCP |
| HTTPS | 443 | TCP |
| MySQL | 3306 | TCP |
| RDP | 3389 | TCP |
| VNC | 5900 | TCP |
| DNS | 53 | TCP/UDP |
| SMTP | 25 | TCP |
| FTP | 21 | TCP |

---

## ⚠️ Disclaimer

**IMPORTANT: This tool is for educational and authorized testing purposes only.**

### Legal Notice

- 🔒 Use only on systems you have permission to scan
- 🚫 Unauthorized scanning may be illegal in your jurisdiction
- ⚖️ The user assumes all responsibility for misuse
- 📜 Check local laws and regulations before use

### Ethical Guidelines

✅ **DO:**
- Scan your own networks
- Test with permission
- Use for legitimate security assessments
- Learn network security concepts

❌ **DON'T:**
- Scan without permission
- Use for malicious purposes
- Attack production systems without consent
- Violate computer fraud laws

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👤 Author

**Created by Rikixz**

- GitHub: [github.com/blaxkmiradev](https://github.com/blaxkmiradev)
- Version: 1.0.0

---

## 🙏 Acknowledgments

- Inspired by the legendary [Nmap](https://nmap.org/) tool
- Built with Python 🐍
- Color output powered by [colorama](https://pypi.org/project/colorama/)

---

<p align="center">
  <strong>Made with ❤️ by Rikixz</strong>
  <br>
  <sub>Star ⭐ this repo if you find it useful!</sub>
</p>
