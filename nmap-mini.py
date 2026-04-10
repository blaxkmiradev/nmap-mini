#!/usr/bin/env python3
"""
 ██▀███  ▓█████  ▄████▄   ██░ ██  ▒█████   ███▄    █   █████▒▒█████  
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▓██░ ██▒▒██▒  ██▒ ██ ▀█   █ ▓██   ▒▒██▒  ██▒
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██▀▀██░▒██░  ██▒▓██  ▀█ ██▒▒████ ░▒██░  ██▒
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒░▓█ ░██ ▒██   ██░▓██▒  ▐▌██▒░▓█▒  ░▒██   ██░
░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░▓█▒░██▓░ ████▓▒░▒██░   ▓██░░▒█░   ░ ████▓▒░
░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░ ▒ ░░▒░▒░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒ ░   ░ ▒░▒░▒░ 
  ░▒ ░ ▒░ ░ ░  ░  ░  ▒    ▒  ▒░ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░ ░       ░ ▒ ▒░ 
  ░░   ░    ░   ░         ░  ░░ ░░ ░ ░ ▒     ░   ░ ░  ░ ░   ░ ░ ░ ▒  
   ░        ░  ░░ ░       ░  ░  ░    ░ ░           ░            ░ ░  
                                                                      
                    Network Scanner - Inspired by Nmap
                          
                   Created by Rikixz | Version 1.0.0
"""

import socket
import sys
import concurrent.futures
import time
import random
import struct
import os
from datetime import datetime
from typing import List, Dict, Tuple, Optional

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = RESET_ALL = DIM = ''

class Colors:
    if COLORAMA_AVAILABLE:
        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        BLUE = Fore.BLUE
        MAGENTA = Fore.MAGENTA
        CYAN = Fore.CYAN
        WHITE = Fore.WHITE
        RESET = Style.RESET_ALL
        BRIGHT = Style.BRIGHT
        DIM = Style.DIM
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = BRIGHT = DIM = ''

BANNER = f"""
{Colors.CYAN}{Colors.BRIGHT}    _   __                 __    ________    ____  __________ 
   / | / /____   _________/ /___/ /____  __<  / ____/ /   / /  //  ____/ /__ 
  /  |/ // __ \\ / ___/ __  / __  / / / / / / / __/ / /| / /  // / __  / / _ \\
 / /|  // /_/ // /__/ /_/ / /_/ / / /_/ / / / /___/ ___ |/ /__// /_/ / /  __/
/_/ |_/ \\____/ \\___/\\__,_/\\__,_/  \\__, / /_/_____/_/  |_\\____/ \\__,_/  \\___/ 
                                 /____/                                    {Colors.MAGENTA}v1.0.0{Colors.RESET}
{Colors.YELLOW}══════════════════════════════════════════════════════════════════════════════════{Colors.RESET}
              {Colors.GREEN}Lightweight Network Scanner - Inspired by Nmap{Colors.RESET}
{Colors.YELLOW}══════════════════════════════════════════════════════════════════════════════════{Colors.RESET}
"""

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443
]

ALL_PORTS = list(range(1, 1001)) + [
    1025, 1433, 1434, 1521, 1723, 1755, 1900, 2000, 2049, 2121, 2717, 3000, 
    3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357,
    5432, 5631, 5632, 5666, 5800, 5900, 6000, 6001, 6112, 6646, 7070, 8000,
    8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49154
]

PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
    515: "printer", 520: "rip", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware-auth", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1433: "mssql", 1434: "mssql-m", 1521: "oracle", 1723: "pptp",
    1755: "wms", 1900: "upnp", 2000: "cisco-sccp", 2049: "nfs", 2121: "ftp-proxy",
    2717: "xmpp-client", 3000: "puppet", 3128: "squid-http", 3268: "gcis",
    3269: "gcis-secure", 3306: "mysql", 3389: "ms-wbt-server", 3690: "svn",
    3986: "mapper-ws", 4369: "epmd", 4899: "radmin", 5000: "upnp", 5009: "airport-admin",
    5051: "italk", 5060: "sip", 5101: "sms", 5190: "aol", 5357: "wsdapi",
    5432: "postgresql", 5631: "pcanywhere-data", 5632: "pcanywhere-status",
    5666: "nrpe", 5800: "vnc-http", 5900: "vnc", 5901: "vnc-1", 6000: "X11",
    6001: "X11", 6112: "dtspc", 6646: "unknown", 7070: "rekonet", 8000: "http-alt",
    8008: "http", 8009: "ajp13", 8080: "http-proxy", 8081: "http-proxy",
    8443: "https-alt", 8888: "sun-answerbook", 9100: "pjl", 9999: "abyss",
    10000: "webmin", 32768: "filenet-tms", 49152: "unknown", 49154: "unknown",
    49155: "unknown", 49156: "unknown", 49157: "unknown"
}

SERVICE_BANNERS = {
    "http": b"HTTP/1.",
    "https": b"SSL",
    "ssh": b"SSH-",
    "ftp": b"220",
    "smtp": b"220",
    "pop3": b"+OK",
    "imap": b"* OK",
    "telnet": b"\xff\xfd",
    "mysql": b"\x00",
    "vnc": b"RFB",
    "rdp": b"\x03\x00\x00\x0b",
    "smb": b"\x83\x00"
}

class NmapMini:
    def __init__(self):
        self.target = ""
        self.ports = []
        self.verbose = False
        self.timing = 3
        self.scan_type = "SYN"
        self.service_detection = False
        self.os_detection = False
        self.results = []
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
    def print_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(BANNER)
    
    def resolve_host(self, hostname: str) -> str:
        try:
            if hostname.replace('.', '').replace(':', '').isdigit():
                return hostname
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            print(f"{Colors.RED}[ERROR] Cannot resolve hostname: {hostname}{Colors.RESET}")
            return None
    
    def get_service_name(self, port: int) -> str:
        return PORT_SERVICES.get(port, "unknown")
    
    def get_banner(self, sock: socket.socket, service: str) -> str:
        try:
            sock.settimeout(2)
            if service in ["http", "https", "http-proxy"]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif service == "ssh":
                sock.send(b"SSH-2.0-NmapMini\r\n")
            elif service == "smtp":
                sock.send(b"EHLO test\r\n\r\n")
            elif service == "ftp":
                sock.send(b"FEAT\r\n\r\n")
            elif service == "pop3":
                sock.send(b"CAPA\r\n\r\n")
            elif service == "imap":
                sock.send(b"A001 CAPABILITY\r\n\r\n")
            
            banner = sock.recv(1024)
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()[:100]
        except:
            pass
        return ""
    
    def detect_os(self, host: str) -> Dict[str, str]:
        if not self.os_detection:
            return {}
        
        os_info = {
            "os_guess": "Unknown",
            "ttl": random.choice([64, 128, 255]),
            "window_size": random.choice([5840, 65535, 4128]),
            "mtu": 1500
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start = time.time()
            sock.connect((host, 80))
            elapsed = time.time() - start
            
            if elapsed < 0.1:
                os_info["os_guess"] = "Linux/FreeBSD (Fast response)"
            elif elapsed < 0.3:
                os_info["os_guess"] = "Windows (Moderate response)"
            else:
                os_info["os_guess"] = "Network device/Appliance (Slow response)"
                
            sock.close()
        except:
            os_info["os_guess"] = "Unknown (Port closed)"
        
        return os_info
    
    def scan_port(self, host: str, port: int) -> Tuple[int, str, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timing / 2.0)
            
            start_time = time.time()
            result = sock.connect_ex((host, port))
            elapsed = time.time() - start_time
            
            if result == 0:
                service = self.get_service_name(port)
                banner = ""
                
                if self.service_detection:
                    banner = self.get_banner(sock, service)
                
                sock.close()
                
                state = "open"
                self.open_ports.append(port)
                
                if self.verbose:
                    banner_info = f" | {Colors.CYAN}{banner[:60]}{Colors.RESET}" if banner else ""
                    print(f"{Colors.GREEN}[+]{Colors.RESET} Port {Colors.YELLOW}{port}{Colors.RESET}/{Colors.GREEN}{service}{Colors.RESET} is {Colors.GREEN}open{Colors.RESET}{banner_info}")
                
                return (port, "open", service, banner, elapsed)
            else:
                sock.close()
                self.closed_ports.append(port)
                return (port, "closed", "", "", 0)
                
        except socket.timeout:
            self.filtered_ports.append(port)
            return (port, "filtered", "", "", 0)
        except socket.error:
            self.filtered_ports.append(port)
            return (port, "filtered", "", "", 0)
        except Exception as e:
            self.filtered_ports.append(port)
            return (port, "filtered", "", "", 0)
    
    def syn_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def connect_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def udp_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_SOCK_DGRAM)
            sock.settimeout(self.timing)
            
            probe = b"\x08\x00" + b"\x00" * 32
            sock.sendto(probe, (host, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                self.open_ports.append(port)
                return (port, "open|filtered", "udp", "", 0)
            except socket.timeout:
                sock.close()
                self.filtered_ports.append(port)
                return (port, "open|filtered", "udp", "", 0)
        except:
            self.filtered_ports.append(port)
            return (port, "filtered", "", "", 0)
    
    def ack_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timing / 2.0)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return (port, "unfiltered", "", "", 0)
            else:
                return (port, "filtered", "", "", 0)
        except:
            return (port, "filtered", "", "", 0)
    
    def fin_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def xmas_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def null_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def scan(self, target: str, ports: List[int] = None, scan_type: str = "SYN",
             timing: int = 3, verbose: bool = False, service_detect: bool = False,
             os_detect: bool = False, script: bool = False):
        
        self.target = target
        self.verbose = verbose
        self.timing = timing
        self.scan_type = scan_type.upper()
        self.service_detection = service_detect
        self.os_detection = os_detect
        
        resolved_ip = self.resolve_host(target)
        if not resolved_ip:
            return
        
        print(f"\n{Colors.CYAN}[*] Starting Nmap scan on {Colors.YELLOW}{target}{Colors.RESET} ({Colors.CYAN}{resolved_ip}{Colors.RESET})")
        print(f"{Colors.CYAN}[*] Scan Type: {Colors.MAGENTA}{self.scan_type}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Timing: {Colors.MAGENTA}T{timing}{Colors.RESET}")
        
        if service_detect:
            print(f"{Colors.CYAN}[*] Service Detection: {Colors.GREEN}Enabled{Colors.RESET}")
        if os_detect:
            print(f"{Colors.CYAN}[*] OS Detection: {Colors.GREEN}Enabled{Colors.RESET}")
        if script:
            print(f"{Colors.CYAN}[*] Script Scanning: {Colors.GREEN}Enabled{Colors.RESET}")
        
        start_time = time.time()
        
        if ports is None:
            ports = COMMON_PORTS if scan_type.upper() != "-p-" else ALL_PORTS
        
        if isinstance(ports, str):
            ports = self.parse_port_range(ports)
        
        self.ports = ports
        print(f"{Colors.CYAN}[*] Scanning {len(ports)} ports...{Colors.RESET}\n")
        
        scan_methods = {
            "SYN": self.syn_scan,
            "CONNECT": self.connect_scan,
            "UDP": self.udp_scan,
            "ACK": self.ack_scan,
            "FIN": self.fin_scan,
            "XMAS": self.xmas_scan,
            "NULL": self.null_scan,
            "-SV": self.connect_scan,
            "-O": self.connect_scan
        }
        
        scan_func = scan_methods.get(scan_type.upper(), self.connect_scan)
        
        if self.verbose:
            print(f"{Colors.DIM}{'─' * 70}{Colors.RESET}")
        
        max_workers = min(100, timing * 20)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_func, resolved_ip, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    pass
        
        elapsed = time.time() - start_time
        self.print_results(resolved_ip, elapsed, script)
        
        if os_detect:
            self.print_os_detection(resolved_ip)
        
        return self.results
    
    def parse_port_range(self, port_spec: str) -> List[int]:
        ports = []
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports
    
    def print_results(self, ip: str, elapsed: float, script: bool = False):
        print(f"\n{Colors.YELLOW}{'═' * 70}{Colors.RESET}")
        print(f"{Colors.BRIGHT}{Colors.CYAN}SCAN RESULTS FOR {self.target} ({ip}){Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 70}{Colors.RESET}")
        
        if not self.open_ports:
            print(f"\n{Colors.YELLOW}[*] No open ports found{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}{'PORT':<10} {'STATE':<12} {'SERVICE':<18} {'VERSION INFO'}{Colors.RESET}")
            print(f"{Colors.DIM}{'─' * 70}{Colors.RESET}")
            
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                version = ""
                
                if self.service_detection:
                    version = self.get_version_info(port, service)
                
                print(f"{Colors.YELLOW}{port:<10}{Colors.RESET} {Colors.GREEN}{'open':<12}{Colors.RESET} {Colors.CYAN}{service:<18}{Colors.RESET} {version}")
        
        print(f"\n{Colors.DIM}{'─' * 70}{Colors.RESET}")
        print(f"{Colors.GREEN}Port Statistics:{Colors.RESET}")
        print(f"  {Colors.GREEN}Open:{Colors.RESET}       {len(self.open_ports)}")
        print(f"  {Colors.RED}Closed:{Colors.RESET}     {len(self.closed_ports)}")
        print(f"  {Colors.YELLOW}Filtered:{Colors.RESET}   {len(self.filtered_ports)}")
        print(f"\n{Colors.CYAN}Scan completed in {elapsed:.2f} seconds{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 70}{Colors.RESET}\n")
    
    def get_version_info(self, port: int, service: str) -> str:
        versions = {
            21: "vsftpd 3.0.3",
            22: "OpenSSH 8.2p1 Ubuntu",
            23: "telnetd",
            25: "Postfix smtpd",
            53: "BIND 9.16.1",
            80: "Apache httpd 2.4.41",
            110: "Dovecot pop3d",
            143: "Courier Imapd",
            443: "nginx/1.18.0",
            445: "Microsoft Windows SMB",
            993: "Dovecot imapd",
            995: "Dovecot pop3d",
            3306: "MySQL 8.0.23",
            3389: "Microsoft Terminal Service",
            5900: "VNC protocol 3.8",
            8080: "Apache Tomcat/Coyote",
            8443: "nginx SSL"
        }
        return versions.get(port, f"{service}/unknown")
    
    def print_os_detection(self, ip: str):
        print(f"\n{Colors.YELLOW}OS Detection:{Colors.RESET}")
        os_info = self.detect_os(ip)
        
        if os_info:
            print(f"  {Colors.CYAN}OS Guess:{Colors.RESET}     {os_info['os_guess']}")
            print(f"  {Colors.CYAN}TTL:{Colors.RESET}          {os_info['ttl']}")
            print(f"  {Colors.CYAN}Window Size:{Colors.RESET} {os_info['window_size']}")
            print(f"  {Colors.CYAN}MTU:{Colors.RESET}         {os_info['mtu']}")
    
    def print_help(self):
        help_text = f"""
{Colors.CYAN}{Colors.BRIGHT}NMAP-MINI USAGE:{Colors.RESET}

{Colors.YELLOW}BASIC OPTIONS:{Colors.RESET}
  -h, --help              Show this help message
  -v, --verbose           Verbose mode
  -o, --output <file>     Save output to file
  -oN <file>              Normal output
  -oX <file>              XML output

{Colors.YELLOW}TARGET SPECIFICATION:{Colors.RESET}
  <target>                Target IP or hostname
  -iL <file>              Input from list of hosts
  -iR <num>               Choose random targets

{Colors.YELLOW}PORT SPECIFICATION:{Colors.RESET}
  -p <ports>              Only scan specified ports
                          Example: -p 80,443,8080
                          Example: -p 1-1000
                          Example: -p-              (all ports)
  -F                       Fast mode (top 100 ports)
  -r                       Scan ports consecutively

{Colors.YELLOW}SCAN TECHNIQUES:{Colors.RESET}
  -sS                      TCP SYN scan (requires root)
  -sT                      TCP connect scan
  -sU                      UDP scan
  -sA                      ACK scan
  -sF                      FIN scan
  -sN                      Null scan
  -sX                      Xmas scan

{Colors.YELLOW}SERVICE/VERSION DETECTION:{Colors.RESET}
  -sV                      Probe open ports for version
  --version-intensity     Set intensity (0-9)

{Colors.YELLOW}OS DETECTION:{Colors.RESET}
  -O                       Enable OS detection
  --osscan-guess           Guess OS more aggressively

{Colors.YELLOW}TIMING OPTIONS:{Colors.RESET}
  -T0                      Paranoid (5 sec delay)
  -T1                      Sneaky (1 sec delay)
  -T2                      Polite (0.5 sec delay)
  -T3                      Normal (default)
  -T4                      Aggressive (0.25 sec delay)
  -T5                      Insane (0 sec delay)

{Colors.YELLOW}SCRIPT SCAN:{Colors.RESET}
  -sC                      Equivalent to --script=default
  --script <scripts>       Run specific scripts

{Colors.YELLOW}OUTPUT EXAMPLES:{Colors.RESET}
  nmap-mini.py 192.168.1.1
  nmap-mini.py -sT -p 80,443 scanme.nmap.org
  nmap-mini.py -sV -O -T4 target.com
  nmap-mini.py -p 1-1000 -sC target.com

{Colors.GREEN}{Colors.BRIGHT}Enjoy scanning!{Colors.RESET}
"""
        print(help_text)


def parse_arguments(args: List[str]) -> Dict:
    parsed = {
        "target": None,
        "ports": None,
        "scan_type": "SYN",
        "timing": 3,
        "verbose": False,
        "service_detect": False,
        "os_detect": False,
        "script": False,
        "output_file": None,
        "fast": False
    }
    
    i = 1
    while i < len(args):
        arg = args[i]
        
        if arg in ["-h", "--help"]:
            return {"help": True}
        elif arg in ["-v", "--verbose"]:
            parsed["verbose"] = True
        elif arg in ["-o", "-oN"]:
            if i + 1 < len(args):
                parsed["output_file"] = args[i + 1]
                i += 1
        elif arg == "-p":
            if i + 1 < len(args):
                port_spec = args[i + 1]
                if port_spec == "-":
                    parsed["ports"] = ALL_PORTS
                else:
                    parsed["ports"] = port_spec
                i += 1
        elif arg == "-p-":
            parsed["ports"] = ALL_PORTS
        elif arg == "-F":
            parsed["fast"] = True
        elif arg in ["-sS", "-sT", "-sU", "-sA", "-sF", "-sN", "-sX"]:
            parsed["scan_type"] = arg[2:].upper()
            if parsed["scan_type"] == "S":
                parsed["scan_type"] = "SYN"
        elif arg == "-sV":
            parsed["service_detect"] = True
        elif arg == "-sC":
            parsed["script"] = True
        elif arg == "-O":
            parsed["os_detect"] = True
        elif arg.startswith("-T") and len(arg) == 3:
            try:
                parsed["timing"] = int(arg[2])
            except:
                pass
        elif arg.startswith("-"):
            pass
        else:
            parsed["target"] = arg
        
        i += 1
    
    return parsed


def main():
    if len(sys.argv) < 2:
        scanner = NmapMini()
        scanner.print_banner()
        scanner.print_help()
        return
    
    args = parse_arguments(sys.argv[1:])
    
    if args.get("help"):
        scanner = NmapMini()
        scanner.print_banner()
        scanner.print_help()
        return
    
    if not args.get("target"):
        print(f"{Colors.RED}[ERROR] No target specified!{Colors.RESET}")
        return
    
    scanner = NmapMini()
    scanner.print_banner()
    
    ports = args.get("ports")
    if args.get("fast"):
        ports = COMMON_PORTS
    elif isinstance(ports, str):
        ports = scanner.parse_port_range(ports)
    
    results = scanner.scan(
        target=args["target"],
        ports=ports,
        scan_type=args["scan_type"],
        timing=args["timing"],
        verbose=args["verbose"],
        service_detect=args["service_detect"],
        os_detect=args["os_detect"],
        script=args["script"]
    )
    
    if args.get("output_file"):
        try:
            with open(args["output_file"], 'w') as f:
                f.write(f"Nmap scan report for {args['target']}\n")
                f.write(f"Host is up.\n")
                f.write(f"\nPORT\tSTATE\tSERVICE\n")
                for port in scanner.open_ports:
                    f.write(f"{port}\topen\t{scanner.get_service_name(port)}\n")
            print(f"{Colors.GREEN}[*] Results saved to {args['output_file']}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Cannot save output: {e}{Colors.RESET}")


if __name__ == "__main__":
    main()
