"""
modules/network_scan.py — Real network scanner for SPECTRE.

Engines:
  - ARP scan  : discover live hosts on LAN (reads /proc/net/arp + active probe)
  - Port scan : threaded TCP connect scan, pure Python socket
  - Ping sweep: ICMP reachability check via subprocess ping

Designed for Raspberry Pi Zero 2 W (512 MB RAM):
  - Max 20 concurrent threads
  - Streaming output (print as found, no buffering)
  - No heavy third-party imports
"""

import os
import socket
import http.client
import subprocess
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Simple in-memory cache so we don't re-query same MAC twice
_vendor_cache: dict = {}
from core.display import (
    print_info, print_ok, print_warn, print_err,
    print_section, print_progress_bar, prompt, Color
)

# ── Constants ──────────────────────────────────────────────────────────────────

MAX_THREADS   = 20          # safe ceiling for Pi Zero 2 W
SCAN_TIMEOUT  = 0.5         # seconds per port connect attempt
PING_TIMEOUT  = 1           # seconds per ping

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143,
    443, 445, 3306, 3389, 5900, 8080, 8443,
]

PORT_LABELS = {
    21:   "FTP",    22:  "SSH",    23:   "Telnet",
    25:   "SMTP",   53:  "DNS",    80:   "HTTP",
    110:  "POP3",   139: "NetBIOS",143:  "IMAP",
    443:  "HTTPS",  445: "SMB",    3306: "MySQL",
    3389: "RDP",    5900:"VNC",    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    while True:
        print_section("Network Scanning")
        for i, (label, _) in enumerate(_MENU, 1):
            print(f"  {Color.CYAN}[{i}]{Color.RESET}  {label}")
        print(f"\n  {Color.DIM}[0]  Back{Color.RESET}")

        choice = prompt("NetScan")
        if choice in ("0", ""):
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(_MENU)):
            print_warn("Invalid choice.")
            continue

        _, handler = _MENU[int(choice) - 1]
        handler()
        prompt("Press Enter to continue")


# ── ARP Scan ───────────────────────────────────────────────────────────────────

def _arp_scan_menu():
    print_section("ARP Scan")

    # Try to detect the local subnet automatically
    default_range = _detect_local_subnet() or "192.168.1.0/24"
    print_info(f"Detected subnet: {default_range}")

    target = prompt(f"Enter range [{default_range}]") or default_range

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print_err(f"Invalid network range: {target}")
        return

    print_info(f"ARP scanning {network} ...")
    hosts = _arp_scan(network)

    if not hosts:
        print_warn("No hosts found.")
        return

    print(f"\n  {Color.GREEN}Found {len(hosts)} host(s):{Color.RESET}\n")
    print(f"  {'IP':<18} {'MAC':<20} {'VENDOR':<22} {'HOSTNAME'}")
    print(f"  {'─'*18} {'─'*20} {'─'*22} {'─'*20}")
    for ip, mac, hostname in hosts:
        vendor = _mac_vendor(mac)
        print(f"  {Color.CYAN}{ip:<18}{Color.RESET} "
              f"{mac:<20} "
              f"{Color.YELLOW}{vendor:<22}{Color.RESET} "
              f"{Color.DIM}{hostname}{Color.RESET}")


def _arp_scan(network: ipaddress.IPv4Network) -> list:
    """
    ARP scan strategy:
      1. Ping every host to populate the ARP cache (parallel, fast)
      2. Read /proc/net/arp (Linux) or use arp -a (Windows/Linux fallback)
    Returns list of (ip, mac, hostname) tuples.
    """
    hosts = list(network.hosts())
    total = len(hosts)

    # Step 1: ping flood to populate ARP cache
    print_info(f"Probing {total} addresses...")
    _ping_sweep_parallel([str(h) for h in hosts], silent=True)

    # Step 2: read ARP table
    results = _read_arp_table()

    # Filter: only real unicast hosts in the target network
    broadcast = str(network.broadcast_address)
    in_range = []
    for ip, mac in results.items():
        try:
            addr = ipaddress.ip_address(ip)
            if (addr in network
                    and ip != broadcast
                    and mac != "ff:ff:ff:ff:ff:ff"):
                hostname = _resolve_hostname(ip)
                in_range.append((ip, mac, hostname))
        except ValueError:
            continue

    return sorted(in_range, key=lambda x: ipaddress.ip_address(x[0]))


def _read_arp_table() -> dict:
    """Return {ip: mac} from the OS ARP cache."""
    table = {}

    if os.path.exists("/proc/net/arp"):
        # Linux: parse /proc/net/arp directly
        with open("/proc/net/arp") as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3]
    else:
        # Windows / macOS fallback: arp -a
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
            for line in out.splitlines():
                parts = line.split()
                # Windows format: "192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic"
                if len(parts) >= 2:
                    ip  = parts[0].strip("()")
                    mac = parts[1].replace("-", ":")
                    try:
                        ipaddress.ip_address(ip)
                        if mac.count(":") == 5:
                            table[ip] = mac
                    except ValueError:
                        continue
        except Exception:
            pass

    return table


def _detect_local_subnet() -> str:
    """Best-effort: return local subnet like 192.168.1.0/24."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        # Assume /24 — good enough for home/lab networks
        base = ".".join(ip.split(".")[:3]) + ".0/24"
        return base
    except Exception:
        return None


# ── Port Scan ──────────────────────────────────────────────────────────────────

def _port_scan_menu():
    print_section("Port Scan")

    target = prompt("Target IP / hostname")
    if not target:
        return

    print(f"\n  {Color.CYAN}[1]{Color.RESET}  Common ports ({len(COMMON_PORTS)} ports)")
    print(f"  {Color.CYAN}[2]{Color.RESET}  Custom range (e.g. 1-1024)")
    mode = prompt("Mode [1]") or "1"

    if mode == "2":
        raw = prompt("Port range (start-end)")
        try:
            start, end = map(int, raw.split("-"))
            ports = list(range(start, end + 1))
        except Exception:
            print_err("Invalid range. Use format: 1-1024")
            return
    else:
        ports = COMMON_PORTS

    # Resolve hostname before scanning
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print_err(f"Cannot resolve: {target}")
        return

    print_info(f"Scanning {target} ({ip}) — {len(ports)} ports ...")
    print(f"\n  {'PORT':<8} {'STATE':<10} {'SERVICE'}")
    print(f"  {'─'*8} {'─'*10} {'─'*12}")

    open_count = 0
    done_count = 0
    total      = len(ports)
    lock       = threading.Lock()
    open_ports = []

    def scan_port(port):
        nonlocal open_count, done_count
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SCAN_TIMEOUT)
                result = s.connect_ex((ip, port))
                if result == 0:
                    label = PORT_LABELS.get(port, "unknown")
                    with lock:
                        open_count += 1
                        open_ports.append((port, label))
        except Exception:
            pass
        finally:
            with lock:
                done_count += 1
                print_progress_bar(done_count, total, f"{done_count}/{total} ports")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        list(as_completed([ex.submit(scan_port, p) for p in ports]))

    # Print results after progress bar finishes
    if open_ports:
        print()
        for port, label in sorted(open_ports):
            print(f"  {Color.GREEN}{port:<8}{Color.RESET} {'open':<10} {label}")

    print(f"\n  {Color.CYAN}Scan complete.{Color.RESET} {open_count} open port(s) found.")


# ── Ping Sweep ─────────────────────────────────────────────────────────────────

def _ping_sweep_menu():
    print_section("Ping Sweep")

    default = _detect_local_subnet() or "192.168.1.0/24"
    target  = prompt(f"Network range [{default}]") or default

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print_err(f"Invalid range: {target}")
        return

    hosts = [str(h) for h in network.hosts()]
    print_info(f"Pinging {len(hosts)} hosts ...")
    print(f"\n  {'HOST':<20} STATUS")
    print(f"  {'─'*20} {'─'*8}")

    alive = _ping_sweep_parallel(hosts, silent=False)
    print(f"\n  {Color.CYAN}Done.{Color.RESET} {alive} host(s) alive.")


def _ping_sweep_parallel(hosts: list, silent: bool) -> int:
    """Ping hosts in parallel. Returns count of alive hosts."""
    alive      = 0
    done_count = 0
    total      = len(hosts)
    lock       = threading.Lock()
    alive_list = []

    is_windows = os.name == "nt"

    def ping(ip):
        nonlocal alive, done_count
        try:
            if is_windows:
                cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip]
            r = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=PING_TIMEOUT + 1
            )
            if r.returncode == 0:
                with lock:
                    alive += 1
                    alive_list.append(ip)
        except Exception:
            pass
        finally:
            with lock:
                done_count += 1
                if not silent:
                    print_progress_bar(done_count, total, f"{done_count}/{total} hosts")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        list(as_completed([ex.submit(ping, h) for h in hosts]))

    if not silent and alive_list:
        print()
        for ip in sorted(alive_list, key=lambda x: [int(o) for o in x.split(".")]):
            print(f"  {Color.GREEN}{ip:<20}{Color.RESET} alive")

    return alive


# ── Banner Grab ────────────────────────────────────────────────────────────────

def _banner_grab_menu():
    print_section("Banner Grabber")
    target = prompt("Target IP / hostname")
    if not target:
        return

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print_err(f"Cannot resolve: {target}")
        return

    ports_input = prompt(f"Ports to grab [{','.join(map(str, COMMON_PORTS[:8]))}]")
    if ports_input:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except ValueError:
            print_err("Invalid port list. Use: 22,80,443")
            return
    else:
        ports = COMMON_PORTS

    print_info(f"Grabbing banners from {ip} ...\n")
    grabbed = 0

    for port in ports:
        banner = _grab_banner(ip, port)
        if banner:
            grabbed += 1
            service = PORT_LABELS.get(port, "unknown")
            print(f"  {Color.GREEN}:{port:<6}{Color.RESET} {Color.CYAN}{service:<12}{Color.RESET} "
                  f"{Color.DIM}{banner[:60]}{Color.RESET}")

    if grabbed == 0:
        print_warn("No banners received — ports may be closed or filtered.")
    else:
        print(f"\n  {Color.CYAN}Grabbed {grabbed} banner(s).{Color.RESET}")


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Connect to port and read first response bytes. Returns clean banner string."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return ""
            # Send HTTP request for web ports, else just read
            if port in (80, 8080, 8443):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 443:
                return ""  # skip SSL for now
            else:
                s.sendall(b"\r\n")

            data = s.recv(1024)
            banner = data.decode(errors="replace").strip()
            # Clean to first meaningful line
            first_line = banner.splitlines()[0] if banner else ""
            return first_line[:80]
    except Exception:
        return ""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


def _mac_vendor(mac: str) -> str:
    """Look up MAC vendor via macvendors.com API. Returns vendor name or ''."""
    if mac in _vendor_cache:
        return _vendor_cache[mac]
    try:
        conn = http.client.HTTPSConnection("api.macvendors.com", timeout=3)
        conn.request("GET", f"/{mac}", headers={"User-Agent": "SPECTRE/2.0"})
        resp = conn.getresponse()
        conn.close()
        if resp.status == 200:
            vendor = resp.read().decode().strip()[:30]
            _vendor_cache[mac] = vendor
            return vendor
    except Exception:
        pass
    _vendor_cache[mac] = ""
    return ""


# ── Patch menu references (functions defined after the list literal) ────────────

_MENU = [
    ("ARP Scan     — discover hosts on local network", _arp_scan_menu),
    ("Port Scan    — scan open ports on a target",     _port_scan_menu),
    ("Ping Sweep   — check which hosts are alive",     _ping_sweep_menu),
    ("Banner Grab  — grab service banners from a host",_banner_grab_menu),
]
