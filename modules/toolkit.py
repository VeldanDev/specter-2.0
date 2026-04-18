"""
modules/toolkit.py — General-purpose security toolkit for SPECTRE.

Sub-menu:
  [1] Hash Tools    — MD5, SHA1, SHA256, SHA512 from text or file
  [2] Traceroute    — trace packet path to a target host
  [3] Speed Test    — measure internet download speed
  [4] mDNS Scanner  — discover local services (printers, TVs, etc.)
  [5] USB Monitor   — alert on new USB devices (Linux/Pi only)
  [6] Temp Alert    — monitor CPU temperature with threshold alert

All pure Python — no third-party deps. Pi Zero 2 W ready.
"""

import os
import hashlib
import socket
import subprocess
import time
import http.client
import threading
from core.display import (
    print_info, print_ok, print_warn, print_err,
    print_section, prompt, Color
)

IS_WINDOWS = os.name == "nt"
BELL       = "\a"


# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    while True:
        print_section("Toolkit")
        items = [
            "Hash Tools    — MD5 / SHA1 / SHA256 / SHA512",
            "Traceroute    — trace path to a host",
            "Speed Test    — measure internet download speed",
            "mDNS Scanner  — discover local network services",
            "USB Monitor   — alert on new USB devices (Linux/Pi)",
            "Temp Alert    — CPU temperature monitor with alert",
        ]
        for i, label in enumerate(items, 1):
            print(f"  {Color.CYAN}[{i}]{Color.RESET}  {label}")
        print(f"\n  {Color.DIM}[0]  Back{Color.RESET}")

        choice = prompt("Toolkit")
        if choice in ("0", ""):
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            print_warn("Invalid choice.")
            continue

        handlers = [
            _hash_tools, _traceroute, _speed_test,
            _mdns_scanner, _usb_monitor, _temp_alert,
        ]
        try:
            handlers[int(choice) - 1]()
        except KeyboardInterrupt:
            print_warn("\n  Stopped.")

        prompt("Press Enter to continue")


# ── [1] Hash Tools ─────────────────────────────────────────────────────────────

def _hash_tools():
    print_section("Hash Tools")

    print(f"  {Color.CYAN}[1]{Color.RESET}  Hash text input")
    print(f"  {Color.CYAN}[2]{Color.RESET}  Hash a file")
    print(f"  {Color.CYAN}[3]{Color.RESET}  Verify file hash")

    choice = prompt("Mode")

    if choice == "1":
        text = prompt("Enter text")
        if not text:
            return
        data = text.encode()
        _print_hashes(data)

    elif choice == "2":
        path = prompt("File path")
        if not path or not os.path.isfile(path):
            print_err("File not found.")
            return
        print_info(f"Hashing {path} ...")
        with open(path, "rb") as f:
            data = f.read()
        _print_hashes(data)

    elif choice == "3":
        path   = prompt("File path")
        expect = prompt("Expected hash (any type)")
        if not path or not os.path.isfile(path):
            print_err("File not found.")
            return
        with open(path, "rb") as f:
            data = f.read()
        expect = expect.strip().lower()
        matched = False
        for algo in ("md5", "sha1", "sha256", "sha512"):
            h = hashlib.new(algo, data).hexdigest()
            if h == expect:
                print_ok(f"MATCH — {algo.upper()}: {h}")
                matched = True
                break
        if not matched:
            print_warn("Hash does NOT match any algorithm.")
            _print_hashes(data)

    else:
        print_warn("Invalid choice.")


def _print_hashes(data: bytes):
    print()
    for algo in ("md5", "sha1", "sha256", "sha512"):
        h = hashlib.new(algo, data).hexdigest()
        print(f"  {Color.CYAN}{algo.upper():<10}{Color.RESET} {h}")


# ── [2] Traceroute ─────────────────────────────────────────────────────────────

def _traceroute():
    print_section("Traceroute")
    target = prompt("Target host / IP")
    if not target:
        return

    print_info(f"Tracing route to {target} ...\n")
    print(f"  {'HOP':<5} {'IP':<20} {'HOSTNAME':<30} TIME")
    print(f"  {'─'*5} {'─'*20} {'─'*30} {'─'*10}")

    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-h", "20", target]
    else:
        cmd = ["traceroute", "-n", "-m", "20", target]

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True
        )
        hop = 0
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            # Windows format: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            if IS_WINDOWS:
                m = re.search(r'^\s*(\d+)\s+(.+?)\s+(\d+\.\d+\.\d+\.\d+)\s*$', line)
                if m:
                    hop      = m.group(1)
                    timing   = m.group(2).strip()
                    ip       = m.group(3)
                    hostname = _resolve_quiet(ip)
                    print(f"  {hop:<5} {Color.CYAN}{ip:<20}{Color.RESET} "
                          f"{Color.DIM}{hostname:<30}{Color.RESET} {timing}")
            else:
                # Linux format: " 1  192.168.1.1  0.5 ms"
                m = re.search(r'^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(.+)', line)
                if m:
                    hop      = m.group(1)
                    ip       = m.group(2)
                    timing   = m.group(3).strip()
                    hostname = _resolve_quiet(ip)
                    print(f"  {hop:<5} {Color.CYAN}{ip:<20}{Color.RESET} "
                          f"{Color.DIM}{hostname:<30}{Color.RESET} {timing}")
                elif "*" in line:
                    hop_m = re.match(r'^\s*(\d+)', line)
                    if hop_m:
                        print(f"  {hop_m.group(1):<5} {'* * *':<20} "
                              f"{'(no response)':<30}")
        proc.wait(timeout=30)
    except FileNotFoundError:
        print_err(f"{'tracert' if IS_WINDOWS else 'traceroute'} not found.")
        print_info("Install: sudo apt install traceroute")
    except subprocess.TimeoutExpired:
        print_warn("Traceroute timed out.")
    except Exception as e:
        print_err(f"Error: {e}")


# ── [3] Speed Test ─────────────────────────────────────────────────────────────

SPEED_TEST_FILES = [
    ("Cloudflare 10MB", "speed.cloudflare.com", "/cdn-cgi/trace", False),
    ("fast.com proxy",  "api.fast.com",          "/netflix/speedtest", False),
]

def _speed_test():
    print_section("Speed Test")
    print_info("Testing download speed using Cloudflare...\n")

    # Download 10MB from Cloudflare speed test endpoint
    host    = "speed.cloudflare.com"
    path    = "/__down?bytes=10000000"  # 10 MB
    size_mb = 10

    try:
        conn  = http.client.HTTPSConnection(host, timeout=30)
        start = time.time()
        conn.request("GET", path, headers={"User-Agent": "SPECTRE/2.0"})
        resp  = conn.getresponse()

        downloaded = 0
        chunk_size = 65536  # 64KB chunks

        print(f"  {'PROGRESS':<12} {'SPEED'}")
        print(f"  {'─'*12} {'─'*20}")

        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            downloaded += len(chunk)
            elapsed = time.time() - start
            speed   = (downloaded / elapsed) / (1024 * 1024) if elapsed > 0 else 0
            pct     = int(downloaded / (size_mb * 1024 * 1024) * 100)
            bar     = ("█" * (pct // 5)).ljust(20)
            print(f"  {Color.CYAN}{pct:>3}%{Color.RESET} [{bar}]  "
                  f"{Color.GREEN}{speed:.2f} MB/s{Color.RESET}",
                  end="\r")

        elapsed = time.time() - start
        speed   = (downloaded / elapsed) / (1024 * 1024)
        speed_mbps = speed * 8

        conn.close()
        print(f"\n\n  {Color.GREEN}Download complete!{Color.RESET}")
        print_ok(f"Downloaded : {downloaded / (1024*1024):.1f} MB in {elapsed:.1f}s")
        print_ok(f"Speed      : {speed:.2f} MB/s  ({speed_mbps:.1f} Mbps)")

        # Rating
        if speed_mbps >= 100:
            rating = f"{Color.GREEN}Excellent{Color.RESET}"
        elif speed_mbps >= 25:
            rating = f"{Color.GREEN}Good{Color.RESET}"
        elif speed_mbps >= 5:
            rating = f"{Color.YELLOW}Average{Color.RESET}"
        else:
            rating = f"{Color.RED}Slow{Color.RESET}"
        print(f"  {Color.CYAN}Rating    {Color.RESET} : {rating}")

    except Exception as e:
        print_err(f"Speed test failed: {e}")
        print_info("Check internet connection.")


# ── [4] mDNS Scanner ──────────────────────────────────────────────────────────

MDNS_ADDR    = "224.0.0.251"
MDNS_PORT    = 5353
MDNS_TIMEOUT = 10  # seconds to listen


def _mdns_scanner():
    print_section("mDNS / Bonjour Scanner")
    print_info(f"Listening for mDNS announcements for {MDNS_TIMEOUT}s...\n")
    print_info("Will discover: printers, smart TVs, Chromecasts, Pi devices, etc.\n")

    print(f"  {'SERVICE':<40} {'HOST':<25} ADDRESS")
    print(f"  {'─'*40} {'─'*25} {'─'*20}")

    seen    = set()
    devices = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)
        sock.bind(("", MDNS_PORT))

        # Join multicast group
        import struct
        mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        end = time.time() + MDNS_TIMEOUT
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                name   = _parse_mdns_name(data)
                key    = (src_ip, name)
                if name and key not in seen:
                    seen.add(key)
                    hostname = _resolve_quiet(src_ip)
                    devices.append((name, hostname, src_ip))
                    print(f"  {Color.CYAN}{name[:39]:<40}{Color.RESET} "
                          f"{Color.DIM}{hostname[:24]:<25}{Color.RESET} {src_ip}")
            except socket.timeout:
                remaining = int(end - time.time())
                print(f"  {Color.DIM}Listening... {remaining}s remaining{Color.RESET}",
                      end="\r")
        sock.close()
    except PermissionError:
        print_err("Permission denied for multicast. Run as root.")
        return
    except Exception as e:
        print_err(f"mDNS error: {e}")
        return

    print(f"\n\n  {Color.CYAN}Found {len(devices)} service(s).{Color.RESET}")


def _parse_mdns_name(data: bytes) -> str:
    """Extract the first DNS name from an mDNS packet (simplified parser)."""
    try:
        if len(data) < 12:
            return ""
        offset = 12  # skip DNS header
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:  # compression pointer
                break
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode(errors="replace"))
            offset += length
        return ".".join(labels) if labels else ""
    except Exception:
        return ""


# ── [5] USB Monitor ────────────────────────────────────────────────────────────

def _usb_monitor():
    print_section("USB Monitor")

    if IS_WINDOWS:
        print_warn("USB monitoring uses WMI on Windows — limited support.")
        print_info("Full USB monitoring works on Raspberry Pi (Linux).")

    print_info("Monitoring USB devices — Ctrl+C to stop\n")

    usb_path  = "/sys/bus/usb/devices"
    known     = set()

    if not IS_WINDOWS and not os.path.exists(usb_path):
        print_err("USB subsystem not found. Are you on Linux/Pi?")
        return

    # Baseline
    if IS_WINDOWS:
        known = _get_usb_windows()
    else:
        known = set(os.listdir(usb_path))

    print_ok(f"Baseline: {len(known)} USB device(s) connected.")
    print(f"\n  Watching for changes...\n")

    while True:
        time.sleep(2)
        now = time.strftime("%H:%M:%S")

        if IS_WINDOWS:
            current = _get_usb_windows()
        else:
            current = set(os.listdir(usb_path))

        # New devices
        for dev in current - known:
            desc = _usb_desc_linux(dev) if not IS_WINDOWS else dev
            print(f"  {Color.GREEN}[+] USB CONNECTED{Color.RESET}  {now}")
            print(f"      Device: {Color.CYAN}{desc}{Color.RESET}")
            print(BELL, end="", flush=True)

        # Removed devices
        for dev in known - current:
            print(f"  {Color.YELLOW}[-] USB DISCONNECTED{Color.RESET}  {now}")
            print(f"      Device: {dev}")

        known = current


def _get_usb_windows() -> set:
    try:
        out = subprocess.check_output(
            ["wmic", "path", "Win32_USBControllerDevice", "get", "Dependent"],
            text=True, timeout=5
        )
        return set(line.strip() for line in out.splitlines() if line.strip())
    except Exception:
        return set()


def _usb_desc_linux(dev_id: str) -> str:
    base = f"/sys/bus/usb/devices/{dev_id}"
    try:
        product = open(f"{base}/product").read().strip()
        return f"{dev_id} — {product}"
    except Exception:
        try:
            vid = open(f"{base}/idVendor").read().strip()
            pid = open(f"{base}/idProduct").read().strip()
            return f"{dev_id} ({vid}:{pid})"
        except Exception:
            return dev_id


# ── [6] Temperature Alert ──────────────────────────────────────────────────────

def _temp_alert():
    print_section("CPU Temperature Alert")

    temp = _read_temp()
    if temp is None:
        print_warn("CPU temperature sensor not available on this system.")
        print_info("This feature works on Raspberry Pi (reads /sys/class/thermal/).")
        return

    threshold_raw = prompt("Alert threshold °C [75]")
    try:
        threshold = float(threshold_raw) if threshold_raw.strip() else 75.0
    except ValueError:
        threshold = 75.0

    interval_raw = prompt("Check interval seconds [5]")
    try:
        interval = int(interval_raw) if interval_raw.strip() else 5
    except ValueError:
        interval = 5

    print_info(f"Monitoring CPU temperature — alert at {threshold}°C — Ctrl+C to stop\n")

    max_temp = 0.0
    readings = 0

    while True:
        temp = _read_temp()
        if temp is None:
            print_warn("Lost temperature reading.")
            break

        readings += 1
        max_temp  = max(max_temp, temp)
        now       = time.strftime("%H:%M:%S")

        if temp >= threshold:
            color = Color.RED
            alert = f"  {Color.RED}[!!!] TEMPERATURE ALERT — {temp:.1f}°C exceeds {threshold}°C{Color.RESET}"
            print(f"\n{alert}")
            print(BELL, end="", flush=True)
        elif temp >= threshold - 10:
            color = Color.YELLOW
        else:
            color = Color.GREEN

        bar_val = min(100, int(temp / 100 * 40))
        bar     = f"{color}{'█' * bar_val}{'░' * (40 - bar_val)}{Color.RESET}"
        print(f"  {Color.DIM}{now}{Color.RESET}  [{bar}]  "
              f"{color}{temp:.1f}°C{Color.RESET}  "
              f"{Color.DIM}max: {max_temp:.1f}°C{Color.RESET}",
              end="\r")

        time.sleep(interval)


def _read_temp() -> float:
    thermal = "/sys/class/thermal/thermal_zone0/temp"
    if os.path.exists(thermal):
        try:
            with open(thermal) as f:
                return int(f.read().strip()) / 1000.0
        except Exception:
            pass
    try:
        out = subprocess.check_output(
            ["vcgencmd", "measure_temp"],
            stderr=subprocess.DEVNULL, text=True, timeout=2
        )
        return float(out.strip().replace("temp=", "").replace("'C", ""))
    except Exception:
        return None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _resolve_quiet(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


# Fix missing import in traceroute
import re
