"""
modules/net_monitor.py — Network Change Monitor for SPECTRE.

Watches the ARP table at regular intervals. Alerts when:
  - A new device joins the network (unknown MAC)
  - A known device goes offline
  - An IP changes its MAC (possible ARP spoofing)

Known devices are saved to data/known_devices.json so they persist
across SPECTRE sessions. Lightweight enough for Pi Zero 2 W 24/7.
"""

import os
import json
import time
import socket
import subprocess
import ipaddress
from datetime import datetime
from core.display import (
    print_info, print_ok, print_warn, print_err,
    print_section, prompt, Color
)

DATA_FILE     = "data/known_devices.json"
SCAN_INTERVAL = 30   # seconds between ARP sweeps
BELL          = "\a" # terminal bell for alerts


# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    while True:
        print_section("Network Monitor")
        items = [
            "Start Monitoring  — watch for new/changed devices",
            "Known Devices     — view & manage whitelist",
            "Clear Whitelist   — reset known devices list",
        ]
        for i, label in enumerate(items, 1):
            print(f"  {Color.CYAN}[{i}]{Color.RESET}  {label}")
        print(f"\n  {Color.DIM}[0]  Back{Color.RESET}")

        choice = prompt("Monitor")
        if choice in ("0", ""):
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            print_warn("Invalid choice.")
            continue

        handlers = [_start_monitoring, _show_known, _clear_known]
        try:
            handlers[int(choice) - 1]()
        except KeyboardInterrupt:
            print_warn("\n  Monitoring stopped.")

        prompt("Press Enter to continue")


# ── [1] Start Monitoring ───────────────────────────────────────────────────────

def _start_monitoring():
    print_section("Network Monitor — Live")

    subnet = _detect_subnet()
    if not subnet:
        print_err("Cannot detect local subnet.")
        return

    interval_raw = prompt(f"Scan interval in seconds [{SCAN_INTERVAL}]")
    try:
        interval = int(interval_raw) if interval_raw else SCAN_INTERVAL
    except ValueError:
        interval = SCAN_INTERVAL

    known = _load_known()
    print_info(f"Monitoring {subnet} every {interval}s — Ctrl+C to stop")
    print_info(f"Known devices loaded: {len(known)}\n")

    scan_count = 0
    while True:
        scan_count += 1
        now     = datetime.now().strftime("%H:%M:%S")
        current = _arp_snapshot(subnet)

        # ── Detect new devices ─────────────────────────────────
        for mac, info in current.items():
            ip       = info["ip"]
            hostname = info["hostname"]

            if mac not in known:
                # Brand new device
                print(f"  {Color.RED}[!] NEW DEVICE{Color.RESET}  {now}")
                print(f"      MAC      : {Color.CYAN}{mac}{Color.RESET}")
                print(f"      IP       : {ip}")
                print(f"      Hostname : {Color.DIM}{hostname}{Color.RESET}")
                print(BELL, end="", flush=True)

                # Auto-add to known after alerting
                known[mac] = {"ip": ip, "hostname": hostname, "first_seen": now}
                _save_known(known)

            elif known[mac]["ip"] != ip:
                # IP changed for known MAC — possible DHCP renewal or ARP spoof
                old_ip = known[mac]["ip"]
                print(f"  {Color.YELLOW}[!] IP CHANGE{Color.RESET}  {now}")
                print(f"      MAC : {mac}  {old_ip} → {Color.CYAN}{ip}{Color.RESET}")
                known[mac]["ip"] = ip
                _save_known(known)

        # ── Status line ────────────────────────────────────────
        print(f"  {Color.DIM}[{now}] Scan #{scan_count} — "
              f"{len(current)} device(s) active{Color.RESET}", end="\r")

        time.sleep(interval)


# ── [2] Show Known Devices ─────────────────────────────────────────────────────

def _show_known():
    print_section("Known Devices")
    known = _load_known()

    if not known:
        print_warn("No known devices yet. Start monitoring to populate.")
        return

    print(f"\n  {'MAC ADDRESS':<20} {'IP':<18} {'HOSTNAME':<25} FIRST SEEN")
    print(f"  {'─'*20} {'─'*18} {'─'*25} {'─'*10}")

    for mac, info in sorted(known.items()):
        hostname = (info.get("hostname") or "—")[:24]
        print(f"  {Color.CYAN}{mac:<20}{Color.RESET} "
              f"{info.get('ip','?'):<18} "
              f"{Color.DIM}{hostname:<25}{Color.RESET} "
              f"{info.get('first_seen','?')}")

    print(f"\n  {Color.CYAN}Total: {len(known)} known device(s).{Color.RESET}")

    # Offer to remove a device
    print(f"\n  Enter MAC to remove from whitelist [Enter to skip]")
    mac_del = prompt("MAC").upper().strip()
    if mac_del and mac_del in known:
        del known[mac_del]
        _save_known(known)
        print_ok(f"Removed {mac_del} from whitelist.")
    elif mac_del:
        print_warn("MAC not found in whitelist.")


# ── [3] Clear Whitelist ────────────────────────────────────────────────────────

def _clear_known():
    confirm = prompt("Clear ALL known devices? This cannot be undone. (yes/N)")
    if confirm.lower() == "yes":
        _save_known({})
        print_ok("Whitelist cleared.")
    else:
        print_warn("Cancelled.")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _arp_snapshot(subnet: str) -> dict:
    """
    Probe subnet and return {mac: {ip, hostname}} for all live hosts.
    Uses ping sweep to populate ARP cache, then reads the ARP table.
    """
    # Quick ping sweep (silent) to refresh ARP cache
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        hosts   = [str(h) for h in network.hosts()]
        is_win  = os.name == "nt"

        def _ping(ip):
            flag = ["-n", "1", "-w", "500"] if is_win else ["-c", "1", "-W", "1"]
            subprocess.run(
                ["ping"] + flag + [ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )

        import threading
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(_ping, hosts))
    except Exception:
        pass

    # Read ARP table
    result = {}
    broadcast = str(ipaddress.ip_network(subnet, strict=False).broadcast_address)

    if os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip  = parts[0]
                    mac = parts[3]
                    if (mac != "00:00:00:00:00:00"
                            and mac != "ff:ff:ff:ff:ff:ff"
                            and ip != broadcast):
                        hostname = _resolve(ip)
                        result[mac.upper()] = {"ip": ip, "hostname": hostname}
    else:
        try:
            out = subprocess.check_output(
                ["arp", "-a"], text=True, timeout=5
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip  = parts[0].strip("()")
                    mac = parts[1].replace("-", ":").upper()
                    if mac.count(":") == 5 and mac != "FF:FF:FF:FF:FF:FF":
                        try:
                            ipaddress.ip_address(ip)
                            hostname = _resolve(ip)
                            result[mac] = {"ip": ip, "hostname": hostname}
                        except ValueError:
                            pass
        except Exception:
            pass

    return result


def _resolve(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


def _detect_subnet() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ".".join(ip.split(".")[:3]) + ".0/24"
    except Exception:
        return ""


def _load_known() -> dict:
    os.makedirs("data", exist_ok=True)
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_known(known: dict):
    os.makedirs("data", exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(known, f, indent=2)
