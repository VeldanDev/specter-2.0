"""
modules/threat_detect.py — Active threat detection for SPECTRE.

Sub-menu:
  [1] ARP Spoof Detector  — detect ARP poisoning / MITM attacks
  [2] Port Scan Detector  — detect if your device is being scanned
  [3] Rogue AP Detector   — detect evil twin / fake access points

All lightweight, Pi Zero 2 W friendly.
Root required for raw socket features.
"""

import os
import re
import socket
import subprocess
import time
import threading
from collections import defaultdict
from core.display import (
    print_info, print_ok, print_warn, print_err,
    print_section, prompt, Color
)

IS_WINDOWS = os.name == "nt"
BELL = "\a"


# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    while True:
        print_section("Threat Detection")
        items = [
            "ARP Spoof Detector — detect ARP poisoning / MITM",
            "Port Scan Detector — detect if you're being scanned",
            "Rogue AP Detector  — detect evil twin access points",
        ]
        for i, label in enumerate(items, 1):
            print(f"  {Color.CYAN}[{i}]{Color.RESET}  {label}")
        print(f"\n  {Color.DIM}[0]  Back{Color.RESET}")

        choice = prompt("Threat")
        if choice in ("0", ""):
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            print_warn("Invalid choice.")
            continue

        handlers = [_arp_spoof_detector, _port_scan_detector, _rogue_ap_detector]
        try:
            handlers[int(choice) - 1]()
        except KeyboardInterrupt:
            print_warn("\n  Detection stopped.")

        prompt("Press Enter to continue")


# ── [1] ARP Spoof Detector ─────────────────────────────────────────────────────

def _arp_spoof_detector():
    print_section("ARP Spoof Detector")

    interval_raw = prompt("Check interval in seconds [10]")
    try:
        interval = int(interval_raw) if interval_raw.strip() else 10
    except ValueError:
        interval = 10

    print_info("Monitoring ARP table for spoofing — Ctrl+C to stop\n")
    print_info("Will alert if: same IP has multiple MACs, or gateway MAC changes.\n")

    # Take baseline snapshot
    baseline = _get_arp_table()
    gateway  = _get_gateway()

    if gateway:
        gw_mac = baseline.get(gateway, "unknown")
        print_ok(f"Gateway: {gateway}  MAC: {gw_mac}")
    else:
        print_warn("Could not detect gateway.")
        gw_mac = None

    print(f"\n  {Color.DIM}Baseline established with {len(baseline)} entries.{Color.RESET}\n")

    scan = 0
    while True:
        scan += 1
        time.sleep(interval)
        now     = time.strftime("%H:%M:%S")
        current = _get_arp_table()
        threat  = False

        # Check 1: Did gateway MAC change? (classic ARP spoof indicator)
        if gateway and gw_mac and gw_mac != "unknown":
            current_gw_mac = current.get(gateway, "")
            if current_gw_mac and current_gw_mac != gw_mac:
                threat = True
                print(f"\n  {Color.RED}[!!!] ARP SPOOF DETECTED — GATEWAY MAC CHANGED!{Color.RESET}  {now}")
                print(f"        Gateway  : {gateway}")
                print(f"        Was      : {Color.GREEN}{gw_mac}{Color.RESET}")
                print(f"        Now      : {Color.RED}{current_gw_mac}{Color.RESET}")
                print(BELL, end="", flush=True)
                gw_mac = current_gw_mac

        # Check 2: Any IP that now appears with a different MAC
        for ip, mac in current.items():
            old_mac = baseline.get(ip)
            if old_mac and old_mac != mac:
                threat = True
                print(f"\n  {Color.RED}[!!!] MAC CHANGE DETECTED{Color.RESET}  {now}")
                print(f"        IP  : {ip}")
                print(f"        Was : {Color.GREEN}{old_mac}{Color.RESET}")
                print(f"        Now : {Color.RED}{mac}{Color.RESET}")
                print(BELL, end="", flush=True)

        # Check 3: Duplicate MACs (one device claiming multiple IPs)
        mac_to_ips = defaultdict(list)
        for ip, mac in current.items():
            mac_to_ips[mac].append(ip)
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                threat = True
                print(f"\n  {Color.YELLOW}[!] DUPLICATE MAC{Color.RESET}  {now}")
                print(f"      MAC {mac} claims: {', '.join(ips)}")

        if not threat:
            print(f"  {Color.DIM}[{now}] Scan #{scan} — ARP table clean ({len(current)} entries){Color.RESET}",
                  end="\r")

        baseline = current


def _get_arp_table() -> dict:
    """Return {ip: mac} from OS ARP cache."""
    table = {}
    if os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3].upper()
    else:
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
            for line in out.splitlines():
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:-]{17})', line, re.I)
                if m:
                    table[m.group(1)] = m.group(2).upper().replace("-", ":")
        except Exception:
            pass
    return table


def _get_gateway() -> str:
    """Detect default gateway IP."""
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["ipconfig"], text=True, timeout=5)
            m = re.search(r'Default Gateway[^:]*:\s+(\d+\.\d+\.\d+\.\d+)', out)
            return m.group(1) if m else ""
        else:
            out = subprocess.check_output(["ip", "route"], text=True, timeout=5)
            m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', out)
            return m.group(1) if m else ""
    except Exception:
        return ""


# ── [2] Port Scan Detector ─────────────────────────────────────────────────────

def _port_scan_detector():
    print_section("Port Scan Detector")

    if IS_WINDOWS:
        print_warn("Full port scan detection requires Linux (uses netstat/ss).")
        print_info("Showing connection attempts via netstat...")

    duration_raw = prompt("Monitor duration in seconds [30]")
    try:
        duration = int(duration_raw) if duration_raw.strip() else 30
    except ValueError:
        duration = 30

    threshold = 5  # connections from same IP within window = suspicious

    print_info(f"Monitoring incoming connections for {duration}s — Ctrl+C to stop\n")
    print(f"  {'TIME':<10} {'SOURCE IP':<20} {'PORT':<8} STATUS")
    print(f"  {'─'*10} {'─'*20} {'─'*8} {'─'*15}")

    connection_counts = defaultdict(list)
    start = time.time()

    while time.time() - start < duration:
        try:
            connections = _get_connections()
            now = time.strftime("%H:%M:%S")

            for src_ip, dst_port, state in connections:
                if src_ip in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                    continue
                key = (src_ip, dst_port)
                if key not in connection_counts:
                    connection_counts[src_ip].append(dst_port)
                    color = Color.GREEN
                    print(f"  {Color.DIM}{now:<10}{Color.RESET} "
                          f"{color}{src_ip:<20}{Color.RESET} "
                          f":{dst_port:<7} {state}")

                    # Check threshold
                    if len(connection_counts[src_ip]) >= threshold:
                        print(f"\n  {Color.RED}[!!!] POSSIBLE PORT SCAN from {src_ip}{Color.RESET}")
                        print(f"        Ports hit: {', '.join(map(str, connection_counts[src_ip]))}")
                        print(BELL, end="", flush=True)
        except Exception:
            pass
        time.sleep(1)

    print(f"\n\n  {Color.CYAN}Monitoring complete.{Color.RESET}")
    if connection_counts:
        print_info("Summary of unique sources:")
        for ip, ports in sorted(connection_counts.items(),
                                key=lambda x: len(x[1]), reverse=True)[:10]:
            risk = f"{Color.RED}SUSPICIOUS{Color.RESET}" if len(ports) >= threshold else f"{Color.GREEN}normal{Color.RESET}"
            print(f"  {ip:<20} {len(ports):>3} port(s)  {risk}")


def _get_connections() -> list:
    """Return list of (src_ip, dst_port, state) for incoming connections."""
    results = []
    try:
        cmd = ["ss", "-tn", "state", "established"] if not IS_WINDOWS else \
              ["netstat", "-n", "-p", "tcp"]
        out = subprocess.check_output(cmd, text=True,
                                      stderr=subprocess.DEVNULL, timeout=3)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if IS_WINDOWS and len(parts) >= 4:
                src = parts[2].rsplit(":", 1)
                dst = parts[1].rsplit(":", 1)
                if len(src) == 2 and len(dst) == 2:
                    results.append((src[0], dst[1], parts[3]))
            elif not IS_WINDOWS and len(parts) >= 4:
                src = parts[4].rsplit(":", 1)
                dst = parts[3].rsplit(":", 1)
                if len(src) == 2 and len(dst) == 2:
                    results.append((src[0], dst[1], "ESTABLISHED"))
    except Exception:
        pass
    return results


# ── [3] Rogue AP Detector ──────────────────────────────────────────────────────

def _rogue_ap_detector():
    print_section("Rogue AP Detector")

    if IS_WINDOWS:
        _rogue_ap_windows()
    else:
        _rogue_ap_linux()


def _rogue_ap_windows():
    """Scan for duplicate SSIDs using netsh."""
    print_info("Scanning for duplicate SSIDs (possible Evil Twin)...\n")
    try:
        raw = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            text=True, encoding="utf-8", errors="ignore", timeout=15
        )
    except Exception as e:
        print_err(f"Scan failed: {e}")
        return

    # Parse SSID → list of BSSIDs
    ssid_map = defaultdict(list)
    current_ssid = ""
    current_bssid = ""
    current_signal = ""

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("SSID") and "BSSID" not in line:
            current_ssid = line.split(":", 1)[-1].strip()
        elif line.startswith("BSSID"):
            current_bssid = line.split(":", 1)[-1].strip()
        elif line.startswith("Signal"):
            current_signal = line.split(":", 1)[-1].strip()
            if current_ssid and current_bssid:
                ssid_map[current_ssid].append({
                    "bssid": current_bssid,
                    "signal": current_signal
                })

    print(f"  {'SSID':<30} {'COUNT':<8} VERDICT")
    print(f"  {'─'*30} {'─'*8} {'─'*20}")

    alerts = 0
    for ssid, entries in sorted(ssid_map.items()):
        count = len(entries)
        if count > 1:
            alerts += 1
            verdict = f"{Color.RED}POSSIBLE EVIL TWIN ({count} BSSIDs){Color.RESET}"
        else:
            verdict = f"{Color.GREEN}OK{Color.RESET}"
        print(f"  {ssid:<30} {count:<8} {verdict}")
        if count > 1:
            for e in entries:
                print(f"    {Color.DIM}↳ {e['bssid']}  Signal: {e['signal']}{Color.RESET}")

    if alerts == 0:
        print(f"\n  {Color.GREEN}No rogue APs detected.{Color.RESET}")
    else:
        print(f"\n  {Color.RED}[!] {alerts} suspicious SSID(s) found.{Color.RESET}")
        print_warn("Verify with your router's admin panel before taking action.")


def _rogue_ap_linux():
    """Use nmcli or iwlist to scan for duplicate SSIDs."""
    print_info("Scanning WiFi for duplicate SSIDs...\n")
    ssid_map = defaultdict(list)

    try:
        raw = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
            text=True, timeout=15
        )
        for line in raw.splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                ssid = parts[0]
                bssid = parts[1].replace("\\:", ":")
                signal = parts[2]
                if ssid:
                    ssid_map[ssid].append({"bssid": bssid, "signal": signal})
    except Exception as e:
        print_warn(f"nmcli failed: {e}")
        return

    alerts = 0
    for ssid, entries in sorted(ssid_map.items()):
        if len(entries) > 1:
            alerts += 1
            print(f"  {Color.RED}[!!!] Duplicate SSID: {ssid} ({len(entries)} BSSIDs){Color.RESET}")
            for e in entries:
                print(f"    {Color.DIM}↳ {e['bssid']}  Signal: {e['signal']}%{Color.RESET}")

    if alerts == 0:
        print(f"  {Color.GREEN}No rogue APs detected.{Color.RESET}")
    else:
        print_warn("Multiple BSSIDs for same SSID could indicate an Evil Twin attack.")
