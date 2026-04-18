"""
modules/wifi_analysis.py — Real WiFi analysis for SPECTRE.

Sub-menu:
  [1] Scan Networks    — list nearby SSIDs with signal, channel, security
  [2] Network Detail   — full info on a specific SSID
  [3] Interface Info   — show WiFi adapter details
  [4] Monitor Mode     — toggle monitor mode (Linux/Pi only)

Windows : uses netsh wlan
Linux   : uses nmcli (primary) → iwlist (fallback)
Pi Zero : full monitor mode support via iw / airmon-ng
"""

import os
import re
import subprocess
from core.display import (
    print_info, print_ok, print_warn, print_err,
    print_section, prompt, Color
)

IS_WINDOWS = os.name == "nt"


# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    while True:
        print_section("WiFi Analysis")
        items = [
            "Scan Networks  — nearby SSIDs, signal, channel, security",
            "Network Detail — full info on a specific network",
            "Interface Info — WiFi adapter details",
            "Monitor Mode   — toggle (Linux / Pi only)",
        ]
        for i, label in enumerate(items, 1):
            print(f"  {Color.CYAN}[{i}]{Color.RESET}  {label}")
        print(f"\n  {Color.DIM}[0]  Back{Color.RESET}")

        choice = prompt("WiFi")
        if choice in ("0", ""):
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            print_warn("Invalid choice.")
            continue

        handlers = [
            _scan_networks,
            _network_detail,
            _interface_info,
            _monitor_mode,
        ]
        handlers[int(choice) - 1]()
        prompt("Press Enter to continue")


# ── [1] Scan Networks ──────────────────────────────────────────────────────────

def _scan_networks():
    print_section("Scan Networks")
    print_info("Scanning for nearby WiFi networks...")

    networks = _windows_scan() if IS_WINDOWS else _linux_scan()

    if not networks:
        print_warn("No networks found or scanner unavailable.")
        return

    # Sort by signal strength descending
    networks.sort(key=lambda x: x.get("signal", 0), reverse=True)

    print(f"\n  {'#':<4} {'SSID':<28} {'BSSID':<20} {'SIG':>5} {'CH':>4}  SECURITY")
    print(f"  {'─'*4} {'─'*28} {'─'*20} {'─'*5} {'─'*4}  {'─'*16}")

    for i, n in enumerate(networks, 1):
        ssid     = (n.get("ssid") or "Hidden")[:27]
        bssid    = n.get("bssid", "—")
        signal   = n.get("signal", 0)
        channel  = n.get("channel", "?")
        security = n.get("security", "Open")

        # Color signal bar
        if signal >= 75:
            sig_color = Color.GREEN
        elif signal >= 45:
            sig_color = Color.YELLOW
        else:
            sig_color = Color.RED

        sig_str = f"{sig_color}{signal:>3}%{Color.RESET}"
        sec_color = Color.DIM if security == "Open" else Color.CYAN
        print(f"  {i:<4} {Color.WHITE}{ssid:<28}{Color.RESET} {Color.DIM}{bssid:<20}{Color.RESET}"
              f" {sig_str} {str(channel):>4}  {sec_color}{security}{Color.RESET}")

    print(f"\n  {Color.CYAN}Found {len(networks)} network(s).{Color.RESET}")


def _windows_scan() -> list:
    """Parse 'netsh wlan show networks mode=Bssid' output."""
    try:
        raw = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            text=True, encoding="utf-8", errors="ignore", timeout=15
        )
    except Exception as e:
        print_warn(f"netsh failed: {e}")
        return []

    networks = []
    current  = {}

    for line in raw.splitlines():
        line = line.strip()

        if line.startswith("SSID") and "BSSID" not in line:
            if current:
                networks.append(current)
            ssid_val = line.split(":", 1)[-1].strip()
            current  = {"ssid": ssid_val}

        elif line.startswith("BSSID"):
            current["bssid"] = line.split(":", 1)[-1].strip()

        elif line.startswith("Signal"):
            raw_sig = line.split(":", 1)[-1].strip().replace("%", "")
            try:
                current["signal"] = int(raw_sig)
            except ValueError:
                current["signal"] = 0

        elif re.match(r'^Channel\s+:', line):
            raw_ch = line.split(":", 1)[-1].strip()
            m = re.search(r'\d+', raw_ch)
            current["channel"] = m.group(0) if m else "?"

        elif line.startswith("Authentication"):
            current["security"] = line.split(":", 1)[-1].strip()

    if current:
        networks.append(current)

    return [n for n in networks if n.get("ssid")]


def _linux_scan() -> list:
    """Try nmcli first, then iwlist."""
    networks = _nmcli_scan()
    if networks:
        return networks
    return _iwlist_scan()


def _nmcli_scan() -> list:
    try:
        raw = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN",
             "dev", "wifi", "list"],
            text=True, timeout=15
        )
    except FileNotFoundError:
        return []
    except Exception as e:
        print_warn(f"nmcli failed: {e}")
        return []

    networks = []
    for line in raw.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        ssid, bssid, signal, security, channel = parts[0], parts[1], parts[2], parts[3], parts[4]
        try:
            sig = int(signal)
        except ValueError:
            sig = 0
        networks.append({
            "ssid":     ssid or "Hidden",
            "bssid":    bssid.replace("\\:", ":"),
            "signal":   sig,
            "security": security or "Open",
            "channel":  channel.strip(),
        })
    return networks


def _iwlist_scan() -> list:
    iface = _detect_wifi_interface()
    if not iface:
        print_warn("No WiFi interface found.")
        return []
    try:
        raw = subprocess.check_output(
            ["iwlist", iface, "scan"],
            text=True, stderr=subprocess.DEVNULL, timeout=20
        )
    except FileNotFoundError:
        print_warn("iwlist not found — install wireless-tools.")
        return []
    except Exception as e:
        print_warn(f"iwlist failed: {e}")
        return []

    networks = []
    current  = {}
    for line in raw.splitlines():
        line = line.strip()
        if "Cell" in line and "Address" in line:
            if current:
                networks.append(current)
            current = {"bssid": line.split("Address:")[-1].strip()}
        elif "ESSID" in line:
            current["ssid"] = line.split('"')[1] if '"' in line else ""
        elif "Signal level" in line:
            m = re.search(r"Signal level[=:](-?\d+)", line)
            if m:
                dbm = int(m.group(1))
                current["signal"] = max(0, min(100, 2 * (dbm + 100)))
        elif "Channel:" in line:
            current["channel"] = line.split(":")[-1].strip()
        elif "Encryption key" in line:
            current["security"] = "Open" if "off" in line else "Encrypted"
        elif "IE: WPA" in line or "WPA2" in line:
            current["security"] = "WPA2"
    if current:
        networks.append(current)
    return networks


# ── [2] Network Detail ─────────────────────────────────────────────────────────

def _network_detail():
    print_section("Network Detail")

    ssid = prompt("Enter SSID to inspect")
    if not ssid:
        return

    if IS_WINDOWS:
        try:
            raw = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                text=True, encoding="utf-8", errors="ignore", timeout=15
            )
            found = False
            capture = False
            for line in raw.splitlines():
                if ssid.lower() in line.lower() and "SSID" in line:
                    capture = True
                    found   = True
                if capture:
                    print(f"  {line}")
                    if line.strip() == "" and found:
                        break
            if not found:
                print_warn(f"SSID '{ssid}' not found in scan.")
        except Exception as e:
            print_warn(f"Error: {e}")
    else:
        try:
            raw = subprocess.check_output(
                ["nmcli", "-f", "ALL", "dev", "wifi", "list"],
                text=True, timeout=15
            )
            for line in raw.splitlines():
                if ssid.lower() in line.lower() or line.startswith("IN-USE"):
                    print(f"  {line}")
        except Exception as e:
            print_warn(f"nmcli error: {e}")


# ── [3] Interface Info ─────────────────────────────────────────────────────────

def _interface_info():
    print_section("WiFi Interface Info")

    if IS_WINDOWS:
        try:
            raw = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True, encoding="utf-8", errors="ignore", timeout=10
            )
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    print(f"  {line}")
        except Exception as e:
            print_warn(f"Error: {e}")
        return

    iface = _detect_wifi_interface()
    if not iface:
        print_warn("No WiFi interface detected.")
        return

    print_ok(f"Interface: {iface}")

    for cmd, args in [
        ("iw",      [iface, "info"]),
        ("iwconfig",[iface]),
    ]:
        try:
            raw = subprocess.check_output(
                [cmd] + args, text=True,
                stderr=subprocess.DEVNULL, timeout=5
            )
            for line in raw.splitlines():
                if line.strip():
                    print(f"  {line}")
            return
        except FileNotFoundError:
            continue
        except Exception as e:
            print_warn(f"{cmd} error: {e}")


# ── [4] Monitor Mode ───────────────────────────────────────────────────────────

def _monitor_mode():
    print_section("Monitor Mode")

    if IS_WINDOWS:
        print_warn("Monitor mode is not supported on Windows.")
        print_info("Use Raspberry Pi with a compatible adapter (e.g. wlan1).")
        return

    iface = prompt("Interface [wlan0]") or "wlan0"
    print_info(f"Current mode for {iface}:")

    try:
        out = subprocess.check_output(
            ["iw", iface, "info"], text=True,
            stderr=subprocess.DEVNULL, timeout=5
        )
        for line in out.splitlines():
            if "type" in line.lower():
                print(f"  {line.strip()}")
    except FileNotFoundError:
        print_warn("'iw' not found — install: sudo apt install iw")
        return
    except Exception:
        pass

    print(f"\n  {Color.CYAN}[1]{Color.RESET}  Enable monitor mode")
    print(f"  {Color.CYAN}[2]{Color.RESET}  Disable monitor mode (back to managed)")

    choice = prompt("Action")
    if choice == "1":
        _set_monitor_mode(iface, enable=True)
    elif choice == "2":
        _set_monitor_mode(iface, enable=False)


def _set_monitor_mode(iface: str, enable: bool):
    mode    = "monitor" if enable else "managed"
    action  = "Enabling" if enable else "Disabling"
    print_info(f"{action} monitor mode on {iface}...")

    cmds = [
        ["ip", "link", "set", iface, "down"],
        ["iw", iface, "set", "type", mode],
        ["ip", "link", "set", iface, "up"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            print_err(f"Failed: {' '.join(cmd)}")
            print_warn("Run SPECTRE as root for monitor mode control.")
            return

    print_ok(f"{iface} is now in {mode} mode.")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _detect_wifi_interface() -> str:
    """Return the first wireless interface found on Linux."""
    wireless_dir = "/sys/class/net"
    if not os.path.exists(wireless_dir):
        return ""
    for iface in os.listdir(wireless_dir):
        if os.path.exists(f"{wireless_dir}/{iface}/wireless"):
            return iface
        if iface.startswith("wlan"):
            return iface
    return ""
