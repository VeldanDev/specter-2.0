"""
modules/bluetooth_scan.py — Bluetooth device discovery for SPECTRE.

Sub-menu:
  [1] Scan Devices     — discover nearby Bluetooth devices
  [2] Adapter Info     — show BT adapter details
  [3] Paired Devices   — list paired/known devices

Linux only (Raspberry Pi). Uses bluetoothctl and hciconfig.
"""

import os
import re
import subprocess
import threading
import time
from core.display import (
    print_info, print_ok, print_warn, print_err,
    print_section, prompt, Color
)

IS_WINDOWS = os.name == "nt"
SCAN_DURATION = 10  # seconds


# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    if IS_WINDOWS:
        print_section("Bluetooth Scanning")
        print_warn("Bluetooth scanning requires Linux (Raspberry Pi).")
        print_info("This module will be fully active on your Pi Zero 2 W.")
        return

    while True:
        print_section("Bluetooth Scanning")
        items = [
            "Scan Devices   — discover nearby Bluetooth devices",
            "Adapter Info   — show BT adapter details",
            "Paired Devices — list known/paired devices",
        ]
        for i, label in enumerate(items, 1):
            print(f"  {Color.CYAN}[{i}]{Color.RESET}  {label}")
        print(f"\n  {Color.DIM}[0]  Back{Color.RESET}")

        choice = prompt("Bluetooth")
        if choice in ("0", ""):
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            print_warn("Invalid choice.")
            continue

        handlers = [_scan_devices, _adapter_info, _paired_devices]
        try:
            handlers[int(choice) - 1]()
        except KeyboardInterrupt:
            print_warn("\n  Scan interrupted.")

        prompt("Press Enter to continue")


# ── [1] Scan Devices ───────────────────────────────────────────────────────────

def _scan_devices():
    print_section("Bluetooth Device Scan")

    if not _check_adapter():
        return

    print_info(f"Scanning for {SCAN_DURATION} seconds — make sure devices are discoverable...")
    print_info("Press Ctrl+C to stop early.\n")

    devices = {}
    lock    = threading.Lock()
    done    = threading.Event()

    def _listener():
        """Read bluetoothctl output and parse discovered devices."""
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            proc.stdin.write("scan on\n")
            proc.stdin.flush()

            while not done.is_set():
                line = proc.stdout.readline()
                if not line:
                    break
                # Match lines like: [NEW] Device AA:BB:CC:DD:EE:FF DeviceName
                m = re.search(
                    r'\[NEW\] Device ([0-9A-F:]{17})\s+(.*)',
                    line, re.IGNORECASE
                )
                if m:
                    mac  = m.group(1).upper()
                    name = m.group(2).strip() or "Unknown"
                    with lock:
                        if mac not in devices:
                            devices[mac] = name
                            print(f"  {Color.GREEN}[+]{Color.RESET} "
                                  f"{Color.CYAN}{mac}{Color.RESET}  {name}")

            proc.stdin.write("scan off\n")
            proc.stdin.flush()
            proc.terminate()
        except Exception:
            pass

    t = threading.Thread(target=_listener, daemon=True)
    t.start()

    try:
        time.sleep(SCAN_DURATION)
    except KeyboardInterrupt:
        pass
    finally:
        done.set()
        t.join(timeout=2)

    if not devices:
        print_warn("No devices found. Ensure target devices are in discoverable mode.")
        return

    print(f"\n  {Color.CYAN}{'MAC ADDRESS':<20} {'DEVICE NAME'}{Color.RESET}")
    print(f"  {'─'*20} {'─'*30}")
    for mac, name in sorted(devices.items()):
        rssi = _get_rssi(mac)
        rssi_str = f"  RSSI {rssi} dBm" if rssi else ""
        print(f"  {Color.CYAN}{mac:<20}{Color.RESET} {name}{Color.DIM}{rssi_str}{Color.RESET}")

    print(f"\n  {Color.GREEN}Found {len(devices)} device(s).{Color.RESET}")


def _get_rssi(mac: str) -> str:
    """Try to get RSSI for a discovered device."""
    try:
        out = subprocess.check_output(
            ["hcitool", "rssi", mac],
            stderr=subprocess.DEVNULL, text=True, timeout=3
        )
        m = re.search(r'RSSI return value:\s*(-?\d+)', out)
        return m.group(1) if m else ""
    except Exception:
        return ""


# ── [2] Adapter Info ───────────────────────────────────────────────────────────

def _adapter_info():
    print_section("Bluetooth Adapter Info")

    for cmd, args in [
        ("hciconfig", ["-a"]),
        ("bluetoothctl", ["--", "show"]),
    ]:
        try:
            out = subprocess.check_output(
                [cmd] + args,
                text=True, stderr=subprocess.DEVNULL, timeout=5
            )
            _print_bt_info(out)
            return
        except FileNotFoundError:
            continue
        except Exception as e:
            print_warn(f"{cmd} error: {e}")

    print_warn("No Bluetooth adapter tools found.")
    print_info("Install: sudo apt install bluez")


def _print_bt_info(raw: str):
    important = [
        "BD Address", "Name", "Class", "HCI Version",
        "Manufacturer", "Features", "Controller",
        "Powered", "Discoverable", "Pairable",
    ]
    for line in raw.splitlines():
        stripped = line.strip()
        if any(k.lower() in stripped.lower() for k in important):
            print(f"  {stripped}")


# ── [3] Paired Devices ─────────────────────────────────────────────────────────

def _paired_devices():
    print_section("Paired Devices")

    try:
        out = subprocess.check_output(
            ["bluetoothctl", "--", "devices", "Paired"],
            text=True, stderr=subprocess.DEVNULL, timeout=5
        )
    except FileNotFoundError:
        print_warn("bluetoothctl not found — install: sudo apt install bluez")
        return
    except Exception as e:
        print_err(f"Error: {e}")
        return

    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if not lines:
        print_warn("No paired devices found.")
        return

    print(f"\n  {'MAC ADDRESS':<20} DEVICE NAME")
    print(f"  {'─'*20} {'─'*30}")
    for line in lines:
        # Format: "Device AA:BB:CC:DD:EE:FF Name"
        parts = line.split(" ", 2)
        if len(parts) >= 3:
            mac  = parts[1]
            name = parts[2]
            print(f"  {Color.CYAN}{mac:<20}{Color.RESET} {name}")

    print(f"\n  {Color.CYAN}{len(lines)} paired device(s).{Color.RESET}")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _check_adapter() -> bool:
    """Check if a Bluetooth adapter is present and up."""
    try:
        out = subprocess.check_output(
            ["hciconfig"], text=True,
            stderr=subprocess.DEVNULL, timeout=5
        )
        if "hci0" not in out:
            print_err("No Bluetooth adapter found (hci0 missing).")
            print_info("Check: sudo hciconfig hci0 up")
            return False
        if "DOWN" in out:
            print_warn("Adapter is DOWN — bringing it up...")
            subprocess.run(["hciconfig", "hci0", "up"],
                           stderr=subprocess.DEVNULL)
            time.sleep(1)
        return True
    except FileNotFoundError:
        print_warn("hciconfig not found — install: sudo apt install bluez")
        return False
    except Exception as e:
        print_err(f"Adapter check failed: {e}")
        return False
