"""
modules/system_monitor.py — Real-time system monitoring for SPECTRE.

Sub-menu:
  [1] Live Dashboard  — auto-refresh snapshot (CPU, RAM, Disk, Net)
  [2] CPU Detail      — usage, frequency, temperature (Pi-friendly)
  [3] Memory Detail   — RAM breakdown
  [4] Network Traffic — interface stats + bytes sent/received
  [5] Top Processes   — top 5 by CPU usage

Pi Zero 2 W notes:
  - CPU temperature is critical (throttles at 80°C)
  - 512 MB RAM — watch usage closely
  - Falls back to /proc files if psutil not installed
"""

import os
import sys
import time
import subprocess
import threading
from core.display import (
    print_info, print_ok, print_warn, print_err,
    print_section, prompt, clear_screen, Color
)

REFRESH_INTERVAL = 2  # seconds for live dashboard


# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    while True:
        print_section("System Monitor")
        items = [
            "Live Dashboard  — auto-refresh (press Ctrl+C to stop)",
            "CPU Detail      — usage, freq, temperature",
            "Memory Detail   — RAM breakdown",
            "Network Traffic — interface stats",
            "Top Processes   — top 5 by CPU",
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

        handlers = [
            _live_dashboard,
            _cpu_detail,
            _memory_detail,
            _network_traffic,
            _top_processes,
        ]
        try:
            handlers[int(choice) - 1]()
        except KeyboardInterrupt:
            print(f"\n  {Color.YELLOW}[!]{Color.RESET}  Stopped.")

        prompt("Press Enter to continue")


# ── Live Dashboard ─────────────────────────────────────────────────────────────

def _live_dashboard():
    print_info("Live dashboard — Ctrl+C to stop\n")
    time.sleep(0.5)

    try:
        import psutil
        _dashboard_psutil(psutil)
    except ImportError:
        _dashboard_proc()


def _dashboard_psutil(psutil):
    while True:
        clear_screen()
        _print_header("SPECTRE — Live Dashboard")

        # CPU
        cpu_pct  = psutil.cpu_percent(interval=None)
        cpu_freq = psutil.cpu_freq()
        cpu_temp = _read_cpu_temp()
        freq_str = f"{cpu_freq.current:.0f} MHz" if cpu_freq else "N/A"
        temp_str = f"{cpu_temp:.1f}°C" if cpu_temp else "N/A"
        temp_color = Color.RED if (cpu_temp or 0) > 75 else Color.GREEN
        _bar("CPU", cpu_pct, 100,
             suffix=f"  {freq_str}  {temp_color}{temp_str}{Color.RESET}")

        # Memory
        vm = psutil.virtual_memory()
        used_mb  = vm.used  // (1024 ** 2)
        total_mb = vm.total // (1024 ** 2)
        _bar("RAM", vm.percent, 100, suffix=f"  {used_mb} / {total_mb} MB")

        # Disk
        try:
            disk = psutil.disk_usage("/")
            used_gb  = disk.used  // (1024 ** 3)
            total_gb = disk.total // (1024 ** 3)
            _bar("DSK", disk.percent, 100, suffix=f"  {used_gb} / {total_gb} GB")
        except Exception:
            pass

        # Network interfaces
        print(f"\n  {Color.CYAN}NET{Color.RESET}")
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family.name == "AF_INET":
                    up = stats[iface].isup if iface in stats else False
                    state = f"{Color.GREEN}UP{Color.RESET}" if up else f"{Color.RED}DOWN{Color.RESET}"
                    print(f"    {iface:<12} {addr.address:<18} {state}")

        print(f"\n  {Color.DIM}Refreshing every {REFRESH_INTERVAL}s — Ctrl+C to stop{Color.RESET}")
        time.sleep(REFRESH_INTERVAL)


def _dashboard_proc():
    """Fallback dashboard using /proc — no psutil needed."""
    while True:
        clear_screen()
        _print_header("SPECTRE — Live Dashboard (lite)")

        # Load average from /proc/loadavg
        if os.path.exists("/proc/loadavg"):
            with open("/proc/loadavg") as f:
                vals = f.read().split()
            print(f"  {Color.CYAN}LOAD{Color.RESET}  1m: {vals[0]}  5m: {vals[1]}  15m: {vals[2]}")

        # Memory from /proc/meminfo
        mem = _read_proc_meminfo()
        if mem:
            total = mem.get("MemTotal", 0)
            avail = mem.get("MemAvailable", 0)
            used  = total - avail
            pct   = (used / total * 100) if total else 0
            _bar("RAM", pct, 100, suffix=f"  {used//1024} / {total//1024} MB")

        # Temperature
        temp = _read_cpu_temp()
        if temp:
            color = Color.RED if temp > 75 else Color.GREEN
            print(f"  {Color.CYAN}TEMP{Color.RESET}  {color}{temp:.1f}°C{Color.RESET}")

        print(f"\n  {Color.DIM}Refreshing every {REFRESH_INTERVAL}s — Ctrl+C to stop{Color.RESET}")
        time.sleep(REFRESH_INTERVAL)


# ── CPU Detail ─────────────────────────────────────────────────────────────────

def _cpu_detail():
    print_section("CPU Detail")
    try:
        import psutil
        for i in range(3):
            pcts = psutil.cpu_percent(percpu=True, interval=1)
            clear_screen()
            print_section("CPU Detail")
            for idx, pct in enumerate(pcts):
                _bar(f"Core {idx}", pct, 100)

            freq = psutil.cpu_freq()
            if freq:
                print_ok(f"Frequency: {freq.current:.0f} MHz  (min {freq.min:.0f} / max {freq.max:.0f})")

            temp = _read_cpu_temp()
            if temp:
                color = Color.RED if temp > 75 else Color.GREEN
                print(f"  {Color.CYAN}[*]{Color.RESET} Temperature: {color}{temp:.1f}°C{Color.RESET}")
            else:
                print_info("Temperature: not available on this platform")

            if i < 2:
                time.sleep(1)
    except ImportError:
        _fallback_cpu()


def _fallback_cpu():
    if os.path.exists("/proc/loadavg"):
        with open("/proc/loadavg") as f:
            vals = f.read().split()
        print_ok(f"Load average — 1m: {vals[0]}  5m: {vals[1]}  15m: {vals[2]}")
    temp = _read_cpu_temp()
    if temp:
        print_ok(f"Temperature: {temp:.1f}°C")
    else:
        print_warn("psutil not installed — run: pip install psutil")


# ── Memory Detail ──────────────────────────────────────────────────────────────

def _memory_detail():
    print_section("Memory Detail")
    try:
        import psutil
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()

        rows = [
            ("Total",     vm.total),
            ("Used",      vm.used),
            ("Available", vm.available),
            ("Cached",    getattr(vm, "cached", 0)),
            ("Buffers",   getattr(vm, "buffers", 0)),
        ]
        for label, val in rows:
            mb = val // (1024 ** 2)
            print_ok(f"{label:<12} {mb:>6} MB")

        print()
        _bar("RAM Usage", vm.percent, 100)

        print()
        print_info("Swap")
        sw_total = sw.total // (1024 ** 2)
        sw_used  = sw.used  // (1024 ** 2)
        print_ok(f"Used: {sw_used} MB / {sw_total} MB  ({sw.percent}%)")

    except ImportError:
        mem = _read_proc_meminfo()
        if mem:
            for key in ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached"):
                if key in mem:
                    print_ok(f"{key:<16} {mem[key]//1024} MB")
        else:
            print_warn("psutil not installed — run: pip install psutil")


# ── Network Traffic ────────────────────────────────────────────────────────────

def _network_traffic():
    print_section("Network Traffic")
    try:
        import psutil

        snap1 = psutil.net_io_counters(pernic=True)
        print_info("Measuring traffic over 2 seconds...")
        time.sleep(2)
        snap2 = psutil.net_io_counters(pernic=True)

        print(f"\n  {'IFACE':<12} {'IP':<18} {'↓ RX/s':<12} {'↑ TX/s':<12} {'Total RX':<12} {'Total TX'}")
        print(f"  {'─'*12} {'─'*18} {'─'*12} {'─'*12} {'─'*12} {'─'*10}")

        addrs = psutil.net_if_addrs()
        for iface, c2 in snap2.items():
            if iface not in snap1:
                continue
            c1  = snap1[iface]
            rx  = (c2.bytes_recv - c1.bytes_recv) // 2
            tx  = (c2.bytes_sent - c1.bytes_sent) // 2
            ip  = "—"
            for addr in addrs.get(iface, []):
                if addr.family.name == "AF_INET":
                    ip = addr.address
                    break
            print(f"  {iface:<12} {ip:<18} {_fmt_bytes(rx):<12} {_fmt_bytes(tx):<12}"
                  f" {_fmt_bytes(c2.bytes_recv):<12} {_fmt_bytes(c2.bytes_sent)}")

    except ImportError:
        print_warn("psutil not installed — run: pip install psutil")


# ── Top Processes ──────────────────────────────────────────────────────────────

def _top_processes():
    print_section("Top Processes")
    try:
        import psutil

        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Let cpu_percent warm up
        time.sleep(0.5)
        procs = sorted(procs, key=lambda x: x["cpu_percent"] or 0, reverse=True)[:10]

        print(f"\n  {'PID':<8} {'CPU%':<8} {'MEM%':<8} NAME")
        print(f"  {'─'*8} {'─'*8} {'─'*8} {'─'*20}")
        for p in procs:
            cpu = f"{p['cpu_percent']:.1f}"
            mem = f"{p['memory_percent']:.1f}"
            print(f"  {p['pid']:<8} {Color.CYAN}{cpu:<8}{Color.RESET} {mem:<8} {p['name']}")

    except ImportError:
        # Fallback: ps aux on Linux
        try:
            result = subprocess.run(
                ["ps", "aux", "--sort=-%cpu"],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.splitlines()[:11]
            for line in lines:
                print(f"  {line}")
        except Exception:
            print_warn("psutil not installed — run: pip install psutil")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _read_cpu_temp():
    """Read CPU temperature — works on Raspberry Pi and most Linux systems."""
    # Raspberry Pi thermal zone
    thermal = "/sys/class/thermal/thermal_zone0/temp"
    if os.path.exists(thermal):
        with open(thermal) as f:
            return int(f.read().strip()) / 1000.0

    # Try vcgencmd (Raspberry Pi OS)
    try:
        out = subprocess.check_output(
            ["vcgencmd", "measure_temp"],
            stderr=subprocess.DEVNULL, text=True, timeout=2
        )
        return float(out.strip().replace("temp=", "").replace("'C", ""))
    except Exception:
        pass

    return None


def _read_proc_meminfo() -> dict:
    """Parse /proc/meminfo into {key: value_in_kb}."""
    result = {}
    if not os.path.exists("/proc/meminfo"):
        return result
    with open("/proc/meminfo") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].rstrip(":")
                try:
                    result[key] = int(parts[1])
                except ValueError:
                    pass
    return result


def _bar(label: str, value: float, maximum: float, suffix: str = ""):
    """Print a simple ASCII progress bar."""
    width   = 20
    filled  = int(width * value / maximum)
    color   = Color.RED if value > 80 else (Color.YELLOW if value > 60 else Color.GREEN)
    bar     = f"{color}{'█' * filled}{'░' * (width - filled)}{Color.RESET}"
    pct_str = f"{value:5.1f}%"
    print(f"  {Color.CYAN}{label:<6}{Color.RESET} [{bar}] {pct_str}{suffix}")


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n //= 1024
    return f"{n:.1f}TB"


def _print_header(title: str):
    now = time.strftime("%H:%M:%S")
    print(f"  {Color.CYAN}{title}{Color.RESET}  {Color.DIM}{now}{Color.RESET}\n")
