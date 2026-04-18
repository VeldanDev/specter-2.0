"""
core/system.py — Startup checks: root privileges, Python version, platform info.
boot.py calls these before handing off to the menu.
"""

import os
import sys
import platform
import subprocess
from core.display import print_ok, print_warn, print_err, print_info, Color


MIN_PYTHON = (3, 7)


def check_python_version() -> bool:
    if sys.version_info < MIN_PYTHON:
        print_err(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required. Found {sys.version.split()[0]}")
        return False
    print_ok(f"Python {sys.version.split()[0]}")
    return True


def check_root() -> bool:
    """Root/admin is required for raw socket operations (nmap, scapy, etc.)."""
    if os.name == "nt":
        # Windows: check for admin via a harmless net session call
        try:
            subprocess.check_output("net session", stderr=subprocess.DEVNULL, shell=True)
            print_ok("Running as Administrator")
            return True
        except subprocess.CalledProcessError:
            print_warn("Not running as Administrator — some modules may fail")
            return False
    else:
        if os.geteuid() == 0:
            print_ok("Running as root")
            return True
        else:
            print_warn("Not running as root — some modules may fail")
            return False


def check_dependency(cmd: str, label: str) -> bool:
    """Return True if an external tool is available on PATH."""
    try:
        subprocess.run(
            [cmd, "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
        print_ok(f"{label} found")
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print_warn(f"{label} not found — install it for full functionality")
        return False


def print_platform_info():
    node = platform.node()
    system = platform.system()
    arch = platform.machine()
    print_info(f"Host: {node}  |  OS: {system}  |  Arch: {arch}")


def run_all_checks() -> dict:
    """
    Run all startup checks and return a status dict.
    The menu can use this to disable unavailable options gracefully.
    """
    print_platform_info()
    status = {
        "python_ok": check_python_version(),
        "root":      check_root(),
        "nmap":      check_dependency("nmap", "nmap"),
    }
    return status
