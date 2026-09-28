"""
menu.py — Main interactive menu for SPECTRE.
To add a new tool: append an entry to MENU_ITEMS and create its module under modules/.
"""

import os
from core.display import (
    print_banner, print_section, print_status_bar, print_warn, print_err,
    print_ok, print_info, prompt, typewriter, Color
)
from core.logger   import logger
from core.reporter import generate_report
from modules import (
    network_scan, wifi_analysis, bluetooth_scan,
    osint, system_monitor, net_monitor,
    packet_sniffer, threat_detect, toolkit
)

IS_WINDOWS = os.name == "nt"
IS_ROOT    = (os.name != "nt" and os.geteuid() == 0) if hasattr(os, "geteuid") else False


def _module_status(requires_root=False, linux_only=False, tool=None) -> tuple:
    """
    Return (status_char, color) for a menu item based on current environment.
    ✓ green  = fully available
    ~ yellow = limited / partial
    ✗ red    = unavailable
    """
    if linux_only and IS_WINDOWS:
        return "~", Color.YELLOW
    if requires_root and not IS_ROOT and not IS_WINDOWS:
        return "~", Color.YELLOW
    if tool:
        import shutil
        if not shutil.which(tool):
            return "~", Color.YELLOW
    return "✓", Color.GREEN


# Each entry: label, handler, kwargs passed to _module_status
MENU_ITEMS = [
    {
        "label":   "Network Scanning",
        "handler": network_scan.run,
        "status":  {"requires_root": True},
    },
    {
        "label":   "WiFi Analysis",
        "handler": wifi_analysis.run,
        "status":  {},
    },
    {
        "label":   "Bluetooth Scanning",
        "handler": bluetooth_scan.run,
        "status":  {"linux_only": True},
    },
    {
        "label":   "OSINT Tools",
        "handler": osint.run,
        "status":  {},
    },
    {
        "label":   "System Monitoring",
        "handler": system_monitor.run,
        "status":  {},
    },
    {
        "label":   "Network Monitor",
        "handler": net_monitor.run,
        "status":  {"requires_root": True},
    },
    {
        "label":   "Packet Sniffer",
        "handler": packet_sniffer.run,
        "status":  {"requires_root": True},
    },
    {
        "label":   "Threat Detection",
        "handler": threat_detect.run,
        "status":  {},
    },
    {
        "label":   "Toolkit",
        "handler": toolkit.run,
        "status":  {},
    },
]


def _render_menu():
    print_section("Main Menu")
    for i, item in enumerate(MENU_ITEMS, start=1):
        char, color = _module_status(**item["status"])
        print(f"  {Color.CYAN}[{i}]{Color.RESET}  "
              f"{color}[{char}]{Color.RESET}  {item['label']}")

    print(f"\n  {Color.CYAN}[H]{Color.RESET}  {Color.DIM}[ ]  Help & About{Color.RESET}")
    print(f"  {Color.CYAN}[L]{Color.RESET}  {Color.DIM}[ ]  View Saved Logs{Color.RESET}")
    print(f"  {Color.CYAN}[R]{Color.RESET}  {Color.DIM}[ ]  Generate HTML Report{Color.RESET}")
    print(f"  {Color.DIM}[0]       Exit{Color.RESET}")

    # Legend
    print(f"\n  {Color.DIM}Legend: "
          f"{Color.GREEN}[✓] Available  "
          f"{Color.YELLOW}[~] Limited (this OS){Color.RESET}")


def run_menu(status: dict):
    """Main loop — keeps running until the user selects Exit."""
    while True:
        print_banner()
        print_status_bar()
        _render_menu()

        choice = prompt()

        if choice == "0" or choice.lower() in ("exit", "quit", "q"):
            typewriter(f"\n  {Color.CYAN}SPECTRE{Color.RESET} session ended. Stay sharp.\n", delay=0.03)
            break

        if choice.lower() == "h":
            _show_help()
            prompt("Press Enter to return to menu")
            continue

        if choice.lower() == "l":
            _show_logs()
            prompt("Press Enter to return to menu")
            continue

        if choice.lower() == "r":
            _do_generate_report()
            prompt("Press Enter to return to menu")
            continue

        if not choice.isdigit():
            print_warn("Enter a number from the menu.")
            prompt("Press Enter to continue")
            continue

        idx = int(choice) - 1
        if idx < 0 or idx >= len(MENU_ITEMS):
            print_err(f"Invalid choice: {choice}")
            prompt("Press Enter to continue")
            continue

        item = MENU_ITEMS[idx]
        print_banner()

        # Start logging this module session
        logger.start(item["label"])

        try:
            item["handler"](status)
        except KeyboardInterrupt:
            print_warn("\n  Module interrupted.")
        finally:
            logger.stop()

        # Offer to save results
        _offer_save()
        prompt("Press Enter to return to menu")


def _offer_save():
    """Ask user if they want to save the session output to a log file."""
    buf = logger.get_buffer()
    # Only offer if there's meaningful content (more than just the header)
    lines = [l for l in buf.splitlines() if l.strip()]
    if len(lines) <= 4:
        return

    print(f"\n  {Color.DIM}{'─' * 46}{Color.RESET}")
    save = prompt("Save results to log file? [y/N]")
    if save.lower() == "y":
        fpath = logger.save()
        print_ok(f"Saved → {fpath}")


def _show_help():
    """About / Help screen."""
    print_banner()
    print_section("Help & About")

    print(f"  {Color.WHITE}SPECTRE 2.0{Color.RESET} — Portable Network Inspection & Security Toolkit")
    print(f"  {Color.DIM}Designed for Raspberry Pi Zero 2 W | Python 3.7+{Color.RESET}\n")

    print(f"  {Color.CYAN}MODULES{Color.RESET}")
    modules_info = [
        ("Network Scanning",   "ARP scan, TCP port scan, ping sweep"),
        ("WiFi Analysis",      "Scan SSIDs, signal, channel, monitor mode"),
        ("Bluetooth Scanning", "Discover nearby BT devices (Linux/Pi only)"),
        ("OSINT Tools",        "DNS, WHOIS, IP geolocation, subdomain enum"),
        ("System Monitoring",  "Live CPU/RAM/disk/network dashboard"),
        ("Network Monitor",    "Live bandwidth and connection tracking"),
        ("Packet Sniffer",     "Capture and inspect live traffic"),
        ("Threat Detection",   "Flag suspicious network activity"),
        ("Toolkit",            "Misc utilities"),
    ]
    for name, desc in modules_info:
        print(f"  {Color.CYAN}•{Color.RESET} {name:<22} {Color.DIM}{desc}{Color.RESET}")

    print(f"\n  {Color.CYAN}NAVIGATION{Color.RESET}")
    nav = [
        ("[1-9]",   "Enter module"),
        ("[0]",     "Exit SPECTRE"),
        ("[H]",     "This help screen"),
        ("[L]",     "View saved logs"),
        ("[R]",     "Generate HTML report"),
        ("Ctrl+C",  "Stop current scan, return to menu"),
    ]
    for key, desc in nav:
        print(f"  {Color.CYAN}{key:<10}{Color.RESET} {desc}")

    print(f"\n  {Color.CYAN}LOGS{Color.RESET}")
    print(f"  {Color.DIM}Scan results are saved to: logs/<module>_<timestamp>.log{Color.RESET}")

    print(f"\n  {Color.CYAN}PI DEPLOYMENT{Color.RESET}")
    print(f"  {Color.DIM}Run installer : sudo bash install.sh{Color.RESET}")
    print(f"  {Color.DIM}Launch        : python3 boot.py  or  spectre (after install){Color.RESET}")


def _show_logs():
    """List saved log files."""
    print_banner()
    print_section("Saved Logs")

    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        print_warn("No logs directory found. Run a scan first.")
        return

    files = sorted(
        [f for f in os.listdir(logs_dir) if f.endswith(".log")],
        reverse=True
    )

    if not files:
        print_warn("No log files saved yet.")
        return

    print(f"  {'#':<4} {'FILENAME':<45} SIZE")
    print(f"  {'─'*4} {'─'*45} {'─'*8}")
    for i, fname in enumerate(files, 1):
        fpath = os.path.join(logs_dir, fname)
        size  = os.path.getsize(fpath)
        print(f"  {i:<4} {Color.CYAN}{fname:<45}{Color.RESET} {size} B")

    print(f"\n  {Color.DIM}Location: {os.path.abspath(logs_dir)}{Color.RESET}")

    # Offer to read a file
    choice = prompt("Enter number to read a log [Enter to skip]")
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        fpath = os.path.join(logs_dir, files[int(choice) - 1])
        print(f"\n  {Color.CYAN}{'─' * 50}{Color.RESET}\n")
        with open(fpath, encoding="utf-8") as f:
            for line in f:
                print(f"  {line}", end="")
        print(f"\n  {Color.CYAN}{'─' * 50}{Color.RESET}")


def _do_generate_report():
    """Generate HTML report from all saved logs."""
    print_banner()
    print_section("Generate Report")

    if not os.path.exists("logs") or not os.listdir("logs"):
        print_warn("No logs found. Run some scans first, then save results.")
        return

    print_info("Building HTML report from all saved logs...")
    try:
        fpath = generate_report()
        print_ok(f"Report saved → {os.path.abspath(fpath)}")
        print_info("Open the file in any browser to view it.")
    except Exception as e:
        print_err(f"Failed to generate report: {e}")
