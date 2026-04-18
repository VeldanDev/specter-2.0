"""
boot.py — SPECTRE entry point.
Runs startup checks then hands control to the main menu.
"""

import sys
import time
from core.display import print_banner, print_section, typewriter, Color
from core.system  import run_all_checks


def _mini_dashboard():
    """Show a small CPU/RAM/disk snapshot before entering the menu."""
    try:
        import shutil
        import platform

        # RAM — read /proc/meminfo on Linux, else skip
        ram_str = ""
        try:
            with open("/proc/meminfo") as f:
                lines = {l.split(":")[0]: int(l.split()[1])
                         for l in f if ":" in l}
            total_mb = lines["MemTotal"] // 1024
            avail_mb = lines["MemAvailable"] // 1024
            used_mb  = total_mb - avail_mb
            pct      = used_mb / total_mb * 100
            color    = Color.RED if pct > 80 else (Color.YELLOW if pct > 60 else Color.GREEN)
            ram_str  = f"{color}{used_mb} MB / {total_mb} MB  ({pct:.0f}%){Color.RESET}"
        except Exception:
            try:
                import ctypes
                class MEMSTATUS(ctypes.Structure):
                    _fields_ = [("dwLength", ctypes.c_ulong),
                                 ("dwMemoryLoad", ctypes.c_ulong),
                                 ("ullTotalPhys", ctypes.c_ulonglong),
                                 ("ullAvailPhys", ctypes.c_ulonglong),
                                 *[(f"_r{i}", ctypes.c_ulonglong) for i in range(5)]]
                ms = MEMSTATUS()
                ms.dwLength = ctypes.sizeof(ms)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
                total_mb = ms.ullTotalPhys // (1024*1024)
                avail_mb = ms.ullAvailPhys // (1024*1024)
                used_mb  = total_mb - avail_mb
                pct      = ms.dwMemoryLoad
                color    = Color.RED if pct > 80 else (Color.YELLOW if pct > 60 else Color.GREEN)
                ram_str  = f"{color}{used_mb} MB / {total_mb} MB  ({pct}%){Color.RESET}"
            except Exception:
                ram_str = f"{Color.DIM}unavailable{Color.RESET}"

        # Disk
        try:
            usage   = shutil.disk_usage("/")
            free_gb = usage.free  / (1024**3)
            tot_gb  = usage.total / (1024**3)
            pct_d   = (usage.used / usage.total) * 100
            color_d = Color.RED if pct_d > 90 else (Color.YELLOW if pct_d > 75 else Color.GREEN)
            disk_str = f"{color_d}{free_gb:.1f} GB free / {tot_gb:.1f} GB  ({pct_d:.0f}% used){Color.RESET}"
        except Exception:
            disk_str = f"{Color.DIM}unavailable{Color.RESET}"

        # Platform
        plat_str = f"{platform.system()} {platform.machine()}"

        print(f"\n  {Color.CYAN}┌─ System Snapshot {'─'*38}┐{Color.RESET}")
        print(f"  {Color.CYAN}│{Color.RESET}  {'Platform':<10} {plat_str}")
        print(f"  {Color.CYAN}│{Color.RESET}  {'RAM':<10} {ram_str}")
        print(f"  {Color.CYAN}│{Color.RESET}  {'Disk':<10} {disk_str}")
        print(f"  {Color.CYAN}└{'─'*57}┘{Color.RESET}\n")

    except Exception:
        pass


def main():
    print_banner(animate=True)
    time.sleep(0.15)
    typewriter(f"  {Color.DIM}Initializing SPECTRE 2.0 ...{Color.RESET}", delay=0.025)
    time.sleep(0.1)

    print_section("System Check")

    status = run_all_checks()

    if not status["python_ok"]:
        sys.exit(1)

    _mini_dashboard()

    typewriter(f"  {Color.GREEN}All systems nominal. Launching ...{Color.RESET}", delay=0.02)
    time.sleep(0.3)

    # Import menu here so any import errors surface after the banner
    from menu import run_menu
    run_menu(status)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interrupted. Goodbye.\n")
        sys.exit(0)
