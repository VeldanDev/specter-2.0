"""
core/display.py — UI primitives for SPECTRE.
Handles: ANSI colors, banner, box borders, spinner, status bar, typewriter.
"""

import os
import sys
import time
import socket
import threading

# ── ANSI colors ────────────────────────────────────────────────────────────────

_IS_TTY = sys.stdout.isatty()

class Color:
    RED     = "\033[91m" if _IS_TTY else ""
    GREEN   = "\033[92m" if _IS_TTY else ""
    YELLOW  = "\033[93m" if _IS_TTY else ""
    CYAN    = "\033[96m" if _IS_TTY else ""
    WHITE   = "\033[97m" if _IS_TTY else ""
    DIM     = "\033[2m"  if _IS_TTY else ""
    BOLD    = "\033[1m"  if _IS_TTY else ""
    RESET   = "\033[0m"  if _IS_TTY else ""

# ── Banner ─────────────────────────────────────────────────────────────────────

BANNER_LINES = [
    r"  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗",
    r"  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝",
    r"  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  ",
    r"  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  ",
    r"  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗",
    r"  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝",
]

VERSION = "2.0.0"
TAGLINE = "Portable Network Inspection & Security Toolkit"


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner(animate: bool = False):
    clear_screen()
    if animate:
        for line in BANNER_LINES:
            sys.stdout.write(f"{Color.CYAN}{line}{Color.RESET}\n")
            sys.stdout.flush()
            time.sleep(0.04)
    else:
        for line in BANNER_LINES:
            print(f"{Color.CYAN}{line}{Color.RESET}")

    print(f"\n  {Color.WHITE}{Color.BOLD}v{VERSION}{Color.RESET}  "
          f"{Color.DIM}{TAGLINE}{Color.RESET}")
    print(f"  {Color.DIM}{'─' * 58}{Color.RESET}\n")


# ── Box-style section headers ──────────────────────────────────────────────────

def print_section(title: str):
    width   = 54
    pad     = max(0, width - len(title) - 2)
    left    = pad // 2
    right   = pad - left
    line    = f"{'═' * left} {title} {'═' * right}"
    print(f"\n  {Color.CYAN}╔{line}╗{Color.RESET}\n")


def print_section_end():
    print(f"\n  {Color.DIM}{'╚' + '═' * 56 + '╝'}{Color.RESET}")


# ── Status bar ────────────────────────────────────────────────────────────────

def print_status_bar():
    """
    Show a one-line status bar with hostname, local IP, time, and CPU temp.
    Displayed above the main menu.
    """
    hostname = _get_hostname()
    ip       = _get_local_ip()
    now      = time.strftime("%H:%M:%S")
    temp     = _get_temp()

    temp_str = ""
    if temp is not None:
        color    = Color.RED if temp > 75 else (Color.YELLOW if temp > 60 else Color.GREEN)
        temp_str = f"  {color}{temp:.1f}°C{Color.RESET}  │"

    bar = (
        f"  {Color.DIM}┌─{Color.RESET}"
        f"  {Color.CYAN}{hostname}{Color.RESET}"
        f"  {Color.DIM}│{Color.RESET}"
        f"  {Color.WHITE}{ip}{Color.RESET}"
        f"  {Color.DIM}│{Color.RESET}"
        f"  {Color.DIM}{now}{Color.RESET}"
        f"  {Color.DIM}│{Color.RESET}"
        f"{temp_str}"
        f"  {Color.DIM}SPECTRE v{VERSION}{Color.RESET}"
        f"  {Color.DIM}─┐{Color.RESET}"
    )
    print(bar)


def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def _get_temp() -> float:
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return int(f.read().strip()) / 1000.0
    except Exception:
        return None


# ── Typewriter effect ──────────────────────────────────────────────────────────

def typewriter(text: str, delay: float = 0.03, newline: bool = True):
    """Print text character by character."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ── Spinner ────────────────────────────────────────────────────────────────────

class Spinner:
    """
    Non-blocking spinner. Use as context manager:
        with Spinner("Scanning..."):
            do_work()

    Writes directly to the real stdout so it isn't captured by the logger.
    """
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, label: str = "Working"):
        self._label   = label
        self._stop    = threading.Event()
        self._thread  = threading.Thread(target=self._spin, daemon=True)
        # Write to the real stdout even if logger has replaced sys.stdout
        self._out     = sys.__stdout__

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            self._out.write(
                f"\r  {Color.CYAN}{frame}{Color.RESET}  {self._label} "
            )
            self._out.flush()
            time.sleep(0.1)
            i += 1
        self._out.write("\r" + " " * (len(self._label) + 10) + "\r")
        self._out.flush()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join(timeout=1)


# ── Progress bar ──────────────────────────────────────────────────────────────

def print_progress_bar(current: int, total: int, label: str = "", width: int = 36):
    """
    Print an in-place progress bar.
    Call repeatedly with increasing current; finish with current == total.
    """
    if total == 0:
        return
    pct   = current / total
    filled = int(width * pct)
    bar   = f"{'█' * filled}{'░' * (width - filled)}"
    pct_str = f"{pct*100:5.1f}%"
    line  = (
        f"\r  {Color.CYAN}[{bar}]{Color.RESET} "
        f"{Color.WHITE}{pct_str}{Color.RESET}"
        f"  {Color.DIM}{label}{Color.RESET}   "
    )
    sys.stdout.write(line)
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ── Print helpers ──────────────────────────────────────────────────────────────

def print_ok(msg: str):
    print(f"  {Color.GREEN}[+]{Color.RESET} {msg}")

def print_warn(msg: str):
    print(f"  {Color.YELLOW}[!]{Color.RESET} {msg}")

def print_err(msg: str):
    print(f"  {Color.RED}[✗]{Color.RESET} {msg}")

def print_info(msg: str):
    print(f"  {Color.CYAN}[*]{Color.RESET} {msg}")


def prompt(label: str = "SPECTRE") -> str:
    """Styled input prompt."""
    try:
        return input(
            f"\n  {Color.CYAN}{label}{Color.RESET} {Color.DIM}»{Color.RESET} "
        ).strip()
    except (KeyboardInterrupt, EOFError):
        return ""
