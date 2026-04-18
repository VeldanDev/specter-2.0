"""
core/logger.py — Session logger for SPECTRE.
Intercepts all print() output during a module run, then offers to save it.
No changes needed in individual modules — works transparently.
"""

import os
import re
import sys
from datetime import datetime


class Logger:
    def __init__(self):
        self._buffer        = []
        self._original      = sys.stdout
        self._active        = False
        self._module_name   = ""

    def start(self, module_name: str):
        """Begin capturing output for this module session."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._module_name = module_name
        self._buffer = [
            f"SPECTRE 2.0 — {module_name}\n",
            f"Timestamp : {ts}\n",
            f"{'─' * 50}\n\n",
        ]
        self._active = True
        sys.stdout = self

    def stop(self):
        """Stop capturing and restore stdout."""
        self._active = False
        sys.stdout   = self._original

    def save(self) -> str:
        """Save buffered output to logs/ directory. Returns file path."""
        os.makedirs("logs", exist_ok=True)
        ts    = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        tag   = self._module_name.lower().replace(" ", "_")
        fpath = os.path.join("logs", f"{tag}_{ts}.log")

        clean    = _strip_ansi("".join(self._buffer))
        filtered = _filter_navigation(clean)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(filtered)
        return fpath

    def get_buffer(self) -> str:
        return "".join(self._buffer)

    # ── stdout duck-typing ─────────────────────────────────
    def write(self, text: str):
        if self._active:
            self._buffer.append(text)
        self._original.write(text)

    def flush(self):
        self._original.flush()


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes so log files are plain text."""
    return re.sub(r'\033\[[0-9;]*[mK]', '', text)


# Patterns that indicate menu navigation lines — not scan results
_NAV_PATTERNS = re.compile(
    r'^\s*(\[\d+\]\s+\w'           # menu items: [1]  ARP Scan
    r'|\[0\]\s+(Back|Exit)'        # back/exit options
    r'|.*»\s*$'                    # any prompt ending with »
    r'|Press Enter'                # continue prompts
    r'|Legend:'                    # legend line
    r'|Refreshing every'           # live dashboard refresh note
    r'|\[H\]|\[L\]|\[R\]'         # special keys
    r')',
    re.IGNORECASE
)


def _filter_navigation(content: str) -> str:
    """Remove menu/navigation lines, keep only scan result lines."""
    lines  = content.splitlines()
    result = []

    for line in lines:
        stripped = line.strip()
        if _NAV_PATTERNS.match(stripped):
            continue
        result.append(line)

    # Collapse more than 2 consecutive blank lines into 1
    collapsed = []
    blank_run = 0
    for line in result:
        if line.strip() == "":
            blank_run += 1
            if blank_run <= 1:
                collapsed.append(line)
        else:
            blank_run = 0
            collapsed.append(line)

    # Strip leading/trailing blank lines
    while collapsed and not collapsed[0].strip():
        collapsed.pop(0)
    while collapsed and not collapsed[-1].strip():
        collapsed.pop()

    return "\n".join(collapsed) + "\n"


# Global singleton — imported by menu.py
logger = Logger()
