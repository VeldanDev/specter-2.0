# SPECTRE 2.0

**Portable network inspection & security toolkit.** Boots into a menu-driven
terminal UI, runs a live system check first, then hands off to whichever
module you need — built lean enough to run on a Raspberry Pi Zero 2 W.

```
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝

  v2.0.0  Portable Network Inspection & Security Toolkit
```

## Install

```bash
# Raspberry Pi Zero 2 W (or any Debian-based board)
sudo bash install.sh

# or run directly with Python 3.7+
python3 boot.py
```

Windows is supported too — `boot.py` checks `os.name` and adapts (admin
check, RAM/disk snapshot) accordingly, though some modules that need raw
sockets are marked "limited" outside Linux.

## What it does

On startup, `boot.py` runs a system check (Python version, root/admin
status, whether `nmap` is on PATH) and prints a live RAM/disk snapshot
before handing off to the main menu:

```
[1]  [✓]  Network Scanning
[2]  [✓]  WiFi Analysis
[3]  [~]  Bluetooth Scanning
[4]  [✓]  OSINT Tools
[5]  [✓]  System Monitoring
[6]  [✓]  Network Monitor
[7]  [✓]  Packet Sniffer
[8]  [✓]  Threat Detection
[9]  [✓]  Toolkit

[H]  Help & About   [L]  View Saved Logs   [R]  Generate HTML Report
```

`[✓]` = fully available on this OS, `[~]` = limited (some modules need raw
sockets or platform APIs only available on Linux).

## Modules

| Module | File | Does |
| --- | --- | --- |
| Network Scanning | `modules/network_scan.py` | Host/port discovery on the local network |
| WiFi Analysis | `modules/wifi_analysis.py` | Nearby network survey |
| Bluetooth Scanning | `modules/bluetooth_scan.py` | Nearby device discovery |
| OSINT Tools | `modules/osint.py` | Public information gathering |
| System Monitoring | `modules/system_monitor.py` | Live CPU/RAM/disk |
| Network Monitor | `modules/net_monitor.py` | Ongoing traffic/connection watch |
| Packet Sniffer | `modules/packet_sniffer.py` | Raw packet capture |
| Threat Detection | `modules/threat_detect.py` | Flags suspicious activity from the above |
| Toolkit | `modules/toolkit.py` | Misc utilities |

Every module shares the same `core/` layer (`display.py` for the terminal
UI, `system.py` for startup checks), which is what keeps the toolkit small
enough to fit on constrained hardware instead of each module reinventing
its own I/O.

## Why a Pi Zero

Field recon usually means carrying a laptop and juggling five different
single-purpose tools. SPECTRE is built to run standalone on hardware the
size of a Pi Zero 2 W — one boot, one menu, everything in one place.

## Windows note

`boot.py`'s banner uses box-drawing Unicode. On Windows, run it with
`PYTHONIOENCODING=utf-8` set (or `chcp 65001` first) if you see a
`UnicodeEncodeError` — that's a console codepage issue, not a bug in the
tool.

## License

MIT
