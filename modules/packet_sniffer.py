"""
modules/packet_sniffer.py — Lightweight packet capture for SPECTRE.

Uses raw sockets (AF_PACKET on Linux, SOCK_RAW on Windows).
Parses: Ethernet → IP → TCP / UDP / ICMP
No third-party libraries — pure Python only.

Requires root/admin for raw socket access.
Pi Zero 2 W: works perfectly with sudo.
"""

import os
import socket
import struct
import time
from core.display import (
    print_info, print_warn, print_err,
    print_section, prompt, Color
)

IS_WINDOWS = os.name == "nt"

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

PROTO_COLORS = {
    "TCP":  Color.CYAN,
    "UDP":  Color.GREEN,
    "ICMP": Color.YELLOW,
    "OTHER": Color.DIM,
}


# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    while True:
        print_section("Packet Sniffer")
        items = [
            "Capture All       — sniff all traffic on interface",
            "Capture Filtered  — filter by protocol (TCP/UDP/ICMP)",
            "HTTP Hunter       — show only HTTP requests",
        ]
        for i, label in enumerate(items, 1):
            print(f"  {Color.CYAN}[{i}]{Color.RESET}  {label}")
        print(f"\n  {Color.DIM}[0]  Back{Color.RESET}")

        choice = prompt("Sniffer")
        if choice in ("0", ""):
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            print_warn("Invalid choice.")
            continue

        handlers = [_capture_all, _capture_filtered, _http_hunter]
        try:
            handlers[int(choice) - 1]()
        except KeyboardInterrupt:
            print_warn("\n  Capture stopped.")
        except PermissionError:
            print_err("Permission denied — run SPECTRE as root/Administrator.")

        prompt("Press Enter to continue")


# ── [1] Capture All ────────────────────────────────────────────────────────────

def _capture_all():
    print_section("Capture — All Traffic")

    iface  = _pick_interface()
    count  = _pick_count()
    proto_filter = None

    _run_capture(iface, count, proto_filter)


# ── [2] Capture Filtered ───────────────────────────────────────────────────────

def _capture_filtered():
    print_section("Capture — Filtered")

    print(f"  {Color.CYAN}[1]{Color.RESET}  TCP only")
    print(f"  {Color.CYAN}[2]{Color.RESET}  UDP only")
    print(f"  {Color.CYAN}[3]{Color.RESET}  ICMP only")
    pf = prompt("Filter")

    proto_map = {"1": 6, "2": 17, "3": 1}
    proto_filter = proto_map.get(pf)
    if not proto_filter:
        print_warn("Invalid filter — capturing all.")
        proto_filter = None

    iface = _pick_interface()
    count = _pick_count()
    _run_capture(iface, count, proto_filter)


# ── [3] HTTP Hunter ────────────────────────────────────────────────────────────

def _http_hunter():
    print_section("HTTP Hunter")
    print_info("Capturing HTTP requests (port 80) — Ctrl+C to stop\n")

    iface = _pick_interface()
    count = _pick_count(default=200)

    print(f"\n  {'TIME':<10} {'SRC':<22} {'DST':<22} METHOD  PATH")
    print(f"  {'─'*10} {'─'*22} {'─'*22} {'─'*7} {'─'*30}")

    captured = 0
    sock     = _open_socket(iface)
    if not sock:
        return

    try:
        while captured < count:
            raw, _ = sock.recvfrom(65535)
            pkt    = _parse_packet(raw)
            if not pkt or pkt["proto_num"] != 6:
                continue
            if pkt.get("dst_port") != 80 and pkt.get("src_port") != 80:
                continue

            payload = pkt.get("payload", b"")
            if not payload:
                continue

            try:
                text = payload.decode("utf-8", errors="replace")
            except Exception:
                continue

            if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                lines  = text.splitlines()
                parts  = lines[0].split(" ", 2)
                method = parts[0] if len(parts) > 0 else "?"
                path   = parts[1][:40] if len(parts) > 1 else "?"
                ts     = time.strftime("%H:%M:%S")
                print(f"  {Color.DIM}{ts:<10}{Color.RESET} "
                      f"{Color.CYAN}{pkt['src_ip']:<22}{Color.RESET} "
                      f"{pkt['dst_ip']:<22} "
                      f"{Color.GREEN}{method:<7}{Color.RESET} "
                      f"{Color.DIM}{path}{Color.RESET}")
                captured += 1
    finally:
        sock.close()


# ── Core capture engine ────────────────────────────────────────────────────────

def _run_capture(iface: str, count: int, proto_filter):
    name = PROTO_NAMES.get(proto_filter, "All") if proto_filter else "All"
    print_info(f"Capturing {count} packets ({name}) on {iface} — Ctrl+C to stop\n")

    print(f"  {'TIME':<10} {'PROTO':<6} {'SRC':<22} {'DST':<22} {'SIZE':>6}  INFO")
    print(f"  {'─'*10} {'─'*6} {'─'*22} {'─'*22} {'─'*6}  {'─'*20}")

    sock = _open_socket(iface)
    if not sock:
        return

    captured = 0
    try:
        while captured < count:
            raw, _ = sock.recvfrom(65535)
            pkt    = _parse_packet(raw)
            if not pkt:
                continue
            if proto_filter and pkt["proto_num"] != proto_filter:
                continue

            proto = pkt["proto"]
            color = PROTO_COLORS.get(proto, Color.DIM)
            ts    = time.strftime("%H:%M:%S")
            info  = _pkt_info(pkt)

            src = f"{pkt['src_ip']}:{pkt.get('src_port','')}" if pkt.get('src_port') else pkt['src_ip']
            dst = f"{pkt['dst_ip']}:{pkt.get('dst_port','')}" if pkt.get('dst_port') else pkt['dst_ip']

            print(f"  {Color.DIM}{ts:<10}{Color.RESET} "
                  f"{color}{proto:<6}{Color.RESET} "
                  f"{src:<22} {dst:<22} "
                  f"{pkt['size']:>6}B  "
                  f"{Color.DIM}{info}{Color.RESET}")
            captured += 1
    finally:
        sock.close()

    print(f"\n  {Color.CYAN}Captured {captured} packet(s).{Color.RESET}")


# ── Packet parser ──────────────────────────────────────────────────────────────

def _parse_packet(raw: bytes) -> dict:
    """Parse raw bytes into a packet dict. Returns None if unparseable."""
    try:
        if IS_WINDOWS:
            # Windows raw socket gives IP header directly
            ip_start = 0
        else:
            # Linux AF_PACKET gives Ethernet frame
            if len(raw) < 14:
                return None
            eth_type = struct.unpack("!H", raw[12:14])[0]
            if eth_type != 0x0800:   # only IPv4
                return None
            ip_start = 14

        ip = raw[ip_start:]
        if len(ip) < 20:
            return None

        ihl      = (ip[0] & 0x0F) * 4
        proto    = ip[9]
        src_ip   = socket.inet_ntoa(ip[12:16])
        dst_ip   = socket.inet_ntoa(ip[16:20])
        pkt_size = len(raw)

        result = {
            "proto_num": proto,
            "proto":     PROTO_NAMES.get(proto, f"#{proto}"),
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "size":      pkt_size,
            "payload":   b"",
        }

        transport = ip[ihl:]

        if proto == 6 and len(transport) >= 20:   # TCP
            result["src_port"] = struct.unpack("!H", transport[0:2])[0]
            result["dst_port"] = struct.unpack("!H", transport[2:4])[0]
            data_offset        = ((transport[12] >> 4) * 4)
            result["payload"]  = transport[data_offset:]
            result["flags"]    = transport[13]

        elif proto == 17 and len(transport) >= 8:  # UDP
            result["src_port"] = struct.unpack("!H", transport[0:2])[0]
            result["dst_port"] = struct.unpack("!H", transport[2:4])[0]
            result["payload"]  = transport[8:]

        return result
    except Exception:
        return None


def _pkt_info(pkt: dict) -> str:
    proto = pkt["proto_num"]
    if proto == 6:
        flags = pkt.get("flags", 0)
        flag_str = ""
        if flags & 0x02: flag_str += "SYN "
        if flags & 0x10: flag_str += "ACK "
        if flags & 0x01: flag_str += "FIN "
        if flags & 0x04: flag_str += "RST "
        return flag_str.strip() or "TCP"
    if proto == 17:
        return "UDP"
    if proto == 1:
        return "ICMP ping"
    return ""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _open_socket(iface: str):
    """Open a raw socket for packet capture."""
    try:
        if IS_WINDOWS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
            if iface and iface != "any":
                sock.bind((iface, 0))
        sock.settimeout(5)
        return sock
    except PermissionError:
        print_err("Raw socket requires root — run: sudo python3 boot.py")
        return None
    except Exception as e:
        print_err(f"Socket error: {e}")
        return None


def _pick_interface() -> str:
    if IS_WINDOWS:
        return "any"
    default = _detect_iface()
    val = prompt(f"Interface [{default}]")
    return val.strip() if val.strip() else default


def _detect_iface() -> str:
    net_dir = "/sys/class/net"
    if os.path.exists(net_dir):
        for iface in os.listdir(net_dir):
            if iface.startswith(("wlan", "eth", "en")):
                return iface
    return "eth0"


def _pick_count(default: int = 50) -> int:
    val = prompt(f"Packet count [{default}]")
    try:
        return int(val) if val.strip() else default
    except ValueError:
        return default
