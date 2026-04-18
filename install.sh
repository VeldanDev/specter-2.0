#!/bin/bash
# ─────────────────────────────────────────────────────────
# SPECTRE 2.0 — Installer for Raspberry Pi Zero 2 W
# Run as root: sudo bash install.sh
# ─────────────────────────────────────────────────────────

set -e  # stop on any error

SPECTRE_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_FILE="/etc/systemd/system/spectre.service"

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'
YELLOW='\033[93m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[+]${RESET} $1"; }
info() { echo -e "  ${CYAN}[*]${RESET} $1"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $1"; }
err()  { echo -e "  ${RED}[✗]${RESET} $1"; }

# ── Banner ─────────────────────────────────────────────────
clear
echo -e "${CYAN}"
echo "  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗"
echo "  ╚════╝  ╚═════╝ ╚══════╝ ╚═════╝╚═══════╝╚═════╝ ╚══════╝"
echo -e "${RESET}"
echo -e "  ${CYAN}SPECTRE 2.0${RESET} — Raspberry Pi Installer"
echo -e "  ${RESET}──────────────────────────────────────────${RESET}"
echo

# ── Root check ────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    err "Please run as root: sudo bash install.sh"
    exit 1
fi
ok "Running as root"

# ── Detect Raspberry Pi ───────────────────────────────────
if grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
    MODEL=$(grep "Model" /proc/cpuinfo | cut -d: -f2 | xargs)
    ok "Detected: $MODEL"
else
    warn "Not a Raspberry Pi — continuing anyway"
fi

# ── System update ─────────────────────────────────────────
info "Updating package list..."
apt-get update -qq
ok "Package list updated"

# ── Install system packages ───────────────────────────────
PACKAGES=(
    python3
    python3-pip
    nmap
    bluetooth
    bluez
    bluez-tools
    iw
    wireless-tools
    net-tools
    whois
    dnsutils
)

info "Installing packages..."
for pkg in "${PACKAGES[@]}"; do
    if dpkg -l "$pkg" &>/dev/null; then
        ok "$pkg already installed"
    else
        apt-get install -y -qq "$pkg" && ok "$pkg installed"
    fi
done

# ── Install Python packages ───────────────────────────────
info "Installing Python dependencies..."
pip3 install psutil --quiet && ok "psutil installed"

# ── Enable Bluetooth service ──────────────────────────────
info "Enabling Bluetooth service..."
systemctl enable bluetooth --quiet
systemctl start bluetooth
ok "Bluetooth service active"

# ── Fix permissions for raw socket ops ───────────────────
info "Setting capabilities for Python (raw sockets without full root)..."
PYTHON_BIN=$(which python3)
setcap cap_net_raw,cap_net_admin+eip "$PYTHON_BIN" 2>/dev/null && \
    ok "Raw socket capability set on $PYTHON_BIN" || \
    warn "setcap failed — run SPECTRE with sudo for scanning features"

# ── Create systemd service (autorun on boot) ──────────────
info "Creating systemd service for autorun..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SPECTRE 2.0 — Network Inspection Toolkit
After=network.target bluetooth.target

[Service]
Type=simple
User=root
WorkingDirectory=$SPECTRE_DIR
ExecStart=/usr/bin/python3 $SPECTRE_DIR/boot.py
Restart=on-failure
RestartSec=5
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "Service file created: $SERVICE_FILE"

# ── Ask user if they want autorun enabled ─────────────────
echo
echo -e "  ${CYAN}[?]${RESET}  Enable SPECTRE autorun on boot? (y/n)"
read -r -p "      > " AUTORUN

if [[ "$AUTORUN" =~ ^[Yy]$ ]]; then
    systemctl enable spectre
    ok "Autorun enabled — SPECTRE will start on next boot"
else
    warn "Autorun skipped — run manually: python3 $SPECTRE_DIR/boot.py"
fi

# ── Create quick launch alias ─────────────────────────────
PROFILE="/etc/profile.d/spectre.sh"
echo "alias spectre='cd $SPECTRE_DIR && python3 boot.py'" > "$PROFILE"
ok "Alias created — type 'spectre' anywhere to launch"

# ── Done ──────────────────────────────────────────────────
echo
echo -e "  ${GREEN}─────────────────────────────────────────${RESET}"
echo -e "  ${GREEN}  SPECTRE installation complete!${RESET}"
echo -e "  ${GREEN}─────────────────────────────────────────${RESET}"
echo
echo -e "  Launch now : ${CYAN}python3 boot.py${RESET}"
echo -e "  Or type    : ${CYAN}spectre${RESET}  (after re-login)"
echo
