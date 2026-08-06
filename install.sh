#!/bin/bash
# VPN Firewall - Installation script
# Usage: sudo bash install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║     VPN FIREWALL - INSTALLATION SCRIPT      ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script requires root privileges!${NC}"
    echo "Usage: sudo bash install.sh"
    exit 1
fi

INSTALL_DIR="/opt/firewall"

echo -e "${YELLOW}[1/6]${NC} Updating system packages..."
apt-get update -qq

echo -e "${YELLOW}[2/6]${NC} Installing required packages..."
apt-get install -y -qq python3 python3-pip python3-venv iptables

echo -e "${YELLOW}[3/6]${NC} Creating firewall directory..."
mkdir -p ${INSTALL_DIR}
cp -r . ${INSTALL_DIR}/
cd ${INSTALL_DIR}

echo -e "${YELLOW}[4/6]${NC} Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt

echo -e "${YELLOW}[5/6]${NC} Creating data directories..."
mkdir -p ${INSTALL_DIR}/data
mkdir -p ${INSTALL_DIR}/logs
touch ${INSTALL_DIR}/data/blocked_domains.txt
touch ${INSTALL_DIR}/data/blocked_ips.txt
touch ${INSTALL_DIR}/data/whitelist.txt

echo -e "${YELLOW}[6/6]${NC} Installing systemd service..."
cp firewall.service /etc/systemd/system/firewall.service
systemctl daemon-reload
systemctl enable firewall.service

echo ""
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo ""
echo "  To start the service:"
echo "    sudo systemctl start firewall"
echo ""
echo "  Web panel:"
echo "    http://server-ip:9450"
echo ""
echo "  Default login:"
echo "    Username: admin"
echo "    Password: admin123"
echo ""
echo -e "${YELLOW}  WARNING: Make sure to change the password!${NC}"
echo ""
