#!/bin/bash
# VPN Firewall - Quraşdırma skripti
# İstifadə: sudo bash install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║     VPN FIREWALL - QURAŞDIRMA SKRİPTİ      ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Root yoxlaması
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Xəta: Bu skript root hüquqları tələb edir!${NC}"
    echo "İstifadə: sudo bash install.sh"
    exit 1
fi

INSTALL_DIR="/opt/firewall"

echo -e "${YELLOW}[1/6]${NC} Sistem paketləri yenilənir..."
apt-get update -qq

echo -e "${YELLOW}[2/6]${NC} Lazımi paketlər quraşdırılır..."
apt-get install -y -qq python3 python3-pip python3-venv iptables

echo -e "${YELLOW}[3/6]${NC} Firewall qovluğu yaradılır..."
mkdir -p ${INSTALL_DIR}
cp -r . ${INSTALL_DIR}/
cd ${INSTALL_DIR}

echo -e "${YELLOW}[4/6]${NC} Python virtual mühit yaradılır..."
python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt

echo -e "${YELLOW}[5/6]${NC} Data qovluqları yaradılır..."
mkdir -p ${INSTALL_DIR}/data
mkdir -p ${INSTALL_DIR}/logs
touch ${INSTALL_DIR}/data/blocked_domains.txt
touch ${INSTALL_DIR}/data/blocked_ips.txt
touch ${INSTALL_DIR}/data/whitelist.txt

echo -e "${YELLOW}[6/6]${NC} Systemd service quraşdırılır..."
cp firewall.service /etc/systemd/system/firewall.service
systemctl daemon-reload
systemctl enable firewall.service

echo ""
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Quraşdırma tamamlandı!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo ""
echo "  Servisi başlatmaq üçün:"
echo "    sudo systemctl start firewall"
echo ""
echo "  Veb panel:"
echo "    http://server-ip:9450"
echo ""
echo "  Default giriş:"
echo "    İstifadəçi: admin"
echo "    Parol: admin123"
echo ""
echo -e "${YELLOW}  DİQQƏT: Parolu mütləq dəyişdirin!${NC}"
echo ""
