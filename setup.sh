#!/usr/bin/env bash
set -e
C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'; NC='\033[0m'
echo -e "${C}"
echo "  ██╗    ██╗██╗██████╗ ███████╗███████╗██╗   ██╗███████╗"
echo "  ██║    ██║██║██╔══██╗██╔════╝██╔════╝╚██╗ ██╔╝██╔════╝"
echo "  ██║ █╗ ██║██║██████╔╝█████╗  █████╗   ╚████╔╝ █████╗  "
echo "  ██║███╗██║██║██╔══██╗██╔══╝  ██╔══╝    ╚██╔╝  ██╔══╝  "
echo "  ╚███╔███╔╝██║██║  ██║███████╗███████╗   ██║   ███████╗"
echo "   ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚══════╝"
echo -e "${NC}"
echo -e "${Y}  PCAP Forensics Platform — Kali Linux Setup${NC}"
echo ""

mkdir -p wireeye/static

echo -e "${G}[1/3] System packages...${NC}"
sudo apt-get update -qq
sudo apt-get install -y python3-pip python3-venv tshark libpcap-dev

echo -e "${G}[2/3] Python virtual environment...${NC}"
python3 -m venv wireeye/venv
source wireeye/venv/bin/activate

echo -e "${G}[3/3] Python dependencies...${NC}"
pip install -q --upgrade pip
pip install -q flask scapy colorama

echo ""
echo -e "${G}✓ Done! Start WireEye:${NC}"
echo "  source wireeye/venv/bin/activate"
echo "  python wireeye/app.py"
echo "  → open http://127.0.0.1:5000"
echo ""
