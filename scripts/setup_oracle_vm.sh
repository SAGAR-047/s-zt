#!/usr/bin/env bash
# ==============================================================================
# SentinelCloud: Automated Setup for Oracle Cloud (OCI) Ubuntu VM
# ==============================================================================
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   SentinelCloud Oracle Cloud VM Setup Script         ${NC}"
echo -e "${BLUE}======================================================${NC}"

# 1. Update OS and install essential tools
echo -e "\n${YELLOW}[1/5] Updating packages and installing prerequisites...${NC}"
sudo apt update -y
sudo apt install -y python3-pip python3-venv git curl iptables-persistent netfilter-persistent

# 2. Configure Host Firewall (Ubuntu on Oracle Cloud)
echo -e "\n${YELLOW}[2/5] Configuring firewall rules for port 5050 and services...${NC}"
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 5050 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 5000:5003 -j ACCEPT
sudo netfilter-persistent save 2>/dev/null || true

# 3. Create Python Virtual Environment & Install Dependencies
echo -e "\n${YELLOW}[3/5] Setting up Python virtual environment...${NC}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt

# 4. Create systemd 24/7 service
echo -e "\n${YELLOW}[4/5] Setting up systemd auto-restart service...${NC}"
CURRENT_USER="$(whoami)"
SERVICE_FILE="/etc/systemd/system/sentinelcloud.service"

sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=SentinelCloud Resilience Backend and Microservices
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/venv/bin:/usr/local/bin:/usr/bin"
Environment="SENTINEL_HOST=0.0.0.0"
Environment="SENTINEL_PORT=5050"
ExecStart=$PROJECT_DIR/scripts/run_cloud_backend.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable sentinelcloud.service

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}✔ Oracle Cloud VM setup completed successfully!${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "To start SentinelCloud as a 24/7 background service:"
echo -e "   ${BLUE}sudo systemctl start sentinelcloud${NC}"
echo -e "To check service status:"
echo -e "   ${BLUE}sudo systemctl status sentinelcloud${NC}"
echo -e "To view live logs:"
echo -e "   ${BLUE}journalctl -u sentinelcloud -f${NC}"
echo -e "------------------------------------------------------"
