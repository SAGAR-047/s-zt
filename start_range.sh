#!/usr/bin/env bash
# ==============================================================================
# SentinelCloud Cyber-Resilience Platform Runner
# Starts:
#   1. Authoritative FastAPI + Socket.IO Backend (:5050)
#   2. Next.js Resilience Dashboard (:3000)
# ==============================================================================

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   SentinelCloud-Advanced Unified Platform Launcher   ${NC}"
echo -e "${BLUE}======================================================${NC}"

# Kill any existing processes on these ports to avoid conflicts
echo -e "[1/4] Checking ports 5000-5003, 5050, 3000..."
lsof -ti:5000 | xargs kill -9 2>/dev/null || true
lsof -ti:5001 | xargs kill -9 2>/dev/null || true
lsof -ti:5002 | xargs kill -9 2>/dev/null || true
lsof -ti:5003 | xargs kill -9 2>/dev/null || true
lsof -ti:5050 | xargs kill -9 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

# Start Medical Microservices
echo -e "[2/4] Starting Medical Microservices (vitals:5000, dispenser:5001, ehr:5002, billing:5003)..."
python3 services/medical/vitals/app.py > vitals.log 2>&1 &
VITALS_PID=$!
python3 services/medical/drug-dispenser/app.py > dispenser.log 2>&1 &
DISPENSER_PID=$!
python3 services/medical/ehr/app.py > ehr.log 2>&1 &
EHR_PID=$!
python3 services/medical/billing/app.py > billing.log 2>&1 &
BILLING_PID=$!

sleep 1

# Start FastAPI Backend Server
echo -e "[3/4] Starting Unified Backend on ${GREEN}http://0.0.0.0:5050${NC}..."
python3 -m backend.main > backend.log 2>&1 &
BACKEND_PID=$!

sleep 1

# Start Next.js Dev Server
echo -e "[4/4] Starting Resilience Dashboard on ${GREEN}http://localhost:3000${NC}..."
npx next dev -H 0.0.0.0 -p 3000 > frontend.log 2>&1 &
FRONTEND_PID=$!

sleep 2

echo -e "\n${GREEN}✔ SentinelCloud Platform is ready!${NC}"
echo -e "------------------------------------------------------"
echo -e "  🛡️  ${BLUE}Command Center:${NC}      http://localhost:3000"
echo -e "  ⚙️   ${BLUE}Backend API & Sockets:${NC} http://localhost:5050"
echo -e "  🏥  ${BLUE}Medical Services:${NC}"
echo -e "      • Vitals Monitor:       http://localhost:5000"
echo -e "      • Drug Dispenser:       http://localhost:5001"
echo -e "      • Electronic Health:    http://localhost:5002"
echo -e "      • Billing Ledger:       http://localhost:5003"
echo -e "------------------------------------------------------"
echo -e "Press Ctrl+C to stop.\n"

cleanup() {
  echo -e "\nShutting down all SentinelCloud services..."
  kill $VITALS_PID $DISPENSER_PID $EHR_PID $BILLING_PID $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
  exit 0
}

trap cleanup SIGINT SIGTERM

wait
