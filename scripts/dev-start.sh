#!/usr/bin/env bash
# ==============================================================================
# SentinelCloud-Advanced: Dev Runner
# Starts:
#   1. Backend API + WebSocket (:5050)
#   2. Next.js Dashboard (:3000)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  SentinelCloud-Advanced · Development Mode            ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Create .env if not exists
if [ ! -f ".env" ]; then
    echo -e "[1/4] Creating .env from template..."
    cp .env.example .env
    echo -e "  ${GREEN}✔${NC} .env created — review and update credentials"
fi

# Ensure data directory
mkdir -p data

# Kill existing processes on ports
echo -e "[2/5] Checking ports 5000-5003, 5050, 3000..."
lsof -ti:5000 | xargs kill -9 2>/dev/null || true
lsof -ti:5001 | xargs kill -9 2>/dev/null || true
lsof -ti:5002 | xargs kill -9 2>/dev/null || true
lsof -ti:5003 | xargs kill -9 2>/dev/null || true
lsof -ti:5050 | xargs kill -9 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

# Start Medical Microservices
echo -e "[3/5] Starting Medical Microservices (vitals:5000, dispenser:5001, ehr:5002, billing:5003)..."
python3 services/medical/vitals/app.py > data/vitals.log 2>&1 &
VITALS_PID=$!
python3 services/medical/drug-dispenser/app.py > data/dispenser.log 2>&1 &
DISPENSER_PID=$!
python3 services/medical/ehr/app.py > data/ehr.log 2>&1 &
EHR_PID=$!
python3 services/medical/billing/app.py > data/billing.log 2>&1 &
BILLING_PID=$!

sleep 1

# Start Backend
echo -e "[4/5] Starting Backend on ${GREEN}http://0.0.0.0:5050${NC}..."
export SENTINEL_MODE=dev
python3 -m backend.main > data/backend.log 2>&1 &
BACKEND_PID=$!

sleep 2

# Start Frontend
echo -e "[5/5] Starting Dashboard on ${GREEN}http://localhost:3000${NC}..."
npx next dev -H 0.0.0.0 -p 3000 > data/frontend.log 2>&1 &
FRONTEND_PID=$!

echo ""
echo -e "${GREEN}✔ SentinelCloud Dev Environment Ready${NC}"
echo -e "═══════════════════════════════════════════════════════"
echo -e "  ${CYAN}🛡  Dashboard:${NC}    http://localhost:3000"
echo -e "  ${CYAN}📡  Backend API:${NC}  http://localhost:5050"
echo -e "  ${CYAN}📄  API Docs:${NC}     http://localhost:5050/docs"
echo -e "  ${CYAN}🏥  Medical Services:${NC}"
echo -e "      • Vitals:         http://localhost:5000"
echo -e "      • Drug Dispenser: http://localhost:5001"
echo -e "      • EHR:            http://localhost:5002"
echo -e "      • Billing:        http://localhost:5003"
echo -e "  ${CYAN}⚙  Mode:${NC}         DEV (no infra required)"
echo -e "═══════════════════════════════════════════════════════"
echo -e "Press Ctrl+C to stop."
echo ""

cleanup() {
    echo -e "\nShutting down SentinelCloud..."
    kill $VITALS_PID $DISPENSER_PID $EHR_PID $BILLING_PID $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM
wait
