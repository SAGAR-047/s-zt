#!/usr/bin/env bash
# ==============================================================================
# SentinelCloud: Cloud Backend & Microservices Launcher
# Starts the 4 medical microservices and the FastAPI backend server.
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

# Activate virtual environment if present
if [ -d "venv" ]; then
    source venv/bin/activate
fi

echo "[1/2] Starting Medical Microservices..."
python3 services/medical/vitals/app.py &
VITALS_PID=$!
python3 services/medical/drug-dispenser/app.py &
DISPENSER_PID=$!
python3 services/medical/ehr/app.py &
EHR_PID=$!
python3 services/medical/billing/app.py &
BILLING_PID=$!

sleep 1

cleanup() {
    echo "Shutting down SentinelCloud microservices and backend..."
    kill $VITALS_PID $DISPENSER_PID $EHR_PID $BILLING_PID $BACKEND_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "[2/2] Starting SentinelCloud Unified Backend on port 5050..."
python3 -m backend.main &
BACKEND_PID=$!

wait $BACKEND_PID
