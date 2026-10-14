#!/usr/bin/env bash
#
# Start SentinelCloud lab environment using Docker Compose + Next.js dashboard.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Pre-flight check for Docker daemon
if ! docker info >/dev/null 2>&1; then
    echo "❌ Error: Docker daemon is not running."
    echo ""
    echo "Please launch Docker Desktop:"
    echo "  👉 Run: open -a Docker"
    echo "  Wait a moment for Docker to finish starting, then run ./scripts/lab-start.sh again."
    echo ""
    echo "💡 Note: To run without Docker, use Development Mode instead:"
    echo "  👉 Run: ./scripts/dev-start.sh"
    exit 1
fi

echo "Starting SentinelCloud lab environment..."
docker compose up -d 2>/dev/null || docker-compose up -d

echo "Waiting for services to become healthy..."
sleep 5

# Check backend health
echo "Backend health:"
curl -s http://localhost:5050/api/health || echo "Backend not ready yet"
echo ""

# Ensure data directory
mkdir -p data

# Start frontend dashboard if not already running
if ! lsof -ti:3000 >/dev/null 2>&1; then
    echo "Starting Next.js Frontend Dashboard on http://localhost:3000..."
    npx next dev -H 0.0.0.0 -p 3000 > data/frontend.log 2>&1 &
    sleep 3
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✔ SentinelCloud Lab Environment is Ready!"
echo "════════════════════════════════════════════════════════════"
echo "  🛡️  Resilience Dashboard: http://localhost:3000"
echo "  📡  Backend API:          http://localhost:5050"
echo "  📄  API Documentation:    http://localhost:5050/docs"
echo "  🏥  Medical Services:     http://localhost:5000-5003"
echo "  🧠  Intelligence Plane:   http://localhost:8080-8083"
echo "════════════════════════════════════════════════════════════"
echo "To check health: ./scripts/health-check.sh"
echo "To stop all:     ./scripts/stop-all.sh"
