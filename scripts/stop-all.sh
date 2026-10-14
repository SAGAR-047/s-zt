#!/usr/bin/env bash
#
# Stop all SentinelCloud services (both Docker Compose and local processes).
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "Stopping Docker Compose services..."
docker compose down 2>/dev/null || docker-compose down 2>/dev/null || true

echo "Stopping any local backend/frontend processes..."
# Kill processes listening on ports 5050 and 3000 if running
if lsof -t -i:5050 >/dev/null 2>&1; then
    echo "Stopping backend on port 5050"
    kill $(lsof -t -i:5050) 2>/dev/null || true
fi

if lsof -t -i:3000 >/dev/null 2>&1; then
    echo "Stopping frontend on port 3000"
    kill $(lsof -t -i:3000) 2>/dev/null || true
fi

echo "All services stopped."
